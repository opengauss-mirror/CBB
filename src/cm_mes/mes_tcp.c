/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * mes_tcp.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_tcp.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes.h"
#include "mes_func.h"
#include "mes_msg_pool.h"
#include "mes_type.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cs_tcp.h"

#define MES_HOST_NAME(id) ((char *)MES_GLOBAL_INST_MSG.profile.inst_net_addr[id].ip)
#define MES_CHANNEL_TIMEOUT (50)
#define MES_SESSION_TO_CHANNEL_ID(sid) (uint8)((sid) % MES_GLOBAL_INST_MSG.profile.channel_cnt)
#define MES_CONNECT_TIMEOUT (60000) // mill-seconds

// channel
int mes_alloc_channels(void)
{
    errno_t ret;
    size_t alloc_size;
    char *temp_buf;
    uint32 i, j;
    mes_channel_t *channel;

    // alloc channel
    if (MES_GLOBAL_INST_MSG.profile.channel_cnt == 0) {
        LOG_RUN_ERR("channel_cnt %u is invalid", MES_GLOBAL_INST_MSG.profile.channel_cnt);
        return ERR_MES_PARAM_INVAIL;
    }

    alloc_size = sizeof(mes_channel_t *) * CM_MAX_INSTANCES +
        sizeof(mes_channel_t) * CM_MAX_INSTANCES * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    temp_buf = (char *)malloc(alloc_size);
    if (temp_buf == NULL) {
        LOG_RUN_ERR("allocate mes_channel_t failed, channel_cnt %u alloc size %ld",
            MES_GLOBAL_INST_MSG.profile.channel_cnt, alloc_size);
        return ERR_MES_MALLOC_FAIL;
    }
    ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        free(temp_buf);
        return ERR_MES_MEMORY_SET_FAIL;
    }

    MES_GLOBAL_INST_MSG.mes_ctx.channels = (mes_channel_t **)temp_buf;
    temp_buf += (sizeof(mes_channel_t *) * CM_MAX_INSTANCES);
    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        MES_GLOBAL_INST_MSG.mes_ctx.channels[i] = (mes_channel_t *)temp_buf;
        temp_buf += sizeof(mes_channel_t) * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    }

    // init channel
    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        for (j = 0; j < MES_GLOBAL_INST_MSG.profile.channel_cnt; j++) {
            channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[i][j];
            channel->send_pipe.connect_timeout = CM_CONNECT_TIMEOUT;
            channel->send_pipe.socket_timeout = CM_SOCKET_TIMEOUT;
            cm_init_thread_lock(&channel->lock);
            mes_init_msgqueue(&channel->msg_queue);
        }
    }

    return CM_SUCCESS;
}

static int mes_read_message_head(cs_pipe_t *pipe, mes_message_head_t *head)
{
    if (cs_read_fixed_size(pipe, (char *)head, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("mes read message head failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE)) {
        LOG_RUN_ERR("message length %u excced max %u", head->size, MES_MESSAGE_BUFFER_SIZE);
        return ERR_MES_MSG_TOO_LARGE;
    }

    return CM_SUCCESS;
}

static void mes_get_message_buf(mes_message_t *msg, const mes_message_head_t *head)
{
    uint64 stat_time = 0;
    mes_get_consume_time_start(&stat_time);
    char *msg_buf;
    msg_buf = mes_alloc_buf_item(head->size);
    MES_MESSAGE_ATTACH(msg, msg_buf);
    mes_consume_with_time(head->cmd, MES_TIME_GET_BUF, stat_time);
    return;
}

static void mes_close_recv_pipe(mes_channel_t *channel)
{
    cm_thread_lock(&channel->lock);
    if (!channel->recv_pipe_active) {
        cm_thread_unlock(&channel->lock);
        return;
    }
    cs_disconnect(&channel->recv_pipe);
    channel->recv_pipe_active = CM_FALSE;
    cm_thread_unlock(&channel->lock);
    return;
}

// recive
static int mes_process_event(mes_channel_t *channel)
{
    uint64 stat_time = 0;
    mes_message_t msg;
    mes_message_head_t head;

    mes_get_consume_time_start(&stat_time);

    int ret = mes_read_message_head(&channel->recv_pipe, &head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]mes_read_message head failed.");
        return ERR_MES_SOCKET_FAIL;
    }

    mes_get_message_buf(&msg, &head);

    errno_t errcode = memcpy_s(msg.buffer, sizeof(mes_message_head_t), &head, sizeof(mes_message_head_t));
    securec_check_ret(errcode);

    ret = cs_read_fixed_size(&channel->recv_pipe, msg.buffer + sizeof(mes_message_head_t),
        msg.head->size - sizeof(mes_message_head_t));
    if (ret != CM_SUCCESS) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("mes read message body failed.");
        return ERR_MES_SOCKET_FAIL;
    }

    mes_consume_with_time(msg.head->cmd, MES_TIME_READ_MES, stat_time);

    (void)cm_atomic_inc(&(channel->recv_count));

    mes_process_message(&channel->msg_queue, MES_CHANNEL_ID(channel->id), &msg);
    return CM_SUCCESS;
}

// connect
static void mes_tcp_try_connect(mes_channel_t *channel)
{
    int32 ret;
    char peer_url[MES_URL_BUFFER_SIZE];
    char *remote_host = MES_HOST_NAME(MES_INSTANCE_ID(channel->id));
    mes_message_head_t head = { 0 };

    ret = snprintf_s(peer_url, MES_URL_BUFFER_SIZE, MES_URL_BUFFER_SIZE, "%s:%d", remote_host,
        MES_GLOBAL_INST_MSG.profile.inst_net_addr[MES_INSTANCE_ID(channel->id)].port);
    if (ret < 0) {
        LOG_RUN_ERR("snprintf_s error %d", ret);
        return;
    }

    cm_thread_lock(&channel->lock);
    if (cs_connect(peer_url, &channel->send_pipe, NULL) != CM_SUCCESS) {
        cm_thread_unlock(&channel->lock);
        /* Deleted spamming LOG_RUN_ERR: can't establish an connection to 'peer_url'. */
        return;
    }
    head.cmd = MES_CONNECT_CMD;
    head.src_inst = MES_GLOBAL_INST_MSG.profile.inst_id;
    head.src_sid = MES_CHANNEL_ID(channel->id); // use sid represent channel id.
    head.size = sizeof(mes_message_head_t);

    if (cs_send_bytes(&channel->send_pipe, (char *)&head, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(&channel->send_pipe);
        cm_thread_unlock(&channel->lock);
        LOG_RUN_ERR("cs_send_bytes failed.");
        return;
    }

    channel->send_pipe_active = CM_TRUE;
    cm_thread_unlock(&channel->lock);
    LOG_RUN_INF("[mes] connect to channel peer %s, success.", peer_url);
    return;
}

static void mes_channel_entry(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    bool32 ready = CM_FALSE;
    mes_channel_t *channel = (mes_channel_t *)thread->argument;

    sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_channel_entry_%d", MES_INSTANCE_ID(channel->id));
    cm_set_thread_name(thread_name);

    while (!thread->closed) {
        if (!channel->send_pipe_active) {
            mes_tcp_try_connect(channel);
        }

        if (!channel->recv_pipe_active) {
            cm_sleep(MES_CHANNEL_TIMEOUT);
            continue;
        }

        if (cs_wait(&channel->recv_pipe, CS_WAIT_FOR_READ, MES_CHANNEL_TIMEOUT, &ready) != CM_SUCCESS) {
            LOG_RUN_ERR("instance %d, recv pipe closed", channel->id);
            mes_close_recv_pipe(channel);
            continue;
        }

        if (!ready) {
            continue;
        }

        if (mes_process_event(channel) == ERR_MES_SOCKET_FAIL) {
            LOG_RUN_ERR("instance %d, recv pipe closed", channel->id);
            mes_close_recv_pipe(channel);
            continue;
        }
    }
}

static int mes_diag_proto_type(cs_pipe_t *pipe)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;

    if (cs_read_bytes(pipe, (char *)&proto_code, sizeof(proto_code), &size) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("[mes]:cs_read_bytes failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (sizeof(proto_code) != size || proto_code != CM_PROTO_CODE) {
        LOG_RUN_ERR("[mes]:invalid protocol.");
        return ERR_MES_PROTOCOL_INVALID;
    }

    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    ack.flags = 0;

    if (cs_send_bytes(pipe, (char *)&ack, sizeof(link_ready_ack_t)) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("[mes]:cs_read_bytes failed.");
        return ERR_MES_SEND_MSG_FAIL;
    }
    return CM_SUCCESS;
}

static int mes_read_message(cs_pipe_t *pipe, mes_message_t *msg)
{
    char *buf;

    if (cs_read_fixed_size(pipe, msg->buffer, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("mes read message head failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (SECUREC_UNLIKELY(msg->head->size > MES_MESSAGE_BUFFER_SIZE)) {
        LOG_RUN_ERR("message length %u excced max %u", msg->head->size, MES_MESSAGE_BUFFER_SIZE);
        return ERR_MES_MSG_TOO_LARGE;
    }

    buf = msg->buffer + sizeof(mes_message_head_t);
    if (cs_read_fixed_size(pipe, buf, msg->head->size - sizeof(mes_message_head_t)) != CM_SUCCESS) {
        LOG_RUN_ERR("mes read message body failed.");
        return ERR_MES_READ_MSG_FAIL;
    }
    return CM_SUCCESS;
}

static void mes_close_send_pipe(mes_channel_t *channel)
{
    cm_thread_lock(&channel->lock);
    if (!channel->send_pipe_active) {
        cm_thread_unlock(&channel->lock);
        return;
    }
    cs_disconnect(&channel->send_pipe);
    channel->send_pipe_active = CM_FALSE;
    cm_thread_unlock(&channel->lock);
    return;
}

static void mes_close_channel(mes_channel_t *channel)
{
    mes_close_recv_pipe(channel);
    mes_close_send_pipe(channel);
}

void mes_tcp_disconnect(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel = NULL;
    uint32 channel_cnt = MES_GLOBAL_INST_MSG.profile.channel_cnt;

    for (i = 0; i < channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        cm_close_thread(&channel->thread);
        mes_close_channel(channel);
    }
}

void mes_stop_channels(void)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.startChannelsTh) {
        return;
    }

    if (MES_GLOBAL_INST_MSG.profile.channel_cnt == 0) {
        LOG_RUN_ERR("channel_cnt %u is invalid", MES_GLOBAL_INST_MSG.profile.channel_cnt);
        return;
    }
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[i].is_connect) {
            mes_tcp_disconnect(i);
            MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[i].is_connect = CM_FALSE;
        }
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startChannelsTh = CM_FALSE;
    return;
}

void mes_free_channels(void)
{
    if (MES_GLOBAL_INST_MSG.mes_ctx.channels == NULL) {
        return;
    }

    free(MES_GLOBAL_INST_MSG.mes_ctx.channels);
    MES_GLOBAL_INST_MSG.mes_ctx.channels = NULL;
    return;
}

int mes_connect_batch(const uint8 *inst_id_list, uint8 inst_id_cnt)
{
    int ret;
    uint8 inst_id;
    uint32 wait_time = 0;
    mes_addr_t *net_addr = MES_GLOBAL_INST_MSG.profile.inst_net_addr;
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
            continue;
        }
        ret = mes_connect(inst_id, net_addr[inst_id].ip, net_addr[inst_id].port);
        if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
            LOG_RUN_ERR("[RC] failed to create mes channel to instance %d", inst_id);
            return ret;
        }
    }

    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
            continue;
        }
        while (!mes_connection_ready(inst_id)) {
            const uint8 once_wait_time = 10;
            cm_sleep(once_wait_time);
            wait_time += once_wait_time;
            if (wait_time > MES_CONNECT_TIMEOUT) {
                LOG_RUN_INF("[RC] connect to instance %u time out.", inst_id);
                return ERR_MES_CONNECT_TIMEOUT;
            }
        }
    }
    return CM_SUCCESS;
}

void mes_disconnect_batch(const uint8 *inst_id_list, uint8 inst_id_cnt)
{
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        if (MES_GLOBAL_INST_MSG.profile.inst_id != inst_id_list[i]) {
            mes_disconnect(inst_id_list[i]);
        }
    }
}

static int mes_accept(cs_pipe_t *pipe)
{
    int ret;
    mes_message_t msg;
    bool32 ready;
    mes_channel_t *channel;
    char msg_buf[MES_MESSAGE_BUFFER_SIZE];
    ret = mes_diag_proto_type(pipe);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: init pipe failed.");
        return ret;
    }

    MES_MESSAGE_ATTACH(&msg, msg_buf);

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_CONNECT_TIMEOUT, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: wait failed.");
        return ERR_MES_WAIT_FAIL;
    }

    ret = mes_read_message(pipe, &msg);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: read message failed.");
        return ret;
    }

    if (msg.head->cmd != (uint8)MES_CONNECT_CMD) {
        LOG_RUN_ERR("when building connection type %u", msg.head->cmd);
        return ERR_MES_CMD_TYPE_ERR;
    }

    channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[msg.head->src_inst][msg.head->src_sid];
    mes_close_recv_pipe(channel);
    cm_thread_lock(&channel->lock);
    channel->recv_pipe = *pipe;
    channel->recv_pipe_active = CM_TRUE;
    channel->recv_pipe.connect_timeout = CM_CONNECT_TIMEOUT;
    channel->recv_pipe.socket_timeout = (int32)CM_INVALID_INT32;
    cm_thread_unlock(&channel->lock);
    LOG_RUN_INF("[mes]: mes_accept: channel %p id %u receive ok.", channel, channel->id);
    return CM_SUCCESS;
}

static status_t mes_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mes_accept(pipe);
}

int mes_start_lsnr(void)
{
    char *lsnr_host = MES_HOST_NAME(MES_GLOBAL_INST_MSG.profile.inst_id);

    strncpy_s(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[0], CM_MAX_IP_LEN, lsnr_host, CM_MAX_IP_LEN);
    MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port =
        MES_GLOBAL_INST_MSG.profile.inst_net_addr[MES_GLOBAL_INST_MSG.profile.inst_id].port;
    MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.type = LSNR_TYPE_MES;

#ifdef WIN32
    if (epoll_init() != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]:epoll init failed.");
        return ERR_MES_EPOLL_INIT_FAIL;
    }
#endif

    if (cs_start_tcp_lsnr(&(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp), mes_tcp_accept) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]:Start tcp lsnr failed.");
        return ERR_MES_START_LSRN_FAIL;
    }

    LOG_RUN_INF("[mes]: MES LSNR %s:%d\n", lsnr_host, MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port);

    return CM_SUCCESS;
}

void mes_stop_lsnr(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == CS_TYPE_TCP) {
        cs_stop_tcp_lsnr(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp);
    } else {
    }
    return;
}

bool32 mes_tcp_connection_ready(uint32 inst_id)
{
    uint32 i;
    if (inst_id >= CM_MAX_INSTANCES) {
        LOG_RUN_ERR("check tcp connection is failed, inst id:%d", inst_id);
        return CM_FALSE;
    }

    mes_channel_t *channel = NULL;
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        if (!channel->recv_pipe_active || !channel->send_pipe_active) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

// connect interface
int mes_tcp_connect(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        channel->id = (inst_id << 8) | i;

        if (cm_create_thread(mes_channel_entry, 0, (void *)channel, &channel->thread) != CM_SUCCESS) {
            LOG_RUN_ERR("create thread channel entry failed, node id %u channel id %u", inst_id, i);
            return ERR_MES_CHANNEL_THREAD_FAIL;
        }
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startChannelsTh = CM_TRUE;
    return CM_SUCCESS;
}

// send
int mes_tcp_send_data(const void *msg_data)
{
    uint64 stat_time = 0;
    int ret;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_channel_t *channel =
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][MES_SESSION_TO_CHANNEL_ID(head->src_sid)];

    cm_thread_lock(&channel->lock);
    if (!channel->send_pipe_active) {
        cm_thread_unlock(&channel->lock);
        LOG_RUN_ERR("send pipe to instance %u is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_REDAY;
    }

    mes_get_consume_time_start(&stat_time);
    ret = cs_send_fixed_size(&channel->send_pipe, (char *)msg_data, head->size);
    if (ret != CM_SUCCESS) {
        cm_thread_unlock(&channel->lock);
        mes_close_send_pipe(channel);
        LOG_RUN_ERR("cs_send_fixed_size failed. instance %d, send pipe closed", channel->id);
        return ERR_MES_SEND_MSG_FAIL;
    }

    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_thread_unlock(&channel->lock);

    (void)cm_atomic_inc(&(channel->send_count));

    return CM_SUCCESS;
}

int mes_tcp_send_bufflist(mes_bufflist_t *buff_list)
{
    uint64 stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)(buff_list->buffers[0].buf);
    mes_channel_t *channel =
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][MES_SESSION_TO_CHANNEL_ID(head->src_sid)];
    int err_no;

    cm_thread_lock(&channel->lock);
    if (!channel->send_pipe_active) {
        cm_thread_unlock(&channel->lock);
        LOG_RUN_ERR("send pipe to instance %u is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_REDAY;
    }

    mes_get_consume_time_start(&stat_time);
    for (int i = 0; i < buff_list->cnt; i++) {
        if (cs_send_fixed_size(&channel->send_pipe, buff_list->buffers[i].buf, buff_list->buffers[i].len) !=
            CM_SUCCESS) {
            err_no = cm_get_os_error();
            cm_thread_unlock(&channel->lock);
            mes_close_send_pipe(channel);
            LOG_RUN_ERR("cs_send_fixed_size failed. channel %d, errno %d, send pipe closed", channel->id, err_no);
            return ERR_MES_SEND_MSG_FAIL;
        }
    }
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_thread_unlock(&channel->lock);

    (void)cm_atomic_inc(&(channel->send_count));
    return CM_SUCCESS;
}
