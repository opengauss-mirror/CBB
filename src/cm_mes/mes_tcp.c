/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
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
#include "mes_interface.h"
#include "mes_func.h"
#include "mes_msg_pool.h"
#include "cm_memory.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_rwlock.h"
#include "cs_tcp.h"
#include "mes_cb.h"

#define MES_HOST_NAME(id) ((char *)MES_GLOBAL_INST_MSG.profile.inst_net_addr[id].ip)
#define MES_CHANNEL_TIMEOUT (50)
#define MES_CONNECT_TIMEOUT (2000) // mill-seconds

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
        return ERR_MES_PARAM_INVALID;
    }

    alloc_size = sizeof(mes_channel_t *) * CM_MAX_INSTANCES +
        sizeof(mes_channel_t) * CM_MAX_INSTANCES * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    temp_buf = (char *)malloc(alloc_size);
    if (temp_buf == NULL) {
        LOG_RUN_ERR("allocate mes_channel_t failed, channel_cnt %u alloc size %zu",
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
            (void)cm_rwlock_init(&channel->send_lock);
            (void)cm_rwlock_init(&channel->recv_lock);
            mes_init_msgqueue(&channel->msg_queue);
        }
    }

    return CM_SUCCESS;
}

static int mes_read_message_head(cs_pipe_t *pipe, mes_message_head_t *head)
{
    if (cs_read_fixed_size(pipe, (char *)head, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        LOG_RUN_ERR("mes read message head failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (SECUREC_UNLIKELY(head->size < sizeof(mes_message_head_t) || head->size > MES_MESSAGE_BUFFER_SIZE)) {
        MES_LOG_ERR_HEAD_EX(head, "message head size invalid or message length excced");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (SECUREC_UNLIKELY(head->src_inst >= CM_MAX_INSTANCES || head->dst_inst >= CM_MAX_INSTANCES)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid instance id");
        return ERR_MES_INVALID_MSG_HEAD;
    }
    return CM_SUCCESS;
}

static int mes_get_message_buf(mes_message_t *msg, const mes_message_head_t *head)
{
    uint64 stat_time = 0;
    mes_get_consume_time_start(&stat_time);
    char *msg_buf;
    msg_buf = mes_alloc_buf_item(head->size);
    if (SECUREC_UNLIKELY(msg_buf == NULL)) {
        return ERR_MES_ALLOC_MSGITEM_FAIL;
    }
    MES_MESSAGE_ATTACH(msg, msg_buf);
    mes_consume_with_time(head->cmd, MES_TIME_GET_BUF, stat_time);
    return CM_SUCCESS;
}

static void mes_close_recv_pipe(mes_channel_t *channel)
{
    cm_rwlock_wlock(&channel->recv_lock);
    if (!channel->recv_pipe_active) {
        cm_rwlock_unlock(&channel->recv_lock);
        return;
    }
    cs_disconnect(&channel->recv_pipe);
    channel->recv_pipe_active = CM_FALSE;
    cm_rwlock_unlock(&channel->recv_lock);
    return;
}

// receive
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

    // ignore heartbeat msg
    if (head.cmd == MES_CMD_HEARTBEAT) {
        return CM_SUCCESS;
    }

    ret = mes_get_message_buf(&msg, &head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes]mes_get_message_buf failed.");
        return ret;
    }

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
    cs_pipe_t send_pipe = channel->send_pipe;
    char peer_url[MES_URL_BUFFER_SIZE];
    char *remote_host = MES_HOST_NAME(MES_INSTANCE_ID(channel->id));

    ret = snprintf_s(peer_url, MES_URL_BUFFER_SIZE, MES_URL_BUFFER_SIZE, "%s:%hu", remote_host,
        MES_GLOBAL_INST_MSG.profile.inst_net_addr[MES_INSTANCE_ID(channel->id)].port);
    if (ret < 0) {
        LOG_RUN_ERR("snprintf_s error %d", ret);
        return;
    }

    if (cs_connect(peer_url, &send_pipe, NULL) != CM_SUCCESS) {
        /* Deleted spamming LOG_RUN_ERR: can't establish an connection to 'peer_url'. */
        return;
    }

    if (g_ssl_enable) {
        if (cs_ssl_connect(MES_GLOBAL_INST_MSG.ssl_connector_fd, &send_pipe) != CM_SUCCESS) {
            cs_disconnect(&send_pipe);
            return;
        }
    }

    char buf[sizeof(mes_message_head_t)];
    mes_message_head_t *head = (mes_message_head_t *)buf;
    head->cmd = MES_CMD_CONNECT;
    head->dst_inst = 0;
    head->src_inst = (uint8)MES_GLOBAL_INST_MSG.profile.inst_id;
    head->caller_tid = MES_CHANNEL_ID(channel->id); // use caller_tid to represent channel id
    head->size = (uint16)sizeof(mes_message_head_t);
    head->ruid = 0;
    head->flags = 0;
    head->version = 0;

    if (cs_send_bytes(&send_pipe, (char *)head, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(&send_pipe);
        LOG_RUN_ERR("cs_send_bytes failed.");
        return;
    }

    cm_rwlock_wlock(&channel->send_lock);
    channel->send_pipe = send_pipe;
    channel->send_pipe_active = CM_TRUE;
    cm_rwlock_unlock(&channel->send_lock);

    LOG_RUN_INF("[mes] connect to channel peer %s, success.", peer_url);
    return;
}

static void mes_tcp_heartbeat(mes_channel_t *channel)
{
    if (g_timer()->now - channel->last_send_time < MES_HEARTBEAT_INTERVAL * MICROSECS_PER_SECOND) {
        return;
    }

    /* dst_inst and caller_tid used to get current channel in mes_tcp_send_data */
    mes_message_head_t head = { 0 };
    head.cmd = MES_CMD_HEARTBEAT;
    head.dst_inst = MES_INSTANCE_ID(channel->id);
    head.caller_tid = MES_CHANNEL_ID(channel->id);
    head.size = (uint16)sizeof(mes_message_head_t);
    (void)mes_tcp_send_data((void *)&head);
}

static void mes_close_send_pipe(mes_channel_t *channel)
{
    cm_rwlock_wlock(&channel->send_lock);
    if (!channel->send_pipe_active) {
        cm_rwlock_unlock(&channel->send_lock);
        return;
    }
    cs_disconnect(&channel->send_pipe);
    channel->send_pipe_active = CM_FALSE;
    cm_rwlock_unlock(&channel->send_lock);
    return;
}

static void mes_close_channel(mes_channel_t *channel)
{
    mes_close_recv_pipe(channel);
    mes_close_send_pipe(channel);
}

static void mes_channel_entry(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    bool32 ready = CM_FALSE;
    mes_channel_t *channel = (mes_channel_t *)thread->argument;

    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_channel_entry_%u",
        MES_INSTANCE_ID(channel->id)));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = get_mes_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_DEBUG_INF("[mes]: status_notify thread init callback: mes channel entry cb_thread_init done");
    }

    while (!thread->closed) {
        if (!channel->send_pipe_active) {
            mes_tcp_try_connect(channel);
        } else {
            mes_tcp_heartbeat(channel);
        }

        cm_rwlock_wlock(&channel->recv_lock);
        if (!channel->recv_pipe_active) {
            cm_rwlock_unlock(&channel->recv_lock);
            cm_sleep(MES_CHANNEL_TIMEOUT);
            continue;
        }

        if (cs_wait(&channel->recv_pipe, CS_WAIT_FOR_READ, MES_CHANNEL_TIMEOUT, &ready) != CM_SUCCESS) {
            cm_rwlock_unlock(&channel->recv_lock);
            LOG_RUN_ERR("instance %d, recv pipe closed", channel->id);
            mes_close_recv_pipe(channel);
            continue;
        }

        if (!ready) {
            cm_rwlock_unlock(&channel->recv_lock);
            continue;
        }

        if (mes_process_event(channel) == ERR_MES_SOCKET_FAIL) {
            cm_rwlock_unlock(&channel->recv_lock);
            LOG_RUN_ERR("instance %d, recv pipe closed", channel->id);
            mes_close_recv_pipe(channel);
            continue;
        }
        cm_rwlock_unlock(&channel->recv_lock);
    }

    // thread closing, release pipes
    mes_close_channel(channel);
}

static int mes_diag_proto_type(cs_pipe_t *pipe)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    char buffer[sizeof(version_proto_code_t)] = {0};
    version_proto_code_t version_proto_code = {0};
    int32 size;

    if (cs_read_bytes(pipe, buffer, sizeof(version_proto_code_t), &size) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("[mes]:cs_read_bytes failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (size == sizeof(version_proto_code_t)) {
        version_proto_code = *(version_proto_code_t *)buffer;
        if (!IS_BIG_ENDIAN) {
            // Unified big-endian mode for VERSION
            version_proto_code.version = cs_reverse_uint32(version_proto_code.version);
        }
        proto_code = version_proto_code.proto_code;
        pipe->version = version_proto_code.version;
    } else if (size == sizeof(proto_code)) {
        proto_code = *(uint32 *)buffer;
        pipe->version = CS_VERSION_0;
    } else {
        LOG_RUN_ERR("[mes] invalid size[%u].", size);
    }

    if (proto_code != CM_PROTO_CODE) {
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
    if (mes_read_message_head(pipe, msg->head) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("mes read message head failed.");
        return ERR_MES_READ_MSG_FAIL;
    }

    char *buf = msg->buffer + sizeof(mes_message_head_t);
    if (SECUREC_UNLIKELY(msg->head->size < sizeof(mes_message_head_t))) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("mes msg head size invalid.");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (cs_read_fixed_size(pipe, buf, msg->head->size - sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("mes read message body failed.");
        return ERR_MES_READ_MSG_FAIL;
    }
    return CM_SUCCESS;
}

void mes_tcp_disconnect(uint32 inst_id, bool32 wait)
{
    uint32 i;
    mes_channel_t *channel = NULL;
    uint32 channel_cnt = MES_GLOBAL_INST_MSG.profile.channel_cnt;

    for (i = 0; i < channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        if (wait) {
            cm_close_thread(&channel->thread);
        } else {
            cm_close_thread_nowait(&channel->thread);
        }
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
        mes_disconnect(i);
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

static int mes_connect_batch_inner(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    int ret = CM_SUCCESS;
    uint8 inst_id;
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

    return CM_SUCCESS;
}

int mes_connect_single(inst_type inst_id, char* ip, unsigned short port)
{
    if (inst_id > CM_INVALID_ID8) {
        LOG_RUN_ERR("[mes] currently not support id=%u > 255", inst_id);
        return ERR_MES_PARAM_INVALID;
    }

    if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
        return CM_SUCCESS;
    }
    int ret = mes_connect(inst_id, ip, port);
    if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
        LOG_RUN_ERR("[RC] failed to create mes channel to instance %d", inst_id);
        return ret;
    }

    uint32 wait_time = 0;
    while (!mes_connection_ready(inst_id)) {
        const uint8 once_wait_time = 10;
        cm_sleep(once_wait_time);
        wait_time += once_wait_time;
        if (wait_time > MES_CONNECT_TIMEOUT) {
            LOG_RUN_INF("[RC] connect to instance %hhu time out.", inst_id);
            return ERR_MES_CONNECT_TIMEOUT;
        }
    }
    return CM_SUCCESS;
}

int mes_connect_batch_no_wait(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    return mes_connect_batch_inner(inst_id_list, inst_id_cnt);
}

int mes_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    int ret = mes_connect_batch_inner(inst_id_list, inst_id_cnt);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint8 inst_id;
    uint32 wait_time = 0;
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
                LOG_RUN_INF("[RC] connect to instance %hhu time out.", inst_id);
                return ERR_MES_CONNECT_TIMEOUT;
            }
        }
    }
    return CM_SUCCESS;
}

void mes_disconnect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        if (MES_GLOBAL_INST_MSG.profile.inst_id != inst_id_list[i]) {
            mes_disconnect_nowait(inst_id_list[i]);
        }
    }
}

int mes_wait_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    uint8 inst_id;
    uint32 wait_time = 0;
    mes_conn_t *conn;
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
            continue;
        }
        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];
        cm_thread_lock(&conn->lock);
        MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_TRUE;
        cm_thread_unlock(&conn->lock);

        while (!mes_connection_ready(inst_id)) {
            const uint8 once_wait_time = 10;
            cm_sleep(once_wait_time);
            wait_time += once_wait_time;
            if (wait_time > MES_CONNECT_TIMEOUT) {
                LOG_RUN_INF("[RC] connect to instance %u time out.", (uint32)inst_id);
                return ERR_MES_CONNECT_TIMEOUT;
            }
        }
    }
    return CM_SUCCESS;
}

static void mes_close_connect_single(uint32 inst_id)
{
    mes_conn_t *conn;
    uint32 i;
    mes_channel_t *channel = NULL;
    uint32 channel_cnt = MES_GLOBAL_INST_MSG.profile.channel_cnt;

    conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];
    cm_thread_lock(&conn->lock);
    if (!MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
        cm_thread_unlock(&conn->lock);
        LOG_RUN_INF("[mes]: mes_close_connect_single: inst_id %u already disconnect.", inst_id);
        return;
    }

    for (i = 0; i < channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        mes_close_channel(channel);
    }
    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_FALSE;
    cm_thread_unlock(&conn->lock);
    LOG_RUN_INF("[mes]: close connection to node %u.", inst_id);
}

int mes_close_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        if (MES_GLOBAL_INST_MSG.profile.inst_id != inst_id_list[i]) {
            mes_close_connect_single(inst_id_list[i]);
        }
    }
    return CM_SUCCESS;
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
    if (g_ssl_enable) {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL4, "[MEC]mes_accept: start cs_ssl_accept...");
        CM_RETURN_IFERR(cs_ssl_accept(MES_GLOBAL_INST_MSG.ssl_acceptor_fd, pipe));
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_CONNECT_TIMEOUT, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: wait failed.");
        return ERR_MES_WAIT_FAIL;
    }

    ret = mes_read_message(pipe, &msg);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: read message failed.");
        return ret;
    }

    if (msg.head->cmd != (uint8)MES_CMD_CONNECT) {
        LOG_RUN_ERR("when building connection type %hhu", msg.head->cmd);
        return ERR_MES_CMD_TYPE_ERR;
    }

    uint8 chid = MES_CALLER_TID_TO_CHANNEL_ID(msg.head->caller_tid);
    channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[msg.head->src_inst][chid];
    mes_close_recv_pipe(channel);
    cm_rwlock_wlock(&channel->recv_lock);
    channel->recv_pipe = *pipe;
    channel->recv_pipe_active = CM_TRUE;
    channel->recv_pipe.connect_timeout = CM_CONNECT_TIMEOUT;
    channel->recv_pipe.socket_timeout = (int32)CM_INVALID_INT32;
    cm_rwlock_unlock(&channel->recv_lock);
    LOG_RUN_INF("[mes]: mes_accept: channel id %u receive ok.", (uint32)channel->id);
    return CM_SUCCESS;
}

static status_t mes_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mes_accept(pipe);
}

int mes_start_lsnr(void)
{
    char *lsnr_host = MES_HOST_NAME(MES_GLOBAL_INST_MSG.profile.inst_id);

    MEMS_RETURN_IFERR(strncpy_s(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[0], CM_MAX_IP_LEN, lsnr_host,
        CM_MAX_IP_LEN));
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
        LOG_RUN_ERR("[mes]:Start tcp lsnr failed. Host_name: %s, inst_id:%u, port:%hu.",
            lsnr_host, MES_GLOBAL_INST_MSG.profile.inst_id, MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port);
        return ERR_MES_START_LSRN_FAIL;
    }
    LOG_RUN_INF("[mes]: MES LSNR %s:%hu", lsnr_host, MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port);

    return CM_SUCCESS;
}

bool32 mes_tcp_connection_ready(uint32 inst_id)
{
    uint32 i;
    if (inst_id >= CM_MAX_INSTANCES) {
        LOG_RUN_ERR("check tcp connection is failed, inst id:%u", inst_id);
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

int mes_init_tcp_resource(void)
{
    int ret;
    ret = mes_init_message_pool();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes init message pool failed.");
        return ret;
    }

    ret = mes_alloc_channels();
    if (ret != CM_SUCCESS) {
        mes_destory_message_pool();
        LOG_RUN_ERR("mes init channels failed.");
        return ret;
    }

    return CM_SUCCESS;
}

// connect interface
int mes_tcp_connect(uint32 inst_id)
{
    uint32 i;
    mes_channel_t *channel;

    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        channel->id = (inst_id << INST_ID_MOVE_LEFT_BIT_CNT) | i;
        channel->last_send_time = g_timer()->now;

        // wait last thread close finish
        cm_close_thread(&channel->thread);

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
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid)];

    cm_rwlock_wlock(&channel->send_lock);
    if (!channel->send_pipe_active) {
        cm_rwlock_unlock(&channel->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "send pipe to instance %d is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_REDAY;
    }

    mes_get_consume_time_start(&stat_time);
    ret = cs_send_fixed_size(&channel->send_pipe, (char *)msg_data, head->size);
    if (ret != CM_SUCCESS) {
        cm_rwlock_unlock(&channel->send_lock);
        mes_close_send_pipe(channel);
        LOG_RUN_ERR("cs_send_fixed_size failed. instance %d, send pipe closed", channel->id);
        return ERR_MES_SEND_MSG_FAIL;
    }

    channel->last_send_time = g_timer()->now;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_rwlock_unlock(&channel->send_lock);

    (void)cm_atomic_inc(&(channel->send_count));

    return CM_SUCCESS;
}

int mes_tcp_send_bufflist(mes_bufflist_t *buff_list)
{
    uint64 stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)(buff_list->buffers[0].buf);
    mes_channel_t *channel =
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid)];

    cm_rwlock_wlock(&channel->send_lock);
    if (!channel->send_pipe_active) {
        cm_rwlock_unlock(&channel->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "send pipe to instance %d is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_REDAY;
    }
    mes_get_consume_time_start(&stat_time);
    if (head->cmd == MES_CMD_SYNCH_ACK) {
        CM_ASSERT(MES_RUID_GET_RSN((head)->ruid) != 0);
    }
    LOG_DEBUG_INF("Begin tcp send buffer, buffer list cnt is %u. cmd=%hhu, ruid=%llu, ruid->rid=%llu, ruid->rsn=%llu, "
        "src_inst=%hhu, dst_inst=%hhu, size=%hhu.", buff_list->cnt, (head)->cmd, (uint64)head->ruid,
        (uint64)MES_RUID_GET_RID((head)->ruid), (uint64)MES_RUID_GET_RSN((head)->ruid),
        (head)->src_inst, (head)->dst_inst, (head)->size);
    for (int i = 0; i < buff_list->cnt; i++) {
        if (cs_send_fixed_size(&channel->send_pipe, buff_list->buffers[i].buf, buff_list->buffers[i].len) !=
            CM_SUCCESS) {
            cm_rwlock_unlock(&channel->send_lock);
            mes_close_send_pipe(channel);
            LOG_RUN_ERR("cs_send_fixed_size failed. channel %d, errno %d, send pipe closed",
                channel->id, cm_get_os_error());
            return ERR_MES_SEND_MSG_FAIL;
        }
    }
    channel->last_send_time = g_timer()->now;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_rwlock_unlock(&channel->send_lock);

    (void)cm_atomic_inc(&(channel->send_count));
    return CM_SUCCESS;
}
