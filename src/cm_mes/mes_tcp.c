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
#include "mec_adapter.h"
#include "mes_recv.h"

#define MES_HOST_NAME(id) ((char *)MES_GLOBAL_INST_MSG.profile.inst_net_addr[id].ip)
#define MES_CONNECT_TIMEOUT (3000) // mill-seconds
usr_cb_convert_inst_id_t g_cb_convert_inst_id = NULL;
usr_cb_conn_state_change_t g_cb_conn_state_change = NULL;

void mes_init_channels_param(mes_channel_t *channel)
{
    for (uint32 i = 0; i < MES_PRIORITY_CEIL; i++) {
        mes_pipe_t *pipe = &channel->pipe[i];
        (void)cm_rwlock_init(&pipe->send_lock);
        (void)cm_rwlock_init(&pipe->recv_lock);
        pipe->priority = i;
        pipe->channel = channel;
        pipe->send_pipe.connect_timeout = MES_GLOBAL_INST_MSG.profile.connect_timeout;
        pipe->send_pipe.socket_timeout = MES_GLOBAL_INST_MSG.profile.socket_timeout;
        pipe->send_pipe_active = CM_FALSE;
        pipe->recv_pipe_active = CM_FALSE;
        pipe->msgbuf = NULL;
    }

    LOG_DEBUG_INF("[mes] mes_init_channels_param, channel_id:%u, instance_id:%u",
                  MES_CHANNEL_ID(channel->id), MES_INSTANCE_ID(channel->id));
}

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

    alloc_size = sizeof(mes_channel_t *) * MES_MAX_INSTANCES +
            sizeof(mes_channel_t) * MES_MAX_INSTANCES * MES_GLOBAL_INST_MSG.profile.channel_cnt;
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
    temp_buf += (sizeof(mes_channel_t *) * MES_MAX_INSTANCES);
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        MES_GLOBAL_INST_MSG.mes_ctx.channels[i] = (mes_channel_t *)temp_buf;
        temp_buf += sizeof(mes_channel_t) * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    }

    // init channel
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        for (j = 0; j < MES_GLOBAL_INST_MSG.profile.channel_cnt; j++) {
            channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[i][j];
            channel->id = (i << INST_ID_MOVE_LEFT_BIT_CNT) | j;
            mes_init_channels_param(channel);
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

    if (SECUREC_UNLIKELY(head->size < sizeof(mes_message_head_t) ||
            head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
        MES_LOG_ERR_HEAD_EX(head, "message head size invalid or message length excced");
        return ERR_MES_READ_MSG_FAIL;
    }

    if (SECUREC_UNLIKELY(head->src_inst >= MES_MAX_INSTANCES || head->dst_inst >= MES_MAX_INSTANCES)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid instance id");
        return ERR_MES_INVALID_MSG_HEAD;
    }

    if (SECUREC_UNLIKELY(head->cmd >= MES_CMD_MAX)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid cmd");
        return ERR_MES_CMD_TYPE_ERR;
    }

    if (SECUREC_UNLIKELY(MES_PRIORITY(head->flags >= MES_PRIORITY_CEIL))) {
        MES_LOG_ERR_HEAD_EX(head, "invalid priority");
        return ERR_MES_INVALID_MSG_HEAD;
    }

    return CM_SUCCESS;
}

static int mes_get_message_buf(mes_message_t *msg, const mes_message_head_t *head)
{
    uint64 stat_time = 0;
    mes_get_consume_time_start(&stat_time);
    char *msg_buf;
    msg_buf = mes_alloc_buf_item(head->size, CM_FALSE, head->src_inst, MES_PRIORITY(head->flags));
    if (SECUREC_UNLIKELY(msg_buf == NULL)) {
        return ERR_MES_ALLOC_MSGITEM_FAIL;
    }
    MES_MESSAGE_ATTACH(msg, msg_buf);
    mes_consume_with_time(head->cmd, MES_TIME_GET_BUF, stat_time);
    return CM_SUCCESS;
}

void mes_close_recv_pipe(mes_pipe_t *pipe)
{
    cm_rwlock_wlock(&pipe->recv_lock);
    if (!pipe->recv_pipe_active) {
        cm_rwlock_unlock(&pipe->recv_lock);
        return;
    }
    (void)mes_remove_pipe_from_epoll(pipe->priority, pipe->channel->id, cs_get_pipe_sock(&pipe->recv_pipe));
    cs_disconnect(&pipe->recv_pipe);
    pipe->recv_pipe_active = CM_FALSE;
    cm_rwlock_unlock(&pipe->recv_lock);

    LOG_RUN_INF("[mes] mes_close_recv_pipe priority=%u, inst_id=%d, channel_id=%u",
        pipe->priority, MES_INSTANCE_ID(pipe->channel->id), MES_CHANNEL_ID(pipe->channel->id));

    return;
}

static status_t check_recv_head_info(const mes_message_head_t *head, mes_priority_t priority)
{
    mes_priority_t flag_priority = MES_PRIORITY(head->flags);
    if (SECUREC_UNLIKELY(flag_priority != priority)) {
        LOG_DEBUG_ERR("[mes] rcvhead:flag_priority %u not equal with priority %u", flag_priority, priority);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// receive
static int mes_process_event(mes_pipe_t *pipe)
{
    uint64 stat_time = 0;
    mes_message_t msg;
    mes_message_head_t head;

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[mes] phase(%d) not begin, disconnect recv channel_id %d, priority %d",
                      MES_GLOBAL_INST_MSG.mes_ctx.phase, MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return ERR_MES_SOCKET_FAIL;
    }

    uint32 version = CM_INVALID_ID32;
    if (mes_get_pipe_version(&pipe->recv_pipe, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_process_event, mes_get_send_pipe_version failed, channel_id %u, priority %u",
                      MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return ERR_MES_SOCKET_FAIL;
    }
    if (is_old_mec_version(version)) {
        return mec_process_event(pipe);
    }

    mes_get_consume_time_start(&stat_time);

    int ret = mes_read_message_head(&pipe->recv_pipe, &head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_read_message head failed.");
        return ERR_MES_SOCKET_FAIL;
    }

    // ignore heartbeat msg
    if (head.cmd == MES_CMD_HEARTBEAT) {
        return CM_SUCCESS;
    }

    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request) && (head.cmd != MES_CMD_ASYNC_MSG)) {
        LOG_RUN_ERR("[mes] mes_process_event, disable_request = 1, no support send request and get response");
        return ERR_MES_SOCKET_FAIL;
    }

    CM_RETURN_IFERR(check_recv_head_info(&head, pipe->priority));
    if (g_cb_convert_inst_id != NULL) {
        g_cb_convert_inst_id(&head.src_inst, &head.dst_inst);
    }

    ret = mes_get_message_buf(&msg, &head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_get_message_buf failed.");
        return ret;
    }

    errno_t errcode = memcpy_s(msg.buffer, sizeof(mes_message_head_t), &head, sizeof(mes_message_head_t));
    if (errcode != EOK) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("[mes] memcpy_s failed.");
        return CM_ERROR;
    }

    ret = cs_read_fixed_size(&pipe->recv_pipe, msg.buffer + sizeof(mes_message_head_t),
                             msg.head->size - sizeof(mes_message_head_t));
    if (ret != CM_SUCCESS) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("[mes] mes read message body failed.");
        return ERR_MES_SOCKET_FAIL;
    }

    mes_consume_with_time(msg.head->cmd, MES_TIME_READ_MES, stat_time);

    (void)cm_atomic_inc(&(pipe->recv_count));

    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head.caller_tid);
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgqueue_t *my_queue = &mq_ctx->channel_private_queue[head.src_inst][channel_id];
    mes_process_message(my_queue, &msg);
    return CM_SUCCESS;
}

static void mes_show_connect_error_info(const char *url)
{
    static date_t last = 0;
    if ((g_timer()->now - last) > CM_30X_FIXED * MICROSECS_PER_SECOND) {
        LOG_DEBUG_ERR("[mes] cs_connect fail, peer_url=%s, err code %d, err msg %s.", url, cm_get_error_code(),
                      cm_get_errormsg(cm_get_error_code()));
        last = g_timer()->now;
    }
}

// connect
static void mes_tcp_try_connect(mes_pipe_t *pipe)
{
    int32 ret;
    cs_pipe_t send_pipe = pipe->send_pipe;
    char peer_url[MES_URL_BUFFER_SIZE];
    char *remote_host = NULL;
    inst_type inst_id = MES_INSTANCE_ID(pipe->channel->id);
    mes_addr_t *inst_net_addr = NULL;
    uint32 index;

    if (mes_get_inst_net_add_index(inst_id, &index) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_tcp_try_connect, inst net addr is null");
        return;
    }
    inst_net_addr = &MES_GLOBAL_INST_MSG.profile.inst_net_addr[index];

    remote_host = !CM_IS_EMPTY_STR(inst_net_addr->ip) ? inst_net_addr->ip : inst_net_addr->secondary_ip;
    LOG_DEBUG_INF("[mes] try connect to remote host %s", (CM_IS_EMPTY_STR(remote_host)) ? "is empty" : remote_host);
    if (CM_IS_EMPTY_STR(remote_host)) {
        LOG_DEBUG_ERR("[mes] try connect remote host is empty");
        return;
    }

    ret = snprintf_s(peer_url, MES_URL_BUFFER_SIZE, MES_URL_BUFFER_SIZE, "%s:%hu", remote_host, inst_net_addr->port);
    if (ret < 0) {
        LOG_RUN_ERR("[mes] snprintf_s error %d", ret);
        return;
    }

    char *bind_host = !CM_IS_EMPTY_STR(inst_net_addr->ip) ? MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[0]
                                                          : MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[1];
    bind_host = CM_IS_EMPTY_STR(bind_host) ? MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[0] : bind_host;
    LOG_DEBUG_INF("[mes] try connect bind host is %s, inst id %u, channel_id=%u,priority=%u", 
        bind_host, inst_id, MES_CHANNEL_ID(pipe->channel->id), pipe->priority);

    if (cs_connect(peer_url, &send_pipe, bind_host) != CM_SUCCESS) {
        mes_show_connect_error_info(peer_url);
        return;
    }

    if (g_cb_conn_state_change != NULL) {
        (void)g_cb_conn_state_change(inst_id, CM_TRUE);
    }

    if (g_ssl_enable) {
        if (cs_ssl_connect(MES_GLOBAL_INST_MSG.ssl_connector_fd, &send_pipe) != CM_SUCCESS) {
            cs_disconnect_ex(&send_pipe, CM_TRUE, inst_id);
            mes_show_connect_error_info(peer_url);
            return;
        }
    }

    LOG_RUN_INF("[mes] mes_tcp_try_connect version:%u, inst_id:%u, channel_id=%u, priority=%u", 
                send_pipe.version, inst_id, MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
    if (is_old_mec_version(send_pipe.version)) {
        mec_tcp_try_connect(pipe, &send_pipe);
        return;
    }

    char buf[sizeof(mes_message_head_t)];
    mes_message_head_t *head = (mes_message_head_t *)buf;
    head->cmd = MES_CMD_CONNECT;
    head->dst_inst = MES_INSTANCE_ID(pipe->channel->id);
    head->src_inst = (uint8)MES_GLOBAL_INST_MSG.profile.inst_id;
    head->caller_tid = MES_CHANNEL_ID(pipe->channel->id); // use caller_tid to represent channel id
    head->size = (uint16)sizeof(mes_message_head_t);
    head->ruid = 0;
    head->flags = pipe->priority;
    head->version = 0;

    if (cs_send_bytes(&send_pipe, (char *)head, sizeof(mes_message_head_t)) != CM_SUCCESS) {
        cs_disconnect_ex(&send_pipe, CM_TRUE, inst_id);
        LOG_RUN_ERR("[mes] cs_send_bytes failed.");
        return;
    }

    cm_rwlock_wlock(&pipe->send_lock);
    pipe->send_pipe = send_pipe;
    pipe->send_pipe_active = CM_TRUE;
    cm_rwlock_unlock(&pipe->send_lock);

    LOG_RUN_INF(
        "[mes] connect to channel peer %s success, src_inst:%d, dst_inst:%d, flags:%u, channel_id:%u, priority:%u",
        peer_url, head->src_inst, head->dst_inst, head->flags, MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
    return;
}

static void mes_tcp_heartbeat(mes_pipe_t *pipe)
{
    if (g_timer()->now - pipe->last_send_time < MES_HEARTBEAT_INTERVAL * MICROSECS_PER_SECOND) {
        return;
    }
    pipe->last_send_time = g_timer()->now;

    uint32 version = CM_INVALID_ID32;
    if (mes_get_pipe_version(&pipe->send_pipe, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_tcp_heartbeat, mes_get_send_pipe_version failed, channel_id %d, priority %d",
                      MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return;
    }
    if (is_old_mec_version(version)) {
        return;
    }

    /* dst_inst and caller_tid used to get current channel in mes_tcp_send_data */
    mes_message_head_t head = {0};
    head.cmd = MES_CMD_HEARTBEAT;
    head.src_inst = MES_GLOBAL_INST_MSG.profile.inst_id;
    head.dst_inst = MES_INSTANCE_ID(pipe->channel->id);
    head.caller_tid = MES_CHANNEL_ID(pipe->channel->id);
    head.size = (uint32)sizeof(mes_message_head_t);
    MES_SET_PRIORITY_FLAG(head.flags, pipe->priority);
    int ret = mes_tcp_send_data((void *)&head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_tcp_heartbeat failed, src:%u, dst:%u, flags:%u, ret:%u",
                    head.src_inst, head.dst_inst, head.flags, ret);
    }
}

void mes_close_send_pipe(mes_pipe_t *pipe)
{
    cm_rwlock_wlock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_rwlock_unlock(&pipe->send_lock);
        return;
    }
    cs_disconnect_ex(&pipe->send_pipe, CM_TRUE, MES_INSTANCE_ID(pipe->channel->id));
    pipe->send_pipe_active = CM_FALSE;
    CM_FREE_PTR(pipe->msgbuf);
    cm_rwlock_unlock(&pipe->send_lock);

    LOG_RUN_INF("[mes] mes_close_send_pipe priority=%u, inst_id=%u, channel_id=%u",
        pipe->priority, MES_INSTANCE_ID(pipe->channel->id), MES_CHANNEL_ID(pipe->channel->id));
    return;
}

static void mes_close_pipe(mes_pipe_t *pipe)
{
    mes_close_recv_pipe(pipe);
    mes_close_send_pipe(pipe);
    LOG_RUN_INF("[mes] mes_close_pipe:inst_id=%u,channel_id=%u, prio=%u, recv pipe closed",
        MES_INSTANCE_ID(pipe->channel->id), MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
}

void mes_close_channel(mes_channel_t *channel)
{
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.priority_cnt; i++) {
        mes_pipe_t *pipe = &channel->pipe[i];
        mes_close_pipe(pipe);
    }

    LOG_DEBUG_INF(
        "[mes] mes_close_channel:inst_id %d,channel_id=%u", MES_INSTANCE_ID(channel->id), MES_CHANNEL_ID(channel->id));
}

cm_event_t g_heartbeat_event;
void mes_heartbeat_channel(mes_channel_t *channel)
{
    for (unsigned int priority = 0; priority < MES_GLOBAL_INST_MSG.profile.priority_cnt; priority++) {
        mes_pipe_t *pipe = &channel->pipe[priority];
        if (!pipe->send_pipe_active) {
            mes_tcp_try_connect(pipe);
        } else {
            mes_tcp_heartbeat(pipe);
        }
    }
}

static void mes_heartbeat_entry(thread_t *thread)
{
    cm_set_thread_name("mes_heartbeat");
    uint64 periods = 0;
    while (!thread->closed) {
        for (unsigned int i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
            inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
            if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
                continue;
            }

            if (!MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
                continue;
            }

            for (unsigned int channel_id = 0; channel_id < MES_GLOBAL_INST_MSG.profile.channel_cnt; channel_id++) {
                mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
                mes_heartbeat_channel(channel);
            }
        }

        if (periods == SECONDS_PER_DAY && g_ssl_enable) {
            periods = 0;
            (void)mes_chk_ssl_cert_expire();
        }
        periods++;

        (void)cm_event_timedwait(&g_heartbeat_event, CM_1000X_FIXED);  
    }
}

void mes_event_proc(uint32 channel_id, uint32 priority, uint32 event)
{
    int ret = 0;

    uint32 inst_id = channel_id >> INST_ID_MOVE_LEFT_BIT_CNT;
    uint32 channel_idx = channel_id & (~(0xffffffff << INST_ID_MOVE_LEFT_BIT_CNT));
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_idx];
    mes_pipe_t *pipe = &channel->pipe[priority];

    LOG_DEBUG_INF(
        "[mes] mes_event_proc:inst_id= %u, channel_idx=%u,priority=%u,event=%u", inst_id, channel_idx, priority, event);

    if (event & EPOLLIN) {
        cm_rwlock_wlock(&pipe->recv_lock);
        ret = mes_process_event(pipe);
        cm_rwlock_unlock(&pipe->recv_lock);

        if (ret == ERR_MES_SOCKET_FAIL) {
            LOG_RUN_ERR("[mes] instance %d, recv pipe closed", MES_INSTANCE_ID(pipe->channel->id));
            mes_close_recv_pipe(pipe);
            return;
        }
    } else {
        LOG_RUN_ERR("[mes] instance %d, recv pipe closed,event=%u", MES_INSTANCE_ID(pipe->channel->id), event);
        mes_close_recv_pipe(pipe);
    }
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
        LOG_RUN_INF("[mes] mes_diag_proto_type proto_code=%u, version=%u.", proto_code, pipe->version);
    } else if (size == sizeof(proto_code)) {
        proto_code = *(uint32 *)buffer;
        pipe->version = CS_VERSION_0;
        LOG_RUN_INF("[mes] mes_diag_proto_type proto_code=%u.", proto_code);
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

    LOG_RUN_INF("[mes] mes_diag_proto_type: send ack[endian=%u].", (uint32)ack.endian);
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
    uint32 i, j;
    mes_channel_t *channel = NULL;
    mes_pipe_t *pipe = NULL;
    uint32 channel_cnt = MES_GLOBAL_INST_MSG.profile.channel_cnt;
    uint32 priority_cnt = MES_GLOBAL_INST_MSG.profile.priority_cnt;
    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_FALSE;
    for (i = 0; i < channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        for (j = 0; j < priority_cnt; j++) {
            pipe = &channel->pipe[j];
            mes_close_pipe(pipe);
        }
    }
}

void mes_tcp_stop_channels(void)
{
    if (MES_GLOBAL_INST_MSG.profile.channel_cnt == 0) {
        LOG_RUN_ERR("channel_cnt %u is invalid", MES_GLOBAL_INST_MSG.profile.channel_cnt);
        return;
    }
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        uint32 inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        mes_disconnect(inst_id);
    }

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
    int ret;
    uint8 inst_id;

    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
            continue;
        }
        ret = mes_connect(inst_id);
        if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
            LOG_RUN_ERR("[RC] failed to create mes channel to instance %d", inst_id);
            return ret;
        }
    }

    return CM_SUCCESS;
}

int mes_connect_single(inst_type inst_id)
{
    if (inst_id > MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes]: currently not support id=%u > 255.", inst_id);
        return ERR_MES_PARAM_INVALID;
    }

    if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
        return CM_SUCCESS;
    }

    int ret = mes_connect(inst_id);
    if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
        LOG_RUN_ERR("[mes] failed to create mes channel to instance %u", inst_id);
        return ret;
    }

    uint32 wait_time = 0;
    uint32 ready_count = 0;
    uint32 pre_ready_count = 0;
    while (!mes_connection_ready(inst_id, &ready_count)) {
        const uint8 once_wait_time = 10;
        cm_sleep(once_wait_time);
        if (ready_count == pre_ready_count) {
            wait_time += once_wait_time;
        }
        pre_ready_count = ready_count;

        if (wait_time > MES_CONNECT_TIMEOUT) {
            LOG_RUN_INF("[mes] connect to instance %u timeout.", inst_id);
            return ERR_MES_CONNECT_TIMEOUT;
        }
    }
    LOG_DEBUG_INF("[mes] reconnect to node %u success", inst_id);
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

static int mes_accept(cs_pipe_t *recv_pipe)
{
    int ret;
    mes_message_t msg;
    bool32 ready;
    mes_channel_t *channel;
    char msg_buf[SIZE_K(1)];

    ret = mes_diag_proto_type(recv_pipe);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: init pipe failed.");
        return ret;
    }

    MES_MESSAGE_ATTACH(&msg, msg_buf);
    if (g_ssl_enable) {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL4, "[mes] mes_accept: start cs_ssl_accept...");
        CM_RETURN_IFERR(cs_ssl_accept(MES_GLOBAL_INST_MSG.ssl_acceptor_fd, recv_pipe));
    }

    if (cs_wait(recv_pipe, CS_WAIT_FOR_READ, CM_CONNECT_TIMEOUT, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: wait failed.");
        return ERR_MES_WAIT_FAIL;
    }

    if (recv_pipe->version < CS_VERSION_5) {
        return mec_accept(recv_pipe);
    }

    ret = mes_read_message(recv_pipe, &msg);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: read message failed.");
        return ret;
    }

    if (msg.head->cmd != (uint8)MES_CMD_CONNECT) {
        LOG_RUN_ERR("when building connection type %hhu", msg.head->cmd);
        return ERR_MES_CMD_TYPE_ERR;
    }

    if (g_cb_convert_inst_id != NULL) {
        g_cb_convert_inst_id(&msg.head->src_inst, &msg.head->dst_inst);
    }

    uint8 child = MES_CALLER_TID_TO_CHANNEL_ID(msg.head->caller_tid);
    channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[msg.head->src_inst][child];
    mes_priority_t priority = MES_PRIORITY(msg.head->flags);
    mes_pipe_t *mes_pipe = &channel->pipe[priority];
    mes_close_recv_pipe(mes_pipe);
    cm_rwlock_wlock(&mes_pipe->recv_lock);
    mes_pipe->recv_pipe = *recv_pipe;
    mes_pipe->recv_pipe_active = CM_TRUE;
    mes_pipe->recv_pipe.connect_timeout = MES_GLOBAL_INST_MSG.profile.connect_timeout;
    mes_pipe->recv_pipe.socket_timeout = MES_GLOBAL_INST_MSG.profile.socket_timeout;
    if (mes_add_pipe_to_epoll(channel->id, priority, cs_get_pipe_sock(&mes_pipe->recv_pipe)) != CM_SUCCESS) {
        cm_rwlock_unlock(&mes_pipe->recv_lock);
        return CM_ERROR;
    }
    cm_rwlock_unlock(&mes_pipe->recv_lock);
    (void)mes_connect(msg.head->src_inst);  //Trigger send pipe to be connected
    LOG_RUN_INF("[mes] mes_accept: channel id %u receive ok, src_inst:%u, dst_inst:%u, flags:%u, priority:%u",
                (uint32)child, msg.head->src_inst, msg.head->dst_inst, msg.head->flags, priority);
    return CM_SUCCESS;
}

static status_t mes_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mes_accept(pipe);
}

int mes_start_lsnr(void)
{
    mes_addr_t *inst_net_addr = NULL;
    uint32 index;
    if (mes_get_inst_net_add_index(MES_GLOBAL_INST_MSG.profile.inst_id, &index) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_start_lsnr, inst net addr is null");
        return CM_ERROR;
    }
    inst_net_addr = &MES_GLOBAL_INST_MSG.profile.inst_net_addr[index];
    char *lsnr_host = inst_net_addr->ip;

    MEMS_RETURN_IFERR(strncpy_s(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[0], CM_MAX_IP_LEN, lsnr_host, CM_MAX_IP_LEN));
    MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port = inst_net_addr->port;
    MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.type = LSNR_TYPE_MES;

#ifdef WIN32
    if (epoll_init() != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]:epoll init failed.");
        return ERR_MES_EPOLL_INIT_FAIL;
    }
#endif

    char *lsnr_secondary_host = inst_net_addr->secondary_ip;
    if (!CM_IS_EMPTY_STR(lsnr_secondary_host) && cm_check_ip_valid(lsnr_secondary_host)) {
        MEMS_RETURN_IFERR(strncpy_s(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[1], CM_MAX_IP_LEN, lsnr_secondary_host,
                                    strlen(lsnr_secondary_host)));
    } else {
        MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.host[1][0] = '\0';
    }

    if (cs_start_tcp_lsnr(&(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp), mes_tcp_accept) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]:Start tcp lsnr failed. Host_name: %s, inst_id:%u, port:%hu, os error:%d.",
                    lsnr_host, MES_GLOBAL_INST_MSG.profile.inst_id, MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port,
                    cm_get_sock_error());
        return ERR_MES_START_LSRN_FAIL;
    }
    LOG_RUN_INF("[mes]: MES LSNR %s:%hu", lsnr_host, MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.port);

    return CM_SUCCESS;
}

bool32 mes_tcp_connection_ready(uint32 inst_id, uint32 *ready_count)
{
    uint32 i, j;
    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("check tcp connection is failed, inst id:%u", inst_id);
        return CM_FALSE;
    }

    *ready_count = 0;
    mes_channel_t *channel = NULL;
    mes_pipe_t *pipe = NULL;
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
        channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        for (j = 0; j < MES_GLOBAL_INST_MSG.profile.priority_cnt; j++) {
            pipe = &channel->pipe[j];
            if (pipe->recv_pipe_active && pipe->send_pipe_active) {
                (*ready_count)++;
            }
        }
    }
    return *ready_count == MES_GLOBAL_INST_MSG.profile.channel_cnt * MES_GLOBAL_INST_MSG.profile.priority_cnt;
}

int mes_init_tcp_resource(void)
{
    int ret;

    ret = mes_alloc_channels();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes init channels failed.");
        return ret;
    }

    ret = mes_alloc_channel_msg_queue(CM_TRUE);
    if (ret != CM_SUCCESS) {
        mes_free_channels();
        LOG_RUN_ERR("[mes] alloc send channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_alloc_channel_msg_queue(CM_FALSE);
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channels();
        LOG_RUN_ERR("[mes] alloc recv channel mesqueue failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// connect interface
int mes_tcp_connect(uint32 inst_id)
{
    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_TRUE;
    cm_event_notify(&g_heartbeat_event);
    LOG_DEBUG_INF("[mes] mes_tcp_connect, inst_id=%u, event_notify to try connect", inst_id);
    return CM_SUCCESS;
}

thread_t g_heartbeat_thread;
int mes_start_heartbeat_thread()
{
    cm_close_thread(&g_heartbeat_thread);
    cm_event_init(&g_heartbeat_event);
    if (cm_create_thread(mes_heartbeat_entry, 0, NULL, &g_heartbeat_thread) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] start_heartbeat_thread");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void mes_stop_heartbeat_thread()
{
    cm_close_thread(&g_heartbeat_thread);
}

// send
int mes_tcp_send_data(const void *msg_data)
{
    uint64 stat_time = 0;
    int ret;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    CM_RETURN_IFERR(mes_check_send_head_info(head));

    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
    mes_priority_t priority = MES_PRIORITY(head->flags);
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];

    if (!pipe->send_pipe_active) {
        LOG_DEBUG_ERR("[mes] tcp send pipe to dst_inst[%u] priority[%u] is not ready.", head->dst_inst, priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    uint32 version = CM_INVALID_ID32;
    if (mes_get_pipe_version(&pipe->send_pipe, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_tcp_send_data, mes_get_send_pipe_version failed, channel_id %u, priority %u",
                      MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    cm_rwlock_wlock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_rwlock_unlock(&pipe->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "tcp send pipe to instance %d is not ready, priority:%u",
                            head->dst_inst, priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    mes_get_consume_time_start(&stat_time);
    if (head->cmd == MES_CMD_SYNCH_ACK) {
        CM_ASSERT(MES_RUID_GET_RSN((head)->ruid) != 0);
    }

    if (CS_DIFFERENT_ENDIAN(pipe->send_pipe.options)) {
        PROC_DIFF_ENDIAN(head);
    }

    LOG_DEBUG_INF("[mes] begin tcp send data, cmd=%u, ruid=%llu, ruid->rid=%llu, ruid->rsn=%llu, src_inst=%u, "
                  "dst_inst=%u, size=%u, flags:%u, pipe version:%u.",
                  (head)->cmd, (uint64)head->ruid, (uint64)MES_RUID_GET_RID((head)->ruid),
                  (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size,
                  (head)->flags, version);

    if (!is_old_mec_version(version)) {
        ret = cs_send_fixed_size(&pipe->send_pipe, (char *)msg_data, (int32)head->size);
    } else {
        mec_message_head_adapter_t *mec_head =
                (mec_message_head_adapter_t *)((char *)msg_data + sizeof(mes_message_head_t));
        ret = cs_send_fixed_size(&pipe->send_pipe, (char *)mec_head, head->size - sizeof(mes_message_head_t));
        LOG_DEBUG_INF("[mes_mec] mes_tcp_send_data src:%u, dst:%u, size:%u, flags:%u, cmd:%u, ret:%d",
                      mec_head->src_inst, mec_head->dst_inst, mec_head->size, mec_head->flags, mec_head->cmd, ret);
    }
    if (ret != CM_SUCCESS) {
        cm_rwlock_unlock(&pipe->send_lock);
        mes_close_send_pipe(pipe);
        LOG_RUN_ERR("[mes] mes_tcp_send_data, cs_send_fixed_size failed. instance %d, send pipe closed, "
                    "os error %d, msg error %d %s.",
                    MES_INSTANCE_ID(pipe->channel->id), cm_get_os_error(), cm_get_error_code(),
                    cm_get_errormsg(cm_get_error_code()));
        return ERR_MES_SEND_MSG_FAIL;
    }

    pipe->last_send_time = g_timer()->now;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_rwlock_unlock(&pipe->send_lock);

    (void)cm_atomic_inc(&(pipe->send_count));

    return CM_SUCCESS;
}

int mes_tcp_send_bufflist(mes_bufflist_t *buff_list)
{
    errno_t errcode;
    uint32 bufsz = 0;
    uint32 totalsz = MES_CHANNEL_MAX_SEND_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
    uint64 stat_time = 0;
    bool32 merged = CM_TRUE;
    mes_message_head_t *head = (mes_message_head_t *)(buff_list->buffers[0].buf);
    CM_RETURN_IFERR(mes_check_send_head_info(head));

    mes_channel_t *channel =
            &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid)];
    mes_priority_t priority = MES_PRIORITY(head->flags);
    mes_pipe_t *pipe = &channel->pipe[priority];

    if (!pipe->send_pipe_active) {
        LOG_DEBUG_ERR("[mes] send pipe to dst_inst[%u] priority[%u] is not ready.", head->dst_inst, priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    uint32 version = CM_INVALID_ID32;
    if (mes_get_pipe_version(&pipe->send_pipe, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_tcp_send_bufflist, mes_get_send_pipe_version failed, channel_id %u, priority %u",
                      MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    cm_rwlock_wlock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_rwlock_unlock(&pipe->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "send pipe to instance %d is not ready, priority:%u",
                            head->dst_inst, priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }
    mes_get_consume_time_start(&stat_time);

    if (head->cmd == MES_CMD_SYNCH_ACK) {
        CM_ASSERT(MES_RUID_GET_RSN((head)->ruid) != 0);
    }

    if (CS_DIFFERENT_ENDIAN(pipe->send_pipe.options)) {
        PROC_DIFF_ENDIAN(head);
    }

    LOG_DEBUG_INF("[mes] Begin tcp send buffer, buff list cnt=%u, cmd=%u, ruid=%llu(%llu-%llu), src_inst=%u, "
                  "dst_inst=%u, size=%u, flags=%u, pipe version=%u.",
                  buff_list->cnt, (head)->cmd, (uint64)head->ruid, (uint64)MES_RUID_GET_RID((head)->ruid),
                  (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size,
                  (head)->flags, version);

    if (is_old_mec_version(version)) {
        buff_list->buffers[0].buf = buff_list->buffers[0].buf + sizeof(mes_message_head_t);
        buff_list->buffers[0].len = buff_list->buffers[0].len - sizeof(mes_message_head_t);
    }
    
    if (pipe->msgbuf == NULL) {
        pipe->msgbuf = (char *)malloc(totalsz);
        if (pipe->msgbuf == NULL) {
            merged = CM_FALSE;
        }
        LOG_RUN_INF("[mes] mes_tcp_send_bufflist, malloc msg buf, merged:%u, priority:%u", merged, priority);
    }

    if (merged) {
        /* merge buffers to one package and send, to improve performance */
        for (int i = 0; i < buff_list->cnt; i++) {
            errcode = memcpy_s(pipe->msgbuf + bufsz, totalsz - bufsz, buff_list->buffers[i].buf,
                               buff_list->buffers[i].len);
            if (errcode != EOK) {
                cm_rwlock_unlock(&pipe->send_lock);
                LOG_RUN_ERR("[mes] memcpy failed. check bufsz=%d, totalsz=%d, syserr=%d",
                            bufsz + buff_list->buffers[i].len, totalsz, cm_get_os_error());
                return ERR_SYSTEM_CALL;
            }
            bufsz += buff_list->buffers[i].len;
        }
        if (cs_send_fixed_size(&pipe->send_pipe, pipe->msgbuf, (int32)bufsz) != CM_SUCCESS) {
            cm_rwlock_unlock(&pipe->send_lock);
            mes_close_send_pipe(pipe);
            LOG_RUN_ERR("[mes] cs_send_fixed_size failed. channel %d, errno %d, send pipe closed",
                        channel->id, cm_get_os_error());
            return ERR_MES_SEND_MSG_FAIL;
        }
    } else {
        /* malloc failed doesn't matter, we need to send every buffer */
        for (int i = 0; i < buff_list->cnt; i++) {
            if (cs_send_fixed_size(&pipe->send_pipe, buff_list->buffers[i].buf, (int32)buff_list->buffers[i].len)
                != CM_SUCCESS) {
                cm_rwlock_unlock(&pipe->send_lock);
                mes_close_send_pipe(pipe);
                LOG_RUN_ERR("[mes] cs_send_fixed_size failed. channel %d, errno %d, send pipe closed",
                            channel->id, cm_get_os_error());
                return ERR_MES_SEND_MSG_FAIL;
            }
        }
    }

    pipe->last_send_time = g_timer()->now;
    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);
    cm_rwlock_unlock(&pipe->send_lock);

    (void)cm_atomic_inc(&(pipe->send_count));
    return CM_SUCCESS;
}

int mes_register_convert_inst_id_proc_func(usr_cb_convert_inst_id_t proc)
{
    g_cb_convert_inst_id = proc;
    return CM_SUCCESS;
}

status_t mes_get_pipe_version(cs_pipe_t *pipe, uint32 *version)
{
    (*version) = pipe->version;
    return (*version) == CM_INVALID_ID32 ? CM_ERROR : CM_SUCCESS;
}

int mes_register_conn_state_proc_func(usr_cb_conn_state_change_t proc)
{
    g_cb_conn_state_change = proc;
    return CM_SUCCESS;
}

void cs_disconnect_ex(cs_pipe_t *pipe, bool8 is_send, inst_type inst_id)
{
    if (is_send && g_cb_conn_state_change != NULL) {
        (void)g_cb_conn_state_change(inst_id, CM_FALSE);
    }
    cs_disconnect(pipe);
}
