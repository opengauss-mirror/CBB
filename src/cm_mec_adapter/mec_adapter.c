/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * mec_adapter.c
 * 
 *
 * IDENTIFICATION
 *    src/cm_mec_adapter/mec_adapter.c
 *
 * -------------------------------------------------------------------------
 */

#include "mec_adapter.h"
#include "mes_recv.h"

bool32 is_old_mec_version(uint32 version)
{
    return version < CS_VERSION_5;
}

static void mec_fill_connect_head(
    mec_message_head_adapter_t *head, mes_profile_t *profile, mes_channel_t *channel, mes_pipe_t *pipe)
{
    head->cmd = MEC_CMD_CONNECT_ADAPTER;
    head->dst_inst = MES_INSTANCE_ID(channel->id);
    head->src_inst = profile->inst_id;
    head->stream_id = MES_CHANNEL_ID(channel->id);
    head->size = sizeof(mec_message_head_adapter_t);
    head->flags = pipe->priority == MES_PRIORITY_ZERO ? 0 : MEC_FLAG_PRIV_LOW_ADAPTER;
    head->serial_no = 0;
    if (CS_DIFFERENT_ENDIAN(pipe->send_pipe.options)) {
        head->src_inst = cs_reverse_uint32(head->src_inst);
        head->stream_id = cs_reverse_uint32(head->stream_id);
        head->size = cs_reverse_uint32(head->size);
        head->serial_no = cs_reverse_uint32(head->serial_no);
    }
}

// mec connect
void mec_tcp_try_connect(mes_pipe_t *mes_pipe, cs_pipe_t *send_pipe)
{
    mec_message_head_adapter_t mec_head;
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mes_channel_t *channel = mes_pipe->channel;
    mec_fill_connect_head(&mec_head, profile, channel, mes_pipe);

    if (cs_send_bytes(send_pipe, (const char *)&mec_head, MEC_MSG_HEAD_SIZE_ADAPTER) != CM_SUCCESS) {
        cs_disconnect_ex(send_pipe, CM_TRUE, mec_head.dst_inst);
        LOG_DEBUG_WAR("[mes_mec] mec_tcp_try_connect, cs_send_bytes fail, instance %u channel_id %u, priority %d.",
            MES_INSTANCE_ID(mes_pipe->channel->id), MES_CHANNEL_ID(mes_pipe->channel->id), mes_pipe->priority);
        return;
    }

    cm_rwlock_wlock(&mes_pipe->send_lock);
    mes_pipe->send_pipe = *send_pipe;
    mes_pipe->send_pipe_active = CM_TRUE;
    cm_rwlock_unlock(&mes_pipe->send_lock);
    LOG_RUN_INF("[mes_mec] connect to channel success, src_inst:%d, channel_id %u, priority %d",
        mec_head.src_inst, MES_CHANNEL_ID(mes_pipe->channel->id), mes_pipe->priority);
}

static status_t mec_handle_cross_cluster_head_info(mec_message_head_adapter_t *mec_head)
{
    if (IS_LOCAL_CLUSTER_NODE_ADAPTER(mec_head->src_inst) && IS_CROSS_CLUSTER_NODE_ADAPTER(mec_head->dst_inst)) {
        LOG_DEBUG_INF("[mes_mec] src_inst %u -> %u, dst_inst %u -> %u",
            mec_head->src_inst, NODE_ID_SWITCH_ADAPTER(mec_head->src_inst), mec_head->dst_inst,
            NODE_ID_SWITCH_ADAPTER(mec_head->dst_inst));
        mec_head->src_inst = NODE_ID_SWITCH_ADAPTER(mec_head->src_inst);
        mec_head->dst_inst = NODE_ID_SWITCH_ADAPTER(mec_head->dst_inst);
    }
    return CM_SUCCESS;
}

static status_t mec_check_connect_head_info(const mec_message_head_adapter_t *mec_head)
{
    mes_context_t *mes_ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    uint32 cur_node = MES_GLOBAL_INST_MSG.profile.inst_id;

    if (mec_head->cmd != (uint8)MEC_CMD_CONNECT_ADAPTER) {
        LOG_RUN_ERR("[mes_mec] cmd %u invalid when building connection.", mec_head->cmd);
        return CM_ERROR;
    }
    if (mec_head->stream_id >= MES_GLOBAL_INST_MSG.profile.channel_cnt ||
        mec_head->src_inst >= MEC_MAX_NODE_COUNT_ADAPTER || mec_head->src_inst == MEC_INVALID_NODE_ID_ADAPTER ||
        mec_head->src_inst == cur_node) {
        LOG_RUN_ERR(
            "[mes_mec] invalid channel %u or src_inst %u, cur=%u", mec_head->stream_id, mec_head->src_inst, cur_node);
        return CM_ERROR;
    }
    if (mes_ctx->channels[mec_head->src_inst] == NULL) {
        LOG_RUN_WAR("[mes_mec] channel for inst[%u] not already malloc, can't accept now.", mec_head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int mec_accept(cs_pipe_t *pipe)
{
    LOG_RUN_INF("[mes_mec] mec_accept start");
    mes_channel_t *channel = NULL;
    mec_message_head_adapter_t mec_head;

    if (cs_read_fixed_size(pipe, (char *)&mec_head, MEC_MSG_HEAD_SIZE_ADAPTER) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes_mec] read message failed.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(mec_handle_cross_cluster_head_info(&mec_head));
    CM_RETURN_IFERR(mec_check_connect_head_info(&mec_head));

    channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[mec_head.src_inst][mec_head.stream_id];
    mes_priority_t priority = MEC_PRIV_LOW_ADAPTER(mec_head.flags) ? MES_PRIORITY_ONE : MES_PRIORITY_ZERO;
    mes_pipe_t *mes_pipe = &channel->pipe[priority];
    cm_rwlock_wlock(&mes_pipe->recv_lock);
    mes_close_recv_pipe_nolock(mes_pipe);
    mes_pipe->recv_pipe = *pipe;
    mes_pipe->recv_pipe_active = CM_TRUE;
    mes_pipe->recv_pipe.connect_timeout = MES_GLOBAL_INST_MSG.profile.connect_timeout;
    mes_pipe->recv_pipe.socket_timeout = MES_GLOBAL_INST_MSG.profile.socket_timeout;
    if (mes_add_pipe_to_epoll(channel->id, priority, cs_get_pipe_sock(&mes_pipe->recv_pipe)) != CM_SUCCESS) {
        cm_rwlock_unlock(&mes_pipe->recv_lock);
        return CM_ERROR;
    }
    cm_rwlock_unlock(&mes_pipe->recv_lock);

    (void)mes_connect(mec_head.src_inst);  //Trigger send pipe to be connected
    LOG_RUN_INF("[mes_mec] mec_accept: channel id %u receive ok, src_inst:%d, dst_inst:%d, flags:%u",
        (uint32)channel->id, mec_head.src_inst, mec_head.dst_inst, mec_head.flags);
    return CM_SUCCESS;
}

static int mec_get_message_buf(mes_message_t *msg, const mec_message_head_adapter_t *mec_head)
{
    uint64 stat_time = 0;
    mes_get_consume_time_start(&stat_time);
    char *msg_buf = NULL;
    mes_priority_t priority = MEC_PRIV_LOW_ADAPTER(mec_head->flags) ? MES_PRIORITY_ONE : MES_PRIORITY_ZERO;
    uint32 size = mec_head->size;
    if (MEC_COMPRESS_ADAPTER(mec_head->flags)) {
        size = mes_get_priority_max_msg_size(priority) - MES_MSG_HEAD_SIZE;
    }
    msg_buf = mes_alloc_buf_item(size + MES_MSG_HEAD_SIZE, CM_FALSE, mec_head->src_inst, priority);
    if (SECUREC_UNLIKELY(msg_buf == NULL)) {
        return ERR_MES_MALLOC_FAIL;
    }
    MES_MESSAGE_ATTACH(msg, msg_buf);
    mes_consume_with_time(mec_head->cmd, MES_TIME_GET_BUF, stat_time);
    return CM_SUCCESS;
}

static status_t mec_check_recv_head_info(const mec_message_head_adapter_t *mec_head)
{
    if (SECUREC_UNLIKELY(mec_head->cmd >= MEC_CMD_CEIL_ADAPTER)) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:invalid msg command %u", mec_head->cmd);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(mec_head->size < sizeof(mec_message_head_adapter_t) ||
                         mec_head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:recv message length %u exceed min", mec_head->size);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(mec_head->src_inst >= MEC_MAX_NODE_COUNT_ADAPTER ||
                         mec_head->dst_inst >= MEC_MAX_NODE_COUNT_ADAPTER)) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:invalid src_inst %u or dst_inst %u", mec_head->src_inst, mec_head->dst_inst);
        return CM_ERROR;
    }

    inst_type cur_node = MES_GLOBAL_INST_MSG.profile.inst_id;
    if (SECUREC_UNLIKELY(mec_head->src_inst == cur_node || mec_head->dst_inst != cur_node)) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:invalid src_inst %u or dst_inst %u, cur_node:%u",
                      mec_head->src_inst, mec_head->dst_inst, cur_node);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.algorithm == COMPRESS_NONE && 
        MEC_COMPRESS_ADAPTER(mec_head->flags))) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:compress is not enable, but recv compress pkt. head_flags=%u", mec_head->flags);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(MEC_MORE_DATA_ADAPTER(mec_head->flags) && MEC_END_DATA_ADAPTER(mec_head->flags))) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:more or end flag error. head_flags=%u", mec_head->flags);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY((MEC_BATCH_ADAPTER(mec_head->flags) && mec_head->batch_size <= 1) ||
                         (mec_head->batch_size == 0))) {
        LOG_DEBUG_ERR("[mes_mec] rcvhead:batch_flag 0x%x or batch_size %u exceed error",
                      mec_head->flags, mec_head->batch_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// mec adapter receive
int mec_process_event(mes_pipe_t *pipe)
{
    LOG_DEBUG_INF("[mes_mec] mec_process_event start");
    uint64 stat_time = 0;
    mes_message_t msg;
    mec_message_head_adapter_t mec_head;
    mes_message_head_t mes_head;

    mes_get_consume_time_start(&stat_time);

    int ret = cs_read_fixed_size(&pipe->recv_pipe, (char *)&mec_head, MEC_MSG_HEAD_SIZE_ADAPTER);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes_mec] mec_read_message head failed.");
        return ERR_MES_SOCKET_FAIL;
    }

    CM_RETURN_IFERR(mec_handle_cross_cluster_head_info(&mec_head));
    CM_RETURN_IFERR(mec_check_recv_head_info(&mec_head));

    mes_priority_t priority = MEC_PRIV_LOW_ADAPTER(mec_head.flags) ? MES_PRIORITY_ONE : MES_PRIORITY_ZERO;
    if (priority != pipe->priority) {
        LOG_RUN_ERR("[mes_mec] flag priority %u not equal with pipe priority %u", priority, pipe->priority);
        return CM_ERROR;
    }

    ret = mec_get_message_buf(&msg, &mec_head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes_mec] mec_get_message_buf failed.");
        return ret;
    }

    // The MES head is assembled in a unified manner
    // to ensure that the subsequent enqueue and receive processes are consistent.
    MES_INIT_MESSAGE_HEAD(&mes_head, 0, MES_CMD_ASYNC_MSG, priority, mec_head.src_inst, mec_head.dst_inst,
        MES_INVLD_RUID, MES_MSG_HEAD_SIZE + mec_head.size);

    errno_t errcode = memcpy_s(msg.buffer, MES_MSG_HEAD_SIZE, &mes_head, MES_MSG_HEAD_SIZE);
    if (errcode != EOK) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("[mes_mec] memcpy_s failed.");
        return CM_ERROR;
    }
    errcode = memcpy_s(msg.buffer + MES_MSG_HEAD_SIZE, MEC_MSG_HEAD_SIZE_ADAPTER, &mec_head, MEC_MSG_HEAD_SIZE_ADAPTER);
    if (errcode != EOK) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("[mes_mec] memcpy_s failed.");
        return CM_ERROR;
    }

    ret = cs_read_fixed_size(&pipe->recv_pipe, msg.buffer + MES_MSG_HEAD_SIZE + MEC_MSG_HEAD_SIZE_ADAPTER,
        mec_head.size - MEC_MSG_HEAD_SIZE_ADAPTER);
    if (ret != CM_SUCCESS) {
        mes_release_message_buf(&msg);
        LOG_RUN_ERR("[mes_mec] mec read message body failed, size:%u, src:%u, dst:%u, flags:%u.",
                    mec_head.size, mec_head.src_inst, mec_head.dst_inst, mec_head.flags);
        return ERR_MES_SOCKET_FAIL;
    }

    mes_consume_with_time(msg.head->cmd, MES_TIME_READ_MES, stat_time);

    (void)cm_atomic_inc(&(pipe->recv_count));

    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID_ADAPTER(mec_head.stream_id, MES_GLOBAL_INST_MSG.profile.channel_cnt);
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgqueue_t *my_queue = &mq_ctx->channel_private_queue[mec_head.src_inst][channel_id];
    mes_process_message(my_queue, &msg);

    LOG_DEBUG_INF("[mes_mec] mec_process_event finish, src:%u, dst:%u, size:%u, flags:%u, cmd:%u, stream_id:%u",
        mec_head.src_inst, mec_head.dst_inst, mec_head.size, mec_head.flags, mec_head.cmd, mec_head.stream_id);
    return CM_SUCCESS;
}