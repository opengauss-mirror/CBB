/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * mes_interface_impl.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_interface_impl.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_func.h"

#define MES_ALLOC_ROOM_SLEEP_TIME 1000

static inline void mes_clean_broadcast_msg_ptr(mes_waiting_room_t *room)
{
    for (uint32 i = 0; i < MES_MAX_INSTANCES; i++) {
        if (room->broadcast_msg[i] != NULL) {
            room->broadcast_msg[i] = NULL;
        }
    }
}

static inline void mes_copy_recv_broadcast_msg(mes_waiting_room_t *room, mes_msg_list_t* responses)
{
    uint32 i;
    responses->count = 0;
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        if (room->broadcast_msg[i] != NULL) {
            mes_msg_t* msg = &responses->messages[responses->count];
            MES_MSG_ATTACH(msg, room->broadcast_msg[i]);
            room->broadcast_msg[i] = NULL;
            responses->count++;
        }
    }
}

static inline void mes_append_bufflist(mes_bufflist_t *buff_list, const void *buff, uint32 len)
{
    buff_list->buffers[buff_list->cnt].buf = (char *)buff;
    buff_list->buffers[buff_list->cnt].len = len;
    buff_list->cnt = buff_list->cnt + 1;
}

static inline void mes_reinit_room(mes_waiting_room_t* room)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_inc((atomic_t *)(&room->rsn));
    room->room_status = STATUS_FREE_ROOM;
    room->ack_count = 0;
    room->req_count = 0;
    room->err_code = 0;
    room->msg_buf = NULL;
    mes_clean_broadcast_msg_ptr(room);
    cm_spin_unlock(&room->lock);
}

static mes_waiting_room_t *mes_alloc_room(void)
{
    mes_waiting_room_t *room = NULL;
    uint32 free_idx;
    mes_waiting_room_pool_t *wrpool = &MES_WAITING_ROOM_POOL;
    mes_room_freelist_t *freelist = NULL;
    while (CM_TRUE) {
        free_idx = wrpool->next_freelist++ % CM_MAX_ROOM_FREELIST_NUM;
        freelist = &wrpool->room_freelists[free_idx];
        cm_spin_lock(&freelist->lock, NULL);
        room = (mes_waiting_room_t *)cm_bilist_pop_first(&freelist->list);
        cm_spin_unlock(&freelist->lock);
        if (room != NULL) {
            CM_ASSERT(room->room_status == STATUS_FREE_ROOM);
            break;
        } else {
            LOG_DEBUG_WAR("freelist %u room leaked, check for unpaired messages!", free_idx);
            cm_sleep(MES_ALLOC_ROOM_SLEEP_TIME);
        }
    }
    return room;
}

static inline void mes_free_room(mes_waiting_room_t *room)
{
    mes_waiting_room_pool_t *wrpool = &MES_WAITING_ROOM_POOL;
    uint32 free_idx = MES_ROOM_ID_TO_FREELIST_ID(room->room_index);
    mes_room_freelist_t *freelist = &wrpool->room_freelists[free_idx];

    mes_reinit_room(room);
    cm_spin_lock(&freelist->lock, NULL);
    cm_bilist_add_tail(&room->node, &freelist->list);
    cm_spin_unlock(&freelist->lock);
}

static inline unsigned long long mes_room_get_ruid(mes_waiting_room_t *room)
{
    ruid_t res;
    res.room_id = room->room_index;
    res.rsn = room->rsn;
    return res.ruid;
}

static int mes_send_data_x_inner(mes_message_head_t *head, unsigned int count, va_list args)
{
    uint64 start_stat_time = 0;
    mes_bufflist_t buff_list;
    va_list apcopy;
    va_copy(apcopy, args);

    if (SECUREC_UNLIKELY((uint32)MES_PRIORITY(head->flags) >= MES_GLOBAL_INST_MSG.profile.priority_cnt)) {
        LOG_RUN_ERR("[mes] flag priority[%u] exceeds the configured number[%d].",
                    MES_PRIORITY(head->flags), MES_GLOBAL_INST_MSG.profile.priority_cnt);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(head->dst_inst >= MES_MAX_INSTANCES)) {
        LOG_RUN_ERR("[mes] mes_send_data_x_inner, invalid dst_inst %u.", head->dst_inst);
        return CM_ERROR;
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, sizeof(mes_message_head_t));
    for (uint32 i = 0; i < count; i++) {
        char *msg = (char *)va_arg(apcopy, char *);
        unsigned int size = (unsigned int)va_arg(apcopy, unsigned int);
        head->size += size;
        if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
            MES_LOG_ERR_HEAD_EX(head, "message length exceeded");
            return ERR_MES_MSG_TOO_LARGE;
        }
        mes_append_bufflist(&buff_list, msg, size);
    }
    va_end(apcopy);

    if (count == 0 || buff_list.cnt == 0) {
        LOG_RUN_ERR("[mes] send data x inner failed, msg data is NULL");
        return ERR_MES_PARAM_NULL;
    }

    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
        MES_LOG_ERR_HEAD_EX(head, "message length exceeded");
        return ERR_MES_MSG_TOO_LARGE;
    }

    mes_context_t *mes_ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    if (mes_ctx->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[mes] mes_send_data_x_inner fail, not begin now. dest[%u], priority[%u]",
                      head->dst_inst, MES_PRIORITY(head->flags));
        return CM_ERROR;
    }

    bool32 is_send = head->dst_inst == MES_MY_ID ? CM_FALSE : CM_TRUE;
    mes_get_consume_time_start(&start_stat_time);
    MES_RESET_COMPRESS_ALGORITHM_FLAG(head->flags);
    int ret = mes_put_buffer_list_queue(&buff_list, is_send);
    if (ret == CM_SUCCESS) {
        mes_send_stat(head->cmd);
        mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);
    }
    return ret;
}

int mes_send_data(inst_type dest_inst, flag_type flag, char* data, unsigned int size)
{
    if (data == NULL) {
        LOG_RUN_ERR("mes send data failed, msg data is NULL");
        return ERR_MES_PARAM_NULL;
    }
    return mes_send_data_x(dest_inst, flag, 1, data, size);
}

/*
 * async p2p message passing with multi-body message
 * mes_send_data is a special case with 1-body message
 */
int mes_send_data_x(inst_type dest_inst, flag_type flag, unsigned int count, ...)
{
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    va_list args;
    va_start(args, count);
    mes_message_head_t head;
    MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_ASYNC_MSG, flag, MES_MY_ID, dest_inst, MES_INVLD_RUID, MES_MSG_HEAD_SIZE);
    int ret = mes_send_data_x_inner(&head, count, args);
    va_end(args);
    return ret;
}

void mes_prepare_request(ruid_type *ruid)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_prepare_request");
        return;
    }
    mes_waiting_room_t *room = mes_alloc_room();
    if (room == NULL) {
        LOG_RUN_ERR("[mes]mes_alloc_room failed");
        return;
    }
    room->room_status = STATUS_PTP_SENT;
    *ruid = mes_room_get_ruid(room);
}


int mes_forward_request_x(inst_type dest_inst, flag_type flag, ruid_type ruid, unsigned int count, ...)
{
    MES_RETURN_IF_BAD_RUID(ruid);
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    va_list args;
    va_start(args, count);
    mes_message_head_t head;
    MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_FORWARD_REQ, flag, MES_MY_ID, dest_inst, ruid, MES_MSG_HEAD_SIZE);
    int ret = mes_send_data_x_inner(&head, count, args);
    va_end(args);
    return ret;
}

int mes_send_request(inst_type dest_inst, flag_type flag, ruid_type *ruid, char *data, unsigned int size)
{
    return mes_send_request_x(dest_inst, flag, ruid, 1, data, size);
}

/*
 * synchronous p2p message passing with multi-body message
 * mes_send_data is a special case with 1-body message
 */
int mes_send_request_x(inst_type dest_inst, flag_type flag, ruid_type *ruid, unsigned int count, ...)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_send_request_x");
        return CM_ERROR;
    }
    *ruid = 0;
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    mes_message_head_t head;

    mes_waiting_room_t* room = mes_alloc_room();
    room->room_status = STATUS_PTP_SENT;
    *ruid = mes_room_get_ruid(room);
    head.ruid = *ruid;

    va_list args;
    va_start(args, count);
    MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_SYNCH_REQ, flag, MES_MY_ID, dest_inst, *ruid, MES_MSG_HEAD_SIZE);
    int ret = mes_send_data_x_inner(&head, count, args);
    va_end(args);

    if (ret != CM_SUCCESS) {
        *ruid = MES_INVLD_RUID;
        mes_free_room(room);
    }

    return ret;
}

int mes_send_response(inst_type dest_inst, flag_type flag, ruid_type ruid, char *data, unsigned int size)
{
    MES_RETURN_IF_BAD_RUID(ruid);
    return mes_send_response_x(dest_inst, flag, ruid, 1, data, size);
}

/*
 * async message response to synchronous request
 * with ruid that mandates specific room for remote
 */
int mes_send_response_x(inst_type dest_inst, flag_type flag, ruid_type ruid, unsigned int count, ...)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_send_response_x");
        return CM_ERROR;
    }

    MES_RETURN_IF_BAD_RUID(ruid);
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    mes_message_head_t head;
    CM_ASSERT(!MES_RUID_IS_ILLEGAL(ruid) && !MES_RUID_IS_INVALID(ruid));

    va_list args;
    va_start(args, count);
    MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_SYNCH_ACK, flag, MES_MY_ID, dest_inst, ruid, MES_MSG_HEAD_SIZE);
    int ret = mes_send_data_x_inner(&head, count, args);
    va_end(args);

    return ret;
}

int mes_get_response(ruid_type ruid, mes_msg_t* response, int timeout_ms)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_get_response");
        return CM_ERROR;
    }
    MES_RETURN_IF_BAD_RUID(ruid);
    uint64 start_stat_time = cm_get_time_usec();
    int32 wait_time = 0;
    mes_message_t msg;
    mes_waiting_room_t *room = mes_ruid_get_room(ruid);
    CM_ASSERT(room != NULL);

    if (room == NULL) {
        LOG_DEBUG_ERR("[mes]ruid%llu:(%llu-%llu) gives invalid room",
            (uint64)ruid, (uint64)MES_RUID_GET_RID(ruid), (uint64)MES_RUID_GET_RSN(ruid));
        return ERR_MES_PARAM_INVALID;
    }

    if (response == NULL) {
        LOG_DEBUG_INF("[mes]room wait canceled by caller, ruid%llu:(%llu-%llu), room(%llu-%llu)",
            (uint64)ruid, (uint64)MES_RUID_GET_RID(ruid), (uint64)MES_RUID_GET_RSN(ruid),
            (uint64)room->room_index, (uint64)room->rsn);
        mes_protect_when_timeout(room);
        mes_free_room(room);
        return CM_SUCCESS;
    }

    for (;;) {
        if (!mes_mutex_timed_lock(&room->mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout_ms || MES_WAITS_INTERRUPTED) {
                // when timeout the ack msg may reach, so need do some check and protect.
                mes_protect_when_timeout(room);
                LOG_DYN_TRC_WAR("[MES][%llu][%llu-%llu]RWT, INT=%u",
                    (uint64)ruid, (uint64)room->room_index, room->rsn, MES_WAITS_INTERRUPTED);
                mes_free_room(room);
                return ERR_MES_WAIT_OVERTIME;
            }
            continue;
        }

        if (room->msg_buf == NULL) {
            mes_free_room(room);
            return ERR_MES_WAIT_OVERTIME;
        }
        MES_MESSAGE_ATTACH(&msg, room->msg_buf);
        MES_MSG_ATTACH(response, room->msg_buf);

        // this situation should not happen, keep this code to observe some time.
        if (SECUREC_UNLIKELY(!ruid_matches_room_rsn(&(&msg)->head->ruid, room->rsn))) {
            // rsn not match, ignore this message
            MES_LOG_WAR_HEAD_EX((&msg)->head, "receive unmatch msg", room);
            LOG_RUN_ERR("[mes]%s: receive unmatch msg, ruid=%llu, room rsn=%llu.", (char *)__func__,
                (&msg)->head->ruid, room->rsn);
            mes_release_message_buf(&msg);
            MES_MESSAGE_DETACH(&msg);
            continue;
        }

        break;
    }

    mes_free_room(room);
    mes_consume_with_time((&msg)->head->cmd, MES_TIME_TEST_RECV, start_stat_time);

    return CM_SUCCESS;
}

int mes_broadcast_x(flag_type flag, unsigned int count, ...)
{
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    va_list args;
    va_start(args, count);
    int ret = CM_SUCCESS;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        mes_message_head_t head;
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_ASYNC_MSG, flag, MES_MY_ID, inst_id, MES_INVLD_RUID, MES_MSG_HEAD_SIZE);
        ret = mes_send_data_x_inner(&head, count, args);
        if (ret != CM_SUCCESS) {
            continue;
        }
    }
    va_end(args);
    return ret;
}

int mes_broadcast(flag_type flag, char* msg_data, unsigned int size)
{
    return mes_broadcast_x(flag, 1, msg_data, size);
}

int mes_broadcast_spx(inst_type* inst_list, unsigned int inst_count, flag_type flag, unsigned int count, ...)
{
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    MES_RETURN_IF_BAD_INST_COUNT(inst_count);
    va_list args;
    va_start(args, count);
    int ret = CM_SUCCESS;

    for (uint32 i = 0; i < inst_count; i++) {
        mes_message_head_t head;
        MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_ASYNC_MSG, flag, MES_MY_ID, inst_list[i], MES_INVLD_RUID,
                              MES_MSG_HEAD_SIZE);
        ret = mes_send_data_x_inner(&head, count, args);
        if (ret != CM_SUCCESS) {
            continue;
        }
    }
    va_end(args);
    return ret;
}

int mes_broadcast_sp(inst_type* inst_list, unsigned int inst_count, flag_type flag, char* msg_data, unsigned int size)
{
    return mes_broadcast_spx(inst_list, inst_count, flag, 1, msg_data, size);
}


int mes_broadcast_request_x(flag_type flag, ruid_type* ruid, unsigned int count, ...)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_broadcast_request_x");
        return CM_ERROR;
    }
    *ruid = 0;
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    va_list args;
    va_start(args, count);
    mes_waiting_room_t* room = mes_alloc_room();
    *ruid = mes_room_get_ruid(room);
    room->room_status = STATUS_BCAST_SENDING;
    room->ack_count = 0;
    room->req_count = 0;
    int ret = CM_SUCCESS;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        mes_message_head_t head;
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_SYNCH_REQ, flag, MES_MY_ID, inst_id, *ruid, MES_MSG_HEAD_SIZE);
        ret = mes_send_data_x_inner(&head, count, args);
        if (ret != CM_SUCCESS) {
            /* room is only freed in paired get response api */
            continue;
        }
        (void)cm_atomic32_inc(&room->req_count);
    }
    room->room_status = STATUS_BCAST_SENT;
    va_end(args);
    return ret;
}

int mes_broadcast_request(flag_type flag, ruid_type* ruid, char* msg_data, unsigned int size)
{
    return mes_broadcast_request_x(flag, ruid, 1, msg_data, size);
}

int mes_broadcast_request_spx(inst_type* inst_list, unsigned int inst_count,
    flag_type flag, ruid_type* ruid, unsigned int count, ...)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR(
            "[mes]disable_request = 1, no support send request and get response, func:mes_broadcast_request_spx");
        return CM_ERROR;
    }
    *ruid = 0;
    MES_RETURN_IF_BAD_INST_COUNT(inst_count);
    MES_RETURN_IF_BAD_MSG_COUNT(count);
    va_list args;
    va_start(args, count);
    mes_waiting_room_t* room = mes_alloc_room();
    *ruid = mes_room_get_ruid(room);
    room->room_status = STATUS_BCAST_SENDING;
    room->ack_count = 0;
    room->req_count = 0;
    int ret = CM_SUCCESS;

    for (uint32 i = 0; i < inst_count; i++) {
        mes_message_head_t head;
        MES_INIT_MESSAGE_HEAD(&head, 0, MES_CMD_SYNCH_REQ, flag, MES_MY_ID, inst_list[i], *ruid, MES_MSG_HEAD_SIZE);
        ret = mes_send_data_x_inner(&head, count, args);
        if (ret != CM_SUCCESS) {
            /* room is only freed in paired get response api */
            continue;
        }
        (void)cm_atomic32_inc(&room->req_count);
    }
    room->room_status = STATUS_BCAST_SENT;
    va_end(args);
    return ret;
}

int mes_broadcast_request_sp(inst_type* inst_list, unsigned int inst_count,
    flag_type flag, ruid_type* ruid, char* msg_data, unsigned int size)
{
    return mes_broadcast_request_spx(inst_list, inst_count, flag, ruid, 1, msg_data, size);
}

int mes_broadcast_get_response(ruid_type ruid, mes_msg_list_t* responses, int timeout_ms)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR(
            "[mes]disable_request = 1, no support send request and get response, func:mes_broadcast_get_response");
        return CM_ERROR;
    }
    MES_RETURN_IF_BAD_RUID(ruid);
    int32 wait_time = 0;
    mes_waiting_room_t *room = mes_ruid_get_room(ruid);
    CM_ASSERT(room != NULL);

    for (;;) {
        if (room->req_count == 0) {
            break;
        }
        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout_ms || MES_WAITS_INTERRUPTED) {
                room->ack_count = 0; // invalid broadcast ack
                // when timeout the ack msg may reach, so need do some check and protect.
                mes_protect_when_brcast_timeout(room);
                LOG_DEBUG_WAR("[mes]room %hhu with rsn=%llu has timed out on brcast, INT=%u",
                    room->room_index, room->rsn - 1, MES_WAITS_INTERRUPTED);
                mes_free_room(room);
                return ERR_MES_WAIT_OVERTIME;
            }
            continue;
        }

        if (room->ack_count >= room->req_count) {
            break;
        }
    }
    mes_copy_recv_broadcast_msg(room, responses);
    mes_free_room(room);

    return CM_SUCCESS;
}
