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
 * mes_func.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_mem_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "mes_interface.h"
#include "mes_func.h"
#include "mes_queue.h"
#include "mes_msg_pool.h"

mes_mem_info_stat_t g_mes_mem_info_stat[MES_MEM_STAT_ROW_RESULT_COUNT] = {
    {"mes_receive_buf_pool", 0, 0, 0},
    {"mes_channel_mem", 0, 0, 0},
    {"mes_room_broadcast_mem", 0, 0, 0},
    {"mes_receive_msgqueue", 0, 0, 0},
    {"mes_receive_msgitem", 0, 0, 0},
};

uint64 mes_calc_channels_mem(uint32 channel_cnt)
{
    uint64 total_mem = (uint64)(sizeof(mes_channel_t *) * MES_MAX_INSTANCES +
        sizeof(mes_channel_t) * MES_MAX_INSTANCES * channel_cnt);
    // send queue
    total_mem += (uint64)(sizeof(mes_msgqueue_t *) * MES_MAX_INSTANCES +
        sizeof(mes_msgqueue_t) * MES_MAX_INSTANCES * channel_cnt);
    // receive queue
    total_mem += (uint64)(sizeof(mes_msgqueue_t *) * MES_MAX_INSTANCES +
        sizeof(mes_msgqueue_t) * MES_MAX_INSTANCES * channel_cnt);
    // send msg item
    total_mem += INIT_MSGITEM_BUFFER_SIZE * MAX_POOL_BUFFER_COUNT * (uint64)sizeof(mes_msgitem_t);
    // receive msg item
    total_mem += INIT_MSGITEM_BUFFER_SIZE * MAX_POOL_BUFFER_COUNT * (uint64)sizeof(mes_msgitem_t);
    return total_mem;
}

uint64 mes_calc_room_pool()
{
    uint64 total_mem = (uint64)sizeof(mes_waiting_room_pool_t);
    // broadcast_msg
    total_mem += sizeof(void *) * CM_MAX_MES_ROOMS * MES_MAX_INSTANCES;
    return total_mem;
}

uint64 mes_calc_buffer_pool_mem(mes_profile_t *profile)
{
    uint64 total_mem = 0;
    for (uint32 i = 0; i < profile->priority_cnt; i++) {
        total_mem += mes_calc_message_pool_size(profile, i);
    }
    return total_mem;
}

long long mes_calc_mem_usage(mes_profile_t *profile)
{
    // mes send buffer pool
    uint64 total_mem = 0;
    total_mem += mes_calc_buffer_pool_mem(profile) * (CM_MAX_INSTANCES - 1);
    // mes receive buffer pool
    total_mem += mes_calc_buffer_pool_mem(profile) * CM_MAX_INSTANCES;
    // mes channels
    total_mem += mes_calc_channels_mem(profile->channel_cnt);
    // mes room pool
    total_mem += mes_calc_room_pool();
    return total_mem;
}

static void calc_percentage(mes_mem_info_stat_t *mem_stat_row_results)
{
    double used_percentage =
        (mem_stat_row_results->total == 0) ? 0 : (double)mem_stat_row_results->used / mem_stat_row_results->total * 100;
    mem_stat_row_results->used_percentage = used_percentage;
}

uint64 mes_get_mem_remain_from_pool(mes_pool_t *pool)
{
    uint64 remain_size = 0;
    for (uint32 i = 0; i < pool->count; i++) {
        mes_buf_chunk_t *chunk = &pool->chunk[i];
        for (uint32 j = 0; j < chunk->queue_num; j++) {
            mes_buf_queue_t *queue = &chunk->queues[j];
            remain_size += (uint64)queue->count * queue->buf_size;
        }
    }
    return remain_size;
}

uint64 mes_calc_buffer_pool_remain(bool32 is_send)
{
    uint64 remain_size = 0;
    mes_pool_t *pool;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (is_send && (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id)) {
            continue;
        }
        for (uint32 priority = 0; priority < MES_GLOBAL_INST_MSG.profile.priority_cnt; priority++) {
            pool = mq_ctx->msg_pool[inst_id][priority];
            remain_size += mes_get_mem_remain_from_pool(pool);
        }
    }
    return remain_size;
}

static uint64 get_msg_item_unused_num()
{
    uint64 unused_num = 0;
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    unused_num += (uint64)mq_ctx->pool.free_list.count;
    unused_num += (uint64)(INIT_MSGITEM_BUFFER_SIZE - mq_ctx->pool.hwm);

    for (uint32 i = 0; i < MES_MAX_INSTANCES; i++) {
        for (uint32 j = 0; j < MES_GLOBAL_INST_MSG.profile.channel_cnt; j++) {
            unused_num += (uint64)mq_ctx->channel_private_queue[i][j].count;
        }
    }
    return unused_num;
}

void mes_collect_mem_usage_stat()
{
    // mes receive buffer pool
    g_mes_mem_info_stat[MEM_RECEIVE_BUF_POOL].total =
        mes_calc_buffer_pool_mem(&MES_GLOBAL_INST_MSG.profile) * (MES_GLOBAL_INST_MSG.profile.inst_cnt);
    g_mes_mem_info_stat[MEM_RECEIVE_BUF_POOL].used =
        g_mes_mem_info_stat[MEM_RECEIVE_BUF_POOL].total - mes_calc_buffer_pool_remain(CM_FALSE);
    calc_percentage(&g_mes_mem_info_stat[MEM_RECEIVE_BUF_POOL]);

    // channel
    g_mes_mem_info_stat[MEM_CHANNEL_MEM].total = (uint64)sizeof(mes_channel_t *) * MES_MAX_INSTANCES +
        (uint64)sizeof(mes_channel_t) * MES_GLOBAL_INST_MSG.profile.inst_cnt * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    g_mes_mem_info_stat[MEM_CHANNEL_MEM].used = g_mes_mem_info_stat[MEM_CHANNEL_MEM].total;
    calc_percentage(&g_mes_mem_info_stat[MEM_CHANNEL_MEM]);

    // room pool broadcast
    g_mes_mem_info_stat[MEM_ROOM_BROADCAST].total =
        (uint64)sizeof(void *) * CM_MAX_MES_ROOMS * MES_GLOBAL_INST_MSG.profile.inst_cnt;
    g_mes_mem_info_stat[MEM_ROOM_BROADCAST].used = g_mes_mem_info_stat[MEM_ROOM_BROADCAST].total;
    calc_percentage(&g_mes_mem_info_stat[MEM_ROOM_BROADCAST]);

    // receive msg queue
    g_mes_mem_info_stat[MEM_RECEIVE_MSGQUEUE].total = (uint64)sizeof(mes_msgqueue_t *) * MES_MAX_INSTANCES +
        (uint64)sizeof(mes_msgqueue_t) * MES_MAX_INSTANCES * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    g_mes_mem_info_stat[MEM_RECEIVE_MSGQUEUE].used = g_mes_mem_info_stat[MEM_RECEIVE_MSGQUEUE].total;
    calc_percentage(&g_mes_mem_info_stat[MEM_RECEIVE_MSGQUEUE]);

    // receive msg item
    if (MES_GLOBAL_INST_MSG.recv_mq.pool.buf_idx != CM_INVALID_ID16) {
        g_mes_mem_info_stat[MEM_RECEIVE_MSGITEM].total =
            (uint64)sizeof(mes_msgitem_t) * INIT_MSGITEM_BUFFER_SIZE * (MES_GLOBAL_INST_MSG.recv_mq.pool.buf_idx + 1);
        uint64 unused_size = get_msg_item_unused_num() * sizeof(mes_msgitem_t);
        g_mes_mem_info_stat[MEM_RECEIVE_MSGITEM].used = g_mes_mem_info_stat[MEM_RECEIVE_MSGITEM].total - unused_size;
        calc_percentage(&g_mes_mem_info_stat[MEM_RECEIVE_MSGITEM]);
    }

}

void mes_get_mem_usage_stat_row(mes_mem_stat_t mem_id, mes_mem_info_stat_t *mes_mem_stat_row_result)
{
    if (mem_id >= MES_MEM_STAT_ROW_RESULT_COUNT) {
        return;
    }
    mes_mem_stat_row_result->area = g_mes_mem_info_stat[mem_id].area;
    mes_mem_stat_row_result->total = g_mes_mem_info_stat[mem_id].total;
    mes_mem_stat_row_result->used = g_mes_mem_info_stat[mem_id].used;
    mes_mem_stat_row_result->used_percentage = g_mes_mem_info_stat[mem_id].used_percentage;
}