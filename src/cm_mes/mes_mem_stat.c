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
    total_mem += (uint64)sizeof(mes_waiting_room_pool_t);
    return total_mem;
}