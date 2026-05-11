/*
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of the Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * mes_shm.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_H
#define MES_SHM_H

#include "cm_spinlock.h"
#include "cm_thread.h"
#include "mes_type.h"

void mes_shm_init_channels_param(uintptr_t channelPtr);

int mes_init_shm_resource(void);
void mes_shm_cleanup(void);

int mes_shm_map_peers(void);
int mes_init_shm_queue(void);

void mes_shm_try_connect(uintptr_t pipePtr);
void mes_shm_heartbeat_channel(uintptr_t channelPtr);
int mes_shm_send_data(const void *msg_data);
int mes_shm_send_bufflist(mes_bufflist_t *buff_list);

void mes_shm_disconnect_handle(uint32 inst_id, bool32 wait); /* wait: mes_disconnect_t; unused in SHM */

#endif
