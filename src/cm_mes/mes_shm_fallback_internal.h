/*
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * mes_shm_fallback_internal.h
 *
 * Internal hooks between mes_shm.c and mes_shm_fallback.c (not for external use).
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_fallback_internal.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_FALLBACK_INTERNAL_H
#define MES_SHM_FALLBACK_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "mes_interface.h"
#include "ub_dist_comm_queue.h"

bool mes_shm_fallback_in_progress(void);

void mes_shm_handle_ub_fault(const char *site);

void mes_ub_fallback_recv_callback(const message_t *msg, void *ctx);

uint32_t mes_get_index_from_inst_id(inst_type inst_id);

/* Shared with mes_shm_ub_queue.c (sizing / init). */
uint32_t mes_shm_ring_capacity(uint32_t ub_queue_idx);
uint64_t mes_shm_get_queue_shm_size(uint32_t ub_queue_idx);
inst_type mes_shm_get_coordinator_inst_id(void);

/* Optional fault-injection thread (MES_SHM_MAP_TOUCH=1); implemented in mes_shm_fallback.c. */
void mes_shm_start_map_touch_thread(void);
void mes_shm_stop_map_touch_thread(void);

#endif
