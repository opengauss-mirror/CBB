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
 * mes_shm_ub_queue.h
 *
 * UB dist-comm queue init/deinit (implementation in mes_shm_ub_queue.c).
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_ub_queue.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_UB_QUEUE_H
#define MES_SHM_UB_QUEUE_H

#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

int mes_init_shm_queue(void);

void mes_shm_deinit_all_ub_handles(shm_rpc_lsnr_t *shm_lsnr);

#ifdef __cplusplus
}
#endif

#endif
