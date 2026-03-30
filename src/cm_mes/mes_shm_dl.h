/*
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
 * mes_shm_dl.h
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_dl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_DL_H
#define MES_SHM_DL_H

#include "ubs_mem.h"
 
#ifdef __cplusplus
extern "C" {
#endif
 
#ifndef PATH_LENGTH
#define PATH_LENGTH PATH_MAX
#endif
 
#define UBS_MEM_ENV_PATH   "UBS_MEM_LIB_PATH"
#define UBS_MEM_SO_NAME    "libubsm_sdk.so"

extern int mes_init_ubs_dlopen_so(void);
extern void FinishUbsMemDl(void);
 
#ifdef __cplusplus
}
#endif
 
#endif /* MES_SHM_DL_H */