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
 * mes_shm_sigbus.h
 *
 * SIGBUS signal handler for MES SHM UB memory access (openGauss ub_sigbus_handler style).
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_sigbus.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_SIGBUS_H
#define MES_SHM_SIGBUS_H

#include <setjmp.h>

#include "cm_defs.h"
#include "cm_error.h"

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB)

extern __thread sigjmp_buf g_mes_shm_sigbus_jump_env;
extern __thread bool8 g_mes_shm_sigbus_jump_active;

int mes_shm_sigbus_register_handler(void);
void mes_shm_sigbus_unregister_handler(void);
void mes_shm_execute_esb_with_fault_handler(void);

#define MES_SHM_SIGBUS_ENABLED() (CM_TRUE)

#define MES_SHM_EXECUTE_ESB()                       \
    do {                                            \
        mes_shm_execute_esb_with_fault_handler();   \
    } while (0)

#define MES_SHM_ESB_BARRIER()                       \
    do {                                            \
        asm volatile("esb" ::: "memory");           \
    } while (0)

#else

#define MES_SHM_SIGBUS_ENABLED() (CM_FALSE)
#define MES_SHM_EXECUTE_ESB() ((void)0)
#define MES_SHM_ESB_BARRIER() ((void)0)

static inline int mes_shm_sigbus_register_handler(void)
{
    return CM_SUCCESS;
}

static inline void mes_shm_sigbus_unregister_handler(void)
{
}

#endif /* __aarch64__ && ENABLE_ARM64_ESB */

#endif /* MES_SHM_SIGBUS_H */
