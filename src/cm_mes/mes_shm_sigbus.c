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
 * mes_shm_sigbus.c
 *
 * SIGBUS handler for MES SHM UB memory (aligned with openGauss ub_sigbus_handler).
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_sigbus.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_shm_sigbus.h"

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB)

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "cm_log.h"

#define MES_SHM_SIGBUS_JMP_POINT 1

__thread sigjmp_buf g_mes_shm_sigbus_jump_env;
__thread bool8 g_mes_shm_sigbus_jump_active = CM_FALSE;

static struct sigaction g_mes_shm_old_sigbus_act;
static volatile sig_atomic_t g_mes_shm_old_sigbus_act_valid = 0;

static void mes_shm_sigbus_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)uc;

    if (si != NULL) {
        LOG_DEBUG_WAR("[mes_shm] SIGBUS si_addr=%p", si->si_addr);
    }

    if (g_mes_shm_sigbus_jump_active) {
        siglongjmp(g_mes_shm_sigbus_jump_env, MES_SHM_SIGBUS_JMP_POINT);
    }

    /*
     * Outside MES SHM protected region: restore previous handler (e.g. BBOX /
     * coredump) and re-raise so it can dump core; fall back to SIG_DFL if none.
     */
    if (g_mes_shm_old_sigbus_act_valid) {
        (void)sigaction(SIGBUS, &g_mes_shm_old_sigbus_act, NULL);
    } else {
        struct sigaction dfl;
        errno_t ret = memset_s(&dfl, sizeof(dfl), 0, sizeof(dfl));
        if (ret != EOK) {
            LOG_RUN_ERR("[mes_shm] memset_s sigaction failed in SIGBUS handler");
            _exit(1);
        }
        dfl.sa_handler = SIG_DFL;
        (void)sigemptyset(&dfl.sa_mask);
        dfl.sa_flags = 0;
        (void)sigaction(SIGBUS, &dfl, NULL);
    }
    (void)raise(SIGBUS);
}

int mes_shm_sigbus_register_handler(void)
{
    struct sigaction sa;
    struct sigaction old_sa;
    errno_t ret = memset_s(&sa, sizeof(sa), 0, sizeof(sa));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes_shm] memset_s sigaction failed");
        return CM_ERROR;
    }

    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = mes_shm_sigbus_handler;
    (void)sigemptyset(&sa.sa_mask);

    if (sigaction(SIGBUS, NULL, &old_sa) != 0) {
        LOG_RUN_ERR("[mes_shm] get old SIGBUS handler failed, errno=%d", errno);
        return CM_ERROR;
    }

    /* Avoid saving ourselves as previous on re-registration. */
    if (!((old_sa.sa_flags & SA_SIGINFO) && old_sa.sa_sigaction == mes_shm_sigbus_handler)) {
        g_mes_shm_old_sigbus_act = old_sa;
        g_mes_shm_old_sigbus_act_valid = 1;
    }

    if (sigaction(SIGBUS, &sa, NULL) != 0) {
        LOG_RUN_ERR("[mes_shm] sigaction SIGBUS failed, errno=%d", errno);
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes_shm] register handler for SIGBUS success");
    return CM_SUCCESS;
}

void mes_shm_sigbus_unregister_handler(void)
{
    if (g_mes_shm_old_sigbus_act_valid) {
        (void)sigaction(SIGBUS, &g_mes_shm_old_sigbus_act, NULL);
        g_mes_shm_old_sigbus_act_valid = 0;
    }
}

__attribute__((noinline)) void mes_shm_execute_esb_with_fault_handler(void)
{
    int rc = sigsetjmp(g_mes_shm_sigbus_jump_env, 1);
    if (rc == 0) {
        g_mes_shm_sigbus_jump_active = CM_TRUE;
        MES_SHM_ESB_BARRIER();
        g_mes_shm_sigbus_jump_active = CM_FALSE;
    } else {
        g_mes_shm_sigbus_jump_active = CM_FALSE;
        LOG_RUN_WAR("[mes_shm] barrier fault handler success");
    }
}

#endif /* __aarch64__ && ENABLE_ARM64_ESB */
