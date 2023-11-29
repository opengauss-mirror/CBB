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
 * mes_cb.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_cb.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include "mes_cb.h"

#ifdef __cplusplus
extern "C" {
#endif

mes_thread_init_t g_cb_thread_init = NULL;
mes_thread_deinit_t g_cb_thread_deinit = NULL;

mes_thread_init_t get_mes_worker_init_cb(void)
{
    return g_cb_thread_init;
}

mes_thread_deinit_t get_mes_worker_deinit_cb(void)
{
    return g_cb_thread_deinit;
}

int set_mes_worker_init_cb(mes_thread_init_t callback)
{
    g_cb_thread_init = callback;
    return 0;
}

int set_mes_worker_deinit_cb(mes_thread_deinit_t callback)
{
    g_cb_thread_deinit = callback;
    return 0;
}

#ifdef __cplusplus
}
#endif
