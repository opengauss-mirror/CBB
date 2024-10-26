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
#include "mes_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

static mes_thread_init_t g_cb_thread_init = NULL;
static mes_thread_deinit_t g_cb_thread_deinit = NULL;
static mes_app_cmd_cb_t g_cb_app_cmd = NULL;

mes_thread_init_t mes_get_worker_init_cb(void)
{
    return g_cb_thread_init;
}

mes_thread_deinit_t mes_get_worker_deinit_cb(void)
{
    return g_cb_thread_deinit;
}

void mes_set_worker_init_cb(mes_thread_init_t callback)
{
    g_cb_thread_init = callback;
}

void mes_set_worker_deinit_cb(mes_thread_deinit_t callback)
{
    g_cb_thread_deinit = callback;
}

void mes_set_app_cmd_cb(mes_app_cmd_cb_t callback)
{
    g_cb_app_cmd = callback;
}

mes_app_cmd_cb_t mes_get_app_cmd_cb()
{
    return g_cb_app_cmd;
}

#ifdef __cplusplus
}
#endif
