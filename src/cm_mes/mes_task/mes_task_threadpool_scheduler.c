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
 * mes_task_threadpool_scheduler.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_scheduler.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_scheduler.h"
#include "mes_task_threadpool_group.h"
#include "mes_func.h"

#define MES_TASK_THREADPOOL_SCHEDULER_TIME_UNIT 200 //ms

void mes_task_threadpool_scheduler(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    PRTS_RETVOID_IFERR(
        sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mttp_scheduler"));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char**)&thread->reg_data);
        LOG_RUN_INF("[MES TASK THREADPOOL][sheduler] thread init");
    }

    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    while (!thread->closed) {
        uint32 group_num = tpool->attr.group_num;
        for (int i = 0; i < group_num; i++) {
            mes_task_threadpool_group_t *group = &tpool->groups[i];
            if (!group->attr.enabled) {
                continue;
            }
            mes_task_threadpool_group_adjust(group);
        }
        cm_sleep(MES_TASK_THREADPOOL_SCHEDULER_TIME_UNIT);
    }

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        cb_thread_deinit();
        LOG_RUN_INF("[MES TASK THREADPOOL][sheduler] thread deinit");
    }
}