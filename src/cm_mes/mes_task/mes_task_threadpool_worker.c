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
 * mes_task_threadpool_worker.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_worker.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_worker.h"
#include "mes_task_threadpool_group.h"
#include "mes_func.h"
#include "mes_type.h"

void mes_task_threadpool_worker(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    mes_task_threadpool_worker_t *worker = (mes_task_threadpool_worker_t *)thread->argument;

    PRTS_RETVOID_IFERR(
        sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mttp_work_g%uw%u",
            worker->group_id, worker->worker_id));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char**)&thread->reg_data);
        LOG_RUN_INF("[MES TASK THREADPOOL][worker] thread init, group_id:%u, worker_id:%u",
            worker->group_id, worker->worker_id);
    }

    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    mes_task_threadpool_group_t *group = &tpool->groups[worker->group_id];
    mes_msgqueue_t finished_msgitem_queue;
    mes_init_msgqueue(&finished_msgitem_queue);
    mes_msgitem_t *msgitem = NULL;

    while (!thread->closed) {
        cm_latch_s(&group->latch, 0, CM_FALSE, NULL);
        mes_task_threadpool_queue_t *cur_queue = mes_task_threadpool_group_get_pop_queue(group);
        mes_task_threadpool_queue_t *next_queue = cur_queue;

        msgitem = mes_get_msgitem(&cur_queue->self_queue);
        for (uint32 loop = 0; msgitem == NULL && loop < group->queue_list.count; ++loop) {
            next_queue = mes_task_threadpool_group_get_pop_queue(group);
            msgitem = mes_get_msgitem(&next_queue->self_queue);
        }

        cm_unlatch(&group->latch, NULL);
        if (msgitem == NULL) {
            cm_sleep(1);
            continue;
        }

        mes_work_proc(msgitem, worker->worker_id);
        mes_put_msgitem_nolock(&finished_msgitem_queue, msgitem);
        if (MSG_ITEM_BATCH_SIZE == finished_msgitem_queue.count) {
            mes_free_msgitems(&g_cbb_mes.recv_mq.pool, &finished_msgitem_queue);
        }
    }

    if (finished_msgitem_queue.count != 0) {
        mes_free_msgitems(&g_cbb_mes.recv_mq.pool, &finished_msgitem_queue);
    }

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        cb_thread_deinit();
        LOG_RUN_INF("[MES TASK THREADPOOL][worker] thread deinit, group_id:%u, worker_id:%u",
            worker->group_id, worker->worker_id);
    }
}