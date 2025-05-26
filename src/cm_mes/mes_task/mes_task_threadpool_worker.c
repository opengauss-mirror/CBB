/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
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
 * src/cm_mes/mes_task/mes_task_threadpool_worker.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_worker.h"
#include "mes_task_threadpool_group.h"
#include "mes_func.h"
#include "mes_type.h"

// 1s
#define MES_TASK_PROC_TIMEOUT 1000

static void mes_task_threadpool_worker_inner(thread_t *thread)
{
    mes_task_threadpool_worker_t *worker = (mes_task_threadpool_worker_t *)thread->argument;
    uint32 *tid = &worker->tid;
    *tid = cm_get_current_thread_id();
    bool8 *is_active = &worker->is_active;
    uint64 *get_msgitem_time = &worker->get_msgitem_time;
    uint64 *longest_get_msgitem_time = &worker->longest_get_msgitem_time;
    uint64 *longest_cost_time = &worker->longest_cost_time;
    uint32 *longest_cmd = &worker->longest_cmd;
    uint64 *msg_ruid = &worker->msg_ruid;
    uint32 *src_inst = &worker->msg_src_inst;

    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    mes_task_threadpool_group_t *group = &tpool->groups[worker->group_id];
    mes_msgqueue_t finished_msgitem_queue;
    mes_init_msgqueue(&finished_msgitem_queue);
    mes_msgitem_t *msgitem = NULL;
    bool8 is_empty = CM_FALSE;

    while (!thread->closed) {
        cm_latch_s(&group->latch, 0, CM_FALSE, NULL);
        is_empty = mes_task_threadpool_group_all_queue_is_empty(group);
        cm_unlatch(&group->latch, NULL);
        if (is_empty) {
            if (cm_event_timedwait(&worker->event, CM_SLEEP_1_FIXED) != CM_SUCCESS) {
                continue;
            }
        }

        cm_latch_s(&group->latch, 0, CM_FALSE, NULL);
        mes_task_threadpool_queue_t *cur_queue = mes_task_threadpool_group_get_pop_queue(group);

        msgitem = mes_get_msgitem(&cur_queue->self_queue);
        for (uint32 loop = 0; msgitem == NULL && loop < group->queue_list.count; ++loop) {
            cur_queue = mes_task_threadpool_group_get_pop_queue(group);
            msgitem = mes_get_msgitem(&cur_queue->self_queue);
        }

        cm_unlatch(&group->latch, NULL);
        if (msgitem == NULL) {
            continue;
        }

        (void)cm_atomic_dec((atomic_t *)(&group->attr.inqueue_msgitem_num));
        mes_message_head_t *head = msgitem->msg.head;
        LOG_DEBUG_INF("[mes] mes_task_threadpool_worker_inner, cmd=%u, ruid=%llu, ruid->rid=%llu, ruid->rsn=%llu, "
            "src_inst=%u, dst_inst=%u, size=%u, flag=%u",
            (head)->cmd, (uint64)head->ruid, (uint64)MES_RUID_GET_RID((head)->ruid),
            (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size, (head)->flags);

        if (MES_GLOBAL_INST_MSG.profile.max_wait_time != CM_INVALID_INT32) {
            uint64 now = cm_get_time_usec();
            if ((now - msgitem->enqueue_time) / MICROSECS_PER_MILLISEC > MES_GLOBAL_INST_MSG.profile.max_wait_time) {
                mes_release_message_buf(&msgitem->msg);
                continue;
            }
        }
        *is_active = CM_TRUE;
        *get_msgitem_time = g_timer()->now;
        *msg_ruid = (uint64)head->ruid;
        *src_inst = (uint32)head->src_inst;
        mes_work_proc(msgitem, worker->worker_id);
        uint64 cost_time = (uint64)g_timer()->now - *get_msgitem_time;
        group->attr.total_cost_time += cost_time;
        if (cost_time > *longest_cost_time) { // sometime, cost_time = 0
            *longest_cost_time = cost_time;
            *longest_get_msgitem_time = *get_msgitem_time;
            memcpy_s(longest_cmd, sizeof(worker->longest_data), worker->data, sizeof(worker->data));
        }
        if (cost_time / MICROSECS_PER_MILLISEC > MES_TASK_PROC_TIMEOUT) {
            group->attr.timeout = CM_TRUE;
        }
        *is_active = CM_FALSE;
        mes_put_msgitem_nolock(&finished_msgitem_queue, msgitem);
        (void)cm_atomic_inc((atomic_t *)(&group->attr.finished_msgitem_num));
        if (MSG_ITEM_BATCH_SIZE == finished_msgitem_queue.count) {
            mes_free_msgitems(&g_cbb_mes.recv_mq.pool, &finished_msgitem_queue);
        }
    }

    if (finished_msgitem_queue.count != 0) {
        mes_free_msgitems(&g_cbb_mes.recv_mq.pool, &finished_msgitem_queue);
    }
}

void mes_task_threadpool_worker(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    mes_task_threadpool_worker_t *worker = (mes_task_threadpool_worker_t *)thread->argument;
    unsigned int group_id = worker->group_id;
    unsigned int worker_id = worker->worker_id;
    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mttp_work_g%uw%u", group_id, worker_id));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char**)&thread->reg_data);
        LOG_RUN_INF("[MES TASK THREADPOOL][worker] thread init, group_id:%u, worker_id:%u, thread id:%lu",
            group_id, worker_id, thread->id);
    }

    mes_task_threadpool_worker_inner(thread);

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        LOG_RUN_INF("[MES TASK THREADPOOL][worker] thread deinit, group_id:%u, worker_id:%u, thread id:%lu",
            group_id, worker_id, thread->id);
        cb_thread_deinit();
    }
}