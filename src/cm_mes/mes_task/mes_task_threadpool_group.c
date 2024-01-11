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
 * mes_task_threadpool_group.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_group.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_group.h"
#include "mes_task_threadpool_worker.h"
#include "mes_func.h"

// time of enlarge 5 * 200ms = 1s
// time of reduce 20 * 200ms = 4s
#define MES_TASK_JUDGE_ROUND_OF_ENLARGE_THREAD 5
#define MES_TASK_JUDGE_ROUND_OF_REDUCE_THREAD 20

// 1 ticket = 10^5 ns = 10^2 us = 0.1 ms
// group latch wait time: 0.1 ms * 10^5 = 1s
#define MES_TASK_GROUP_LATCH_WAIT_TICKETS 10000

void mes_task_threadpool_group_init(mes_task_threadpool_group_t *group,
    mes_task_threadpool_group_attr_t *attr)
{
    group->attr = *attr;
    cm_bilist_init(&group->worker_list);
    cm_bilist_init(&group->queue_list);
    group->pop_queue = NULL;
    group->push_queue = NULL;
    cm_latch_init(&group->latch);
    group->min_cnt_queue = NULL;
    group->leaving_queue = NULL;
    group->inited = CM_TRUE;
    group->is_available = CM_FALSE;
    group->busy_count = 0;
    group->idle_count = 0;
    group->current_task_count = 0;
}

unsigned int mes_task_threadpool_group_get_all_queue_task_num(mes_task_threadpool_group_t *group)
{
    unsigned int total_cnt = 0;
    unsigned int min_cnt = CM_INVALID_ID32;
    mes_task_threadpool_queue_t *queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
    for (int i = 0; i < group->queue_list.count; i++) {
        unsigned int cnt = queue->self_queue.count;
        if (cnt < min_cnt) {
            group->min_cnt_queue = queue;
            min_cnt = cnt;
        }
        total_cnt += cnt;
        queue = (mes_task_threadpool_queue_t*)queue->node.next;
    }
    return total_cnt;
}

void mes_task_threadpool_group_check_busyness(mes_task_threadpool_group_t *group)
{
    uint32 cnt = mes_task_threadpool_group_get_all_queue_task_num(group);
    group->current_task_count = cnt;
    if (cnt >= group->attr.task_num_ceiling) {
        group->busy_count++;
        group->idle_count = 0;
    } else if (cnt <= group->attr.task_num_floor) {
        group->busy_count = 0;
        group->idle_count++;
    }
    return;
}

mes_task_add_worker_status_t mes_task_threadpool_group_add_worker(mes_task_threadpool_group_t *group)
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    if (group->worker_list.count == group->attr.max_cnt) {
        LOG_DEBUG_INF("[MES TASK THREADPOOL][add worker] group worker cnt has reach max, group_id:%u,"
            "worker cnt%u, max cnt:%u",
            group->attr.group_id, group->worker_list.count, group->attr.max_cnt);
        return MTTP_ADD_WORKER_STATUS_REACH_MAX;
    }

    if (group->worker_list.count > group->attr.max_cnt ||
        tpool->cur_worker_cnt > tpool->attr.max_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL][add worker] group worker cnt large than max cnt, group_id:%u,"
            "worker cnt%u, max cnt:%u",
            group->attr.group_id, group->worker_list.count, group->attr.max_cnt);
        cm_panic(0);
        return MTTP_ADD_WORKER_STATUS_FAILED_NOT_EXPECT;
    }

    if (group->leaving_queue != NULL) {
        LOG_DEBUG_INF("[MES TASK THREADPOOL][add worker][delete leaving-queue] begin, group_id:%u",
            group->attr.group_id);
        if (!cm_latch_timed_x(&group->latch, 0, MES_TASK_GROUP_LATCH_WAIT_TICKETS, NULL)) {
            LOG_DEBUG_WAR("[MES TASK THREADPOOL][add worker][delete leaving-queue] can not get latch, group_id:%u",
                group->attr.group_id);
            return MTTP_ADD_WORKER_STATUS_FAILED_GET_LATCH;
        }
        
        mes_task_threadpool_queue_t *queue = group->leaving_queue;
        cm_spin_lock(&queue->self_queue.lock, NULL);
        queue->status = MTTP_QUEUE_RUN;
        cm_spin_unlock(&queue->self_queue.lock);
        group->leaving_queue = NULL;
        LOG_DEBUG_INF("[MES TASK THREADPOOL][add worker][delete leaving-queue] end, group_id:%u",
            group->attr.group_id);
        cm_unlatch(&group->latch, NULL);
    }

    LOG_DEBUG_INF("[MES TASK THREADPOOL][add worker] begin, group_id:%u",
            group->attr.group_id);
    if (!cm_latch_timed_x(&group->latch, 0, MES_TASK_GROUP_LATCH_WAIT_TICKETS, NULL)) {
        LOG_DEBUG_WAR("[MES TASK THREADPOOL][add worker] end, can not get latch, group_id:%u",
            group->attr.group_id);
        return MTTP_ADD_WORKER_STATUS_FAILED_GET_LATCH;
    }

    LOG_DEBUG_INF("[MES TASK THREADPOOL][add worker] before add worker, group_id:%u "
            "group queue cnt:%u, worker cnt:%u, "
            "threadpool free queues:%u, free workers:%u",
            group->attr.group_id, group->queue_list.count, group->worker_list.count,
            tpool->free_queues.count, tpool->free_workers.count);
    mes_task_threadpool_worker_t *new_worker =
        (mes_task_threadpool_worker_t*)cm_bilist_pop_first(&tpool->free_workers);
    if (new_worker == NULL) {
        cm_panic_log(0, "[MES TASK THREADPOOL][add worker] unexcept situation happen, new_worker is NULL.");
    }
    new_worker->status = MTTP_WORKER_STATUS_IN_GROUP;
    cm_bilist_add_tail(&new_worker->node, &group->worker_list);
    tpool->cur_worker_cnt++;

    status_t ret = cm_create_thread(mes_task_threadpool_worker, 0, new_worker, &new_worker->thread);
    if (ret != CM_SUCCESS) {
        (void)cm_bilist_pop_back(&group->worker_list);
        cm_bilist_add_tail(&new_worker->node, &tpool->free_workers);
        tpool->cur_worker_cnt--;
        cm_unlatch(&group->latch, NULL);
        LOG_RUN_ERR("[MES TASK THREADPOOL][add worker] create worker failed, ret:%d", ret);
        return MTTP_ADD_WORKER_STATUS_FAILED_START_THREAD;
    }

    mes_task_threadpool_queue_t *new_queue =
        (mes_task_threadpool_queue_t*)cm_bilist_pop_first(&tpool->free_queues);
    if (new_queue == NULL) {
        cm_panic_log(0, "[MES TASK THREADPOOL][add worker] unexcept situation happen, new_queue is NULL.");
    }
    new_queue->status = MTTP_QUEUE_RUN;
    cm_bilist_add_tail(&new_queue->node, &group->queue_list);
    tpool->cur_queue_cnt++;

    if (group->queue_list.count == 1) {
        group->push_queue = group->pop_queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
    }
    cm_unlatch(&group->latch, NULL);

    new_worker->group_id = group->attr.group_id;

    // check
    if (group->queue_list.count != group->worker_list.count) {
        cm_panic(0);
    }
    LOG_RUN_INF("[MES TASK THREADPOOL][add worker] end, group_id:%u "
            "group queue cnt:%u, worker cnt:%u, "
            "threadpool free queues:%u, free workers:%u",
            group->attr.group_id, group->queue_list.count, group->worker_list.count,
            tpool->free_queues.count, tpool->free_workers.count);
    return MTTP_ADD_WORKER_STATUS_SUCCESS;
}

void mes_task_threadpool_group_delete_worker_inner(mes_task_threadpool_group_t *group)
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    mes_task_threadpool_worker_t *worker =
        (mes_task_threadpool_worker_t*)cm_bilist_pop_back(&group->worker_list);
    cm_close_thread(&worker->thread);
    cm_bilist_add_tail(&worker->node, &tpool->free_workers);
    worker->status = MTTP_WORKER_STATUS_IN_FREELIST;
}

status_t mes_task_threadpool_group_delete_worker(mes_task_threadpool_group_t *group)
{
    if (group->worker_list.count == group->attr.min_cnt) {
        return CM_SUCCESS;
    } else if (group->worker_list.count < group->attr.min_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL][delete worker] group worker cnt less than min cnt, group_id:%u,"
            "worker cnt%u, min cnt:%u",
            group->attr.group_id, group->worker_list.count, group->attr.min_cnt);
        cm_panic(0);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[MES TASK THREADPOOL][delete worker] begin, group_id:%u",
            group->attr.group_id);
    if (!cm_latch_timed_x(&group->latch, 0, MES_TASK_GROUP_LATCH_WAIT_TICKETS, NULL)) {
        LOG_DEBUG_WAR("[MES TASK THREADPOOL][delete worker] end, can not get latch, group_id:%u",
            group->attr.group_id);
        return CM_ERROR;
    }

    if (group->leaving_queue == NULL) {
        group->leaving_queue = group->min_cnt_queue;
    }

    bool8 is_empty = CM_FALSE;
    mes_task_threadpool_queue_t *queue = group->leaving_queue;
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    
    uint32 cur_count = 0;
    cm_spin_lock(&queue->self_queue.lock, NULL);
    queue->status = MTTP_QUEUE_FORBIDDEN_PUT;
    if (queue->self_queue.count == 0) {
        is_empty = CM_TRUE;
    }
    cur_count = queue->self_queue.count;
    cm_spin_unlock(&queue->self_queue.lock);

    if (!is_empty) {
        LOG_DEBUG_INF("[MES TASK THREADPOOL][delete worker] end, need to wait queue empty, "
            "group_id:%u, queue_id:%u, cnt:%u",
            group->attr.group_id, queue->queue_id, cur_count);
        cm_unlatch(&group->latch, NULL);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[MES TASK THREADPOOL][delete worker] before delete worker, group_id:%u "
            "group queue cnt:%u, worker cnt:%u, "
            "threadpool free queues:%u, free workers:%u",
            group->attr.group_id, group->queue_list.count, group->worker_list.count,
            tpool->free_queues.count, tpool->free_workers.count);

    if (group->pop_queue == queue) {
        group->pop_queue = mes_task_threadpool_group_get_pop_queue(group);
    }

    if (group->push_queue == queue) {
        group->push_queue = mes_task_threadpool_group_get_push_queue(group);
    }

    cm_bilist_del(&queue->node, &group->queue_list);
    cm_bilist_add_tail(&queue->node, &tpool->free_queues);
    queue->status = MTTP_QUEUE_IN_FREELIST;
    group->leaving_queue = NULL;
    tpool->cur_queue_cnt--;
    cm_unlatch(&group->latch, NULL);

    mes_task_threadpool_group_delete_worker_inner(group);
    tpool->cur_worker_cnt--;
    if (group->queue_list.count != group->worker_list.count) {
        cm_panic(0);
    }

    LOG_RUN_INF("[MES TASK THREADPOOL][delete worker] end, group_id:%u "
            "group queue cnt:%u, worker cnt:%u, "
            "threadpool free queues:%u, free workers:%u",
            group->attr.group_id, group->queue_list.count, group->worker_list.count,
            tpool->free_queues.count, tpool->free_workers.count);
    return CM_SUCCESS;
}

void mes_task_threadpool_group_adjust(mes_task_threadpool_group_t *group)
{
    if (group->attr.num_fixed) {
        return;
    }

    mes_task_threadpool_group_check_busyness(group);
    if (group->busy_count >= MES_TASK_JUDGE_ROUND_OF_ENLARGE_THREAD) {
        mes_task_add_worker_status_t ret = mes_task_threadpool_group_add_worker(group);
        if (ret == MTTP_ADD_WORKER_STATUS_SUCCESS || ret == MTTP_ADD_WORKER_STATUS_REACH_MAX) {
            group->busy_count = 0;
        } else if (ret == MTTP_ADD_WORKER_STATUS_FAILED_START_THREAD) {
            cm_panic(0);
        }
    } else if (group->idle_count >= MES_TASK_JUDGE_ROUND_OF_REDUCE_THREAD) {
        if (mes_task_threadpool_group_delete_worker(group) == CM_SUCCESS) {
            group->idle_count = 0;
        }
    }
}

status_t mes_put_msgitem_to_threadpool_queue(mes_task_threadpool_queue_t *tp_queue, mes_msgitem_t *msgitem)
{
    mes_msgqueue_t *queue = &tp_queue->self_queue;
    cm_spin_lock(&queue->lock, NULL);
    if (tp_queue->status == MTTP_QUEUE_FORBIDDEN_PUT) {
        cm_spin_unlock(&queue->lock);
        return CM_ERROR;
    }

    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
    } else {
        queue->last->next = msgitem;
        queue->last = msgitem;
    }

    msgitem->next = NULL;
    queue->count++;
    cm_spin_unlock(&queue->lock);
    return CM_SUCCESS;
}

mes_task_threadpool_queue_t *mes_task_threadpool_group_get_pop_queue(mes_task_threadpool_group_t *group)
{
    mes_task_threadpool_queue_t *pop_queue = group->pop_queue;
    mes_task_threadpool_queue_t *next_queue = (mes_task_threadpool_queue_t*)pop_queue->node.next;
    if (next_queue == NULL) {
        next_queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
    }
    group->pop_queue = (mes_task_threadpool_queue_t*)next_queue;
    return pop_queue;
}

mes_task_threadpool_queue_t *mes_task_threadpool_group_get_next_push_queue(mes_task_threadpool_group_t *group,
    mes_task_threadpool_queue_t *queue)
{
    int loop = 0;
    bool8 found = CM_FALSE;
    mes_task_threadpool_queue_t *next_queue = queue;
    if (queue == NULL) {
        LOG_RUN_ERR("[MES TASK THREADPOOL][push queue] queue is NULL, please check");
        next_queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
    }

    if (group->queue_list.count == 1) {
        if (next_queue->status == MTTP_QUEUE_FORBIDDEN_PUT) {
            LOG_RUN_ERR("[MES TASK THREADPOOL][push queue] can not find available queue, please check");
        }
        return next_queue;
    }

    while (loop < group->queue_list.count) {
        next_queue = (mes_task_threadpool_queue_t*)next_queue->node.next;
        if (next_queue == NULL) {
            next_queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
        }
        if (next_queue->status != MTTP_QUEUE_FORBIDDEN_PUT) {
            found = CM_TRUE;
            break;
        }
        loop++;
    }
    if (!found) {
        LOG_RUN_ERR("[MES TASK THREADPOOL][push queue] can not find available queue, please check");
        next_queue = (mes_task_threadpool_queue_t*)group->queue_list.head;
    }
    return next_queue;
}

mes_task_threadpool_queue_t *mes_task_threadpool_group_get_push_queue(mes_task_threadpool_group_t *group)
{
    mes_task_threadpool_queue_t *push_queue = group->push_queue;
    mes_task_threadpool_queue_t *next_queue;
    if (push_queue->status != MTTP_QUEUE_FORBIDDEN_PUT) {
        next_queue = mes_task_threadpool_group_get_next_push_queue(group, push_queue);
        group->push_queue = next_queue;
        return push_queue;
    }

    push_queue = mes_task_threadpool_group_get_next_push_queue(group, push_queue);
    next_queue = mes_task_threadpool_group_get_next_push_queue(group, push_queue);
    group->push_queue = next_queue;
    return push_queue;
}