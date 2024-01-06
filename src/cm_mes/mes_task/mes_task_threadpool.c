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
 * mes_task_threadpool.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_interface.h"
#include "mes_task_threadpool_group.h"
#include "mes_task_threadpool_scheduler.h"
#include "mes_task_threadpool_worker.h"
#include "mes_func.h"

status_t mes_task_threadpool_start_thread()
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    unsigned int group_num = tpool->attr.group_num;
    for (int i = 0; i < group_num; i++) {
        mes_task_threadpool_group_t *cur_group = &tpool->groups[i];
        if (!cur_group->attr.enabled) {
            continue;
        }

        for (int j = 0; j < cur_group->attr.min_cnt; j++) {
            mes_task_add_worker_status_t ret = MTTP_ADD_WORKER_STATUS_SUCCESS;
            do {
                ret = mes_task_threadpool_group_add_worker(cur_group);
                if (ret == MTTP_ADD_WORKER_STATUS_REACH_MAX ||
                    ret == MTTP_ADD_WORKER_STATUS_FAILED_NOT_EXPECT ||
                    ret == MTTP_ADD_WORKER_STATUS_FAILED_START_THREAD) {
                    LOG_RUN_ERR("[MES TASK THREADPOOL][init] group add worker failed, group_id:%u",
                        cur_group->attr.group_id);
                    return CM_ERROR;
                } 
            } while (ret != MTTP_ADD_WORKER_STATUS_SUCCESS);

            if (!cur_group->is_available) {
                cur_group->is_available = CM_TRUE;
            }
        }
        LOG_DEBUG_INF("[MES TASK THREADPOOL][init] group add worker finished, group_id:%u",
            cur_group->attr.group_id);

    }
    status_t ret = cm_create_thread(mes_task_threadpool_scheduler, 0, &tpool->scheduler, &tpool->scheduler.thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[MES TASK THREADPOOL][init] start mttp_scheduler failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void mes_task_threadpool_stop_thread()
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    cm_close_thread(&tpool->scheduler.thread);

    unsigned int group_num = tpool->attr.group_num;
    for (int i = 0; i < group_num; i++) {
        mes_task_threadpool_group_t *cur_group = &tpool->groups[i];
        if (!cur_group->attr.enabled) {
            continue;
        }

        bilist_node_t *node = cur_group->worker_list.head;
        for (int i = 0; i < cur_group->worker_list.count; i++) {
            mes_task_threadpool_worker_t *cur_worker = (mes_task_threadpool_worker_t*)node;
            cm_close_thread(&cur_worker->thread);
            node = BINODE_NEXT(node);
        }
    }
}

status_t mes_task_threadpool_init(mes_task_threadpool_attr_t *tpool_attr)
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    tpool->attr = *tpool_attr;
    void *ptr = NULL;

    LOG_RUN_INF("[MES TASK THREADPOOL][init] begin");
    // init worker resource
    unsigned int max_worker = tpool_attr->max_cnt;
    ptr = malloc(sizeof(mes_task_threadpool_worker_t) * max_worker);
    if (ptr == NULL) {
        return CM_ERROR;
    }
    tpool->all_workers = (mes_task_threadpool_worker_t*)ptr;
    ptr = NULL;
    cm_bilist_init(&tpool->free_workers);
    for (int i = 0; i < max_worker; i++) {
        mes_task_threadpool_worker_t *cur_worker = &tpool->all_workers[i];
        cur_worker->node.prev = cur_worker->node.next = NULL;
        cur_worker->worker_id = i;
        cm_bilist_add_tail(&cur_worker->node, &tpool->free_workers);
        cur_worker->status = MTTP_WORKER_STATUS_IN_FREELIST;
    }
    tpool->cur_worker_cnt = 0;

    // init queue resource
    unsigned max_queues = tpool_attr->max_cnt;
    ptr = malloc(sizeof(mes_task_threadpool_queue_t) * max_queues);
    if (ptr == NULL) {
        CM_FREE_PTR(tpool->all_workers);
        return CM_ERROR;
    }
    tpool->all_queues = (mes_task_threadpool_queue_t*)ptr;
    ptr = NULL;
    cm_bilist_init(&tpool->free_queues);
    for (int i = 0; i < max_queues; i++) {
        mes_task_threadpool_queue_t *cur_queue = &tpool->all_queues[i];
        cur_queue->node.prev = cur_queue->node.next = NULL;
        cur_queue->queue_id = i;
        mes_init_msgqueue(&cur_queue->self_queue);
        cur_queue->status = MTTP_QUEUE_IN_FREELIST;
        cm_bilist_add_tail(&cur_queue->node, &tpool->free_queues);
    }
    tpool->cur_queue_cnt = 0;

    // init group
    unsigned int group_num = tpool_attr->group_num;
    for (int i = 0; i < group_num; i++) {
        mes_task_threadpool_group_init(&tpool->groups[i], &tpool->attr.group_attr[i]);
    }
    LOG_RUN_INF("[MES TASK THREADPOOL][init] finish init group");

    if (mes_task_threadpool_start_thread() != CM_SUCCESS) {
        LOG_RUN_INF("[MES TASK THREADPOOL][init] failed, start thread failed");
    }

    tpool->inited = CM_TRUE;
    LOG_RUN_INF("[MES TASK THREADPOOL][init] end");
    return CM_SUCCESS;
}

status_t mes_task_threadpool_uninit()
{
    LOG_RUN_INF("[MES TASK THREADPOOL][uninit] begin");
    mes_task_threadpool_stop_thread();
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    CM_FREE_PTR(tpool->all_queues);
    CM_FREE_PTR(tpool->all_workers);
    LOG_RUN_INF("[MES TASK THREADPOOL][uninit] end");
    return CM_SUCCESS;
}

void mes_put_msgitem_to_threadpool(mes_msgitem_t *msgitem)
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    unsigned int group_id = MES_PRIORITY(msgitem->msg.head->flags);
    mes_task_threadpool_group_t *group = &tpool->groups[group_id];

    if (!group->attr.enabled) {
        LOG_DEBUG_ERR("[MES TASK THREADPOOL][put msg][error] group is not enabled but receive msg, group_id:%d",
            group->attr.group_id);
        return;
    }
    
    if (!group->is_available) {
        LOG_DEBUG_WAR("[MES TASK THREADPOOL][put msg] group is not available, group_id:%d",
            group->attr.group_id);
        return;
    }

    cm_latch_s(&group->latch, 0, CM_FALSE, NULL);
    mes_task_threadpool_queue_t *push_queue = mes_task_threadpool_group_get_push_queue(group);
    status_t ret = mes_put_msgitem_to_threadpool_queue(push_queue, msgitem);
    if (ret != CM_SUCCESS) {
        LOG_RUN_WAR("[MES TASK THREADPOOL][put msg] put failed, group_id:%d",
            group->attr.group_id);
    }
    cm_unlatch(&group->latch, NULL);
}