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
 * mes_task_threadpool.c
 *
 *
 * IDENTIFICATION
 * src/cm_mes/mes_task/mes_task_threadpool.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_task_threadpool_interface.h"
#include "mes_task_threadpool_group.h"
#include "mes_task_threadpool_scheduler.h"
#include "mes_task_threadpool_worker.h"
#include "mes_func.h"

static status_t mes_task_threadpool_start_thread()
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    unsigned int group_num = tpool->attr.group_num;
    for (unsigned int i = 0; i < group_num; i++) {
        mes_task_threadpool_group_t *cur_group = &tpool->groups[i];
        for (unsigned int j = 0; j < cur_group->attr.min_cnt; j++) {
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

              cur_group->is_available = CM_TRUE;
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

static void mes_task_threadpool_stop_thread()
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    cm_close_thread(&tpool->scheduler.thread);

    unsigned int group_num = tpool->attr.group_num;
    for (unsigned int i = 0; i < group_num; i++) {
        mes_task_threadpool_group_t *cur_group = &tpool->groups[i];
        bilist_node_t *node = cur_group->worker_list.head;
        for (uint32 j = 0; j < cur_group->worker_list.count; j++) {
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
    LOG_RUN_INF("[MES TASK THREADPOOL][init] threadpool max worker:%u", max_worker);
    ptr = cm_malloc_prot(sizeof(mes_task_threadpool_worker_t) * max_worker);
    if (ptr == NULL) {
        return CM_ERROR;
    }
    tpool->all_workers = (mes_task_threadpool_worker_t*)ptr;
    ptr = NULL;
    cm_bilist_init(&tpool->free_workers);
    for (unsigned int i = 0; i < max_worker; i++) {
        mes_task_threadpool_worker_t *cur_worker = &tpool->all_workers[i];
        cur_worker->node.prev = cur_worker->node.next = NULL;
        cur_worker->worker_id = i;
        cur_worker->group_id = MES_PRIORITY_CEIL;
        cur_worker->tid = CM_INVALID_ID32;
        cur_worker->is_active = CM_FALSE;
        cur_worker->get_msgitem_time = CM_INVALID_ID64;
        cur_worker->msg_ruid = CM_INVALID_ID64;
        cur_worker->msg_src_inst = CM_INVALID_ID32;
        cur_worker->longest_cost_time = 0;
        cur_worker->longest_get_msgitem_time = CM_INVALID_ID32;
        if (memset_s(&cur_worker->data, sizeof(cur_worker->data), 0,
            sizeof(cur_worker->data)) != EOK) {
            LOG_RUN_ERR("[mes] memset failed.");
            return CM_ERROR;
        }

        cm_event_init(&cur_worker->event);
        cm_bilist_add_tail(&cur_worker->node, &tpool->free_workers);
        cur_worker->status = MTTP_WORKER_STATUS_IN_FREELIST;
    }
    tpool->cur_worker_cnt = 0;

    // init queue resource
    unsigned max_queues = tpool_attr->max_cnt;
    ptr = cm_malloc_prot(sizeof(mes_task_threadpool_queue_t) * max_queues);
    if (ptr == NULL) {
        CM_FREE_PROT_PTR(tpool->all_workers);
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
    CM_FREE_PROT_PTR(tpool->all_queues);
    CM_FREE_PROT_PTR(tpool->all_workers);
    LOG_RUN_INF("[MES TASK THREADPOOL][uninit] end");
    return CM_SUCCESS;
}

void mes_put_msgitem_to_threadpool(mes_msgitem_t *msgitem)
{
    mes_task_threadpool_t *tpool = MES_TASK_THREADPOOL;
    unsigned int group_id = MES_PRIORITY(msgitem->msg.head->flags);
    mes_task_threadpool_group_t *group = &tpool->groups[group_id];

    cm_latch_s(&group->latch, 0, CM_FALSE, NULL);
    mes_task_threadpool_queue_t *push_queue = mes_task_threadpool_group_get_push_queue(group);
    status_t ret = mes_put_msgitem_to_threadpool_queue(push_queue, msgitem);
    if (ret != CM_SUCCESS) {
        LOG_RUN_WAR("[MES TASK THREADPOOL][put msg] put failed, group_id:%d",
            group->attr.group_id);
    }

    mes_task_threadpool_worker_t *worker= mes_task_threadpool_group_get_notify_worker(group);
    cm_event_notify(&worker->event);
    cm_unlatch(&group->latch, NULL);
}

status_t mes_check_task_threadpool_attr(mes_profile_t *profile)
{
    if (!profile->tpool_attr.enable_threadpool) {
        LOG_RUN_INF("[mes][MES TASK THREADPOOL] work threadpool is off");
        MES_GLOBAL_INST_MSG.profile.tpool_attr.enable_threadpool = CM_FALSE;
        return CM_SUCCESS;
    }

    bool8 work_task_count_all_zero = CM_TRUE;
    for (int i = 0; i < MES_PRIORITY_CEIL; i++) {
        if (profile->work_task_count[i] > 0 ) {
            work_task_count_all_zero = CM_FALSE;
            break;
        }
    }

    if (profile->tpool_attr.enable_threadpool && !work_task_count_all_zero) {
        LOG_RUN_WAR("[mes][MES TASK THREADPOOL] work threadpool is on and work_task_count is not zero, "
            "which is not allowed. so we turn off work threadpool");
        profile->tpool_attr.enable_threadpool = CM_FALSE;
        MES_GLOBAL_INST_MSG.profile.tpool_attr.enable_threadpool = CM_FALSE;
        return CM_SUCCESS;
    }
    
    mes_task_threadpool_attr_t *tpool_attr = &profile->tpool_attr;
    if (tpool_attr->group_num > MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] group_num large than MES_PRIORITY_CEIL");
        return CM_ERROR;
    }

    if (tpool_attr->min_cnt < MES_MIN_TASK_NUM) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] min_cnt less than MES_MIN_TASK_NUM, min_cnt:%u, MES_MIN_TASK_NUM:%u",
            tpool_attr->min_cnt, MES_MIN_TASK_NUM);
        return CM_ERROR;
    }

    if (tpool_attr->max_cnt > MES_MAX_TASK_NUM) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] max_cnt large than MES_MAX_TASK_NUM, max_cnt:%u, MES_MAX_TASK_NUM:%u",
            tpool_attr->max_cnt, MES_MAX_TASK_NUM);
        return CM_ERROR;
    }

    unsigned int total_min = 0;
    unsigned int total_max = 0;
    for (int i = 0; i < tpool_attr->group_num; i++) {
        mes_task_threadpool_group_attr_t *group_attr = &tpool_attr->group_attr[i];
        if (group_attr->enabled) {
            if (group_attr->min_cnt > group_attr->max_cnt) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group min_cnt large than max_cnt "
                    "group_id:%u, min_cnt:%u, max_cnt:%u",
                    group_attr->group_id, group_attr->min_cnt, group_attr->max_cnt);
                return CM_ERROR;
            }
            if (group_attr->min_cnt < MES_MIN_TASK_NUM) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group min_cnt less than MES_MIN_TASK_NUM "
                    "group_id:%u, min_cnt:%u, MES_MIN_TASK_NUM:%u",
                    group_attr->group_id, group_attr->min_cnt, MES_MIN_TASK_NUM);
                return CM_ERROR;
            }
            if (group_attr->max_cnt > MES_MAX_TASK_NUM) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group max_cnt large than MES_MAX_TASK_NUM "
                    "group_id:%u, max_cnt:%u, MES_MAX_TASK_NUM:%u",
                    group_attr->group_id, group_attr->max_cnt, MES_MAX_TASK_NUM);
                return CM_ERROR;
            }
            total_min += group_attr->min_cnt;
            total_max += group_attr->max_cnt;
        }
    }

    if (total_min != tpool_attr->min_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] min_cnt not equal to sum of group min_cnt "
            "min_cnt:%u, sum of group:%u",
            tpool_attr->min_cnt, total_min);
        return CM_ERROR;
    }

    if (total_max != tpool_attr->max_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] max_cnt not equal to sum of group max_cnt "
            "max_cnt:%u, sum of group:%u",
            tpool_attr->max_cnt, total_max);
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes][MES TASK THREADPOOL] work threadpool is on");
    MES_GLOBAL_INST_MSG.profile.tpool_attr = profile->tpool_attr;
    return CM_SUCCESS;
}