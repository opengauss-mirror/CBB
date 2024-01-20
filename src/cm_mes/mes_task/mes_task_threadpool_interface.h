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
 * mes_task_threadpool_interface.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_TASK_THREADPOOL_INTERFACE_H__
#define __MES_TASK_THREADPOOL_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "cm_latch.h"
#include "cm_bilist.h"
#include "cm_atomic.h"
#include "mes_queue.h"
#include "mes_interface.h"

typedef enum st_mes_task_threadpool_worker_status {
    MTTP_WORKER_STATUS_UNINIT,
    MTTP_WORKER_STATUS_IN_FREELIST,
    MTTP_WORKER_STATUS_IN_GROUP,
    MTTP_WORKER_STATUS_OUTSIDE_OF_GROUP,
} mes_task_threadpool_worker_status_e;

typedef struct st_mes_task_threadpool_worker {
    bilist_node_t node;
    thread_t thread;
    unsigned int worker_id;
    mes_task_threadpool_worker_status_e status;
    unsigned int group_id;
    cm_event_t event;
} mes_task_threadpool_worker_t;

typedef enum st_mes_task_threadpool_queue_status {
    MTTP_QUEUE_UNINIT,
    MTTP_QUEUE_IN_FREELIST,
    MTTP_QUEUE_RUN,
    MTTP_QUEUE_FORBIDDEN_PUT,
} mes_task_threadpool_queue_status_e;

typedef struct st_mes_task_threadpool_queue {
    bilist_node_t node;
    unsigned int queue_id;
    mes_msgqueue_t self_queue;
    mes_task_threadpool_queue_status_e status;
    unsigned int group_id;
} mes_task_threadpool_queue_t;

typedef struct st_mes_task_threadpool_scheduler {
    thread_t thread;
} mes_task_threadpool_scheduler_t;

typedef struct st_mes_task_threadpool_group {
    mes_task_threadpool_group_attr_t attr;
    bilist_t worker_list; // get from head, put to tail
    bilist_t queue_list; // get from head, put to tail
    mes_task_threadpool_queue_t *pop_queue;
    mes_task_threadpool_queue_t *push_queue;
    latch_t latch;
    mes_task_threadpool_queue_t *min_cnt_queue;
    mes_task_threadpool_queue_t *leaving_queue;
    unsigned char inited;
    unsigned char is_available;
    unsigned int busy_count;
    unsigned int idle_count;
    unsigned int current_task_count;
    mes_task_threadpool_worker_t *notify_worker;
} mes_task_threadpool_group_t;

typedef struct st_mes_task_threadpool {
    mes_task_threadpool_attr_t attr;
    mes_task_threadpool_worker_t *all_workers;
    bilist_t free_workers;
    unsigned int cur_worker_cnt;
    atomic32_t in_recycle_worker_cnt;
    mes_task_threadpool_queue_t *all_queues;
    bilist_t free_queues;
    unsigned int cur_queue_cnt;
    mes_task_threadpool_group_t groups[MES_PRIORITY_CEIL];
    mes_task_threadpool_scheduler_t scheduler;
    unsigned char inited;
} mes_task_threadpool_t;
 
status_t mes_task_threadpool_init(mes_task_threadpool_attr_t *tpool_attr);
status_t mes_task_threadpool_uninit();
void mes_put_msgitem_to_threadpool(mes_msgitem_t *msgitem);

#ifdef __cplusplus
}
#endif

#endif