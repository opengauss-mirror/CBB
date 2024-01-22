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
 * mes_task_threadpool_group.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_group.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_TASK_THREADPOOL_GROUP_H__
#define __MES_TASK_THREADPOOL_GROUP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "mes_task_threadpool_interface.h"

typedef enum st_task_add_worker_status {
    MTTP_ADD_WORKER_STATUS_SUCCESS = 0,
    MTTP_ADD_WORKER_STATUS_REACH_MAX,
    MTTP_ADD_WORKER_STATUS_FAILED_NOT_EXPECT,
    MTTP_ADD_WORKER_STATUS_FAILED_TRY_AGAIN,
    MTTP_ADD_WORKER_STATUS_FAILED_START_THREAD,
    MTTP_ADD_WORKER_STATUS_FAILED_EXIST_WORKER_IN_RECYCLE,
} mes_task_add_worker_status_t;

void mes_task_threadpool_group_init(mes_task_threadpool_group_t *group,
    mes_task_threadpool_group_attr_t *attr);
void mes_task_threadpool_group_adjust(mes_task_threadpool_group_t *group);
status_t mes_put_msgitem_to_threadpool_queue(mes_task_threadpool_queue_t *tp_queue, mes_msgitem_t *msgitem);
mes_task_threadpool_queue_t *mes_task_threadpool_group_get_push_queue(mes_task_threadpool_group_t *group);
mes_task_threadpool_queue_t *mes_task_threadpool_group_get_pop_queue(mes_task_threadpool_group_t *group);
mes_task_add_worker_status_t mes_task_threadpool_group_add_worker(mes_task_threadpool_group_t *group);
mes_task_threadpool_worker_t* mes_task_threadpool_group_get_notify_worker(mes_task_threadpool_group_t *group);
bool8 mes_task_threadpool_group_all_queue_is_empty(mes_task_threadpool_group_t *group);

#ifdef __cplusplus
}
#endif

#endif