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
 * mes_task_threadpool_scheduler.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_task/mes_task_threadpool_scheduler.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_TASK_THREADPOOL_SCHEDULER_H__
#define __MES_TASK_THREADPOOL_SCHEDULER_H__

#ifdef __cplusplus
extern "C" {
#endif
#include "mes_task_threadpool_interface.h"

void mes_task_threadpool_scheduler(thread_t *thread);

#ifdef __cplusplus
}
#endif

#endif