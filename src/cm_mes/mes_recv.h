/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * mes_recv.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_recv.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_RECV_H__
#define __MES_RECV_H__
#include "cm_types.h"
#include "mes_interface.h"

typedef void(*mes_event_proc_t)(uint32 channel_id, uint32 priority, uint32 event);
int mes_start_receivers(uint32 priority_count, unsigned int *recv_task_count, mes_event_proc_t event_proc);
void mes_stop_receivers();
int mes_add_pipe_to_epoll(uint32 channel_id, mes_priority_t priority, int sock);
int mes_remove_pipe_from_epoll(mes_priority_t priority, uint32 channel_id, int sock);

#endif