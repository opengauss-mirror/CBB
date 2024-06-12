/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * mes_stat.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_STAT_H__
#define __MES_STAT_H__

#include "mes_interface.h"
#include "mes_type.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void mes_init_stat(const mes_profile_t *profile);
void mes_send_stat(uint32 cmd);
void mes_recv_message_stat(const mes_message_t *msg);

uint64 cm_get_time_usec(void);

void mes_local_stat(uint32 cmd);

void mes_get_wait_event(unsigned int cmd, unsigned long long *event_cnt, unsigned long long *event_time);
#ifdef __cplusplus  
}
#endif

#endif