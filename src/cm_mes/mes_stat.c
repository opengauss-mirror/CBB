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
 * mes_stat.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_func.h"
#include "mes_stat.h"

mes_elapsed_stat_t g_mes_elapsed_stat;
mes_stat_t g_mes_stat;

static void mes_consume_time_init(const mes_profile_t *profile)
{
    for (uint32 j = 0; j < CM_MAX_MES_MSG_CMD; j++) {
        g_mes_elapsed_stat.time_consume_stat[j].cmd = j;
        for (int i = 0; i < MES_TIME_CEIL; i++) {
            g_mes_elapsed_stat.time_consume_stat[j].cmd_time_stats[i].time = 0;
            g_mes_elapsed_stat.time_consume_stat[j].cmd_time_stats[i].count = 0;
            GS_INIT_SPIN_LOCK(g_mes_elapsed_stat.time_consume_stat[j].cmd_time_stats[i].lock);
        }
    }
    g_mes_elapsed_stat.mes_elapsed_switch = profile->mes_elapsed_switch;
    return;
}

void mes_init_stat(const mes_profile_t *profile)
{
    g_mes_stat.mes_elapsed_switch = profile->mes_elapsed_switch;
    for (uint32 i = 0; i < CM_MAX_MES_MSG_CMD; i++) {
        g_mes_stat.mes_command_stat[i].cmd = i;
        g_mes_stat.mes_command_stat[i].send_count = 0;
        g_mes_stat.mes_command_stat[i].recv_count = 0;
        g_mes_stat.mes_command_stat[i].local_count = 0;
        g_mes_stat.mes_command_stat[i].occupy_buf = 0;
    }
    mes_consume_time_init(profile);
    return;
}

void mes_send_stat(uint32 cmd)
{
    if (g_mes_stat.mes_elapsed_switch) {
        (void)cm_atomic_inc(&(g_mes_stat.mes_command_stat[cmd].send_count));
    }
    return;
}

void mes_local_stat(uint32 cmd)
{
    if (g_mes_stat.mes_elapsed_switch) {
        (void)cm_atomic_inc(&(g_mes_stat.mes_command_stat[cmd].local_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_command_stat[cmd].occupy_buf));
    }
    return;
}

void mes_recv_message_stat(const mes_message_t *msg)
{
    if (g_mes_stat.mes_elapsed_switch) {
        (void)cm_atomic_inc(&(g_mes_stat.mes_command_stat[msg->head->cmd].recv_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_command_stat[msg->head->cmd].occupy_buf));
    }
    return;
}

static void cm_get_time_of_day(cm_timeval *tv)
{
    (void)cm_gettimeofday(tv);
}

uint64 cm_get_time_usec(void)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        cm_timeval now;
        uint64 now_usec;
        cm_get_time_of_day(&now);
        now_usec = (uint64)now.tv_sec * MICROSECS_PER_SECOND + (uint64)now.tv_usec;
        return now_usec;
    }
    return 0;
}

uint64 mes_get_stat_send_count(unsigned int cmd)
{
    return (uint64)g_mes_stat.mes_command_stat[cmd].send_count;
}

uint64 mes_get_stat_recv_count(unsigned int cmd)
{
    return (uint64)g_mes_stat.mes_command_stat[cmd].recv_count;
}

volatile long mes_get_stat_occupy_buf(unsigned int cmd)
{
    return g_mes_stat.mes_command_stat[cmd].occupy_buf;
}

unsigned char mes_get_elapsed_switch(void)
{
    return (bool8)g_mes_elapsed_stat.mes_elapsed_switch;
}

void mes_set_elapsed_switch(unsigned char elapsed_switch)
{
    g_mes_elapsed_stat.mes_elapsed_switch = elapsed_switch;
    g_mes_stat.mes_elapsed_switch = elapsed_switch;
}

uint64 mes_get_elapsed_time(unsigned int cmd, mes_time_stat_t type)
{
    return g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type].time;
}

uint64 mes_get_elapsed_count(unsigned int cmd, mes_time_stat_t type)
{
    return (uint64)g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type].count;
}

void mes_get_wait_event(unsigned int cmd, unsigned long long *event_cnt, unsigned long long *event_time)
{
    unsigned long long cnt = 0;
    unsigned long long time = 0;
    for (int type = 0; type < MES_TIME_CEIL; ++type) {
        cnt += g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type].count;
        time += g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type].time;
    }
    if (event_cnt != NULL) {
        *event_cnt = cnt;
    }
    if (event_time != NULL) {
        *event_time = time;
    }
}