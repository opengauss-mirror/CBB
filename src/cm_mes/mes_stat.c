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
mes_msg_size_stats_t g_mes_msg_size_stat;

int mes_get_worker_info(unsigned int worker_id, mes_worker_info_t *mes_worker_info)
{
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    if (worker_id >= mq_ctx->task_num || !mq_ctx->work_thread_idx[worker_id].is_start) {
        return CM_ERROR;
    }
    mes_worker_info->tid = mq_ctx->work_thread_idx[worker_id].tid;
    mes_worker_info->priority = mq_ctx->work_thread_idx[worker_id].priority;
    mes_worker_info->get_msgitem_time = mq_ctx->work_thread_idx[worker_id].get_msgitem_time;
    mes_worker_info->is_active = mq_ctx->work_thread_idx[worker_id].is_active;
    mes_worker_info->msg_ruid = mq_ctx->work_thread_idx[worker_id].msg_ruid;
    mes_worker_info->msg_src_inst = mq_ctx->work_thread_idx[worker_id].msg_src_inst;
    errno_t ret = memcpy_s(mes_worker_info->data, sizeof(mes_worker_info->data),
        mq_ctx->work_thread_idx[worker_id].data, sizeof(mes_worker_info->data));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes] memcpy_s failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int mes_get_worker_priority_info(unsigned int priority_id, mes_task_priority_info_t *mes_task_priority_info)
{
    if (priority_id >= MES_GLOBAL_INST_MSG.profile.priority_cnt) {
        return CM_ERROR;
    }

    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    mes_task_priority_t *task_priority = &mq_ctx->priority.task_priority[priority_id];
    if (!task_priority->is_set) {
        return CM_ERROR;
    }

    mes_task_priority_info->priority = task_priority->priority;
    mes_task_priority_info->worker_num = task_priority->task_num;
    mes_task_priority_info->inqueue_msgitem_num = task_priority->inqueue_msgitem_num;
    mes_task_priority_info->finished_msgitem_num = task_priority->finished_msgitem_num;
    mes_task_priority_info->msgitem_free_num = 0;
    return CM_SUCCESS;
}

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

static void mes_msg_size_stats_init()
{
    for (uint32 i = 0; i < CMD_SIZE_HISTOGRAM_COUNT; i++) {
        size_histogram_t *hist = &g_mes_msg_size_stat.histograms[i];
        GS_INIT_SPIN_LOCK(hist->lock);
        hist->count = 0;
        hist->max_size = 0;
        hist->avg_size = 0;
        hist->min_size = CM_INVALID_ID64;
    }
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
    mes_msg_size_stats_init();
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

#ifdef WIN32
static uint32 cmd_size_to_histogram_index(uint32 size)
{
    uint32 index = 0;
    if (size <= (1 << CMD_SIZE_2_MIN_POWER)) {
        return 0;
    } else if (size > (1 << CMD_SIZE_2_MAX_POWER)) {
        return CMD_SIZE_HISTOGRAM_COUNT - 1;
    } else {
        uint32 clz = 0;
        uint32 bits = CMD_SIZE_2_MAX_POWER;
        bool32 is_2_power = (size & (size - 1)) == 0;
        while ((size & (1 << bits)) == 0) {
            bits--;
            clz++;
        }

        index = CMD_SIZE_2_MAX_POWER - CMD_SIZE_2_MIN_POWER - clz;
        index += (is_2_power ? 0 : 1);
        return index;
    }
}
#else
static uint32 cmd_size_to_histogram_index(uint32 size)
{
    if (SECUREC_UNLIKELY(size == 0)) {
        return 0;
    }

    uint32 clz = __builtin_clz(size);
    bool32 is_2_power = (size & (size - 1)) == 0;
    uint32 index = 31 - clz + (is_2_power ? 0 : 1);
    if (index <= CMD_SIZE_2_MIN_POWER) {
        return 0;
    } else if (index <= CMD_SIZE_2_MAX_POWER) {
        return index - CMD_SIZE_2_MIN_POWER;
    } else {
        return CMD_SIZE_HISTOGRAM_COUNT - 1;
    }
}
#endif

void mes_msg_size_stats(uint32 size)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        uint32 index = cmd_size_to_histogram_index(size);
        size_histogram_t *hist = &g_mes_msg_size_stat.histograms[index];
        cm_spin_lock(&hist->lock, NULL);
        hist->count++;
        hist->min_size = (hist->min_size > size) ? size : hist->min_size;
        hist->max_size = (hist->max_size < size) ? size : hist->max_size;
        double f = 1.0 / (hist->count + 1);
        hist->avg_size = (uint64)(hist->avg_size * hist->count * f + size * f);
        cm_spin_unlock(&hist->lock);
    }
}