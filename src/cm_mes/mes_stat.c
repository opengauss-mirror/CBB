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
#include <time.h>

#include "cm_atomic.h"
#include "cm_spinlock.h"
#include "cm_log.h"
#include "securec.h"
#include "mes_func.h"
#include "mes_stat.h"

#define MES_SHM_LAT_LOG_INTERVAL_S (10ULL)

typedef struct st_mes_shm_lat_acc {
    uint64 sum_us;
    uint64 cnt;
    uint64 max_us;
    uint64 min_us;
} mes_shm_lat_acc_t;

static spinlock_t g_mes_shm_lat_lock = 0;
static uint64 g_mes_shm_lat_next_log_sec = 0;
static mes_shm_lat_acc_t g_mes_shm_send_lat[MES_SHM_UB_QUEUE_NUM] = {0};
static uint64 g_mes_shm_send_cnt[MES_SHM_UB_QUEUE_NUM] = {0};
static uint64 g_mes_shm_recv_cnt[MES_SHM_UB_QUEUE_NUM] = {0};

static void mes_shm_lat_acc_record(mes_shm_lat_acc_t *acc, uint64 cost_us)
{
    acc->sum_us += cost_us;
    acc->cnt++;
    if (acc->cnt == 1) {
        acc->max_us = cost_us;
        acc->min_us = cost_us;
        return;
    }
    if (cost_us > acc->max_us) {
        acc->max_us = cost_us;
    }
    if (cost_us < acc->min_us) {
        acc->min_us = cost_us;
    }
}

static void mes_shm_lat_try_log(void)
{
    if (!g_mes_stat.mes_elapsed_switch) {
        return;
    }
    time_t now = time(NULL);
    if (now <= 0) {
        return;
    }

    mes_shm_lat_acc_t send_snap[MES_SHM_UB_QUEUE_NUM];
    uint64 send_cnt_snap[MES_SHM_UB_QUEUE_NUM];
    uint64 recv_cnt_snap[MES_SHM_UB_QUEUE_NUM];
    int need_log = 0;

    cm_spin_lock(&g_mes_shm_lat_lock, NULL);
    if (g_mes_shm_lat_next_log_sec == 0) {
        g_mes_shm_lat_next_log_sec = (uint64)now + MES_SHM_LAT_LOG_INTERVAL_S;
    }
    if ((uint64)now >= g_mes_shm_lat_next_log_sec) {
        g_mes_shm_lat_next_log_sec = (uint64)now + MES_SHM_LAT_LOG_INTERVAL_S;
        errno_t rc;
        rc = memcpy_s(send_snap, sizeof(send_snap), g_mes_shm_send_lat, sizeof(g_mes_shm_send_lat));
        if (rc != EOK) {
            LOG_RUN_ERR("memcpy_s g_mes_shm_send_lat failed, rc=%d.", rc);
        }
        rc = memcpy_s(send_cnt_snap, sizeof(send_cnt_snap), g_mes_shm_send_cnt, sizeof(g_mes_shm_send_cnt));
        if (rc != EOK) {
            LOG_RUN_ERR("memcpy_s g_mes_shm_send_cnt failed, rc=%d.", rc);
        }
        rc = memcpy_s(recv_cnt_snap, sizeof(recv_cnt_snap), g_mes_shm_recv_cnt, sizeof(g_mes_shm_recv_cnt));
        if (rc != EOK) {
            LOG_RUN_ERR("memcpy_s g_mes_shm_recv_cnt failed, rc=%d.", rc);
        }
        rc = memset_s(g_mes_shm_send_lat, sizeof(g_mes_shm_send_lat), 0, sizeof(g_mes_shm_send_lat));
        if (rc != EOK) {
            LOG_RUN_ERR("memset_s g_mes_shm_send_lat failed, rc=%d.", rc);
        }
        rc = memset_s(g_mes_shm_send_cnt, sizeof(g_mes_shm_send_cnt), 0, sizeof(g_mes_shm_send_cnt));
        if (rc != EOK) {
            LOG_RUN_ERR("memset_s g_mes_shm_send_cnt failed, rc=%d.", rc);
        }
        rc = memset_s(g_mes_shm_recv_cnt, sizeof(g_mes_shm_recv_cnt), 0, sizeof(g_mes_shm_recv_cnt));
        if (rc != EOK) {
            LOG_RUN_ERR("memset_s g_mes_shm_recv_cnt failed, rc=%d.", rc);
        }
        need_log = 1;
    }
    cm_spin_unlock(&g_mes_shm_lat_lock);

    if (!need_log) {
        return;
    }

    uint64 total_send_cnt = 0;
    uint64 total_recv_cnt = 0;
    for (uint32 qi = 0; qi < (uint32)MES_SHM_UB_QUEUE_NUM; qi++) {
        const mes_shm_lat_acc_t *s = &send_snap[qi];
        uint64 avg_us = (s->cnt == 0 ? 0 : ((s->sum_us + s->cnt / 2) / s->cnt));
        total_send_cnt += send_cnt_snap[qi];
        total_recv_cnt += recv_cnt_snap[qi];
        LOG_RUN_INF(
            "[mes][shm latency] q=%u send(avg/max/min)=%llu us/%llu us/%llu us "
            "send_cnt=%llu recv_cnt=%llu (interval=%llu s)",
            (unsigned int)qi, (unsigned long long)avg_us,
            (unsigned long long)s->max_us, (unsigned long long)s->min_us,
            (unsigned long long)send_cnt_snap[qi],
            (unsigned long long)recv_cnt_snap[qi],
            (unsigned long long)MES_SHM_LAT_LOG_INTERVAL_S);
    }
    LOG_RUN_INF("[mes][shm latency] total send_cnt=%llu recv_cnt=%llu (interval=%llu s)",
        (unsigned long long)total_send_cnt,
        (unsigned long long)total_recv_cnt,
        (unsigned long long)MES_SHM_LAT_LOG_INTERVAL_S);
}

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

static void mes_msg_size_stats_init(bool32 enable)
{
    g_mes_msg_size_stat.enable = enable;
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
    mes_msg_size_stats_init((bool32)profile->mes_size_histogram_switch);
    return;
}

void mes_send_stat(uint16 cmd, uint32 size)
{
    if (g_mes_stat.mes_elapsed_switch && cmd < CM_MAX_MES_MSG_CMD) {
        mes_command_stat_t *stats = &g_mes_stat.mes_command_stat[cmd];
        cm_spin_lock(&stats->lock, NULL);
        uint64 avg = stats->avg_size;
        if (avg == 0 || avg == size) {
            stats->avg_size = size;
        } else {
            double f1 = 1.0 / (stats->send_count + 1);
            double f2 = (stats->send_count) * f1;
            stats->avg_size = (uint64)(avg * f2 + size * f1);
        }
        (void)cm_atomic_inc(&(stats->send_count));
        cm_spin_unlock(&stats->lock);
    }
    return;
}

void mes_local_stat(uint16 cmd)
{
    if (g_mes_stat.mes_elapsed_switch && cmd < CM_MAX_MES_MSG_CMD) {
        (void)cm_atomic_inc(&(g_mes_stat.mes_command_stat[cmd].local_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_command_stat[cmd].occupy_buf));
    }
    return;
}

void mes_recv_message_stat(const mes_message_t *msg)
{
    if (g_mes_stat.mes_elapsed_switch && msg->head->app_cmd < CM_MAX_MES_MSG_CMD) {
        (void)cm_atomic_inc(&(g_mes_stat.mes_command_stat[msg->head->app_cmd].recv_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_command_stat[msg->head->app_cmd].occupy_buf));
    }
    return;
}

uint64 cm_get_time_usec()
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        return cm_clock_monotonic_now();
    }
    return g_timer()->monotonic_now;
}

void mes_consume_with_time(uint16 cmd, mes_time_stat_t type, uint64 start_time)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch && cmd < CM_MAX_MES_MSG_CMD) {
        uint64 elapsed_time = cm_get_time_usec() - start_time;
        mes_command_time_stat_t *stats = &g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type];
        cm_spin_lock(&stats->lock, NULL);
        stats->time += elapsed_time;
        stats->count++;
        cm_spin_unlock(&stats->lock);
    }
    return;
}

void mes_consume_with_time_shm_send(uint16 cmd, uint64 start_time, uint32 ub_q)
{
    mes_consume_with_time(cmd, MES_TIME_WRITE_SOCKET, start_time);

    if (!g_mes_elapsed_stat.mes_elapsed_switch || cmd >= CM_MAX_MES_MSG_CMD) {
        return;
    }
    uint64 now_usec = cm_get_time_usec();
    if (now_usec < start_time) {
        return;
    }
    uint64 elapsed_time = now_usec - start_time;
    if (ub_q < MES_SHM_UB_QUEUE_NUM) {
        cm_spin_lock(&g_mes_shm_lat_lock, NULL);
        mes_shm_lat_acc_record(&g_mes_shm_send_lat[ub_q], elapsed_time);
        g_mes_shm_send_cnt[ub_q]++;
        cm_spin_unlock(&g_mes_shm_lat_lock);
    }
    mes_shm_lat_try_log();
}

void mes_shm_latency_note_shm_recv(uint32 ub_q)
{
    if (!g_mes_stat.mes_elapsed_switch) {
        return;
    }
    if (ub_q >= MES_SHM_UB_QUEUE_NUM) {
        return;
    }
    cm_spin_lock(&g_mes_shm_lat_lock, NULL);
    g_mes_shm_recv_cnt[ub_q]++;
    cm_spin_unlock(&g_mes_shm_lat_lock);
}

void mes_set_elapsed_switch(unsigned char elapsed_switch)
{
    g_mes_elapsed_stat.mes_elapsed_switch = elapsed_switch;
    g_mes_stat.mes_elapsed_switch = elapsed_switch;
}

#ifdef WIN32
static uint32 cmd_size_to_histogram_index(uint32 size)
{
    static uint32 array[CMD_SIZE_HISTOGRAM_COUNT] = {128, 256, 512, 1024, 2048,
        4096, 8192, 16384, 32768, CM_MAX_UINT32};
    int32 left = 0, right = CMD_SIZE_HISTOGRAM_COUNT - 1;
    int32 mid;
    while (left < right) {
        mid = (left + right) / 2;
        if (array[mid] < size) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return right;
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
    if (g_mes_msg_size_stat.enable) {
        uint32 index = cmd_size_to_histogram_index(size);
        size_histogram_t *hist = &g_mes_msg_size_stat.histograms[index];
        cm_spin_lock(&hist->lock, NULL);
        hist->min_size = (hist->min_size > size) ? size : hist->min_size;
        hist->max_size = (hist->max_size < size) ? size : hist->max_size;
        double f = 1.0 / (hist->count + 1);
        hist->avg_size = (uint64)(hist->avg_size * hist->count * f + size * f);
        hist->count++;
        cm_spin_unlock(&hist->lock);
    }
}

void mes_elapsed_stat(uint16 cmd, mes_time_stat_t type)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch && cmd < CM_MAX_MES_MSG_CMD) {
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].cmd_time_stats[type].count));
    }
    return;
}

void mes_release_buf_stat(uint16 cmd)
{
    if (g_mes_stat.mes_elapsed_switch && cmd < CM_MAX_MES_MSG_CMD) {
        cm_atomic32_dec(&(g_mes_stat.mes_command_stat[cmd].occupy_buf));
        mes_elapsed_stat(cmd, MES_TIME_PUT_BUF);
    }
    return;
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