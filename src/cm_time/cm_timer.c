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
 * cm_timer.c
 *
 *
 * IDENTIFICATION
 *    src/cm_time/cm_timer.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_timer.h"
#include "cm_log.h"

#define DAY_USECS (uint64)86400000000
#define MES_DEFAULT_SLEEP_TIME 100000  // 0.1ms

static gs_timer_t g_timer_t;

gs_timer_t *g_timer(void)
{
    return &g_timer_t;
}

static inline int32 cm_get_time_zone(void)
{
#ifdef WIN32
    TIME_ZONE_INFORMATION tmp;
    GetTimeZoneInformation(&tmp);
    return tmp.Bias * (-1);
#else
    time_t t = time(NULL);
    struct tm now_time;
    (void)localtime_r(&t, &now_time);

    return (int32)((uint64)now_time.tm_gmtoff / SECONDS_PER_MIN);
#endif
}

static void timer_proc(thread_t *thread)
{
    date_t start_time;
    gs_timer_t *timer_temp = (gs_timer_t *)thread->argument;
    int16 tz_min;

    start_time = cm_now();

    cm_set_thread_name("timer");

#ifndef _WIN32
    struct timespec tq, tr;
    tq.tv_sec = 0;
    tq.tv_nsec = timer_temp->sleep_time;
#endif

    while (!thread->closed) {
        cm_now_detail((date_detail_t *)&timer_temp->detail);
        timer_temp->now = cm_encode_date((const date_detail_t *)&timer_temp->detail);
        timer_temp->today = (timer_temp->now / (int64)DAY_USECS) * (int64)DAY_USECS;
        timer_temp->systime = (uint32)((timer_temp->now - start_time) / (int64)MICROSECS_PER_SECOND);

        // flush timezone
        tz_min = (int16)cm_get_time_zone();
        timer_temp->tz = tz_min / MINUTES_PER_HOUR;
        timer_temp->host_tz_offset = tz_min * SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;
        timer_temp->monotonic_now = cm_clock_monotonic_now();
#ifdef _WIN32
        cm_sleep(1);
#else
        (void)nanosleep(&tq, &tr);
#endif
    }
}

status_t cm_start_timer(gs_timer_t *timer)
{
    return cm_start_timer_ex(timer, MES_DEFAULT_SLEEP_TIME);
}

status_t cm_start_timer_ex(gs_timer_t *timer, uint64 sleep_time)
{
    if (timer->init) {
        return CM_SUCCESS;
    }
    cm_now_detail((date_detail_t *)&timer->detail);
    timer->now = cm_encode_date((const date_detail_t *)&timer->detail);
    timer->today = (date_t)(timer->now / (int64)DAY_USECS) * (int64)DAY_USECS;
    timer->systime = 0;
    int16 tz_min = (int16)cm_get_time_zone();
    timer->tz = tz_min / (int32)SECONDS_PER_MIN;
    timer->host_tz_offset = tz_min * SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;
    timer->init = CM_TRUE;
    timer->sleep_time = sleep_time;
    LOG_RUN_INF("[mes] start timer, sleep_time:%llu", sleep_time);
    timer->monotonic_now = cm_clock_monotonic_now();
    return cm_create_thread(timer_proc, 0, timer, &timer->thread);
}

void cm_close_timer(gs_timer_t *timer)
{
    cm_close_thread(&timer->thread);
    timer->init = CM_FALSE;
}

date_t cm_timeval2date(struct timeval tv)
{
    date_t dt = cm_scn_delta();
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);
    return dt;
}
