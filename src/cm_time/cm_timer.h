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
 * cm_timer.h
 *
 *
 * IDENTIFICATION
 *    src/cm_time/cm_timer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TIMER_H__
#define __CM_TIMER_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_HOST_TIMEZONE (g_timer()->host_tz_offset)


typedef struct st_gs_timer {
    volatile date_detail_t detail;  // detail of date, yyyy-mm-dd hh24:mi:ss
    volatile date_t now;
    volatile date_t today;          // the day with time 00:00:00
    volatile uint32 systime;        // seconds between timer started and now
    volatile int32 tz;              // time zone (h)
    volatile int64 host_tz_offset;  // host timezone offset (us)
    thread_t thread;
    bool32 init;
    uint64 sleep_time;              // ns
    /* The time continue starts from the system startup, which is not affected by the change of the system time. */
    volatile uint64 monotonic_now;
} gs_timer_t;


status_t cm_start_timer(gs_timer_t *timer);
status_t cm_start_timer_ex(gs_timer_t *timer, uint64 sleep_time);
void cm_close_timer(gs_timer_t *timer);
gs_timer_t *g_timer(void);

static inline uint64 cm_clock_monotonic_now()
{
#ifndef WIN32
    struct timespec now = {0, 0};
#ifdef CLOCK_MONOTONIC_RAW
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &now);
#else
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
#endif
    return (uint64)(now.tv_sec) * MICROSECS_PER_SECOND + (uint64)(now.tv_nsec) / NANOSECS_PER_MICROSECS;
#else
    uint64 now = GetTickCount64();
    return (now * MICROSECS_PER_MILLISEC);
#endif
}

static inline int64 cm_scn_delta(void)
{
    return CM_UNIX_EPOCH + CM_HOST_TIMEZONE;
}

date_t cm_timeval2date(struct timeval tv);

#ifdef __cplusplus
}
#endif

#endif
