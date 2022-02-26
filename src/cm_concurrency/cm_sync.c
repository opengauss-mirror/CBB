/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
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
 * cm_sync.c
 *
 *
 * IDENTIFICATION
 *    src/cm_concurrency/cm_sync.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_sync.h"
#include "cm_error.h"
#ifndef WIN32
#include <sys/time.h>
#endif
#include "cm_date_to_text.h"

int32 cm_event_init(cm_event_t *event)
{
#ifdef WIN32
    event->evnt = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (event->evnt == NULL) {
        return CM_ERROR;
    }
#else
    event->status = CM_FALSE;
    if (pthread_condattr_init(&event->attr) != 0) {
        (void)pthread_cond_destroy(&event->cond);
        return CM_ERROR;
    }

    if (pthread_mutex_init(&event->lock, 0) != 0) {
        (void)pthread_cond_destroy(&event->cond);
        return CM_ERROR;
    }

    if (pthread_condattr_setclock(&event->attr, CLOCK_MONOTONIC) != 0) {
        (void)pthread_cond_destroy(&event->cond);
        return CM_ERROR;
    }

    if (pthread_cond_init(&event->cond, &event->attr) != 0) {
        (void)pthread_cond_destroy(&event->cond);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

void cm_event_destory(cm_event_t *event)
{
#ifdef WIN32
    (void)CloseHandle(event->evnt);
#else
    (void)pthread_mutex_destroy(&event->lock);
    (void)pthread_cond_destroy(&event->cond);
    (void)pthread_condattr_destroy(&event->attr);
#endif
}

#ifndef WIN32
void cm_get_timespec(struct timespec *tim, uint32 timeout)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);

    tim->tv_sec = tv.tv_sec + timeout / MILLISECS_PER_SECOND;
    tim->tv_nsec = tv.tv_nsec + ((long)timeout % MILLISECS_PER_SECOND) * NANOSECS_PER_MILLISECS_LL;
    if (tim->tv_nsec >= NANOSECS_PER_SECOND_LL) {
        tim->tv_sec++;
        tim->tv_nsec -= NANOSECS_PER_SECOND_LL;
    }
}
#endif

// timeout's unit is milliseconds
int32 cm_event_timedwait(cm_event_t *event, uint32 timeout)
{
#ifdef WIN32
    int ret;
    ret = WaitForSingleObject(event->evnt, timeout);
    switch (ret) {
        case WAIT_OBJECT_0:
            return CM_SUCCESS;
        case WAIT_TIMEOUT:
            return CM_TIMEDOUT;
        default:
            return CM_ERROR;
    }
#else
    struct timespec tim;

    (void)pthread_mutex_lock(&event->lock);
    if (event->status) {
        event->status = CM_FALSE;
        (void)pthread_mutex_unlock(&(event->lock));
        return CM_SUCCESS;
    }

    if (timeout == 0xFFFFFFFF) {
        while (!event->status) {
            (void)pthread_cond_wait(&event->cond, &event->lock);
        }
        event->status = CM_FALSE;
        (void)pthread_mutex_unlock(&event->lock);
        return CM_SUCCESS;
    }

    cm_get_timespec(&tim, timeout);
    (void)pthread_cond_timedwait(&event->cond, &event->lock, &tim);
    if (event->status) {
        event->status = CM_FALSE;
        (void)pthread_mutex_unlock(&event->lock);
        return CM_SUCCESS;
    }
    (void)pthread_mutex_unlock(&event->lock);
    return CM_TIMEDOUT;
#endif
}

void cm_event_wait(cm_event_t *event)
{
    (void)cm_event_timedwait(event, 50); // 50ms
}

void cm_event_notify(cm_event_t *event)
{
#ifdef WIN32
    (void)SetEvent(event->evnt);
#else
    (void)pthread_mutex_lock(&event->lock);
    if (!event->status) {
        event->status = CM_TRUE;
        (void)pthread_cond_signal(&event->cond);
    }
    (void)pthread_mutex_unlock(&event->lock);
#endif
}
