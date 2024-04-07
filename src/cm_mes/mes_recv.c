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
 * mes_recv.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_recv.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_thread.h"
#include "cm_log.h"
#include "cm_debug.h"
#include "mes_recv.h"
#include "mes_interface.h"
#include "mes_func.h"

typedef union un_ev_data {
    struct {
        uint32 id;
        uint32 priority;
    };
    struct {
        uint64 data;
    };
} ev_data_t;

#define MES_MAX_RECV_THREAD_PER_PRIO 32

receiver_t g_receiver[MES_PRIORITY_CEIL][MES_MAX_RECV_THREAD_PER_PRIO] = {0};

uint32 g_priority_count = 0;
uint32 g_receiver_count[MES_PRIORITY_CEIL] = {0};

static void mes_recv_proc(thread_t *thread);

void mes_init_receivers(mes_event_proc_t proc)
{
    for (uint32 i = 0; i < MES_PRIORITY_CEIL; i++) {
        for (uint32 j = 0; j < MES_MAX_RECV_THREAD_PER_PRIO; j++) {
            g_receiver[i][j].priority = i;
            g_receiver[i][j].id = j;
            g_receiver[i][j].proc = proc;
        }
    }
}

receiver_t *mes_get_receiver(uint32 priority, uint32 id)
{
    cm_panic(priority < MES_PRIORITY_CEIL && id < MES_MAX_RECV_THREAD_PER_PRIO);
    return &g_receiver[priority][id];
}

int start_one_receiver(receiver_t *receiver)
{
    int epfd = epoll_create(1);
    if (epfd < 0) {
        LOG_RUN_ERR("[mes] epoll_create failed: errno=%d", errno);
        return CM_ERROR;
    } 
    if (receiver->epfd > 0) {
        (void)epoll_close(receiver->epfd);
        LOG_RUN_INF("[mes] start_one_receiver: close epfd: %d", receiver->epfd);
    }
    receiver->epfd = epfd;
    LOG_RUN_INF("[mes] start_one_receiver create epfd: %d", receiver->epfd);
    
    // start thread
    if (receiver->thread.id == 0) {
        if (cm_create_thread(mes_recv_proc, 0, (void *)receiver, &receiver->thread) != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] create receive thread:priority=%u , id=%u failed.", receiver->priority, receiver->id);
            (void)epoll_close(receiver->epfd);
            receiver->epfd = -1;
            return CM_ERROR;
        }

        LOG_RUN_INF("[mes] start_one_receiver start receiver:priority=%u , id=%u.", receiver->priority, receiver->id);
    }

    return CM_SUCCESS;
}

int start_receiver_prio(uint32 priority, unsigned int count)
{
    for (uint32 i = 0; i < count; i++) {
        receiver_t *receiver = mes_get_receiver(priority, i);
        if (start_one_receiver(receiver) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int mes_start_receivers(uint32 priority_count, unsigned int *recv_task_count, mes_event_proc_t event_proc)
{
    CM_ASSERT(priority_count <= MES_PRIORITY_CEIL);
    g_priority_count = priority_count;

    mes_init_receivers(event_proc);
    for (uint32 i = 0; i < priority_count; i++) {
        if (recv_task_count[i] > MES_MAX_RECV_THREAD_PER_PRIO) {
            LOG_RUN_ERR("[mes] recv_task_count[%u]=%u is greater than %d:", 
                i, 
                recv_task_count[i], 
                MES_MAX_RECV_THREAD_PER_PRIO);
            return CM_ERROR;
        }

        if (recv_task_count[i] == 0) {
            g_receiver_count[i] = 1;
        } else if (recv_task_count[i] > MES_MAX_RECV_THREAD_PER_PRIO) {
            LOG_RUN_WAR("[mes] recv_task_count[%u]=%u is greater than %d,reset to %d",
                i,
                recv_task_count[i],
                MES_MAX_RECV_THREAD_PER_PRIO,
                MES_MAX_RECV_THREAD_PER_PRIO);
            g_receiver_count[i] = MES_MAX_RECV_THREAD_PER_PRIO;
        } else {
            g_receiver_count[i] = recv_task_count[i];
        }

        if (start_receiver_prio(i, g_receiver_count[i]) != CM_SUCCESS) {
            mes_stop_receivers();
            return CM_ERROR;
        }
    }

    LOG_RUN_INF("[mes] start_receiver finish");

    return CM_SUCCESS;    
}

static void mes_stop_one_receiver(receiver_t *receiver)
{
    cm_close_thread(&receiver->thread);
    if (receiver->epfd > 0) {
        (void)epoll_close(receiver->epfd);
    }
    receiver->epfd = -1;
}

void mes_stop_receivers()
{
    for (uint32 priority = 0; priority < g_priority_count; priority++) {
        for (uint32 i = 0; i < g_receiver_count[priority]; i++) {
            mes_stop_one_receiver(&g_receiver[priority][i]);
        }
    }
}

int mes_add_recv_pipe_to_epoll(uint32 channel_id, mes_priority_t priority, int sock)
{
    if ((uint32)priority >= g_priority_count) {
        LOG_RUN_ERR("[mes] invaid priority");
        return CM_ERROR;
    }

    struct epoll_event ev = {0};
    ev_data_t ev_data;
    ev_data.id = channel_id;
    ev_data.priority = (uint32)priority;
    ev.events = EPOLLIN;
    ev.data.u64 = ev_data.data;

    if (g_receiver_count[priority] == 0) {
        LOG_RUN_ERR("[mes] receiver is not started.");
        return CM_ERROR;
    }
    
    uint32 id = channel_id % g_receiver_count[priority];

    if (epoll_ctl(g_receiver[priority][id].epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        LOG_RUN_ERR("[mes] epoll_ctl event add failed [fd=%d],channel_id=%u, priority=%d,errno=%d.", 
            sock, 
            channel_id, 
            priority, 
            errno);
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes] mes_add_recv_pipe_to_epoll:channel_id=%u, priority=%d, sock=%d", channel_id, priority, sock);
    
    return CM_SUCCESS;
}

int mes_remove_recv_pipe_from_epoll(mes_priority_t priority, uint32 channel_id, int sock)
{
    if ((uint32)priority >= g_priority_count) {
        LOG_RUN_ERR("[mes] invaid priority");
        return CM_ERROR;
    }

    struct epoll_event ev = {0};

    if (g_receiver_count[priority] == 0) {
        LOG_RUN_ERR("[mes] receiver is not started.");
        return CM_ERROR;
    }

    uint32 id = channel_id % g_receiver_count[priority];

    if (epoll_ctl(g_receiver[priority][id].epfd, EPOLL_CTL_DEL, sock, &ev) < 0) {
        LOG_RUN_ERR("[mes] epoll_ctl event Del failed [fd=%d],errno=%d.", sock, errno);
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes] mes_remove_recv_pipe_from_epoll:priority=%d, sock=%d, channel_id=%u",
        priority, sock, channel_id);

    return CM_SUCCESS;
}

static void mes_recv_proc(thread_t *thread)
{
    receiver_t *receiver = (receiver_t *)thread->argument;
    struct epoll_event events[CM_MES_MAX_CHANNEL_NUM];
    ev_data_t ev_data;
    char thread_name[CM_MAX_THREAD_NAME_LEN];

    PRTS_RETVOID_IFERR(
        sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_recv_%u_%u", receiver->priority, receiver->id));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_DEBUG_INF("[mes]: mes_recv_proc thread init callback: mes recv proc cb_thread_init done");
    }

    while (!thread->closed) {
        int nfds = epoll_wait(receiver->epfd, events, (int)CM_MES_MAX_CHANNEL_NUM, (int)CM_POLL_WAIT);
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                LOG_RUN_ERR("[mes] epoll_wait failed,errno=%d.", errno);
                break;
            }
        }

        for (int i = 0; i < nfds; i++) {
            ev_data.data = events[i].data.u64;
            receiver->proc(ev_data.id, ev_data.priority, events[i].events);
        }
    }

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        cb_thread_deinit();
        LOG_RUN_INF("[mes] mes_recv_proc thread deinit callback: cb_thread_deinit done");
    }
}

int mes_start_sender_monitor()
{
    receiver_t *receiver = &MES_GLOBAL_INST_MSG.mes_ctx.sender_monitor;
    receiver->priority = MES_PRIORITY_CEIL;
    receiver->id = 0;
    receiver->epfd = -1;
    receiver->thread.id = 0;
    receiver->proc = mes_send_pipe_event_proc;

    int32 ret = start_one_receiver(receiver);
    LOG_RUN_INF("[mes] start sender monitor finish");
    return ret;
}

void mes_stop_sender_monitor()
{
    receiver_t *receiver = &MES_GLOBAL_INST_MSG.mes_ctx.sender_monitor;
    mes_stop_one_receiver(receiver);
    LOG_RUN_INF("[mes] stop sender monitor finish");
}

int mes_add_send_pipe_to_epoll(mes_priority_t priority, uint32 channel_id, int sock)
{
    receiver_t *receiver = &MES_GLOBAL_INST_MSG.mes_ctx.sender_monitor;

    struct epoll_event ev = {0};
    ev_data_t ev_data;
    ev_data.id = channel_id;
    ev_data.priority = (uint32)priority;
    ev.events = EPOLLIN;
    ev.data.u64 = ev_data.data;

    if (epoll_ctl(receiver->epfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        LOG_RUN_ERR("[mes] epoll_ctl event add failed, priority=%u, channel_id=%u, fd=%d, errno=%d.\n",
            priority, channel_id, sock, errno);
        return CM_ERROR;        
    }

    LOG_RUN_INF("[mes] mes_add_send_pipe_to_epoll:priority=%u, channel_id=%u, sock=%d", priority, channel_id, sock);
    return CM_SUCCESS;
}

int mes_remove_send_pipe_from_epoll(mes_priority_t priority, uint32 channel_id, int sock)
{
    receiver_t *receiver = &MES_GLOBAL_INST_MSG.mes_ctx.sender_monitor;
    struct epoll_event ev = {0};
    if (epoll_ctl(receiver->epfd, EPOLL_CTL_DEL, sock, &ev) < 0) {
        LOG_RUN_ERR("[mes] epoll_ctl event delete failed, priority=%u, channel_id=%u, fd=%d, errno=%d.\n",
            priority, channel_id, sock, errno);
        return CM_ERROR;
    }

    LOG_RUN_INF(
        "[mes] mes_remove_send_pipe_from_epoll:priority=%u, channel_id=%u, sock=%d", priority, channel_id, sock);
    return CM_SUCCESS;
}

void mes_get_receiver_thread(mes_thread_set_t *mes_thread_set)
{
    errno_t err;
    for (uint32 i = 0; i < g_priority_count; i++) {
        for (uint32 j = 0; j < g_receiver_count[i]; j++) {
            if (mes_thread_set->thread_count >= MAX_MES_THREAD_NUM) {
                return;
            }
            err = sprintf_s(mes_thread_set->threads[mes_thread_set->thread_count].thread_name,
                MES_MAX_NAME_LEN, "mes receiver %u: priority_cnt:%u", j, i);
            PRTS_RETVOID_IFERR(err);
            mes_thread_set->threads[mes_thread_set->thread_count].thread_info = (void *)&g_receiver[i][j].thread;
            mes_thread_set->thread_count++;
        }
    }
}