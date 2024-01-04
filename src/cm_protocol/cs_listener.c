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
 * cs_listener.c
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cs_listener.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_listener.h"
#include "cm_epoll.h"
#include "cm_file.h"
#include "mes_interface.h"
#include "mes_cb.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 cs_create_tcp_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    pipe->type = CS_TYPE_TCP;
    tcp_link_t *link = &pipe->link.tcp;
    link->local.salen = (socklen_t)sizeof(link->local.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->local.addr, (socklen_t *)&link->local.salen);

    link->remote.salen = (socklen_t)sizeof(link->remote.addr);
#ifdef WIN32
    link->sock = (socket_t)accept(sock_ready, SOCKADDR(&link->remote), &link->remote.salen);
#else
    link->sock = (socket_t)accept4(sock_ready, SOCKADDR(&link->remote), &link->remote.salen, SOCK_CLOEXEC);
#endif

    if (link->sock == CS_INVALID_SOCKET) {
        return CM_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->sock, CM_TRUE, CM_TRUE);
    cs_set_keep_alive(link->sock, CM_TCP_KEEP_IDLE, CM_TCP_KEEP_INTERVAL, CM_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, pipe->l_onoff, pipe->l_linger);

    link->closed = CM_FALSE;
    return CM_TRUE;
}

void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 loop;
    int32 ret;
    struct epoll_event evnts[CM_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, CM_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        return;
    }

    for (loop = 0; loop < ret && (uint32)loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_create_tcp_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            cs_tcp_disconnect(&pipe->link.tcp);
            continue;
        }
        if (lsnr->action(lsnr, pipe) != CM_SUCCESS) {
            cs_tcp_disconnect(&pipe->link.tcp);
            continue;
        }
    }
}

static void srv_tcp_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    tcp_lsnr_t *lsnr = NULL;
    errno_t rc_memzero;

    lsnr = (tcp_lsnr_t *)thread->argument;

    rc_memzero = memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    MEMS_RETVOID_IFERR(rc_memzero);

    pipe.type = CS_TYPE_TCP;
    cm_set_thread_name("tcp_lsnr");

    mes_thread_init_t cb_thread_init = get_mes_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_RUN_INF("[mes]: tcp lsnr thread init callback done");
    }

    while (!thread->closed) {
        cs_try_tcp_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }

    mes_thread_deinit_t cb_thread_deinit = get_mes_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        cb_thread_deinit();
        LOG_RUN_INF("[mes] tcp lsnr thread deinit callback: cb_thread_deinit done");
    }
}


static status_t cs_alloc_sock_slot(tcp_lsnr_t *lsnr, int32 *slot_id)
{
    uint32 loop;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            lsnr->socks[loop] = CS_SOCKET_SLOT_USED;
            *slot_id = loop;
            return CM_SUCCESS;
        }
    }

    CM_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CM_MAX_LSNR_HOST_COUNT);
    return CM_ERROR;
}

status_t cs_create_one_lsnr_sock(tcp_lsnr_t *lsnr, const char *host, int32 *slot_id)
{
    socket_t *sock = NULL;
    tcp_option_t option;
    int32 code;
    sock_addr_t sock_addr;

    if (lsnr->sock_count == CM_MAX_LSNR_HOST_COUNT) {
        CM_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CM_MAX_LSNR_HOST_COUNT);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[mes] host:%s, port:%u", host, lsnr->port);

    CM_RETURN_IFERR(cm_ipport_to_sockaddr(host, lsnr->port, &sock_addr));

    CM_RETURN_IFERR(cs_alloc_sock_slot(lsnr, slot_id));
    sock = &lsnr->socks[*slot_id];
    if (cs_create_socket(SOCKADDR_FAMILY(&sock_addr), sock) != CM_SUCCESS) {
        return CM_ERROR;
    }

    cs_set_io_mode(*sock, CM_TRUE, CM_TRUE);

    /************************************************************************
        When a process is killed, the address bound by the process can not be bound
        by other process immediately, this situation is unacceptable, so we use the
        SO_REUSEADDR parameter which allows the socket to be bound to an address
        that is already in use.
        ************************************************************************/
    option = 1;
    code = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(uint32));
    if (-1 == code) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CM_THROW_ERROR(ERR_SET_SOCKET_OPTION, "");
        return CM_ERROR;
    }

    /************************************************************************
        Because of two processes could bpage to the same address, so we need check
        whether the address has been bound before bpage to it.
        ************************************************************************/
    if (cs_tcp_try_connect(host, lsnr->port)) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CM_THROW_ERROR(ERR_TCP_PORT_CONFLICTED, host, (uint32)lsnr->port);
        return CM_ERROR;
    }

    code = bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CM_THROW_ERROR(ERR_SOCKET_BIND, host, (uint32)lsnr->port, cm_get_os_error());
        return CM_ERROR;
    }

    code = listen(*sock, SOMAXCONN);
    if (code != 0) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CM_THROW_ERROR(ERR_SOCKET_LISTEN, "listen socket", cm_get_os_error());
        return CM_ERROR;
    }

    (void)cm_atomic_inc(&lsnr->sock_count);
    LOG_RUN_INF("[mes] create new listen socket, ip:%s, port:%u, slot_id:%u", host, (uint32)lsnr->port, *slot_id);
    return CM_SUCCESS;
}

void cs_close_one_lsnr_sock(tcp_lsnr_t *lsnr, int32 slot_id)
{
    if (slot_id == CM_MAX_LSNR_HOST_COUNT) {
        return;
    }
    if (lsnr->socks[slot_id] == CS_INVALID_SOCKET) {
        return;
    }
    (void)cs_close_socket(lsnr->socks[slot_id]);
    lsnr->socks[slot_id] = CS_INVALID_SOCKET;
    lsnr->slots[slot_id] = (int32)CM_MAX_LSNR_HOST_COUNT;

    (void)cm_atomic_dec(&lsnr->sock_count);
    LOG_RUN_INF(
        "[mes] close old listen socket, ip:%s, port:%u, slot_id:%u", lsnr->host[slot_id], (uint32)lsnr->port, slot_id);
}

void cs_close_lsnr_socks(tcp_lsnr_t *lsnr)
{
    uint32 loop;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            (void)cs_close_socket(lsnr->socks[loop]);
            lsnr->socks[loop] = CS_INVALID_SOCKET;
            lsnr->slots[loop] = (int32)CM_MAX_LSNR_HOST_COUNT;
        }
    }
    (void)cm_atomic_set(&lsnr->sock_count, 0);
}

status_t cs_create_lsnr_socks(tcp_lsnr_t *lsnr)
{
    uint32 loop;
    char(*host)[CM_MAX_IP_LEN] = lsnr->host;
    int32 slot_id;
    lsnr->sock_count = 0;

    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        if (host[loop][0] != '\0') {
            if (cs_create_one_lsnr_sock(lsnr, host[loop], &slot_id) != CM_SUCCESS) {
                cs_close_lsnr_socks(lsnr);
                return CM_ERROR;
            }
            lsnr->slots[loop] = slot_id;
        }
    }

    return CM_SUCCESS;
}

status_t cs_lsnr_init_epoll_fd(tcp_lsnr_t *lsnr)
{
    struct epoll_event ev;
    uint32 loop;

    lsnr->epoll_fd = epoll_create1(0);
    if (-1 == lsnr->epoll_fd) {
        CM_THROW_ERROR(ERR_SOCKET_LISTEN, "create epoll fd for listener", cm_get_os_error());
        return CM_ERROR;
    }

    ev.events = EPOLLIN;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            continue;
        }
        ev.data.fd = (int)lsnr->socks[loop];
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) != 0) {
            cm_close_file(lsnr->epoll_fd);
            CM_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epoll fd", cm_get_os_error());
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action)
{
    uint32 loop;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;

    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    if (cs_create_lsnr_socks(lsnr) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] failed to create lsnr sockets for listener type %d", (int32)lsnr->type);
        return CM_ERROR;
    }

    if (cs_lsnr_init_epoll_fd(lsnr) != CM_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        LOG_RUN_ERR("[mes] failed to init epoll fd for listener type %d", (int32)lsnr->type);
        return CM_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(srv_tcp_lsnr_proc, 0, lsnr, &lsnr->thread) != CM_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);
        lsnr->status = LSNR_STATUS_STOPPED;
        LOG_RUN_ERR("[mes] failed to create accept thread for listener type %d", (int32)lsnr->type);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void cs_stop_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    cm_close_thread(&lsnr->thread);
    cs_close_lsnr_socks(lsnr);
    (void)epoll_close(lsnr->epoll_fd);
}

void cs_pause_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_PAUSING;
    while (lsnr->status != LSNR_STATUS_PAUSED && !lsnr->thread.closed) {
        cm_sleep(5);
    }
}

void cs_resume_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_RUNNING;
}


#ifdef __cplusplus
}
#endif
