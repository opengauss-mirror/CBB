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
#include "cm_system.h"
#include "cm_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 cs_create_tcp_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    pipe->type = CS_TYPE_TCP;
    tcp_link_t *link = &pipe->link.tcp;
    link->sock = sock_ready;
    link->local.salen = (socklen_t)sizeof(link->local.addr);
    link->remote.salen = (socklen_t)sizeof(link->remote.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->local.addr, (socklen_t *)&link->local.salen);
    (void)getpeername(sock_ready, SOCKADDR(&link->remote), &link->remote.salen);

    /* set default options of sock */
    cs_set_io_mode(link->sock, CM_TRUE, CM_TRUE);
    cs_set_keep_alive(link->sock, CM_TCP_KEEP_IDLE, CM_TCP_KEEP_INTERVAL, CM_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, pipe->l_onoff, pipe->l_linger);

    link->closed = CM_FALSE;
    return CM_TRUE;
}

static bool32 cs_is_listen_sock(tcp_lsnr_t *lsnr, socket_t sock)
{
    for (int64 i = 0; i < lsnr->sock_count; i++) {
        if(lsnr->socks[i] == sock) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

static int cs_add_accept_sock(tcp_lsnr_t* lsnr, socket_t sock_accept)
{
    struct epoll_event ev;

    accept_sock_t* node = cm_malloc_prot(sizeof(accept_sock_t));
    if(node == NULL) {
        cm_close_file(sock_accept);
        LOG_DEBUG_ERR("[mes] alloc memeory failed:sock:%d,errno:%d", sock_accept, cm_get_os_error());
        return CM_ERROR;
    }

    ev.events = (EPOLLIN | EPOLLRDHUP | EPOLLERR);
    ev.data.fd = sock_accept;
    if(epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, sock_accept, &ev) != 0) {
        cm_close_file(sock_accept);
        cm_free_prot(node);
        LOG_DEBUG_ERR("[mes] add accepted sock to epoll fd failed:sock:%d,errno%d", sock_accept,cm_get_os_error());
        return CM_ERROR;
    }

    node->accept_sock = sock_accept;
    node->accept_time_ms = cm_clock_monotonic_now() / MICROSECS_PER_MILLISEC;
    cm_bilist_add_tail(&node->node,&lsnr->accepted_socks);

    return CM_SUCCESS;
}

static int cs_remove_accept_sock(tcp_lsnr_t* lsnr, socket_t sock_accept, bool32 need_close)
{
    struct epoll_event ev;
    ev.events = (EPOLLIN | EPOLLRDHUP | EPOLLERR);
    ev.data.fd = sock_accept;

    (void)epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_DEL, sock_accept, &ev);
    accept_sock_t* node = (accept_sock_t*)lsnr->accepted_socks.head;
    if(need_close) {
        close(sock_accept);
    }

    while(node != NULL) {
        accept_sock_t* cur = node;
        node =  (accept_sock_t*)node->node.next;
        if(cur->accept_sock == sock_accept) {
            cm_bilist_del((bilist_node_t*)cur,&lsnr->accepted_socks);
            cm_free_prot(cur);
            return CM_SUCCESS;
        }
    }

    LOG_RUN_ERR("[mes] cs_remove_accept_sock failed:not found sock:%d",sock_accept);
    return CM_ERROR;
}

static void cs_remove_timeout_accept_sock(tcp_lsnr_t* lsnr)
{
    struct epoll_event ev;
    uint64 now_time_ms = cm_clock_monotonic_now() / MICROSECS_PER_MILLISEC;
    accept_sock_t* node = (accept_sock_t*)lsnr->accepted_socks.head;
    while(node != NULL) {
        accept_sock_t* cur = node;
        node =  (accept_sock_t*)node->node.next;
        if(now_time_ms > cur->accept_time_ms + lsnr->timeout_ms) {
            LOG_RUN_ERR("[mes]accepted sock is timeout,sock=:%d, accept_time=%lld,now=%lld", cur->accept_sock,
                cur->accept_time_ms, now_time_ms);
            (void)epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_DEL, cur->accept_sock, &ev);
            close(cur->accept_sock);
            cm_bilist_del((bilist_node_t*)cur,&lsnr->accepted_socks);
            cm_free_prot(cur);
        }
    }
}

static void cs_remove_all_accept_sock(tcp_lsnr_t* lsnr)
{
    struct epoll_event ev;

    LOG_RUN_INF("[mes] close all accepted sock.");
    accept_sock_t* node = (accept_sock_t*)lsnr->accepted_socks.head;
    while(node != NULL) {
        accept_sock_t* cur = node;
        node =  (accept_sock_t*)node->node.next;
        (void)epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_DEL, cur->accept_sock, &ev);
        close(cur->accept_sock);
        cm_free_prot(cur);
    }

    cm_bilist_init(&lsnr->accepted_socks);
}

void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 loop, ret;

    struct epoll_event evnts[CM_MAX_POLL_COUNT];

    cs_remove_timeout_accept_sock(lsnr);

    ret = epoll_wait(lsnr->epoll_fd, evnts, CM_MAX_POLL_COUNT, CM_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        return;
    }

    for (loop = 0; loop < ret && (uint32)loop < CM_MAX_POLL_COUNT; ++loop) {
        sock_ready = evnts[loop].data.fd;
        if(cs_is_listen_sock(lsnr, sock_ready)) {
#ifdef WIN32
            socket_t sock_accept = (socket_t)accept(sock_ready, NULL, NULL);
#else
            socket_t sock_accept = (socket_t)accept4(sock_ready, NULL, NULL, SOCK_CLOEXEC);
#endif
            if (sock_accept == CS_INVALID_SOCKET) {
                continue;
            }

            (void)cs_add_accept_sock(lsnr, sock_accept);
        } else {
            if ((evnts[loop].events & EPOLLRDHUP) || (evnts[loop].events & EPOLLERR)) {
                (void)cs_remove_accept_sock(lsnr, sock_ready, CM_TRUE);
                LOG_DEBUG_ERR("[mes] listner received a abnormal event, close the sock:%d,event:%d",
                    sock_ready,
                    evnts[loop].events);
                continue;
            } else if (evnts[loop].events & EPOLLIN) {
                if(!cs_create_tcp_link(sock_ready, pipe)) {
                    (void)cs_remove_accept_sock(lsnr, sock_ready, CM_TRUE);
                    LOG_DEBUG_ERR("[mes] listner cs_create_tcp_link failed:%d", sock_ready);
                    continue;
                }

                (void)cs_remove_accept_sock(lsnr, sock_ready, CM_FALSE);
                if (lsnr->status != LSNR_STATUS_RUNNING) {
                    cs_tcp_disconnect(&pipe->link.tcp);
                    LOG_DEBUG_ERR("[mes] listener status is abnormal:%d", sock_ready);
                    continue;
                }
                if (lsnr->action(lsnr, pipe) != CM_SUCCESS) {
                    LOG_DEBUG_ERR("[mes] connect action failed:%d", sock_ready);
                    continue;
                }
            } else {
                LOG_DEBUG_ERR("[mes] listener get unknown event on sock:%d, event:%d", sock_ready, evnts[loop].events);
            }
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
    cm_block_sighup_signal();

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_RUN_INF("[mes]: tcp lsnr thread init callback done");
    }

    cm_bilist_init(&lsnr->accepted_socks);

    while (!thread->closed) {
        cs_try_tcp_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }

    //close all accepted sock
    cs_remove_all_accept_sock(lsnr);

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
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
                LOG_RUN_ERR("[mes]cs_create_one_lsnr_sock failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
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

status_t cs_start_tcp_lsnr1(tcp_lsnr_t *lsnr, connect_action_t action, int timeout_ms)
{
    uint32 loop;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;
    lsnr->timeout_ms = timeout_ms;

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

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action)
{
    return cs_start_tcp_lsnr1(lsnr, action, CM_LSNR_TIMEOUT);
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
