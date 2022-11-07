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
 * cs_uds.c
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cs_uds.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_uds.h"
#include "cs_pipe.h"
#include "cm_file.h"
#include "cm_signal.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t cs_uds_init(void)
{
    return cs_tcp_init();
}

status_t cs_create_uds_socket(socket_t *sock)
{
    CM_RETURN_IFERR(cs_uds_init());
#ifndef WIN32
    *sock = (socket_t)socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (*sock == CS_INVALID_SOCKET) {
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

status_t cs_uds_connect(const char *server_path, const char *client_path, uds_link_t *link)
{
    if (CM_IS_EMPTY_STR(server_path) || link == NULL) {
        return CM_ERROR;
    }

#ifdef WIN32
    socket_attr_t attr;
    attr.connect_timeout = CM_CONNECT_TIMEOUT;
    attr.l_linger = 1;
    attr.l_onoff = 1;
    int port = 0;
    FILE *hFile = fopen(server_path, "r");
    if (hFile == NULL) {
        return CM_ERROR;
    }

    if (fscanf_s(hFile, "%d", &port) < 0) {
        (void)fclose(hFile);
        return CM_ERROR;
    }

    (void)fclose(hFile);
    if (cs_tcp_connect("127.0.0.1", port, (tcp_link_t *)link, NULL, &attr) != CM_SUCCESS) {
        return CM_ERROR;
    }
#else
    if (!CM_IS_EMPTY_STR(client_path)) {
        cs_uds_build_addr(&link->local, client_path);
        (void)unlink(link->local.addr.sun_path);
        if (bind(link->sock, SOCKADDR(&link->local), link->local.salen) < 0) {
            return CM_ERROR;
        }
        (void)chmod(client_path, SERVICE_FILE_PERMISSIONS);
    }

    cs_uds_build_addr(&link->remote, server_path);
    cs_set_buffer_size(link->sock, CM_TCP_DEFAULT_BUFFER_SIZE, CM_TCP_DEFAULT_BUFFER_SIZE);
    if (connect(link->sock, SOCKADDR(&link->remote), link->remote.salen) != 0) {
        return CM_ERROR;
    }

#endif
    link->closed = CM_FALSE;

    return CM_SUCCESS;
}

void cs_uds_disconnect(uds_link_t *link)
{
    CM_ASSERT(link != NULL);
    if (link->closed) {
        return;
    }
#ifdef WIN32
    (void)cs_close_socket(link->sock);
    link->sock = CS_INVALID_SOCKET;
#else
    cs_uds_socket_close(&link->sock);
#endif
    link->closed = CM_TRUE;
}

#ifdef WIN32
status_t cs_uds_wait(uds_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    int32 count;
    fd_set socket_set;
    struct timeval *tv_ptr = NULL;
    struct timeval tv;

    if (ready != NULL) {
        *ready = CM_FALSE;
    }

    if (link->closed) {
        return CM_ERROR;
    }

    FD_ZERO(&socket_set);
    FD_SET(link->sock, &socket_set);

    if (timeout != 0) {
        tv.tv_sec = timeout / CM_TIME_THOUSAND_UN;
        tv.tv_usec = ((long)timeout - tv.tv_sec * CM_TIME_THOUSAND_UN) * (long)CM_TIME_THOUSAND_UN;
        tv_ptr = &tv;
    } else {
        tv_ptr = NULL;
    }

    if (wait_for == CS_WAIT_FOR_WRITE) {
        count = select((int)link->sock + 1, NULL, &socket_set, NULL, tv_ptr);
    } else {
        count = select((int)link->sock + 1, &socket_set, NULL, NULL, tv_ptr);
    }

    if (count >= 0) {
        if (ready != NULL) {
            *ready = (count > 0);
        }

        return CM_SUCCESS;
    }

    if (errno != EINTR) {
        link->closed = CM_TRUE;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}
#else
status_t cs_uds_wait(uds_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = CM_FALSE;
    }

    if (link->closed) {
        CM_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CM_ERROR;
    }

    tv = (timeout == 0 ? -1 : timeout);

    fd.fd = link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = poll(&fd, 1, tv);
    if (ret == 0) {
        if (ready != NULL) {
            *ready = CM_FALSE;
        }
        return CM_SUCCESS;
    }

    if (ret > 0) {
        if (ready != NULL) {
            *ready = CM_TRUE;
        }

        if ((uint16)fd.revents & POLLHUP) {
            cs_uds_disconnect(link);
            CM_THROW_ERROR(ERR_PEER_CLOSED, "uds");
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }

    if (errno != EINTR) {
        cs_uds_disconnect(link);
        CM_THROW_ERROR(ERR_PEER_CLOSED, "uds");
        return CM_ERROR;
    }

    if (ready != NULL) {
        *ready = CM_TRUE;
    }

    return CM_SUCCESS;
}
#endif

status_t cs_uds_send(const uds_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    int code;

    if (size == 0) {
        *send_size = 0;
        return CM_SUCCESS;
    }

    *send_size = (int32)send(link->sock, buf, size, 0);
    if (*send_size <= 0) {
#ifdef WIN32
        code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) {
#else
        code = errno;
        if (code == EWOULDBLOCK) {
#endif
            *send_size = 0;
            return CM_SUCCESS;
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cs_uds_send_timed(uds_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    int32 remain_size, offset, writen_size;
    uint32 wait_interval = 0;
    bool32 ready = CM_FALSE;

    if (link->closed) {
        return CM_ERROR;
    }

    /* for most cases, all data are written by the following call */
    if (cs_uds_send(link, buf, size, &writen_size) != CM_SUCCESS) {
        return CM_ERROR;
    }

    remain_size = size - writen_size;
    offset = writen_size;

    while (remain_size > 0) {
        if (cs_uds_wait(link, CS_WAIT_FOR_WRITE, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= timeout) {
                return CM_ERROR;
            }

            continue;
        }

        if (cs_uds_send(link, buf + offset, (uint32)remain_size, &writen_size) != CM_SUCCESS) {
            return CM_ERROR;
        }

        remain_size -= writen_size;
        offset += writen_size;
    }

    return CM_SUCCESS;
}

/* cs_tcp_recv must following cs_tcp_wait */
status_t cs_uds_recv(const uds_link_t *link, char *buf, uint32 size, int32 *recv_size)
{
    int32 rsize;

    if (size == 0) {
        *recv_size = 0;
        return CM_SUCCESS;
    }

    for (;;) {
        rsize = (int32)recv(link->sock, buf, size, 0);
        if (rsize > 0) {
            break;
        }
        if (rsize == 0) {
            return CM_ERROR;
        }
        if (cm_get_sock_error() == EINTR || cm_get_sock_error() == EAGAIN) {
            continue;
        }
        return CM_ERROR;
    }
    *recv_size = rsize;
    return CM_SUCCESS;
}

status_t cs_uds_recv_timed(uds_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    uint32 wait_interval = 0;
    int32 recv_size;
    bool32 ready = CM_FALSE;

    remain_size = size;
    if (cs_uds_recv(link, buf, remain_size, &recv_size) != CM_SUCCESS) {
        return CM_ERROR;
    }

    remain_size -= recv_size;
    offset = (uint32)recv_size;

    while (remain_size > 0) {
        if (cs_uds_wait(link, CS_WAIT_FOR_READ, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= timeout) {
                return CM_ERROR;
            }

            continue;
        }

        if (cs_uds_recv(link, buf + offset, remain_size, &recv_size) != CM_SUCCESS) {
            return CM_ERROR;
        }

        remain_size -= recv_size;
        offset += recv_size;
    }

    return CM_SUCCESS;
}

#ifndef WIN32
static bool32 cs_uds_try_connect(const char *path)
{
    status_t status;
    socket_t sock = CS_INVALID_SOCKET;
    cs_sockaddr_un_t un;
    bool32 result = CM_FALSE;
    CM_ASSERT(path != NULL);

    status = cs_create_uds_socket(&sock);
    if (status != CM_SUCCESS) {
        return CM_FALSE;
    }

    cs_uds_build_addr(&un, path);
    result = (0 == connect(sock, SOCKADDR(&un), un.salen));
    (void)cs_close_socket(sock);
    return result;
}
#endif

#ifdef WIN32
static status_t cs_uds_init_socket(const char *name, sock_addr_t *sock_addr, socket_t *sock, HANDLE *hFile)
{
    *hFile = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0,
        NULL); // | TRUNCATE_EXISTING
    if (INVALID_HANDLE_VALUE == *hFile) {
        *sock = CS_INVALID_SOCKET;
        return CM_ERROR;
    }

    /* random to choose listen port  */
    if (cm_ip_to_sockaddr("127.0.0.1", sock_addr) != CM_SUCCESS) {
        *sock = CS_INVALID_SOCKET;
        CloseHandle(*hFile);
        return CM_ERROR;
    }

    if (cs_create_socket(SOCKADDR_FAMILY(sock_addr), sock) != CM_SUCCESS) {
        *sock = CS_INVALID_SOCKET;
        CloseHandle(*hFile);
        return CM_ERROR;
    }
    cs_set_io_mode(*sock, CM_TRUE, CM_TRUE);
    /************************************************************************
        When a process is killed, the address bound by the process can not be bound
        by other process immediately, this situation is unacceptable, so we use the
        SO_REUSEADDR parameter which allows the socket to be bound to an address
        that is already in use.
        ************************************************************************/
    tcp_option_t option = 1;
    int32 code = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(uint32));
    if (-1 == code) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(*hFile);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cs_uds_create_listener(const char *name, socket_t *sock, uint16 permissions)
{
    char port[32];
    DWORD bytes;
    OVERLAPPED ovp;
    sock_addr_t sock_addr;
    HANDLE *hFile = NULL;

    if (cs_uds_init_socket(name, &sock_addr, sock, hFile) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int32 code = bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(*hFile);
        return CM_ERROR;
    }

    sock_addr_t sockname;
    sockname.salen = sizeof(sockname.addr);

    (void)getsockname(*sock, SOCKADDR(&sockname), &sockname.salen);
    int iret_snprintf = snprintf_s(port, sizeof(port), sizeof(port) - 1, "%u", ntohs(SOCKADDR_PORT(&sockname)));
    if (iret_snprintf == -1) {
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        CloseHandle(*hFile);
        return CM_ERROR;
    }
    /* save the listen port to domain socket file */
    WriteFile(hFile, port, (DWORD)strlen(port), &bytes, NULL);
    FlushFileBuffers(hFile);
    (void)memset_s(&ovp, sizeof(ovp), 0, sizeof(ovp));
    if (!LockFileEx(*hFile, LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ovp)) {
        CloseHandle(*hFile);
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        return CM_ERROR;
    }

    code = listen(*sock, 20);
    if (code != 0) {
        CloseHandle(*hFile);
        (void)cs_close_socket(*sock);
        *sock = CS_INVALID_SOCKET;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}
#else
status_t cs_uds_create_listener(const char *name, socket_t *sock, uint16 permissions)
{
    status_t status;
    cs_sockaddr_un_t un;

    /************************************************************************
     TRY TO TEST IF DOMAIN SOCKET LISTEN EXIST.
    ************************************************************************/
    if (cs_uds_try_connect(name)) {
        return CM_ERROR;
    }

    status = cs_create_uds_socket(sock);
    CM_RETURN_IFERR(status);
    cs_uds_build_addr(&un, name);

    (void)unlink(un.addr.sun_path);
    /* bind the name to the descriptor */
    if (bind(*sock, SOCKADDR(&un), un.salen) < 0) {
        cs_uds_socket_close(sock);
        return CM_ERROR;
    }

    if (listen(*sock, 20) < 0) {
        cs_uds_socket_close(sock);
        return CM_ERROR;
    }

    (void)chmod(name, permissions);
    return CM_SUCCESS;
}
#endif

int32 cs_uds_getsockname(socket_t sock_ready, cs_sockaddr_un_t *un)
{
    int ret = getsockname(sock_ready, SOCKADDR(un), &un->salen);
    if (ret < 0) {
        return ret;
    }
#ifndef WIN32
    if (un->salen >= sizeof(cs_sockaddr_un_t)) {
        un->salen = (socklen_t)(sizeof(cs_sockaddr_un_t) - 1);
    }

    un->addr.sun_path[sizeof_sun_path(un->salen)] = 0;
#endif

    return ret;
}

void cs_uds_socket_close(socket_t *sockfd)
{
    cs_sockaddr_un_t un;
    un.salen = (socklen_t)sizeof(un.addr);
    int ret = cs_uds_getsockname(*sockfd, &un);
    if (ret < 0) {
        return;
    }

    (void)cs_close_socket(*sockfd);
    *sockfd = CS_INVALID_SOCKET;
    return;
}

#ifdef __cplusplus
}
#endif
