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
 * cs_pipe.c
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cs_pipe.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_pipe.h"
#include "cm_ip.h"
#include "cm_num.h"
#include "cm_profile_stat.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef status_t (*recv_func_t)(const void *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
typedef status_t (*send_func_t)(const void *link, const char *buf, uint32 size, int32 *send_size);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32 size, uint32 timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32 size, uint32 timeout);
typedef status_t (*wait_func_t)(void *link, uint32 wait_for, int32 timeout, bool32 *ready);

const text_t g_pipe_type_names[CS_TYPE_CEIL] = {
    { "UNKNOWN", 7 },
    { "TCP", 3 },
    { "SSL", 3 },
};

typedef struct st_vio {
    recv_func_t vio_recv;
    send_func_t vio_send;
    wait_func_t vio_wait;
    recv_timed_func_t vio_recv_timed;
    send_timed_func_t vio_send_timed;
} vio_t;


static const vio_t g_vio_list[] = {
    { NULL, NULL, NULL, NULL, NULL },

    // TCP io functions
    { (recv_func_t)cs_tcp_recv, (send_func_t)cs_tcp_send, (wait_func_t)cs_tcp_wait,
      (recv_timed_func_t)cs_tcp_recv_timed, (send_timed_func_t)cs_tcp_send_timed },

    // IPC not implemented
    { NULL, NULL, NULL, NULL, NULL },

    // UDS io functions
    { (recv_func_t)cs_uds_recv, (send_func_t)cs_uds_send, (wait_func_t)cs_uds_wait,
      (recv_timed_func_t)cs_uds_recv_timed, (send_timed_func_t)cs_uds_send_timed },

    // SSL io functions
    { (recv_func_t)cs_ssl_recv, (send_func_t)cs_ssl_send, (wait_func_t)cs_ssl_wait,
      (recv_timed_func_t)cs_ssl_recv_timed, (send_timed_func_t)cs_ssl_send_timed },
};

/*
  Macro definitions for pipe I/O operations
  @note
    Performance sensitive, the pipe->type should be guaranteed by the caller.
      e.g. CS_TYPE_TCP, CS_TYPE_SSL, CS_TYPE_DOMAIN_SOCKET
*/
#define GET_VIO(pipe) \
    (&g_vio_list[MIN((pipe)->type, CS_TYPE_CEIL - 1)])
#define VIO_SEND(pipe, buf, size, len) \
    GET_VIO(pipe)->vio_send(&(pipe)->link, buf, size, len)
#define VIO_SEND_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_send_timed(&(pipe)->link, buf, size, timeout)
#define VIO_RECV(pipe, buf, size, len, wait_event) \
    GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len, wait_event)
#define VIO_RECV_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)
#define VIO_WAIT(pipe, ev, timeout, ready) \
    GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)

static status_t cs_send_proto_code(cs_pipe_t *pipe, link_ready_ack_t *ack, bool32 need_send_version)
{
    tcp_link_t *link = NULL;
    bool32 ready = CM_FALSE;
    link = &pipe->link.tcp;

    if (need_send_version) {
        LOG_RUN_INF("[MES] cs_send_proto_code, send version and proto code");
        version_proto_code_t version_proto_code = {.version = CS_LOCAL_VERSION, .proto_code = CM_PROTO_CODE};
        if (!IS_BIG_ENDIAN) {
            // Unified big-endian mode for VERSION
            version_proto_code.version = cs_reverse_uint32(version_proto_code.version);
        }

        if (cs_tcp_send_timed(link, (char *)&version_proto_code, sizeof(version_proto_code_t), CM_NETWORK_IO_TIMEOUT) !=
            CM_SUCCESS) {
            LOG_RUN_ERR("[MES] cs_send_proto_code, send version proto code failed");
            return CM_ERROR;
        }
    } else {
        uint32 proto_code = CM_PROTO_CODE;
        LOG_RUN_INF("[MES] cs_send_proto_code, only send proto code");
        if (cs_tcp_send_timed(link, (char *)&proto_code, sizeof(proto_code), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
            LOG_RUN_ERR("[MES] cs_send_proto_code, send proto code failed");
            return CM_ERROR;
        }
    }

    if (cs_tcp_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[MES] cs_send_proto_code, cs_tcp_wait failed");
        return CM_ERROR;
    }

    if (!ready) {
        CM_THROW_ERROR(ERR_TCP_TIMEOUT, "connect wait for server response");
        LOG_RUN_ERR("[MES] cs_send_proto_code, not ready");
        return CM_ERROR;
    }

    // read link_ready_ack
    if (cs_tcp_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
        LOG_RUN_ERR("[MES] cs_send_proto_code, cs_tcp_recv_timed failed");
        return CM_ERROR;
    }

    LOG_RUN_INF("[MES] cs_send_proto_code:recv ack:endian=%u, version=%u, flag=%u",
                (uint32)ack->endian, (uint32)ack->version, (uint32)ack->flags);
    return CM_SUCCESS;
}

static status_t cs_open_tcp_link(
    const char *host, uint16 port, cs_pipe_t *pipe, link_ready_ack_t *ack, const char *bind_host)
{
    status_t ret = CM_ERROR;
    bool32 send_version = CM_TRUE;
    tcp_link_t *link = NULL;
    uint8 local_endian;
    socket_attr_t sock_attr = {
        .connect_timeout = pipe->connect_timeout, .l_onoff = pipe->l_onoff, .l_linger = pipe->l_linger};

    link = &pipe->link.tcp;

    /* create socket */
    CM_RETURN_IFERR(cs_tcp_connect(host, port, link, bind_host, &sock_attr));
    do {
        ret = cs_send_proto_code(pipe, ack, CM_TRUE);
        if (ret == CM_SUCCESS) {
            send_version = CM_TRUE;
        } else {
            /* close socket */
            (void)cs_close_socket(link->sock);
            link->sock = CS_INVALID_SOCKET;
            link->closed = CM_TRUE;

            /* create socket */
            CM_RETURN_IFERR(cs_tcp_connect(host, port, link, bind_host, &sock_attr));
            if (cs_send_proto_code(pipe, ack, CM_FALSE) != CM_SUCCESS) {
                break;
            }
            send_version = CM_FALSE;
        }

        // reverse if endian is different
        local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
        if (local_endian != ack->endian) {
            ack->flags = cs_reverse_int16(ack->flags);
            ack->version = cs_reverse_int32(ack->version);
            pipe->options |= CSO_DIFFERENT_ENDIAN;
            LOG_RUN_INF("[mes] cs_open_tcp_link:set CSO_DIFFERENT_ENDIAN flag");
        } else {
            pipe->options &= ~CSO_DIFFERENT_ENDIAN;
            LOG_RUN_INF("[mes] cs_open_tcp_link:clear CSO_DIFFERENT_ENDIAN flag");
        }

        LOG_RUN_INF(
            "[mes] cs_open_tcp_link: send_version:%s, ack version:%u", send_version ? "TRUE" : "FALSE", ack->version);
        if ((send_version && ack->version < CS_VERSION_5) || (!send_version && ack->version >= CS_VERSION_5)) {
            LOG_RUN_ERR("[mes] the sent version does not match the received version, send_version:%u, ack version:%u",
                send_version, ack->version);
            break;
        }

        if (ack->flags & CSO_SUPPORT_SSL) {
            pipe->options |= CSO_SUPPORT_SSL;
        } else {
            pipe->options &= ~CSO_SUPPORT_SSL;
        }

        return CM_SUCCESS;
    } while (0);

    /* close socket */
    (void)cs_close_socket(link->sock);
    link->sock = CS_INVALID_SOCKET;
    link->closed = CM_TRUE;
    return CM_ERROR;
}


/* URL SAMPLE:
TCP 192.168.1.10:1622, database_server1:1622
RDMA: RDMA@192.168.1.10:1622
IPC:/home/gsdb
UDS:/home/gsdb */
typedef struct st_server_info {
    cs_pipe_type_t type;
    char path[CM_FILE_NAME_BUFFER_SIZE]; /* host name(TCP) or home path(IPC) or domain socket file (uds) */
    uint16 port;
} server_info_t;

static status_t cs_parse_url(const char *url, server_info_t *server)
{
    text_t text, part1, part2;
    cm_str2text((char *)url, &text);
    (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);

    server->type = CS_TYPE_TCP;
    CM_RETURN_IFERR(cm_text2str(&part1, server->path, CM_FILE_NAME_BUFFER_SIZE));
    if (!cm_is_short(&part2)) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, "URL", url);
        return CM_ERROR;
    }

    if (cm_text2uint16(&part2, &server->port) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cs_connect(const char *url, cs_pipe_t *pipe, const char *bind_host)
{
    link_ready_ack_t ack = {0};
    server_info_t server = {0};

    /* parse url and get pipe type */
    CM_RETURN_IFERR(cs_parse_url(url, &server));

    /* create socket to server */
    if (server.type == CS_TYPE_TCP) {
        CM_RETURN_IFERR(cs_open_tcp_link(server.path, server.port, pipe, &ack, bind_host));
        pipe->type = server.type;
    } else {
        CM_THROW_ERROR(ERR_PROTOCOL_NOT_SUPPORT, "");
        return CM_ERROR;
    }

    /* SSL before handshake since v9.0 */
    pipe->version = ack.version;
    return CM_SUCCESS;
}

static status_t cs_open_uds_link(const char *server_path, const char *client_path, cs_pipe_t *pipe,
    link_ready_ack_t *ack)
{
    uds_link_t *link = NULL;
    bool32 ready = CM_FALSE;
    uint32 proto_code = CM_PROTO_CODE;
    uint8 local_endian;

    link = &pipe->link.uds;

    if (cs_create_uds_socket(&link->sock) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cs_uds_connect(server_path, client_path, link) != CM_SUCCESS) {
        cs_uds_socket_close(&link->sock);
        return CM_ERROR;
    }

    if (cs_uds_send_timed(link, (char *)&proto_code, sizeof(proto_code), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
        cs_uds_socket_close(&link->sock);
        return CM_ERROR;
    }

    if (cs_uds_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != CM_SUCCESS) {
        cs_uds_socket_close(&link->sock);
        return CM_ERROR;
    }

    if (!ready) {
        CM_THROW_ERROR(ERR_TCP_TIMEOUT, "connect wait for server response");
        cs_uds_socket_close(&link->sock);
        return CM_ERROR;
    }

    // read link_ready_ack
    if (cs_uds_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
        cs_uds_socket_close(&link->sock);
        return CM_ERROR;
    }

    // reverse if endian is different
    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack->endian) {
        ack->flags = cs_reverse_int16(ack->flags);
        ack->version = cs_reverse_int32(ack->version);
    }
    return CM_SUCCESS;
}

status_t cs_connect_ex(const char *url, cs_pipe_t *pipe, const char *bind_host,
    const char *server_path, const char *client_path)
{
    link_ready_ack_t ack;
    uint8 local_endian;

    if (pipe->type == CS_TYPE_TCP) {
        return cs_connect(url, pipe, bind_host);
    } else if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        CM_RETURN_IFERR(cs_open_uds_link(server_path, client_path, pipe, &ack));
    } else {
        CM_THROW_ERROR(ERR_PROTOCOL_NOT_SUPPORT, "");
        return CM_ERROR;
    }

    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack.endian) {
        pipe->options |= CSO_DIFFERENT_ENDIAN;
    }

    /* SSL before handshake since v9.0 */
    pipe->version = ack.version;

    return CM_SUCCESS;
}

void cs_disconnect(cs_pipe_t *pipe)
{
    pipe->version = CM_INVALID_ID32;
    if (pipe->type == CS_TYPE_TCP) {
        cs_tcp_disconnect(&pipe->link.tcp);
    }
    if (pipe->type == CS_TYPE_SSL) {
        cs_ssl_disconnect(&pipe->link.ssl);
    }
    if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        cs_uds_disconnect(&pipe->link.uds);
    }
}

void cs_shutdown(const cs_pipe_t *pipe)
{
    switch (pipe->type) {
        case CS_TYPE_TCP:
            cs_shutdown_socket(pipe->link.tcp.sock);
            break;
        case CS_TYPE_SSL:
            cs_shutdown_socket(pipe->link.ssl.tcp.sock);
            break;
        default:
            break;
    }
}

status_t cs_send_fixed_size(cs_pipe_t *pipe, char *buf, int32 size)
{
    bool32 ready;
    int32 send_size;
    int32 remain_size = size;
    char *send_buf = buf;
    int32 wait_interval = 0;

    if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != CM_SUCCESS) {
        return CM_ERROR;
    }

    send_buf += send_size;
    remain_size -= send_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_WRITE, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= pipe->socket_timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return CM_ERROR;
            }
            continue;
        }
        if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != CM_SUCCESS) {
            return CM_ERROR;
        }

        send_buf += send_size;
        remain_size -= send_size;
    }

    return CM_SUCCESS;
}

status_t cs_send_bytes(cs_pipe_t *pipe, const char *buf, uint32 size)
{
    return VIO_SEND_TIMED(pipe, buf, size, CM_NETWORK_IO_TIMEOUT);
}

status_t cs_read_bytes(cs_pipe_t *pipe, char *buf, uint32 max_size, int32 *size)
{
    uint32 wait_event;
    if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, NULL) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return VIO_RECV(pipe, buf, max_size, size, &wait_event);
}

status_t cs_read_fixed_size(cs_pipe_t *pipe, char *buf, uint32 size)
{
    bool32 ready;
    int32 read_size;
    uint32 wait_event;
    int32 remain_size = (int32)size;
    char *read_buf = buf;
    int32 wait_interval = 0;
    if (size == 0) {
        return CM_SUCCESS;
    }

    if (VIO_RECV(pipe, read_buf, remain_size, &read_size, &wait_event) != CM_SUCCESS) {
        return CM_ERROR;
    }

    read_buf += read_size;
    remain_size -= read_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= pipe->socket_timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return CM_ERROR;
            }
            continue;
        }

        if (VIO_RECV(pipe, read_buf, remain_size, &read_size, &wait_event) != CM_SUCCESS) {
            return CM_ERROR;
        }

        read_buf += read_size;
        remain_size -= read_size;
    }

    return CM_SUCCESS;
}

status_t cs_wait(cs_pipe_t *pipe, uint32 wait_for, int32 timeout, bool32 *ready)
{
    if (pipe->type == CS_TYPE_TCP) {
        return cs_tcp_wait(&pipe->link.tcp, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_SSL) {
        return cs_ssl_wait(&pipe->link.ssl, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        return cs_uds_wait(&pipe->link.uds, wait_for, timeout, ready);
    }
    return CM_ERROR;
}


socket_t cs_get_socket_fd(const cs_pipe_t *pipe)
{
    if (pipe->type == CS_TYPE_TCP) {
        return pipe->link.tcp.sock;
    } else if (pipe->type == CS_TYPE_SSL) {
        return pipe->link.ssl.tcp.sock;
    } else {
        return CS_INVALID_SOCKET;
    }
}

status_t cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_accept_socket(link, pipe->link.tcp.sock, CM_SSL_IO_TIMEOUT) != CM_SUCCESS) {
        return CM_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return CM_SUCCESS;
}

status_t cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_connect_socket(link, pipe->link.tcp.sock, CM_SSL_IO_TIMEOUT) != CM_SUCCESS) {
        return CM_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return CM_SUCCESS;
}

static status_t cs_try_realloc_packet_buffer(cs_packet_t *pack, uint32 offset)
{
    errno_t errcode = 0;
    if (pack->head->size > pack->buf_size) {
        uint32 new_buf_size = CM_ALIGN_8K(pack->head->size); // align with 8K
        if (pack->head->size > pack->max_buf_size || new_buf_size > pack->max_buf_size) {
            CM_THROW_ERROR(ERR_FULL_PACKET, "request", new_buf_size, pack->max_buf_size);
            return CM_ERROR;
        }
        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "large packet buffer");
            return CM_ERROR;
        }
        errcode = memcpy_s(new_buf, new_buf_size, pack->buf, offset);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            CM_FREE_PTR(new_buf);
            return CM_ERROR;
        }

        if (pack->buf != pack->init_buf) {
            CM_FREE_PTR(pack->buf);
        }

        pack->buf_size = new_buf_size;
        pack->buf = new_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }

    return CM_SUCCESS;
}


static status_t cs_read_packet(cs_pipe_t *pipe, cs_packet_t *pack, bool32 cs_client)
{
    int32 remain_size;
    int32 head_size = (int32)sizeof(cs_packet_head_t);
    int32 err_code = 0;

    if (VIO_RECV_TIMED(pipe, pack->buf, head_size, CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
        err_code = cm_get_error_code();
        if (err_code == (int32)ERR_TCP_TIMEOUT) {
            CM_THROW_ERROR(ERR_TCP_TIMEOUT,
                cs_client ? "read wait for server response" : "read wait for client request");
        }
        return CM_ERROR;
    }

    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        pack->head->size = cs_reverse_int32(pack->head->size);
        pack->head->flags = cs_reverse_int16(pack->head->flags);
        pack->head->version = cs_reverse_int32(pack->head->version);
        pack->head->serial_number = cs_reverse_int32(pack->head->serial_number);
    }

    CM_RETURN_IFERR(cs_try_realloc_packet_buffer(pack, (uint32)head_size));

    remain_size = (int32)pack->head->size - head_size;
    if (remain_size <= 0) {
        return CM_SUCCESS;
    }

    if (VIO_RECV_TIMED(pipe, pack->buf + head_size, remain_size, CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
        err_code = cm_get_error_code();
        if (err_code == (int32)ERR_TCP_TIMEOUT) {
            CM_THROW_ERROR(ERR_TCP_TIMEOUT,
                cs_client ? "read wait for server response" : "read wait for client request");
        }
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cs_read(cs_pipe_t *pipe, cs_packet_t *pack, bool32 cs_client)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return cs_read_packet(pipe, pack, cs_client);
}

static status_t cs_write_packet(cs_pipe_t *pipe, cs_packet_t *pack)
{
    uint32 size = pack->head->size;

    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        pack->head->size = cs_reverse_int32(pack->head->size);
        pack->head->flags = cs_reverse_int16(pack->head->flags);
        pack->head->version = cs_reverse_int32(pack->head->version);
        pack->head->serial_number = cs_reverse_int32(pack->head->serial_number);
    }

    if (VIO_SEND_TIMED(pipe, pack->buf, size, CM_DEFAULT_NULL_VALUE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cs_write(cs_pipe_t *pipe, cs_packet_t *pack)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return cs_write_packet(pipe, pack);
}

status_t cs_call(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack)
{
    if (cs_write(pipe, req) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, -1, NULL) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return cs_read(pipe, ack, CM_TRUE);
}

/* only for client which contains socket timeout and ready check */
status_t cs_call_timed(cs_pipe_t *pipe, cs_packet_t *req, cs_packet_t *ack)
{
    bool32 ready = CM_FALSE;

    if (cs_write(pipe, req) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!ready) {
        CM_THROW_ERROR(ERR_SOCKET_TIMEOUT, ((uint32)pipe->socket_timeout) / CM_TIME_THOUSAND_UN);
        return CM_ERROR;
    }

    return cs_read(pipe, ack, CM_TRUE);
}


#define LOOPBACK_ADDRESS "127.0.0.1"
void cm_get_remote_host(cs_pipe_t *pipe, char *os_host)
{
    if (pipe->type == CS_TYPE_TCP || pipe->type == CS_TYPE_SSL) {
        (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr, os_host, (int)CM_HOST_NAME_BUFFER_SIZE);
    } else if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        errno_t errcode = strncpy_s(os_host, CM_HOST_NAME_BUFFER_SIZE, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS));
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return;
        }
    }
    return;
}


int cs_get_pipe_sock(cs_pipe_t *pipe)
{
    if (pipe->type == CS_TYPE_TCP) {
        return (int)pipe->link.tcp.sock;
    } else if (pipe->type == CS_TYPE_SSL) {
        return (int)pipe->link.ssl.tcp.sock;
    } else if (pipe->type == CS_TYPE_DOMAIN_SCOKET) {
        return (int)pipe->link.uds.sock;
    } else {
        CM_ASSERT(0);
    }
    
    return CM_ERROR;
}

#ifdef __cplusplus
}
#endif
