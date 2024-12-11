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
 * cm_ip.c
 *
 *
 * IDENTIFICATION
 *    src/cm_network/cm_ip.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <netdb.h>
#include <net/if.h>
#else
#include <ws2tcpip.h>
#endif
#include "cm_num.h"
#include "cm_ip.h"

static inline int32 cm_get_ip_version(const char *ip_str)
{
    const char *temp_ip = ip_str;

    // support IPV6 local-link
    if (strchr(temp_ip, '%') != NULL) {
        return AF_INET6;
    }

    // cidr or ip string
#define IP_CHARS "0123456789ABCDEFabcdef.:*/"
    if (strspn(temp_ip, IP_CHARS) != strlen(temp_ip)) {
        return -1;
    }

    while (*temp_ip != '\0') {
        if (*temp_ip == '.') {
            return AF_INET;
        }

        if (*temp_ip == ':') {
            return AF_INET6;
        }

        ++temp_ip;
    }

    return AF_INET;
}

static inline char *ipv6_local_link(const char *host, char *ip, uint32 ip_len)
{
    errno_t errcode;
    size_t host_len;

    int i = 0;

    while (host[i] && host[i] != '%') {
        i++;
    }

    if (host[i] == '\0') {
        return NULL;
    } else { // handle local link
        host_len = (uint32)strlen(host);
        errcode = strncpy_s(ip, (size_t)ip_len, host, (size_t)host_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }

        ip[i] = '\0';
        return ip + i + 1;
    }
}

static inline status_t cm_ipport_to_sockaddr_ipv4(const char *host, int port, sock_addr_t *sock_addr)
{
    struct sockaddr_in *in4 = NULL;

    sock_addr->salen = (socklen_t)sizeof(struct sockaddr_in);
    in4 = SOCKADDR_IN4(sock_addr);

    MEMS_RETURN_IFERR(memset_sp(in4, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in)));

    in4->sin_family = AF_INET;
    in4->sin_port = htons((uint16)port);
#ifndef WIN32
    in4->sin_addr.s_addr = inet_addr(host);
    // Upon successful completion, inet_addr() shall return the Internet address.
    // Otherwise, it shall return (in_addr_t)(-1).
    if (in4->sin_addr.s_addr == (in_addr_t)(-1) || (inet_pton(AF_INET, host, &in4->sin_addr.s_addr) != 1)) {
#else
    // If no error occurs, the InetPton function returns a value of 1.
    if (InetPton(AF_INET, host, &in4->sin_addr.s_addr) != 1) {
#endif
        CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline status_t cm_ipport_to_sockaddr_ipv6(const char *host, int port, sock_addr_t *sock_addr)
{
    struct sockaddr_in6 *in6 = NULL;
#ifndef WIN32
    char ip[CM_MAX_IP_LEN];
    char *scope = NULL;
#endif

    sock_addr->salen = (socklen_t)sizeof(struct sockaddr_in6);
    in6 = SOCKADDR_IN6(sock_addr);

    MEMS_RETURN_IFERR(memset_sp(in6, sizeof(struct sockaddr_in6), 0, sizeof(struct sockaddr_in6)));

    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons((uint16)port);

#ifndef WIN32
    scope = ipv6_local_link(host, ip, CM_MAX_IP_LEN);
    if (scope != NULL) {
        in6->sin6_scope_id = if_nametoindex(scope);
        if (in6->sin6_scope_id == 0) {
            CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid local link \"%s\"", scope);
            return CM_ERROR;
        }

        host = ip;
    }
    // The inet_pton() function shall return 1 if the conversion succeeds
    if (inet_pton(AF_INET6, host, &in6->sin6_addr) != 1) {
#else
    // If no error occurs, the InetPton function returns a value of 1.
    if (InetPton(AF_INET6, host, &in6->sin6_addr) != 1) {
#endif
        CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cm_ipport_to_sockaddr(const char *host, int port, sock_addr_t *sock_addr)
{
    int sa_family = cm_get_ip_version(host);
    switch (sa_family) {
        case AF_INET: {
            return cm_ipport_to_sockaddr_ipv4(host, port, sock_addr);
        }
        case AF_INET6: {
            return cm_ipport_to_sockaddr_ipv6(host, port, sock_addr);
        }
        default: {
            CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
            return CM_ERROR;
        }
    }
}

status_t cm_ip_to_sockaddr(const char *host, sock_addr_t *sock_addr)
{
#define INVALID_PORT 0
    return cm_ipport_to_sockaddr(host, INVALID_PORT, sock_addr);
}

bool32 cm_check_ip_valid(const char *ip)
{
    sock_addr_t sock_addr;

    if (cm_ip_to_sockaddr(ip, &sock_addr) != CM_SUCCESS) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

status_t cm_get_host_type(const char *host, host_type_t *type)
{
    if (CM_IS_DIGIT(host[0])) {
        int ip_type = cm_get_ip_version(host);
        CM_RETVALUE_IFTRUE(ip_type == -1, CM_ERROR);
        *type = (ip_type == AF_INET ? HOST_TYPE_IP_V4 : HOST_TYPE_IP_V6);
    } else {
        if (strchr(host, ':') != NULL) {
            CM_RETVALUE_IFTRUE(cm_get_ip_version(host) != AF_INET6, CM_ERROR);
            *type = HOST_TYPE_IP_V6;
        } else {
            // domain string
#define DOMAIN_CHARS "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-"
            CM_RETVALUE_IFTRUE(strspn(host, DOMAIN_CHARS) != strlen(host), CM_ERROR);
            *type = HOST_TYPE_DOMAIN;
        }
    }
    return CM_SUCCESS;
}

static bool32 cm_check_ss_ip(text_t *ip, char *ip_str)
{
    host_type_t type;
    if (ip->len == 0 || ip->len >= CM_MAX_IP_LEN) {
        CM_THROW_ERROR(ERR_INVALID_IPADDRESS_OR_DOMAIN_LENGTH, ip->len);
        return CM_FALSE;
    }
    if (cm_get_host_type(ip_str, &type) != CM_SUCCESS) {
        return CM_FALSE;
    }
    if (type != HOST_TYPE_IP_V4 && type != HOST_TYPE_IP_V6) {
        CM_THROW_ERROR(ERR_TCP_INVALID_URLADDRESS, "ip type");
        return CM_FALSE;
    }
    return CM_TRUE;
}

static status_t cm_split_mes_single_url(char nodes[][CM_MAX_IP_LEN], uint16 ports[], char *single_url)
{
    char *urlstr = single_url;
    uint32 status = 0; // 0 is nodeid, 1 is ip
    uint32 url_len = 0;
    uint32 node_id = 0;
    text_t text;
    uint32 len = (uint32)strlen(urlstr);
    if (len == 0) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "mes single url");
        return CM_ERROR;
    }

    char *pos = urlstr;
    for (; len > 0; len--) {
        if (*pos != ':') {
            url_len++;
            pos++;
            continue;
        }
        *pos = '\0';
        if (status == 0) {
            CM_RETURN_IFERR(cm_str2uint32(urlstr, &node_id));
            if (node_id >= CM_MAX_INSTANCES) {
                CM_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "node_id", CM_MAX_INSTANCES);
                return CM_ERROR;
            }
            status++;
        } else if (status == 1) {
            cm_str2text(urlstr, &text);
            cm_trim_text(&text);
            CM_RETURN_IF_FALSE(cm_check_ss_ip(&text, urlstr));
            MEMS_RETURN_IFERR(strncpy_s(nodes[node_id], CM_MAX_IP_LEN, text.str, text.len));
            status++;
        } else {
            return CM_ERROR;
        }

        *pos = ':';
        urlstr += (url_len + 1);
        url_len = 0;
        pos = urlstr;
    }

    if (url_len > 0) {
        CM_RETURN_IFERR(cm_str2uint16(urlstr, &ports[node_id]));
        if (ports[node_id] < CM_MIN_PORT) {
            CM_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "node port", CM_MIN_PORT);
            return CM_ERROR;
        }
    } else {
        // need port
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_split_mes_urls(char nodes[][CM_MAX_IP_LEN], uint16 ports[], char *urls)
{
    char *pos = NULL;
    uint32 url_len = 0;
    uint32 len = (uint32)strlen(urls);
    char str_tmp[CM_MES_MAX_URLS_LEN] = { 0 };
    errno_t errcode = strncpy_s(str_tmp, CM_MES_MAX_URLS_LEN, urls, len);
    if (errcode != EOK) {
        return CM_ERROR;
    }

    uint32 url_num = 0;
    char *urlstr = str_tmp;
    for (pos = urlstr; len > 0 && url_num < CM_MAX_INSTANCES; len--) {
        if (*pos != ',') {
            url_len++;
            pos++;
            continue;
        }

        *pos = '\0';
        if (len == 1 || cm_split_mes_single_url(nodes, ports, urlstr) != CM_SUCCESS) {
            return CM_ERROR;
        }

        *pos = ',';
        urlstr += (url_len + 1);
        url_len = 0;
        pos = urlstr;
    }

    if (url_num >= CM_MAX_INSTANCES) {
        CM_THROW_ERROR(ERR_IPADDRESS_OR_DOMAIN_NUM_EXCEED, (uint32)CM_MAX_INSTANCES);
        return CM_ERROR;
    }

    if (url_len > 0) {
        if (cm_split_mes_single_url(nodes, ports, urlstr) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}
