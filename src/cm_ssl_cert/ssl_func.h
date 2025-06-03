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
 * mes_func.h
 *
 *
 * IDENTIFICATION
 *    src/cm_ssl_cert/ssl_func.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SSL_FUNC_H__
#define __SSL_FUNC_H__

#include "cm_utils.h"
#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_error.h"
#include "cm_timer.h"
#include "cm_bilist.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "cm_rwlock.h"
#include "cm_system.h"

#define SSL_WAIT_TIMEOUT 10

typedef struct st_ssl_instance {
    ssl_ctx_t *ssl_fd;
} ssl_instance_t;

extern ssl_instance_t g_cli_ssl;
extern ssl_instance_t g_ser_ssl;

status_t cli_init_ssl(void);
status_t cli_ssl_connect(cs_pipe_t *pipe);
status_t ser_init_ssl(socket_t sock);
void ser_ssl_uninit(void);
status_t ser_cert_accept(cs_pipe_t *pipe);

#endif