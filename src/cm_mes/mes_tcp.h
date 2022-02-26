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
 * mes_tcp.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_tcp.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_TCP_H__
#define __MES_TCP_H__


#include "cm_defs.h"
#include "cm_thread.h"
#include "cs_pipe.h"
#include "cs_listener.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_URL_BUFFER_SIZE (CM_HOST_NAME_BUFFER_SIZE + 16)
#define MES_INSTANCE_ID(id) (uint8)((id) >> 8)
#define MES_CHANNEL_ID(id) (uint8)((id)&0x00FF)
#define MES_CONNECT_CMD (uint8)(CM_MAX_MES_MSG_CMD + 1)

typedef struct st_mes_channel {
    thread_lock_t lock;
    cs_pipe_t send_pipe;
    cs_pipe_t recv_pipe;
    thread_t thread;
    uint16 id;
    volatile bool8 recv_pipe_active;
    volatile bool8 send_pipe_active;
    atomic_t send_count;
    atomic_t recv_count;
    mes_msgqueue_t msg_queue;
} mes_channel_t;


void mes_stop_lsnr(void);
void mes_free_channels(void);
void mes_stop_channels(void);
void mes_tcp_disconnect(uint32 inst_id);
int mes_tcp_connect(uint32 inst_id);
int mes_tcp_send_data(const void *msg_data);
int mes_start_lsnr(void);
int mes_alloc_channels(void);
int mes_tcp_send_bufflist(mes_bufflist_t *buff_list);
bool32 mes_tcp_connection_ready(uint32 inst_id);


#ifdef __cplusplus
}
#endif

#endif
