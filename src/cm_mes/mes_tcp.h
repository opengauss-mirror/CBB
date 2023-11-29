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
#include "mes_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_URL_BUFFER_SIZE         (CM_HOST_NAME_BUFFER_SIZE + 16)
#define MES_INSTANCE_ID(id)         (uint8)((id) >> UINT8_BITS)
#define MES_CHANNEL_ID(id)          (uint8)((id)&0x00FF)
#define MES_HEARTBEAT_INTERVAL      (1)


int mes_init_tcp_resource(void);
void mes_free_channels(void);
void mes_stop_channels(void);
void mes_tcp_disconnect(uint32 inst_id, bool32 wait);
int mes_tcp_connect(uint32 inst_id);
int mes_tcp_send_data(const void *msg_data);
int mes_start_lsnr(void);
int mes_alloc_channels(void);
int mes_tcp_send_bufflist(mes_bufflist_t *buff_list);
bool32 mes_tcp_connection_ready(uint32 inst_id);

int mes_connect_single(inst_type inst_id);
status_t mes_get_pipe_version(cs_pipe_t *pipe, uint32 *version);
void cs_disconnect_ex(cs_pipe_t *pipe, bool8 is_send, inst_type inst_id);
void mes_event_proc(uint32 channel_id, uint32 priority, uint32 event);
int mes_start_heartbeat_thread();
void mes_stop_heartbeat_thread();

#ifdef __cplusplus
}
#endif

#endif
