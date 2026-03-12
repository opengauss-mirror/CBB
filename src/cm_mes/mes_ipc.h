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
 * mes_ipc.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_ipc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_IPC_H__
#define __MES_IPC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "cm_defs.h"
#include "mes_interface.h"
#include "mes_type.h"

typedef struct st_mes_msgitem mes_msgitem_t;
typedef struct st_mes_msgqueue mes_msgqueue_t;

#define MES_IPC_SHM_KEY_BASE 0x88880000
#define MES_IPC_MAX_MSG_SIZE (64 * 1024)
#define MES_IPC_MSG_QUEUE_SIZE 256
#define MES_IPC_BATCH_SIZE 16
#define MES_IPC_SHM_SIZE (sizeof(mes_ipc_shm_t))

#define MES_IPC_CACHE_LINE_SIZE 64
#define MES_IPC_CACHE_ALIGNED __attribute__((aligned(MES_IPC_CACHE_LINE_SIZE)))

typedef struct st_mes_ipc_msg {
    mes_message_head_t head;
    char buffer[MES_IPC_MAX_MSG_SIZE];
} mes_ipc_msg_t;

typedef struct st_mes_ipc_queue {
    volatile uint32_t head MES_IPC_CACHE_ALIGNED;
    volatile uint32_t tail MES_IPC_CACHE_ALIGNED;
    volatile uint32_t size;
    uint32_t capacity;
    char _pad[MES_IPC_CACHE_LINE_SIZE - 3 * sizeof(uint32_t)];
    mes_ipc_msg_t messages[MES_IPC_MSG_QUEUE_SIZE];
} mes_ipc_queue_t;

typedef struct st_mes_ipc_inst_queues {
    mes_ipc_queue_t recv_queue;
    uint32_t connected;
    volatile uint32_t msg_pending;
} mes_ipc_inst_queues_t;

typedef struct st_mes_ipc_shm {
    uint32_t magic;
    uint32_t version;
    uint32_t inst_count;
    mes_ipc_inst_queues_t queues[MES_MAX_INSTANCES];
    uint32_t sem_global;
} mes_ipc_shm_t;

typedef struct st_mes_ipc_conn {
    int shm_id;
    mes_ipc_shm_t *shm_ptr;
    int sem_send_id;
    int sem_recv_id;
    inst_type inst_id;
    bool8 is_connected;
} mes_ipc_conn_t;

int mes_ipc_init_shm(void);
void mes_ipc_init_channels_param(uintptr_t channelPtr);
void mes_ipc_try_connect(uintptr_t pipePtr);
void mes_ipc_heartbeat_channel(uintptr_t channelPtr);
void mes_ipc_disconnect(uint32 inst_id, bool32 wait);
int mes_ipc_send_data(const void *msg_data);
int mes_ipc_send_bufflist(mes_bufflist_t *buff_list);
mes_msgitem_t *mes_ipc_alloc_msgitem(mes_msgqueue_t *queue, bool32 is_send);
void mes_ipc_cleanup(void);

int mes_ipc_start_receivers(void);
void mes_ipc_stop_receivers(void);
int mes_ipc_recv_message(mes_message_t *msg);
int mes_ipc_add_recv_pipe_to_epoll(uint16 channel_id, mes_priority_t priority, uint32 version);
int mes_ipc_remove_recv_pipe_from_epoll(mes_priority_t priority, uint32 channel_id);

#ifdef __cplusplus
}
#endif

#endif /* __MES_IPC_H__ */