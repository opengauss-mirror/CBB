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
 * mes_msg_pool.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_msg_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_MSG_POOL_H__
#define __MES_MSG_POOL_H__

#include "mes_type.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "mes_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_MAX_BUFFER_QUEUE_NUM (0xFF)

typedef struct st_mes_chunk_info {
    inst_type inst_id;
    mes_priority_t priority;
    uint8 chunk_no;
    bool8 is_send;
} mes_chunk_info_t;

typedef struct st_mes_buffer_item {
    struct st_mes_buffer_item *next;
    mes_chunk_info_t chunk_info;
    uint8 queue_no;
    uint8 reserved[1];
    char data[0];
} mes_buffer_item_t;

#define MES_BUFFER_ITEM_SIZE (offsetof(mes_buffer_item_t, data))

#ifndef WIN32
// old code the mes buf queue aligned 128
// will cause gcc10.3 compile to movaps %xmm0,0x10(%rdi), forbid it at present
typedef struct st_mes_buf_queue {
#else
typedef struct st_mes_buf_queue {
#endif
    spinlock_t lock;
    uint8 chunk_no;
    uint8 queue_no;
    uint8 reserved[2];
    uint32 buf_size;
    uint32 count;
    mes_buffer_item_t *first;
    mes_buffer_item_t *last;
    char *addr;
} mes_buf_queue_t;

typedef struct st_mes_buf_chunk {
    uint32 buf_size;
    uint8 chunk_no;
    volatile uint8 queue_num;
    volatile uint8 current_no;
    uint8 reserved;
    mes_buf_queue_t *queues;
} mes_buf_chunk_t;

typedef struct st_mes_pool {
    uint32 count;
    mes_buf_chunk_t chunk[MES_MAX_BUFFPOOL_NUM];
} mes_pool_t;

typedef struct st_message_pool {
    spinlock_t lock;
    spinlock_t *lock_arr;
    char *buffer;
    char *real_buffer;
    char **items;
    int64 get_no;
    uint32 buffer_size;
    uint32 size;
    int mr_id; // used for xnet register id
} message_pool_t;

int mes_init_message_pool(bool32 is_send, uint32 inst_id, mes_priority_t priority);
void mes_destroy_message_pool(bool32 is_send, uint32 inst_id, mes_priority_t priority);
void mes_destroy_all_message_pool(void);
void mes_init_buf_queue(mes_buf_queue_t *queue);
int mes_create_buffer_queue(
    mes_buf_queue_t *queue, mes_chunk_info_t chunk_info, uint8 queue_no, uint32 buf_size, uint32 buf_count);
void mes_destroy_buffer_queue(mes_buf_queue_t *queue);
int mes_create_buffer_chunk(mes_buf_chunk_t *chunk, mes_chunk_info_t chunk_info, uint32 queue_num,
    const mes_buffer_attr_t *buf_attr);
void mes_destroy_buffer_chunk(mes_buf_chunk_t *chunk);
char *mes_alloc_buf_item(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
char *mes_alloc_buf_item_fc(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
void mes_free_buf_item(char *buffer);
uint32 mes_get_priority_max_msg_size(mes_priority_t priority);

#ifdef __cplusplus
}
#endif

#endif
