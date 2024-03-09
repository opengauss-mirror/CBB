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
#include "cm_memory.h"
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

/*
 * old style" ``typedef struct __attribute__((aligned(128))) st_mes_buf_queue``,
 * DO NOT USE aligned(128), it will tell gcc to generate ``movaps %xmm0, 0x10(%rdi)``
 * instruction to operate st_mes_buf_queue variable's members, but it requires
 * st_mes_buf_queue variable's address is aligned by 128, otherwise it will crash.
 * now we don't ensure its address is aligned by 128.
 *
*/
typedef struct st_mes_buf_queue {
    spinlock_t lock;
    spinlock_t init_lock; // defer format memory to buffer item allocation, to speed mes_init
    mes_chunk_info_t chunk_info;
    uint8 queue_no;
    volatile bool8 inited;
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
    memory_chunk_t mem_chunk;
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
char *mes_alloc_buf_item(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
char *mes_alloc_buf_item_fc(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
void mes_free_buf_item(char *buffer);
uint32 mes_get_priority_max_msg_size(mes_priority_t priority);
uint64 mes_calc_message_pool_size(mes_profile_t *profile, uint32 priority);

#ifdef __cplusplus
}
#endif

#endif
