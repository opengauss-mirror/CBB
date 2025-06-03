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

typedef struct st_mes_buffer_item_tag {
    inst_type inst_id;
    mes_priority_t priority;
    uint8 buf_pool_no;
    uint8 queue_no;
    unsigned char is_send : 1;
    unsigned char is_shared : 1;
    unsigned char reserved : 6;
    uint8 reserved2;
} mes_buffer_item_tag_t;

typedef struct st_mes_buffer_item {
    struct st_mes_buffer_item *next;
    mes_buffer_item_tag_t tag;
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
    uint32 init_count;
    uint8 queue_no;
    volatile bool8 inited;
    uint8 reserved[2];
    uint32 buf_size;
    uint32 count;
    mes_buffer_item_t *first;
    mes_buffer_item_t *last;
    char *addr;
} mes_buf_queue_t;

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

typedef struct st_mes_msg_buffer_inner_pool {
    uint32 queue_num;
    mes_buf_queue_t *queues;
    uint32 pop_cursor; // used for thread find queue
    uint32 push_cursor;
} mes_msg_buffer_inner_pool_t;

typedef struct st_mes_msg_buffer_pool_tag {
    bool8 is_send;
    bool8 enable_inst_dimension;
    uint8 inst_id;
    uint8 buf_pool_no;
} mes_msg_buffer_pool_tag_t;

typedef struct st_mes_msg_buffer_pool {
    bool8 inited;
    mes_msg_buffer_pool_tag_t tag;
    uint32 buf_size;
    uint32 buf_num;
    uint32 priority_cnt;
    mes_msg_buffer_inner_pool_t private_pool[MES_PRIORITY_CEIL];
    mes_msg_buffer_inner_pool_t shared_pool;
    void *msg_pool;
    atomic32_t pop_priority;
    bool8 need_recycle;
    uint32 recycle_threshold;
    uint32 recycle_queue_no;
    spinlock_t mem_chunk_lock;
    memory_chunk_t mem_chunk;
} mes_msg_buffer_pool_t;

typedef struct st_mes_msg_pool_tag {
    bool8 is_send;
    bool8 enable_inst_dimension;
    inst_type inst_id;
} mes_msg_pool_tag_t;

typedef struct st_mes_msg_pool {
    mes_msg_pool_tag_t tag;
    unsigned long long size;
    uint32 buf_pool_count;
    mes_msg_buffer_pool_t *buf_pool[MES_MAX_BUFFPOOL_NUM];
    memory_chunk_t mem_chunk;
} mes_msg_pool_t;

typedef struct st_mes_msg_inst_pool_set {
    uint64 total_size;
    uint32 inst_pool_count;
    uint64 per_inst_pool_size;
    mes_msg_pool_t *inst_pool[MES_MAX_INSTANCES];
} mes_msg_inst_pool_set_t;

typedef struct st_mes_msg_buffer_relation {
    uint8 buf_count;
    uint32 origin_buf_size[MES_MAX_BUFFPOOL_NUM];
    uint32 changed_buf_size[MES_MAX_BUFFPOOL_NUM];
} mes_msg_buffer_relation_t;

int mes_check_msg_pool_attr(mes_profile_t *profile, mes_profile_t *out_profile, bool8 check_proportion,
    mes_msg_buffer_relation_t *buf_rel);
int mes_init_message_pool(bool8 is_send);
void mes_deinit_all_message_pool();
char *mes_alloc_buf_item(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
char *mes_alloc_buf_item_fc(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority);
void mes_free_buf_item(char *buffer);
uint32 mes_get_priority_max_msg_size(mes_priority_t priority);
int mes_check_message_pool_size(mes_profile_t *profile);

#ifdef __cplusplus
}
#endif

#endif
