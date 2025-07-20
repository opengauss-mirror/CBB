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
 * mes_queue.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_queue.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_QUEUE_H__
#define __MES_QUEUE_H__

#include "mes_type.h"
#include "mes_interface.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "cm_thread.h"
#include "cm_sync.h"
#include "cm_compress.h"
#include "mes_msg_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_TASK_QUEUE_CHOICE (4)
#define MSG_ITEM_BATCH_SIZE 32
#define INIT_MSGITEM_BUFFER_SIZE 8192
#define MAX_POOL_BUFFER_COUNT 8192
#define MES_MSG_QUEUE_NUM (1)
#define MES_MAX_SERIAL_ARRAY_NUM 32

typedef struct st_mes_msgitem {
    mes_message_t msg;
    struct st_mes_msgitem *next;
    uint64 enqueue_time;
} mes_msgitem_t;

#ifdef WIN32
typedef struct st_mes_msgqueue
#else
// old code the msgqueue aligned 128
// will cause gcc10.3 compile to movaps %xmm0,0x10(%rdi), forbid it at present
typedef struct st_mes_msgqueue
#endif
{
    spinlock_t lock;
    volatile uint32 count;
    mes_msgitem_t *first;
    mes_msgitem_t *last;
} mes_msgqueue_t;

typedef struct st_mes_msgitem_pool {
    spinlock_t lock;
    mes_msgitem_t *buffer[MAX_POOL_BUFFER_COUNT];
    uint16 buf_idx;
    uint16 hwm;
    uint16 unused;

    mes_msgqueue_t free_list;
} mes_msgitem_pool_t;

typedef struct st_mes_task_context {
    thread_t thread;
    uint8 choice;
    uint8 reserved[3];
    mes_msgqueue_t queue;
    atomic_t serial_array[MES_MAX_SERIAL_ARRAY_NUM];
} mes_task_context_t;

#define MES_PRIORITY_TASK_QUEUE_NUM CM_MES_MAX_TASK_NUM
typedef struct st_mes_task_priority {
    uint8 is_set;
    uint8 task_num;
    uint8 start_task_idx;
    uint8 reserved;
    mes_priority_t priority;
    char aligned1[CM_CACHE_LINE_SIZE];
    uint32 push_cursor;
    uint32 pop_cursor;
    char aligned2[CM_CACHE_LINE_SIZE];
    uint64_t finished_msgitem_num;
    uint64_t inqueue_msgitem_num;
} mes_task_priority_t;

typedef struct st_mes_mq_priority {
    uint32 assign_task_idx;  // task index assigned to priority.
    mes_task_priority_t task_priority[MES_PRIORITY_CEIL];
} mes_mq_priority_t;

typedef struct st_mes_command_attr {
    mes_priority_t priority;
} mes_command_attr_t;

typedef struct st_task_arg {
    spinlock_t lock;
    struct {
        bool32 is_start : 1;
        bool32 is_send : 1;
        bool32 reserved : 30;
    };
    void *mq_ctx;
    uint32 index;
    cm_event_t event;
    uint32 tid;
    mes_priority_t priority;
    uint64 get_msgitem_time;
    uint64 msg_ruid;
    uint32 msg_src_inst;
    bool8 is_active;
    char data[MES_INFO_LEN];
} task_arg_t;

typedef struct st_mq_context_t {
    uint32 task_num;
    mes_task_context_t tasks[MES_MAX_TASK_NUM];  // mes task thread
    task_arg_t work_thread_idx[MES_MAX_TASK_NUM];
    mes_msgitem_pool_t pool;
    mes_msgqueue_t **channel_private_queue;
    mes_profile_t *profile;
    void *mes_ctx;
    mes_mq_priority_t priority;
    spinlock_t msg_pool_init_lock;
    bool8 enable_inst_dimension;
    mes_msg_pool_t *single_pool;
    mes_msg_inst_pool_set_t inst_pool_set;
    bool8 msg_pool_inited;
} mq_context_t;

#define PROC_DIFF_ENDIAN(head)                                      \
    do {                                                            \
        (head)->version = cs_reverse_uint32((head)->version);       \
        (head)->cmd = cs_reverse_uint32((head)->cmd);               \
        (head)->flags = cs_reverse_uint32((head)->flags);           \
        (head)->caller_tid = cs_reverse_uint32((head)->caller_tid); \
        (head)->ruid = cs_reverse_int64((head)->ruid);              \
        (head)->src_inst = cs_reverse_uint32((head)->src_inst);     \
        (head)->dst_inst = cs_reverse_uint32((head)->dst_inst);     \
        (head)->size = cs_reverse_uint32((head)->size);             \
    } while (0)

#ifndef WIN32
void delete_compress_thread_key(void);
status_t create_compress_ctx();
#endif

void mes_init_msgitem_pool(mes_msgitem_pool_t *pool);
void mes_free_msgitem_pool(mes_msgitem_pool_t *pool);
void mes_init_msgqueue(mes_msgqueue_t *queue);
void mes_put_msgitem_nolock(mes_msgqueue_t *queue, mes_msgitem_t *msgitem);
void mes_put_msgitem(mes_msgqueue_t *queue, mes_msgitem_t *msgitem);

void mes_task_proc(thread_t *thread);
status_t mes_start_task_dynamically(bool32 is_send, uint32 index);
int mes_put_msg_queue(mes_message_t *msg, bool32 is_send);
void mes_put_msgitem_enqueue(mes_msgitem_t *msgitem, bool32 is_send, uint32 *work_index);
mes_msgitem_t *mes_alloc_msgitem_nolock(mes_msgqueue_t *queue, bool32 is_send);
mes_msgitem_t *mes_alloc_msgitem(mes_msgqueue_t *queue, bool32 is_send);
mes_task_priority_t *mes_get_task_priority(uint32 task_index, bool32 is_send);
int mes_alloc_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems);
mes_msgitem_t *mes_get_msgitem(mes_msgqueue_t *queue);
status_t mes_create_compress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                                 mes_priority_t priority);
int mes_create_decompress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                              mes_priority_t priority);
int mes_decompress(mes_message_t *msg);
status_t mes_alloc_channel_msg_queue(bool32 is_send);
void mes_free_channel_msg_queue(bool32 is_send);
int mes_put_buffer_list_queue(mes_bufflist_t *buff_list, bool32 is_send);
status_t mes_check_send_head_info(const mes_message_head_t *head);
void mes_free_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems);
void mes_work_proc(mes_msgitem_t *msgitem, uint32 work_idx);

#ifdef __cplusplus
}
#endif


#endif
