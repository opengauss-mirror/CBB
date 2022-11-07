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
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_TASK_QUEUE_CHOICE (4)
#define MSG_ITEM_BATCH_SIZE 32
#define INIT_MSGITEM_BUFFER_SIZE 8192
#define MAX_POOL_BUFFER_COUNT 8192
#define MES_MSG_QUEUE_NUM (1)

typedef struct st_mes_msgitem {
    mes_message_t msg;
    struct st_mes_msgitem *next;
} mes_msgitem_t;

#ifdef WIN32
typedef struct st_mes_msgqueue
#else
typedef struct __attribute__((aligned(128))) st_mes_msgqueue
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
} mes_task_context_t;

#define MES_GROUP_QUEUE_NUM CM_MES_MAX_CHANNEL_NUM
typedef struct st_mes_task_group {
    uint8 is_set;
    uint8 task_num;
    uint8 start_task_idx;
    uint8 reserved;
    mes_task_group_id_t group_id;
    mes_msgqueue_t queue[MES_GROUP_QUEUE_NUM];
    uint32_t push_cursor;
    uint32_t pop_cursor;
} mes_task_group_t;

typedef struct st_mes_mq_group {
    uint32 assign_task_idx; // task index assigned to group.
    mes_task_group_t task_group[MES_TASK_GROUP_ALL];
} mes_mq_group_t;

typedef struct st_mes_command_attr {
    mes_task_group_id_t group_id;
} mes_command_attr_t;

typedef struct st_mq_context_t {
    uint32 task_num;
    mes_task_context_t tasks[CM_MES_MAX_TASK_NUM]; // mes task thread
    mes_command_attr_t command_attr[CM_MAX_MES_MSG_CMD];
    mes_msgitem_pool_t pool;
    mes_mq_group_t group;
    mes_msgqueue_t local_queue; // used for local message
} mq_context_t;

void mes_init_msgitem_pool(mes_msgitem_pool_t *pool);
void mes_free_msgitem_pool(mes_msgitem_pool_t *pool);
void mes_init_msgqueue(mes_msgqueue_t *queue);
void mes_put_msgitem(mes_msgqueue_t *queue, mes_msgitem_t *msgitem);

void mes_task_proc(thread_t *thread);
void mes_init_msg_queue(void);
void mes_free_msg_queue(void);
int mes_put_inter_msg(mes_message_t *msg);
int mes_put_inter_msg_in_queue(mes_message_t *msg, mes_msgqueue_t *queue);
void mes_put_msgitem_enqueue(mes_msgitem_t *msgitem);
mes_msgitem_t *mes_alloc_msgitem_nolock(mes_msgqueue_t *queue);
mes_msgitem_t *mes_alloc_msgitem(mes_msgqueue_t *queue);
mes_msgqueue_t *mes_get_command_task_queue(const mes_message_head_t *head);
mes_task_group_t *mes_get_task_group(uint32 task_index);
int mes_alloc_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems);

#ifdef __cplusplus
}
#endif


#endif
