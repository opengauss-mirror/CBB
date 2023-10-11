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
 * mes_queue.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_queue.c
 *
 * -------------------------------------------------------------------------
 */

#include "mes_queue.h"
#include "mes_func.h"
#include "cm_memory.h"
#include "mes_cb.h"

#define MSG_QUEUE_THRESHOLD 100

static int mes_alloc_msgitems_by_freelist(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
{
    if (pool->free_list.count < MSG_ITEM_BATCH_SIZE) {
        LOG_RUN_ERR("pool free_list count not enough, current count:%u.", pool->free_list.count);
        return ERR_MES_FREELIST_CNT_ERR;
    }

    msgitems->first = pool->free_list.first;
    for (uint32 loop = 0; loop < MSG_ITEM_BATCH_SIZE - 1; loop++) {
        pool->free_list.first = pool->free_list.first->next;
    }

    msgitems->last = pool->free_list.first;
    pool->free_list.first = pool->free_list.first->next;
    msgitems->last->next = NULL;
    msgitems->count = MSG_ITEM_BATCH_SIZE;

    pool->free_list.count -= MSG_ITEM_BATCH_SIZE;
    if (pool->free_list.count == 0) {
        pool->free_list.last = NULL;
    }

    return CM_SUCCESS;
}

int mes_alloc_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
{
    mes_msgitem_t *item;

    cm_spin_lock(&pool->free_list.lock, NULL);
    if (pool->free_list.count == 0) {
        cm_spin_unlock(&pool->free_list.lock);
        cm_spin_lock(&pool->lock, NULL);
        if (pool->buf_idx == CM_INVALID_ID16 || pool->hwm >= INIT_MSGITEM_BUFFER_SIZE) {
            pool->buf_idx++;
            if (pool->buf_idx >= MAX_POOL_BUFFER_COUNT) {
                cm_spin_unlock(&pool->lock);
                LOG_RUN_ERR("pool->buf_idx exceed.");
                return ERR_MES_BUF_ID_EXCEED;
            }
            pool->hwm = 0;
            pool->buffer[pool->buf_idx] = (mes_msgitem_t *)malloc(INIT_MSGITEM_BUFFER_SIZE * sizeof(mes_msgitem_t));
            if (pool->buffer[pool->buf_idx] == NULL) {
                cm_spin_unlock(&pool->lock);
                return ERR_MES_MALLOC_FAIL;
            }
        }
        item = (mes_msgitem_t *)(pool->buffer[pool->buf_idx] + pool->hwm);
        pool->hwm += MSG_ITEM_BATCH_SIZE;
        cm_spin_unlock(&pool->lock);

        msgitems->first = item;
        for (uint32 loop = 0; loop < MSG_ITEM_BATCH_SIZE - 1; loop++) {
            item->next = item + 1;
            item = item->next;
        }
        msgitems->last = item;
        item->next = NULL;
        msgitems->count = MSG_ITEM_BATCH_SIZE;
        return CM_SUCCESS;
    }

    // get msg item by free list
    int ret = mes_alloc_msgitems_by_freelist(pool, msgitems);
    cm_spin_unlock(&pool->free_list.lock);
    return ret;
}

void mes_init_msgqueue(mes_msgqueue_t *queue)
{
    GS_INIT_SPIN_LOCK(queue->lock);
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
}

static void mes_put_msgitem_nolock(mes_msgqueue_t *queue, mes_msgitem_t *msgitem)
{
    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
    } else {
        if (queue->last != NULL) {
            queue->last->next = msgitem;
        }
        queue->last = msgitem;
    }

    msgitem->next = NULL;
    queue->count++;
}

mes_msgitem_t *mes_alloc_msgitem_nolock(mes_msgqueue_t *queue)
{
    mes_msgitem_t *result = NULL;

    if (queue->count == 0) {
        if (mes_alloc_msgitems(&MES_GLOBAL_INST_MSG.mq_ctx.pool, queue) != CM_SUCCESS) {
            LOG_RUN_ERR("alloc msg item failed");
            return NULL;
        }
    }

    if (queue->count > 0) {
        result = queue->first;
        queue->count--;
        if (queue->count == 0) {
            queue->first = NULL;
            queue->last = NULL;
        } else {
            queue->first = result->next;
        }
        result->next = NULL;
    }
    return result;
}

mes_msgitem_t *mes_alloc_msgitem(mes_msgqueue_t *queue)
{
    mes_msgitem_t *item = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        if (mes_alloc_msgitems(&MES_GLOBAL_INST_MSG.mq_ctx.pool, queue) != CM_SUCCESS) {
            cm_spin_unlock(&queue->lock);
            LOG_RUN_ERR("alloc inner msg item failed");
            return NULL;
        }
    }

    item = queue->first;
    queue->count--;
    if (queue->count == 0) {
        queue->first = NULL;
        queue->last = NULL;
    } else {
        queue->first = item->next;
    }
    item->next = NULL;
    cm_spin_unlock(&queue->lock);
    return item;
}

void mes_init_msgitem_pool(mes_msgitem_pool_t *pool)
{
    GS_INIT_SPIN_LOCK(pool->lock);
    pool->buf_idx = CM_INVALID_ID16;
    pool->hwm = 0;
    mes_init_msgqueue(&pool->free_list);
}

void mes_free_msgitem_pool(mes_msgitem_pool_t *pool)
{
    if (pool->buf_idx == CM_INVALID_ID16) {
        return;
    }

    for (uint16 i = 0; i <= pool->buf_idx; i++) {
        free(pool->buffer[i]);
        pool->buffer[i] = NULL;
    }
}

void mes_put_msgitem(mes_msgqueue_t *queue, mes_msgitem_t *msgitem)
{
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
    } else {
        queue->last->next = msgitem;
        queue->last = msgitem;
    }

    msgitem->next = NULL;
    queue->count++;
    cm_spin_unlock(&queue->lock);
}

void mes_init_msg_queue(void)
{
    uint32 loop;
    uint32 queueIdx;
    for (loop = 0; loop < CM_MES_MAX_TASK_NUM; loop++) {
        mes_init_msgqueue(&MES_GLOBAL_INST_MSG.mq_ctx.tasks[loop].queue);
        MES_GLOBAL_INST_MSG.mq_ctx.tasks[loop].choice = 0;
    }

    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        for (queueIdx = 0; queueIdx < MES_GROUP_QUEUE_NUM; queueIdx++) {
            mes_init_msgqueue(&MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[loop].queue[queueIdx]);
        }
    }

    mes_init_msgqueue(&MES_GLOBAL_INST_MSG.mq_ctx.local_queue);
    mes_init_msgitem_pool(&MES_GLOBAL_INST_MSG.mq_ctx.pool);
    return;
}

mes_msgqueue_t *mes_get_command_task_queue(const mes_message_head_t *head)
{
    mes_msgqueue_t *queue;
    mes_task_group_id_t group_id;
    uint32 queue_id;
    uint32 queue_num;

    group_id = head->flags & MES_FLAG_PRIO_7;
    mes_task_group_t* group = &MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[group_id];
    queue_num = group->task_num > MES_GROUP_QUEUE_NUM ? MES_GROUP_QUEUE_NUM : group->task_num;
    queue_id = (group->push_cursor++) % queue_num;
    queue = &group->queue[queue_id];

    return queue;
}

void mes_put_msgitem_enqueue(mes_msgitem_t *msgitem)
{
    mes_msgqueue_t *queue;

    queue = mes_get_command_task_queue(msgitem->msg.head);

    mes_put_msgitem(queue, msgitem);

    return;
}

int mes_put_inter_msg_in_queue(mes_message_t *msg, mes_msgqueue_t *queue)
{
    mes_msgitem_t *msgitem;

    msgitem = mes_alloc_msgitem(&MES_GLOBAL_INST_MSG.mq_ctx.local_queue);
    if (msgitem == NULL) {
        LOG_RUN_ERR("mes_alloc_msgitem failed.");
        return ERR_MES_ALLOC_MSGITEM_FAIL;
    }

    mes_local_stat(msg->head->cmd);
    msgitem->msg.head = msg->head;
    msgitem->msg.buffer = msg->buffer;

    mes_put_msgitem(queue, msgitem);

    return CM_SUCCESS;
}

int mes_put_inter_msg(mes_message_t *msg)
{
    mes_msgitem_t *msgitem;

    msgitem = mes_alloc_msgitem(&MES_GLOBAL_INST_MSG.mq_ctx.local_queue);
    if (msgitem == NULL) {
        LOG_RUN_ERR("mes_alloc_msgitem failed.");
        return ERR_MES_ALLOC_MSGITEM_FAIL;
    }

    mes_local_stat(msg->head->cmd);
    msgitem->msg.head = msg->head;
    msgitem->msg.buffer = msg->buffer;

    mes_put_msgitem_enqueue(msgitem);

    return CM_SUCCESS;
}

mes_task_group_t *mes_get_task_group(uint32 task_index)
{
    mes_task_group_t *group;

    for (uint32 i = 0; i < MES_TASK_GROUP_ALL; i++) {
        group = &MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[i];
        if (task_index < ((uint32)group->start_task_idx + group->task_num)) {
            return group;
        }
    }
    return NULL;
}

static mes_msgitem_t *mes_get_msgitem(mes_msgqueue_t *queue)
{
    mes_msgitem_t *ret = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        ret = queue->first;
        queue->count--;
        if (queue->count == 0) {
            queue->first = NULL;
            queue->last = NULL;
        } else {
            queue->first = ret->next;
        }
        CM_MFENCE;
    }
    cm_spin_unlock(&queue->lock);
    return ret;
}

static mes_msgitem_t *mes_get_task_msg(mes_task_group_t *group, uint32 queue_id)
{
    mes_msgqueue_t *msg_queue = &group->queue[queue_id];
    mes_msgitem_t *msgitem = mes_get_msgitem(msg_queue);
    if (msgitem == NULL) {
        return msgitem;
    }

    if (msg_queue->count > MSG_QUEUE_THRESHOLD) {
        LOG_RUN_INF("[mes]: group %u queue %u length num %u.", group->group_id, queue_id, msg_queue->count);
    }

    return msgitem;
}

static void mes_free_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
{
    cm_spin_lock(&pool->free_list.lock, NULL);
    if (pool->free_list.count > 0) {
        pool->free_list.last->next = msgitems->first;
        pool->free_list.last = msgitems->last;
        pool->free_list.count += msgitems->count;
    } else {
        pool->free_list.first = msgitems->first;
        pool->free_list.last = msgitems->last;
        pool->free_list.count = msgitems->count;
    }
    cm_spin_unlock(&pool->free_list.lock);
    mes_init_msgqueue(msgitems);
}

void mes_task_proc(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    uint32 index = *(uint32 *)thread->argument;
    mes_msgitem_t *msgitem;
    mes_task_group_t *group;
    uint32 loop;
    uint32 queue_id = 0;
    uint32 queue_num;

    mes_msg_t app_msg;

    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_task_proc_%u", index));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = get_mes_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_DEBUG_INF("[mes]: status_notify thread init callback: cb_thread_init done");
    }

    mes_msgqueue_t finished_msgitem_queue;
    mes_init_msgqueue(&finished_msgitem_queue);

    group = mes_get_task_group(index);
    if (group == NULL) {
        LOG_RUN_ERR("[mes]: task index %u not belong any group.", index);
        return;
    }

    queue_num = group->task_num > MES_GROUP_QUEUE_NUM ? MES_GROUP_QUEUE_NUM : group->task_num;

    while (!thread->closed) {
        uint64 start_stat_time = 0;
        mes_get_consume_time_start(&start_stat_time);
        queue_id = (group->pop_cursor) % queue_num;
        msgitem = mes_get_task_msg(group, queue_id);

        for (loop = 0; msgitem == NULL && loop < queue_num; ++loop) {
            queue_id = (queue_id + 1) % queue_num;
            msgitem = mes_get_task_msg(group, queue_id);
        }

        if (msgitem == NULL) {
            cm_sleep(1);
            continue;
        }

        group->pop_cursor = queue_id + 1;

        if (msgitem->msg.head->cmd == MES_CMD_SYNCH_ACK) {
            mes_notify_msg_recv(&msgitem->msg);
        } else {
            mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_GET_QUEUE, start_stat_time);
            mes_get_consume_time_start(&start_stat_time);

            app_msg.buffer = msgitem->msg.buffer + sizeof(mes_message_head_t);
            app_msg.size = msgitem->msg.head->size - sizeof(mes_message_head_t);
            app_msg.src_inst = (unsigned int)msgitem->msg.head->src_inst;
            MES_GLOBAL_INST_MSG.proc(index, msgitem->msg.head->ruid, &app_msg);

            mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_QUEUE_PROC, start_stat_time);
        }

        mes_put_msgitem_nolock(&finished_msgitem_queue, msgitem);
        if (MSG_ITEM_BATCH_SIZE == finished_msgitem_queue.count) {
            mes_free_msgitems(&MES_GLOBAL_INST_MSG.mq_ctx.pool, &finished_msgitem_queue);
        }
    }
    return;
}
