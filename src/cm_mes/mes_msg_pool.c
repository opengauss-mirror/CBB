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
 * mes_msg_pool.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_msg_pool.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_msg_pool.h"
#include "mes_func.h"
#include "mes_type.h"

#define RECV_MSG_POOL_FC_THRESHOLD 10

static mes_buf_chunk_t *mes_get_buffer_chunk(uint32 len)
{
    mes_buf_chunk_t *chunk;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.count; i++) {
        chunk = &MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.chunk[i];
        if (len <= chunk->buf_size) {
            return chunk;
        }
    }

    LOG_RUN_ERR("[mes]: There is not long enough buffer pool for %u.", len);
    return NULL;
}

static inline mes_buf_queue_t *mes_get_buffer_queue(mes_buf_chunk_t *chunk)
{
    mes_buf_queue_t *queue = NULL;
    queue = &chunk->queues[chunk->current_no % chunk->queue_num];
    chunk->current_no++;
    return queue;
}

// new buffer pool
void mes_init_buf_queue(mes_buf_queue_t *queue)
{
    GS_INIT_SPIN_LOCK(queue->lock);
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
    queue->addr = NULL;
}

int mes_create_buffer_queue(mes_buf_queue_t *queue, uint8 chunk_no, uint8 queue_no, uint32 buf_size, uint32 buf_count)
{
    uint64 mem_size;
    mes_buffer_item_t *buf_node;
    mes_buffer_item_t *buf_node_next;
    uint64 buf_item_size;
    char *temp_buffer;

    if (buf_count == 0) {
        LOG_RUN_ERR("[mes]: mes_pool_size should greater than 0.");
        return ERR_MES_PARAM_INVAIL;
    }

    // init queue
    mes_init_buf_queue(queue);
    queue->chunk_no = chunk_no;
    queue->queue_no = queue_no;
    queue->buf_size = buf_size;
    queue->count = buf_count;

    // alloc memery
    buf_item_size = (uint64)(sizeof(mes_buffer_item_t) + buf_size);
    mem_size = (uint64)buf_count * buf_item_size;
    queue->addr = malloc(mem_size); // reserve MEX_XNET_PAGE_SIZE for register addr 4096 align.
    if (queue->addr == NULL) {
        LOG_RUN_ERR("[mes]: allocate memory size %llu for MES msg pool failed", mem_size);
        return ERR_MES_MALLOC_FAIL;
    }

    // init queue list
    temp_buffer = queue->addr;
    buf_node = (mes_buffer_item_t *)temp_buffer;
    queue->first = buf_node;
    for (uint32 i = 1; i < buf_count; i++) {
        temp_buffer += buf_item_size;
        buf_node_next = (mes_buffer_item_t *)temp_buffer;
        buf_node->chunk_no = chunk_no;
        buf_node->queue_no = queue_no;
        buf_node->next = buf_node_next;
        buf_node = buf_node_next;
    }
    buf_node->chunk_no = chunk_no;
    buf_node->queue_no = queue_no;
    buf_node->next = NULL;
    queue->last = buf_node;

    return CM_SUCCESS;
}

static void mes_set_buffer_queue_count(mes_buf_chunk_t *chunk, uint32 queue_num, uint32 total_count)
{
    uint32 buf_count;
    uint32 buf_leftover;

    buf_count = total_count / queue_num;
    buf_leftover = total_count % queue_num;

    for (uint32 i = 0; i < queue_num; i++) {
        chunk->queues[i].count = buf_count;
    }

    for (uint32 i = 0; i < buf_leftover; i++) {
        chunk->queues[i].count++;
    }

    return;
}

int mes_create_buffer_chunk(mes_buf_chunk_t *chunk, uint32 chunk_no, uint32 queue_num,
    const mes_buffer_attr_t *buf_attr)
{
    errno_t ret;
    uint64 queues_size;

    if (queue_num == 0 || queue_num > MES_MAX_BUFFER_QUEUE_NUM) {
        LOG_RUN_ERR("[mes]: pool_count %u is invalid, legal scope is [1, %d].", queue_num, MES_MAX_BUFFPOOL_NUM);
        return ERR_MES_PARAM_INVAIL;
    }

    queues_size = (uint64)(queue_num * sizeof(mes_buf_queue_t));
    chunk->queues = (mes_buf_queue_t *)malloc(queues_size);
    if (chunk->queues == NULL) {
        LOG_RUN_ERR("[mes]:allocate memory queue_num %u failed", queue_num);
        return ERR_MES_MALLOC_FAIL;
    }
    ret = memset_sp(chunk->queues, queues_size, 0, queues_size);
    if (ret != EOK) {
        free(chunk->queues);
        chunk->queues = NULL;
        return ERR_MES_MEMORY_SET_FAIL;
    }

    chunk->chunk_no = (uint8)chunk_no;
    chunk->buf_size = buf_attr->size;
    chunk->queue_num = (uint8)queue_num;
    chunk->current_no = 0;

    mes_set_buffer_queue_count(chunk, queue_num, buf_attr->count);

    for (uint32 i = 0; i < queue_num; i++) {
        ret = mes_create_buffer_queue(&chunk->queues[i], (uint8)chunk_no, (uint8)i, buf_attr->size,
            chunk->queues[i].count);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes]: create buf queue failed.");
            mes_destory_buffer_chunk(chunk);
            return ret;
        }
    }

    return CM_SUCCESS;
}

void mes_destory_buffer_queue(mes_buf_queue_t *queue)
{
    if (queue == NULL || queue->addr == NULL) {
        return;
    }

    free(queue->addr);
    queue->addr = NULL;
}

void mes_destory_buffer_chunk(mes_buf_chunk_t *chunk)
{
    if (chunk == NULL || chunk->queues == NULL) {
        return;
    }

    for (uint32 i = 0; i < chunk->queue_num; i++) {
        mes_destory_buffer_queue(&chunk->queues[i]);
    }

    free(chunk->queues);
    chunk->queues = NULL;

    return;
}

int mes_init_message_pool(void)
{
    int ret;

    if ((MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count == 0) ||
        (MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count > MES_MAX_BUFFPOOL_NUM)) {
        LOG_RUN_ERR("[mes]: pool_count %u is invalid, legal scope is [1, %d].",
            MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count, MES_MAX_BUFFPOOL_NUM);
        return ERR_MES_PARAM_INVAIL;
    }

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count; i++) {
        ret = mes_create_buffer_chunk(&MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.chunk[i], i,
            MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.queue_count,
            &MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.buf_attr[i]);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes]: create buf chunk failed.");
            return ret;
        }
    }

    MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.count = MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count;
    MES_GLOBAL_INST_MSG.mes_ctx.creatMsgPool = CM_TRUE;
    return CM_SUCCESS;
}

void mes_destory_message_pool(void)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.creatMsgPool) {
        return;
    }

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count; i++) {
        mes_destory_buffer_chunk(&MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.chunk[i]);
    }

    MES_GLOBAL_INST_MSG.mes_ctx.creatMsgPool = CM_FALSE;
    return;
}

char *mes_alloc_buf_item(uint32 len)
{
    mes_buf_chunk_t *chunk = NULL;
    mes_buf_queue_t *queue = NULL;
    mes_buffer_item_t *buf_node = NULL;
    uint32 find_times = 0;

    chunk = mes_get_buffer_chunk(len);
    if (chunk == NULL) {
        LOG_RUN_ERR("[mes]: Get buffer failed.");
        return NULL;
    }

    do {
        queue = mes_get_buffer_queue(chunk);
        cm_spin_lock(&queue->lock, NULL);
        if (queue->count > 0) {
            buf_node = queue->first;
            queue->count--;
            if (queue->count == 0) {
                queue->first = NULL;
                queue->last = NULL;
            } else {
                queue->first = buf_node->next;
            }
            buf_node->next = NULL;
            cm_spin_unlock(&queue->lock);
            break;
        } else {
            cm_spin_unlock(&queue->lock);
            find_times++;
            if ((find_times % chunk->queue_num) == 0) {
                LOG_RUN_WAR_INHIBIT(LOG_INHIBIT_LEVEL5, "[mes]: There is no buffer, sleep and try again.");
                cm_sleep(1);
            }
        }
    } while (buf_node == NULL);

    return buf_node->data;
}

char *mes_alloc_buf_item_fc(uint32 len)
{
    mes_buf_chunk_t *chunk = NULL;
    mes_buf_queue_t *queue = NULL;
    mes_buffer_item_t *buf_node = NULL;
    uint32 find_times = 0;

    chunk = mes_get_buffer_chunk(len);
    if (chunk == NULL) {
        LOG_RUN_ERR("[mes]: Get buffer failed.");
        return NULL;
    }

    uint32_t count = MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.buf_attr[chunk->chunk_no].count / chunk->queue_num;

    do {
        queue = mes_get_buffer_queue(chunk);
        cm_spin_lock(&queue->lock, NULL);
        if (count / queue->count <= RECV_MSG_POOL_FC_THRESHOLD) {
            buf_node = queue->first;
            queue->count--;
            if (queue->count == 0) {
                queue->first = NULL;
                queue->last = NULL;
            } else {
                queue->first = buf_node->next;
            }
            buf_node->next = NULL;
            cm_spin_unlock(&queue->lock);
            break;
        } else {
            cm_spin_unlock(&queue->lock);
            find_times++;
            if ((find_times % chunk->queue_num) == 0) {
                LOG_RUN_WAR_INHIBIT(LOG_INHIBIT_LEVEL5, "[mes]: There is no buffer, sleep and try again.");
                cm_sleep(1);
            }
        }
    } while (buf_node == NULL);

    return buf_node->data;
}

static void mes_release_buf_stat(const char *msg_buf)
{
    if (g_mes_stat.mes_elapsed_switch) {
        mes_message_head_t *head = (mes_message_head_t *)msg_buf;
        cm_spin_lock(&(g_mes_stat.mes_commond_stat[head->cmd].lock), NULL);
        cm_atomic32_dec(&(g_mes_stat.mes_commond_stat[head->cmd].occupy_buf));
        cm_spin_unlock(&(g_mes_stat.mes_commond_stat[head->cmd].lock));
        mes_elapsed_stat(head->cmd, MES_TIME_PUT_BUF);
    }
    return;
}

void mes_free_buf_item(char *buffer)
{
    if (buffer == NULL) {
        return;
    }

    mes_buffer_item_t *buf_item = (mes_buffer_item_t *)(buffer - MES_BUFFER_ITEM_SIZE);
    mes_buf_chunk_t *chunk = &MES_GLOBAL_INST_MSG.mes_ctx.msg_pool.chunk[buf_item->chunk_no];
    mes_buf_queue_t *queue = &chunk->queues[buf_item->queue_no];

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        queue->last->next = buf_item;
        queue->last = buf_item;
    } else {
        queue->first = buf_item;
        queue->last = buf_item;
    }

    buf_item->next = NULL;
    queue->count++;
    cm_spin_unlock(&queue->lock);
    mes_release_buf_stat(buffer);
    return;
}