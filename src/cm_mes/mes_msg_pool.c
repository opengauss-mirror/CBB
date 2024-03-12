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

#define RECV_MSG_POOL_FC_THRESHOLD 10

static mes_buf_chunk_t *mes_get_buffer_chunk(uint32 len, bool32 is_send, uint32 inst_id, mes_priority_t priority)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_buf_chunk_t *chunk;

    if (inst_id >= MES_MAX_INSTANCES || priority >= MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[mes] mes_get_buffer_chunk failed, invalid inst_id[%u] or priority[%u], is_send:%u",
                    inst_id, priority, is_send);
        return NULL;
    }

    if (mq_ctx->msg_pool[inst_id][priority] == NULL) {
        cm_spin_lock(&mq_ctx->msg_pool_init_lock, NULL);
        if (mq_ctx->msg_pool[inst_id][priority] == NULL) {
            if (mes_init_message_pool(is_send, inst_id, priority) != CM_SUCCESS) {
                cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
                LOG_RUN_ERR("[mes] mes_init_message_pool failed, inst_id:%u, priority:%u, is_send:%u",
                            inst_id, priority, is_send);
                return NULL;
            }
        }
        cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
    }

    for (uint32 i = 0; i < mq_ctx->msg_pool[inst_id][priority]->count; i++) {
        chunk = &mq_ctx->msg_pool[inst_id][priority]->chunk[i];
        if (len <= chunk->buf_size) {
            return chunk;
        }
    }

    LOG_RUN_ERR("[mes] There is not long enough buffer pool for %u, is_send:%u, inst_id:%u, priority:%u.",
                len, is_send, inst_id, priority);
    return NULL;
}

static void mes_format_buf_queue_memory(mes_buf_queue_t *queue)
{
    mes_buffer_item_t *buf_node = NULL;
    mes_buffer_item_t *buf_node_next = NULL;
    uint64 buf_item_size = sizeof(mes_buffer_item_t) + queue->buf_size;
    char *temp_buffer = queue->addr;

    cm_panic(!queue->inited);

    buf_node = (mes_buffer_item_t *)temp_buffer;
    queue->first = buf_node;
    for (uint32 i = 1; i < queue->count; i++) {
        temp_buffer += buf_item_size;
        buf_node_next = (mes_buffer_item_t *)temp_buffer;
        buf_node->chunk_info = queue->chunk_info;
        buf_node->queue_no = queue->queue_no;
        buf_node->next = buf_node_next;
        buf_node = buf_node_next;
    }
    buf_node->chunk_info = queue->chunk_info;
    buf_node->queue_no = queue->queue_no;
    buf_node->next = NULL;
    queue->last = buf_node;
    queue->inited = CM_TRUE;
}

static mes_buf_queue_t *mes_get_buffer_queue(mes_buf_chunk_t *chunk)
{
    mes_buf_queue_t *queue = NULL;
    queue = &chunk->queues[chunk->current_no % chunk->queue_num];
    chunk->current_no++;

    if (!queue->inited) {
        cm_spin_lock(&queue->init_lock, NULL);
        if (!queue->inited) {
            mes_format_buf_queue_memory(queue);
        }
        cm_spin_unlock(&queue->init_lock);
    }
    return queue;
}

static void mes_init_buf_queue(mes_buf_queue_t *queue)
{
    GS_INIT_SPIN_LOCK(queue->lock);
    GS_INIT_SPIN_LOCK(queue->init_lock);
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
    queue->addr = NULL;
    queue->inited = CM_FALSE;
}

static int mes_create_buffer_queue(mes_buf_queue_t *queue, memory_chunk_t *mem_chunk,
    mes_chunk_info_t chunk_info, uint8 queue_no, uint32 buf_count, uint32 buf_size)
{
    uint64 mem_size;
    uint64 buf_item_size;

    if (buf_count == 0) {
        LOG_RUN_ERR("[mes]: mes_pool_size should greater than 0.");
        return ERR_MES_PARAM_INVALID;
    }

    /* init queue */
    mes_init_buf_queue(queue);
    queue->queue_no = queue_no;
    queue->buf_size = buf_size;
    queue->count = buf_count;
    queue->chunk_info = chunk_info;

    /* alloc memory from memory chunk */
    buf_item_size = (uint64)(sizeof(mes_buffer_item_t) + buf_size);
    mem_size = (uint64)buf_count * buf_item_size;
    queue->addr = cm_alloc_memory_from_chunk(mem_chunk, mem_size);

    /* defer format memory to buffer item allocation, to speed mes_init */
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

static int mes_create_buffer_chunk(mes_buf_chunk_t *chunk, memory_chunk_t *mem_chunk, mes_chunk_info_t chunk_info,
    uint32 queue_count, const mes_buffer_attr_t *buf_attr)
{
    errno_t ret;
    uint64 queues_size = (uint64)(queue_count * sizeof(mes_buf_queue_t));

    if (queue_count == 0 || queue_count > MES_MAX_BUFFER_QUEUE_NUM) {
        LOG_RUN_ERR("[mes]: pool_count %u is invalid, legal scope is [1, %d].", queue_count, MES_MAX_BUFFPOOL_NUM);
        return ERR_MES_PARAM_INVALID;
    }

    chunk->queues = (mes_buf_queue_t *)cm_alloc_memory_from_chunk(mem_chunk, queue_count * sizeof(mes_buf_queue_t));
    ret = memset_sp(chunk->queues, queues_size, 0, queues_size);
    if (ret != EOK) {
        return ERR_MES_MEMORY_SET_FAIL;
    }

    chunk->chunk_no = (uint8)chunk_info.chunk_no;
    chunk->buf_size = buf_attr->size;
    chunk->queue_num = (uint8)queue_count;
    chunk->current_no = 0;

    mes_set_buffer_queue_count(chunk, queue_count, buf_attr->count);

    for (uint32 i = 0; i < queue_count; i++) {
        ret = mes_create_buffer_queue(&chunk->queues[i], mem_chunk, chunk_info, (uint8)i,
            chunk->queues[i].count, buf_attr->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes]: create buf queue failed.");
            return ret;
        }
    }

    return CM_SUCCESS;
}

uint64 mes_calc_message_pool_size(mes_profile_t *profile, uint32 priority)
{
    uint64 total_size = 0;
    total_size += sizeof(mes_pool_t);

    uint32 pool_count = profile->buffer_pool_attr[priority].pool_count;
    uint32 queue_count = 0;
    uint32 buf_size = 0;
    uint32 buf_count = 0;

    for (uint32 i = 0; i < pool_count; i++) {
        queue_count = profile->buffer_pool_attr[priority].queue_count;
        buf_count = profile->buffer_pool_attr[priority].buf_attr[i].count;
        buf_size = profile->buffer_pool_attr[priority].buf_attr[i].size;

        total_size += queue_count * sizeof(mes_buf_queue_t);
        total_size += ((uint64)(sizeof(mes_buffer_item_t) + buf_size)) * buf_count;
    }

    return total_size;
}

mes_pool_t *mes_alloc_message_pool(bool32 is_send, uint32 inst_id, uint32 priority)
{
    uint64 total_size = mes_calc_message_pool_size(&MES_GLOBAL_INST_MSG.profile, priority);
    char *addr = cm_malloc_prot(total_size);
    if (addr == NULL) {
        LOG_RUN_ERR("[mes]failed to allocate memory for message pool, total_size  = %llu,"
        "priority:%u, inst_id:%u, is_send:%u,", total_size, priority, inst_id, is_send);
        return NULL;
    }

    mes_pool_t *pool = (mes_pool_t *)addr;
    if (memset_s(pool, sizeof(mes_pool_t), 0, sizeof(mes_pool_t)) != EOK) {
        cm_free_prot(addr);
        cm_panic(0);
        return NULL;
    }

    pool->mem_chunk.addr = addr;
    pool->mem_chunk.offset = sizeof(mes_pool_t);
    pool->mem_chunk.total_size = total_size;
    return pool; 
}

void mes_free_message_pool(mes_pool_t *pool)
{
    /*
     * DO NOT USE CM_FREE_PROT_PTR, because the freed memory contains msg_pool variable's memory.
     * when the memory is freed, can't assign anything to it.
     */
    cm_panic(pool->mem_chunk.addr != NULL);
    cm_free_prot(pool->mem_chunk.addr);
}

int mes_init_message_pool(bool32 is_send, uint32 inst_id, mes_priority_t priority)
{
    int ret;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;

    if (inst_id >= MES_MAX_INSTANCES || priority >= MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[mes] mes_init_message_pool failed, invalid inst_id[%u] or priority[%u], is_send:%u.",
                    inst_id, priority, is_send);
        return ERR_MES_PARAM_INVALID;
    }

    if ((MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].pool_count == 0) ||
        (MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].pool_count > MES_MAX_BUFFPOOL_NUM)) {
        LOG_RUN_ERR("[mes] pool_count %u is invalid, legal scope is [1, %d], priority:%u, inst_id:%u, is_send:%u.",
            MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].pool_count, MES_MAX_BUFFPOOL_NUM, priority, inst_id,
            is_send);
        return ERR_MES_PARAM_INVALID;
    }

    mes_pool_t *curr_pool = mes_alloc_message_pool(is_send, inst_id, priority);
    if (curr_pool == NULL) {
        return ERR_MES_MALLOC_FAIL;
    }

    curr_pool->count = MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].pool_count;
    mes_buffer_pool_attr_t *pool_attr = &MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority];
    for (uint32 i = 0; i < curr_pool->count; i++) {
        mes_chunk_info_t chunk_info = {.inst_id = inst_id, .priority = priority, .chunk_no = i, .is_send = is_send};
        ret = mes_create_buffer_chunk(&curr_pool->chunk[i], &curr_pool->mem_chunk,
            chunk_info, pool_attr->queue_count, &pool_attr->buf_attr[i]);
        if (ret != CM_SUCCESS) {
            mes_free_message_pool(curr_pool);
            LOG_RUN_ERR("[mes] create buf chunk failed, priority:%u.", priority);
            return ret;
        }
    }

    mq_ctx->msg_pool[inst_id][priority] = curr_pool;
    return CM_SUCCESS;
}

void mes_destroy_all_message_pool()
{
    uint32 i;
    uint32 priority;

    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        uint32 inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id >= MES_MAX_INSTANCES) {
            continue;
        }
        for (priority = 0; priority < MES_GLOBAL_INST_MSG.profile.priority_cnt; priority++) {
            mes_destroy_message_pool(CM_TRUE, inst_id, priority);
            mes_destroy_message_pool(CM_FALSE, inst_id, priority);
        }
    }
}

void mes_destroy_message_pool(bool32 is_send, uint32 inst_id, mes_priority_t priority)
{
    if (inst_id >= MES_MAX_INSTANCES || priority >= MES_PRIORITY_CEIL) {
        LOG_RUN_WAR("[mes] mes_destroy_message_pool invalid inst_id[%u] or priority[%u]", inst_id, priority);
        return;
    }
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_pool_t *msg_pool = mq_ctx->msg_pool[inst_id][priority];
    if (msg_pool == NULL) {
        return;
    }
    
    mes_free_message_pool(msg_pool);
    mq_ctx->msg_pool[inst_id][priority] = NULL;
}

char *mes_alloc_buf_item(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority)
{
    mes_buf_chunk_t *chunk = NULL;
    mes_buf_queue_t *queue = NULL;
    mes_buffer_item_t *buf_node = NULL;
    uint32 find_times = 0;

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[mes] mes_alloc_buf_item fail, phase %u", MES_GLOBAL_INST_MSG.mes_ctx.phase);
        return NULL;
    }

    chunk = mes_get_buffer_chunk(len, is_send, dst_inst, priority);
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
            CM_ASSERT(buf_node != NULL);
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

char *mes_alloc_buf_item_fc(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority)
{
    mes_buf_chunk_t *chunk = NULL;
    mes_buf_queue_t *queue = NULL;
    mes_buffer_item_t *buf_node = NULL;
    uint32 find_times = 0;

    chunk = mes_get_buffer_chunk(len, is_send, dst_inst, priority);
    if (chunk == NULL) {
        LOG_RUN_ERR("[mes]: Get buffer failed.");
        return NULL;
    }

    uint32_t count =
        MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].buf_attr[chunk->chunk_no].count / chunk->queue_num;

    do {
        queue = mes_get_buffer_queue(chunk);
        cm_spin_lock(&queue->lock, NULL);
        if (queue->count > 0 && count / queue->count <= RECV_MSG_POOL_FC_THRESHOLD) {
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

static void mes_release_buf_stat(uint32 cmd)
{
    if (g_mes_stat.mes_elapsed_switch) {
        cm_atomic32_dec(&(g_mes_stat.mes_command_stat[cmd].occupy_buf));
        mes_elapsed_stat(cmd, MES_TIME_PUT_BUF);
    }
    return;
}

void mes_free_buf_item(char *buffer)
{
    if (buffer == NULL) {
        return;
    }

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return;
    }

    mes_buffer_item_t *buf_item = (mes_buffer_item_t *)(buffer - MES_BUFFER_ITEM_SIZE);
    mes_chunk_info_t chunk_info = buf_item->chunk_info;
    mq_context_t *mq_ctx = chunk_info.is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_pool_t *msg_pool = mq_ctx->msg_pool[chunk_info.inst_id][chunk_info.priority];
    if (msg_pool == NULL) {
        return;
    }
    mes_buf_chunk_t *chunk = &msg_pool->chunk[chunk_info.chunk_no];
    if (chunk == NULL || chunk->queues == NULL) {
        return;
    }
    mes_buf_queue_t *queue = &chunk->queues[buf_item->queue_no];
    if (queue == NULL) {
        return;
    }

    cm_panic(queue->inited);

    uint32 cmd = 0;
    cm_spin_lock(&queue->lock, NULL);
    if (buffer == NULL) {
        cm_spin_unlock(&queue->lock);
        return;
    }
    if (queue->count > 0) {
        queue->last->next = buf_item;
        queue->last = buf_item;
    } else {
        queue->first = buf_item;
        queue->last = buf_item;
    }

    buf_item->next = NULL;
    queue->count++;
    cmd = ((mes_message_head_t *)buffer)->cmd;
    buffer = NULL;
    cm_spin_unlock(&queue->lock);
    mes_release_buf_stat(cmd);
    return;
}

uint32 mes_get_priority_max_msg_size(mes_priority_t priority)
{
    uint32 max_size = 0;
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].pool_count; i++) {
        if (max_size < MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].buf_attr[i].size) {
            max_size = MES_GLOBAL_INST_MSG.profile.buffer_pool_attr[priority].buf_attr[i].size;
        }
    }
    return max_size;
}