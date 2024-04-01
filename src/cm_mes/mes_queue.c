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
#include "mes_interface.h"
#include "mec_adapter.h"
#include "cm_hash.h"

typedef struct st_mes_compress_ctx_t {
    compress_t *compress_ctx[COMPRESS_CEIL];
    compress_t *decompress_ctx[COMPRESS_CEIL];
} mes_compress_ctx_t;

void destroy_compress_ctx(void *compress_ctx)
{
    if (compress_ctx != NULL) {
        mes_compress_ctx_t *ctx = (mes_compress_ctx_t *)compress_ctx;
        for (int i = 0; i < COMPRESS_CEIL; i++) {
            if (ctx->compress_ctx[i] != NULL) {
                free_compress_ctx(ctx->compress_ctx[i]);
                CM_FREE_PROT_PTR(ctx->compress_ctx[i]);
            }
        }
        for (int i = 0; i < COMPRESS_CEIL; i++) {
            if (ctx->decompress_ctx[i] != NULL) {
                free_compress_ctx(ctx->decompress_ctx[i]);
                CM_FREE_PROT_PTR(ctx->decompress_ctx[i]);
            }
        }
        CM_FREE_PROT_PTR(ctx);
    }
}

#ifndef WIN32
static pthread_key_t g_compress_thread_key;

void delete_compress_thread_key(void)
{
    if (g_compress_thread_key == 0) {
        LOG_RUN_WAR("[mes] delete_compress_thread_key, thread key is 0");
        return;
    }

    (void)pthread_key_delete(g_compress_thread_key);
}

void create_compress_ctx()
{
    (void)pthread_key_create(&g_compress_thread_key, destroy_compress_ctx);
}

int get_mes_compress_ctx_core(mes_compress_ctx_t **ctx)
{
    *ctx = pthread_getspecific(g_compress_thread_key);
    if (*ctx == NULL) {
        *ctx = (mes_compress_ctx_t *)cm_malloc_prot(sizeof(mes_compress_ctx_t));
        if (*ctx == NULL) {
            return ERR_MES_MALLOC_FAIL;
        }
        errno_t ret = memset_sp(*ctx, sizeof(mes_compress_ctx_t), 0, sizeof(mes_compress_ctx_t));
        if (ret != EOK) {
            CM_FREE_PROT_PTR(*ctx);
            return CM_ERROR;
        }

        pthread_setspecific(g_compress_thread_key, *ctx);
    }

    return CM_SUCCESS;
}

static int get_compress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                            mes_priority_t priority)
{
    mes_compress_ctx_t *ctx = NULL;

    if (get_mes_compress_ctx_core(&ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] get_mes_compress_ctx_core failed.");
        return CM_ERROR;
    }

    if (ctx->compress_ctx[algorithm] == NULL || ctx->compress_ctx[algorithm]->level != compress_level ||
        (ctx->compress_ctx[algorithm]->frag_size + sizeof(mes_message_head_t)) !=
        mes_get_priority_max_msg_size(priority)) {
        LOG_DEBUG_INF("[mes] mes_create_compress_ctx, algorithm:%u, level:%u.", algorithm, compress_level);
        free_compress_ctx(ctx->compress_ctx[algorithm]);
        CM_FREE_PROT_PTR(ctx->compress_ctx[algorithm]);
        if (mes_create_compress_ctx(&ctx->compress_ctx[algorithm], algorithm, compress_level, priority) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[mes] mes_create_compress_ctx failed.");
            return CM_ERROR;
        }
    }
    *compress_ctx = ctx->compress_ctx[algorithm];

    LOG_DEBUG_INF("[mes] get_compress_ctx finish, in_buf_capacity=%d, algorithm:%d, level:%u.",
                  (int)(*compress_ctx)->in_buf_capacity, (int)(*compress_ctx)->algorithm, (*compress_ctx)->level);

    return CM_SUCCESS;
}

static int get_decompress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                              mes_priority_t priority)
{
    mes_compress_ctx_t *ctx = NULL;

    if (get_mes_compress_ctx_core(&ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] get_mes_compress_ctx_core failed.");
        return CM_ERROR;
    }

    if (ctx->decompress_ctx[algorithm] == NULL || ctx->decompress_ctx[algorithm]->level != compress_level ||
        (ctx->decompress_ctx[algorithm]->frag_size + sizeof(mes_message_head_t)) !=
        mes_get_priority_max_msg_size(priority)) {
        LOG_DEBUG_INF("[mes] mes_create_decompress_ctx, algorithm:%u, level:%u.", algorithm, compress_level);
        free_compress_ctx(ctx->decompress_ctx[algorithm]);
        CM_FREE_PROT_PTR(ctx->decompress_ctx[algorithm]);
        if (mes_create_decompress_ctx(&ctx->decompress_ctx[algorithm], algorithm, compress_level, priority) !=
            CM_SUCCESS) {
            LOG_DEBUG_ERR("[mes] mes_create_decompress_ctx failed.");
            return CM_ERROR;
        }
    }
    *compress_ctx = ctx->decompress_ctx[algorithm];

    LOG_DEBUG_INF("[mes] get_decompress_ctx finish, in_buf_capacity=%d, algorithm:%d, level:%u.",
                  (int)(*compress_ctx)->in_buf_capacity, (int)(*compress_ctx)->algorithm, (*compress_ctx)->level);

    return CM_SUCCESS;
}
#endif

static status_t mes_init_compress(compress_t *compress, compress_algorithm_t algorithm, uint32 compress_level,
                                  mes_priority_t priority)
{
    LOG_DEBUG_INF("[mes] mes_init_compress, algorithm=%u, level:%u.", algorithm, compress_level);
    if (algorithm == COMPRESS_NONE) {
        return CM_SUCCESS;
    }
    compress->algorithm = algorithm;
    compress->level = compress_level;
    compress->frag_size = mes_get_priority_max_msg_size(priority) - (unsigned int)sizeof(mes_message_head_t);
    compress->is_compress = CM_TRUE;
    if (cm_compress_alloc(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_compress_alloc_buff(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[mes] mes_init_compress finish, algorithm:%u, level:%u, in_buf_capacity=%d",
                  compress->algorithm, compress_level, (int)compress->in_buf_capacity);
    return CM_SUCCESS;
}

status_t mes_create_compress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                                 mes_priority_t priority)
{
    compress_t *temp = NULL;
    temp = (compress_t *)cm_malloc_prot(sizeof(compress_t));
    if (temp == NULL) {
        return CM_ERROR;
    }
    errno_t ret = memset_sp(temp, sizeof(compress_t), 0, sizeof(compress_t));
    if (ret != EOK) {
        CM_FREE_PROT_PTR(temp);
        return CM_ERROR;
    }
    if (mes_init_compress(temp, algorithm, compress_level, priority) != CM_SUCCESS) {
        free_compress_ctx(temp);
        CM_FREE_PROT_PTR(temp);
        return CM_ERROR;
    }
    *compress_ctx = temp;

    LOG_DEBUG_INF("[mes] mes_create_compress_ctx finish, algorithm:%u, level:%u, in_buf_capacity:%d.",
                  algorithm, compress_level, (int)(*compress_ctx)->in_buf_capacity);

    return CM_SUCCESS;
}

static status_t mes_init_decompress(compress_t *compress, compress_algorithm_t algorithm, uint32 compress_level,
                                    mes_priority_t priority)
{
    LOG_DEBUG_INF("[mes] mes_init_decompress, algorithm=%u, level:%u.", algorithm, compress_level);
    if (algorithm == COMPRESS_NONE) {
        return CM_SUCCESS;
    }
    compress->algorithm = algorithm;
    compress->level = compress_level;
    compress->frag_size = mes_get_priority_max_msg_size(priority) - (unsigned int)sizeof(mes_message_head_t);
    compress->is_compress = CM_FALSE;
    if (cm_compress_alloc(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (cm_compress_alloc_buff(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[mes] mes_init_decompress finish, algorithm:%u, level:%u, in_buf_capacity=%d",
                  compress->algorithm, compress_level, (int)compress->in_buf_capacity);
    return CM_SUCCESS;
}

int mes_create_decompress_ctx(compress_t **compress_ctx, compress_algorithm_t algorithm, uint32 compress_level,
                              mes_priority_t priority)
{
    compress_t *temp = NULL;
    temp = (compress_t *)cm_malloc_prot(sizeof(compress_t));
    if (temp == NULL) {
        return CM_ERROR;
    }
    errno_t ret = memset_sp(temp, sizeof(compress_t), 0, sizeof(compress_t));
    if (ret != EOK) {
        CM_FREE_PROT_PTR(temp);
        return CM_ERROR;
    }
    if (mes_init_decompress(temp, algorithm, compress_level, priority) != CM_SUCCESS) {
        free_compress_ctx(temp);
        CM_FREE_PROT_PTR(temp);
        return CM_ERROR;
    }
    *compress_ctx = temp;

    LOG_DEBUG_INF("[mes] mes_create_decompress_ctx finish, algorithm:%u, level:%u, in_buf_capacity:%d.",
                  algorithm, compress_level, (int)(*compress_ctx)->in_buf_capacity);

    return CM_SUCCESS;
}

status_t mes_compress_core(compress_t *compress_ctx, char *write_buf, size_t *write_buf_len)
{
    size_t buf_size = *write_buf_len;
    *write_buf_len = 0;

    /* 1) write frame header */
    if (cm_compress_begin(compress_ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] compress frame header failed");
        return CM_ERROR;
    }
    errno_t ret;
    if (compress_ctx->write_len > 0) {
        ret = memcpy_sp(write_buf, buf_size, compress_ctx->out_buf, compress_ctx->write_len);
        MEMS_RETURN_IFERR(ret);
    }

    /* 2) stream data */
    if (cm_compress_stream(compress_ctx, write_buf, buf_size) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] compress stream failed");
        return CM_ERROR;
    }
    size_t write_len = compress_ctx->write_len;

    /* 3) flush whatever remains within internal buffers */
    if (cm_compress_flush(compress_ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] compress flush remain data failed");
        return CM_ERROR;
    }
    if (compress_ctx->write_len - write_len > 0) {
        ret = memcpy_sp(write_buf + write_len, buf_size - write_len, compress_ctx->out_buf,
                        compress_ctx->write_len - write_len);
        MEMS_RETURN_IFERR(ret);
    }

    *write_buf_len = compress_ctx->write_len;
    return CM_SUCCESS;
}

static status_t mes_compress(compress_t *compress_ctx, mes_message_head_t *head)
{
    if (cm_compress_init(compress_ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }

    size_t len = head->size - sizeof(mes_message_head_t);
    CM_ASSERT(compress_ctx->in_buf_capacity >= len);
    errno_t ret = memcpy_sp(compress_ctx->in_buf, compress_ctx->in_buf_capacity, (void *)(head + 1), len);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    compress_ctx->in_chunk_size = len;
    char *write_buf = (char *)(head + 1);
    size_t buf_len = compress_ctx->frag_size;

    if (mes_compress_core(compress_ctx, write_buf, &buf_len) != CM_SUCCESS) {
        return CM_ERROR;
    }
    head->size = (uint32)(sizeof(mes_message_head_t) + buf_len);
    LOG_DEBUG_INF("[mes] compress finish, compress size=%u.", head->size);

    return CM_SUCCESS;
}

int mes_decompress_core(compress_t *compress_ctx, mes_message_head_t *head)
{
    if (cm_compress_init(compress_ctx) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] cm_compress_init failed");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[mes] mes_decompress_core, algorithm:%u, level:%u, in_buf_capacity=%d.",
                  compress_ctx->algorithm, compress_ctx->level, (int)(compress_ctx)->in_buf_capacity);

    compress_ctx->in_chunk_size = head->size - sizeof(mes_message_head_t);
    CM_ASSERT(compress_ctx->in_buf_capacity >= compress_ctx->in_chunk_size);
    errno_t ret = memcpy_sp(compress_ctx->in_buf, compress_ctx->in_buf_capacity, (char *)(head + 1),
                            compress_ctx->in_chunk_size);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        LOG_RUN_ERR("[mes] memcpy_sp failed, in_buf_capacity=%d, in_chunk_size=%d",
                    (int)compress_ctx->in_buf_capacity, (int)compress_ctx->in_chunk_size);
        return CM_ERROR;
    }

    size_t buf_len = compress_ctx->frag_size;
    if (cm_decompress_stream(compress_ctx, (char *)(head + 1), &buf_len) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] cm_decompress_stream failed:buf_len=%zu", buf_len);
        return CM_ERROR;
    }

    head->size = (uint32)(buf_len + sizeof(mes_message_head_t));
    return CM_SUCCESS;
}

int mes_decompress(mes_message_t *msg)
{
    mes_message_head_t *head = msg->head;
    compress_algorithm_t algorithm = MES_COMPRESS_ALGORITHM(head->flags);
    uint32 level = MES_COMPRESS_LEVEL(head->flags);
    mes_priority_t priority = MES_PRIORITY(head->flags);
    LOG_DEBUG_INF("[mes] mes_decompress, src_inst:%u, dst_inst:%u, compress algorithm:%u, compress level:%u, size:%u, "
                  "priority:%u",
                  head->src_inst, head->dst_inst, algorithm, level, head->size, priority);

    if (!MES_COMPRESS_ALGORITHM(head->flags) || head->size == MES_MSG_HEAD_SIZE) {
        return CM_SUCCESS;
    }

    if (algorithm >= COMPRESS_CEIL) {
        return CM_ERROR;
    }

    if (level < MES_DEFAULT_COMPRESS_LEVEL || level > MES_MAX_COMPRESS_LEVEL) {
        return CM_ERROR;
    }

    compress_t *compress_ctx = NULL;
#ifndef WIN32
    if (get_decompress_ctx(&compress_ctx, algorithm, level, priority) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] get_decompress_ctx failed.");
        return CM_ERROR;
    }
#else
    if (mes_create_decompress_ctx(&compress_ctx, algorithm, level, priority) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_create_decompress_ctx failed.");
        return CM_ERROR;
    }
#endif

    if (mes_decompress_core(compress_ctx, head) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_decompress_core failed.");
        return CM_ERROR;
    }

#ifdef WIN32
    free_compress_ctx(compress_ctx);
    CM_FREE_PROT_PTR(compress_ctx);
#endif

    MES_MESSAGE_ATTACH(msg, msg->buffer);

    LOG_DEBUG_INF("[mes] mes_decompress finish, size:%u, algorithm:%u, level:%u.", head->size, algorithm, level);
    return CM_SUCCESS;
}

static int mes_alloc_msgitems_by_freelist(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
{
    uint32 size = MIN(pool->free_list.count, MSG_ITEM_BATCH_SIZE);
    msgitems->first = pool->free_list.first;
    for (uint32 loop = 0; loop < size - 1; loop++) {
        pool->free_list.first = pool->free_list.first->next;
    }
    msgitems->last = pool->free_list.first;
    pool->free_list.first = pool->free_list.first->next;
    msgitems->last->next = NULL;
    msgitems->count = size;

    pool->free_list.count -= size;
    if (pool->free_list.count == 0) {
        pool->free_list.last = NULL;
        pool->free_list.first = NULL;
    }
    return CM_SUCCESS;
}

int mes_alloc_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
{
    if (pool->free_list.count > 0) {
        cm_spin_lock(&pool->free_list.lock, NULL);
        if (pool->free_list.count > 0) {
            (void)mes_alloc_msgitems_by_freelist(pool, msgitems);
            cm_spin_unlock(&pool->free_list.lock);
            return CM_SUCCESS;
        }
        cm_spin_unlock(&pool->free_list.lock);
    }

    mes_msgitem_t *item = NULL;
    cm_spin_lock(&pool->lock, NULL);
    if (pool->buf_idx == CM_INVALID_ID16 || pool->hwm >= INIT_MSGITEM_BUFFER_SIZE) {
        pool->buf_idx++;
        if (pool->buf_idx >= MAX_POOL_BUFFER_COUNT) {
            cm_spin_unlock(&pool->lock);
            LOG_RUN_ERR("[mes] pool->buf_idx exceed.");
            return ERR_MES_BUF_ID_EXCEED;
        }
        pool->hwm = 0;
        uint32 size = INIT_MSGITEM_BUFFER_SIZE * (uint32)sizeof(mes_msgitem_t);
        pool->buffer[pool->buf_idx] = (mes_msgitem_t *)cm_malloc_prot(size);
        if (pool->buffer[pool->buf_idx] == NULL) {
            cm_spin_unlock(&pool->lock);
            return ERR_MES_MALLOC_FAIL;
        }
        if (memset_sp(pool->buffer[pool->buf_idx], size, 0, size) != EOK) {
            CM_FREE_PROT_PTR(pool->buffer[pool->buf_idx]);
            cm_spin_unlock(&pool->lock);
            return CM_ERROR;
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
    item->next = NULL;
    msgitems->last = item;
    msgitems->count = MSG_ITEM_BATCH_SIZE;
    return CM_SUCCESS;
}

void mes_init_msgqueue(mes_msgqueue_t *queue)
{
    GS_INIT_SPIN_LOCK(queue->lock);
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
}

void mes_put_msgitem_nolock(mes_msgqueue_t *queue, mes_msgitem_t *msgitem)
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

mes_msgitem_t *mes_alloc_msgitem_nolock(mes_msgqueue_t *queue, bool32 is_send)
{
    mes_msgitem_t *result = NULL;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;

    if (queue->count == 0) {
        if (mes_alloc_msgitems(&mq_ctx->pool, queue) != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] alloc msg item failed");
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
        result->msg.head = NULL;
        result->msg.buffer = NULL;
    }
    return result;
}

mes_msgitem_t *mes_alloc_msgitem(mes_msgqueue_t *queue, bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgitem_t *item = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        if (mes_alloc_msgitems(&mq_ctx->pool, queue) != CM_SUCCESS) {
            cm_spin_unlock(&queue->lock);
            LOG_RUN_ERR("[mes] alloc inner msg item failed");
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
    item->msg.head = NULL;
    item->msg.buffer = NULL;
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
        CM_FREE_PROT_PTR(pool->buffer[i]);
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

mes_msgqueue_t *mes_get_task_queue(const mes_message_head_t *head, bool32 is_send, uint32 *work_index)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgqueue_t *queue = NULL;
    mes_task_priority_t *task_priority = &mq_ctx->priority.task_priority[MES_PRIORITY(head->flags)];
    uint32 inst_id = is_send ? head->dst_inst : head->src_inst;
    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
    bool32 need_serial = MES_GLOBAL_INST_MSG.profile.need_serial;
    uint32 shift_num = 24;

    if (task_priority->task_num < MES_MIN_TASK_NUM) {
        *work_index = CM_INVALID_ID32;
        LOG_RUN_ERR("[mes] get task queue failed, invalid task num, priority:%u", MES_PRIORITY(head->flags));
        return NULL;
    }

    if (need_serial) {
        *work_index = cm_hash_uint32((inst_id & 0xFFFFFF) | (channel_id << shift_num), task_priority->task_num) +
                task_priority->start_task_idx;
    } else {
        uint32 queue_num = task_priority->task_num > MES_PRIORITY_TASK_QUEUE_NUM ?
                MES_PRIORITY_TASK_QUEUE_NUM : task_priority->task_num;
        if (!is_send) {
            *work_index = (task_priority->push_cursor++) % queue_num + task_priority->start_task_idx;
        } else {
            *work_index = cm_hash_uint32(((head->caller_tid + inst_id) & 0xFFFFFF) | (channel_id << shift_num),
                                         queue_num) +
                          task_priority->start_task_idx;
        }
    }
    queue = &mq_ctx->tasks[*work_index].queue;
    return queue;
}

void mes_put_msgitem_enqueue(mes_msgitem_t *msgitem, bool32 is_send, uint32 *work_index)
{
    mes_msgqueue_t *queue;

    queue = mes_get_task_queue(msgitem->msg.head, is_send, work_index);
    if (queue == NULL || *work_index == CM_INVALID_ID32 || *work_index >= MES_MAX_TASK_NUM) {
        return;
    }

    CM_MFENCE;
    mes_put_msgitem(queue, msgitem);

    return;
}

static status_t mes_send_compress(mes_message_head_t *head)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    uint8 enable_compress_priority = profile->enable_compress_priority;
    uint8 priority = (uint8)MES_PRIORITY(head->flags);
    compress_algorithm_t algorithm = profile->algorithm;
    LOG_DEBUG_INF("[mes] mes_send_compress, src_inst:%u, dst_inst:%u, flags:%u, priority:%u, compress algorithm:%u, "
                  "size:%u, enable_compress_priority:%u",
                  head->src_inst, head->dst_inst, head->flags, priority, algorithm, head->size,
                  enable_compress_priority);

    if (!cm_bitmap8_exist(&enable_compress_priority, priority) || algorithm == COMPRESS_NONE ||
        algorithm >= COMPRESS_CEIL || head->size == MES_MSG_HEAD_SIZE) {
        return CM_SUCCESS;
    }

    compress_t *compress_ctx = NULL;
    uint32 level = profile->compress_level;

#ifndef WIN32
    if (get_compress_ctx(&compress_ctx, algorithm, level, priority) != CM_SUCCESS) {
        return CM_ERROR;
    }
#else
    if (mes_create_compress_ctx(&compress_ctx, algorithm, level, priority) != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif

    MES_SET_COMPRESS_ALGORITHM_FLAG(head->flags, algorithm);
    MES_SET_COMPRESS_LEVEL_FLAG(head->flags, level);
    status_t status = mes_compress(compress_ctx, head);
#ifdef WIN32
    free_compress_ctx(compress_ctx);
    CM_FREE_PROT_PTR(compress_ctx);
#endif

    LOG_DEBUG_INF("[mes] mes_send_compress, src_inst[%u] to dst_inst[%u], flags:%u, priority:%u, size:%u, "
                  "algorithm:%u, level:%u.",
                  head->src_inst, head->dst_inst, head->flags, priority, head->size, compress_ctx->algorithm,
                  compress_ctx->level);
    return status;
}

int mes_put_msg_queue(mes_message_t *msg, bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgitem_t *msgitem = NULL;
    mes_msgqueue_t *my_queue = NULL;
    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(msg->head->caller_tid);

    if (is_send) {
        if (mes_send_compress(msg->head) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[mes] mes compress failed, msg len[%u], src inst[%d], dst inst[%d], cmd[%u], flag[%u]",
                          msg->head->size, msg->head->src_inst, msg->head->dst_inst, msg->head->cmd, msg->head->flags);
            return CM_ERROR;
        }
    }

    if (MES_GLOBAL_INST_MSG.profile.send_directly && is_send) {
        LOG_DEBUG_INF("[mes] send msg directly, msg len[%u], src inst[%d], dst inst[%d], cmd[%u], flag[%u]",
                      msg->head->size, msg->head->src_inst, msg->head->dst_inst, msg->head->cmd, msg->head->flags);
        return MES_SEND_DATA(msg->buffer);
    }

    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[msg->head->dst_inst][channel_id];
    mes_priority_t priority = MES_PRIORITY(msg->head->flags);
    mes_pipe_t *pipe = &channel->pipe[priority];
    if (is_send && !pipe->send_pipe_active) {
        LOG_RUN_ERR("[mes] mes send data to dst_inst[%u] priority[%u] is not ready.", msg->head->dst_inst, priority);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    uint32 inst_id = is_send ? msg->head->dst_inst : msg->head->src_inst;
    my_queue = &mq_ctx->channel_private_queue[inst_id][channel_id];
    msgitem = mes_alloc_msgitem(my_queue, is_send);
    if (msgitem == NULL) {
        LOG_RUN_ERR("[mes] mes_alloc_msgitem failed.");
        return ERR_MES_ALLOC_MSGITEM_FAIL;
    }

    mes_local_stat(msg->head->cmd);
    msgitem->msg.head = msg->head;
    msgitem->msg.buffer = msg->buffer;
    msgitem->enqueue_time = g_timer()->now;

    if (!is_send && ENABLE_MES_TASK_THREADPOOL) {
        mes_put_msgitem_to_threadpool(msgitem);
        return CM_SUCCESS;
    }

    uint32 work_index = 0;
    mes_put_msgitem_enqueue(msgitem, is_send, &work_index);
    if (work_index == CM_INVALID_ID32 || work_index >= MES_MAX_TASK_NUM) {
        LOG_RUN_ERR("[mes] work index invalid.");
        return CM_ERROR;
    }

    // need_serial = CM_TRUE, will start task dynamically
    // else will event notify
    return mes_start_task_dynamically(is_send, work_index);
}

mes_task_priority_t *mes_get_task_priority(uint32 task_index, bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_task_priority_t *task_priority = NULL;

    for (uint32 i = 0; i < MES_PRIORITY_CEIL; i++) {
        task_priority = &mq_ctx->priority.task_priority[i];
        if (task_priority == NULL) {
            return NULL;
        }
        if (task_index < ((uint32)task_priority->start_task_idx + task_priority->task_num)) {
            return task_priority;
        }
    }
    return NULL;
}

mes_msgitem_t *mes_get_msgitem(mes_msgqueue_t *queue)
{
    mes_msgitem_t *ret = NULL;

    if (queue->count == 0) {
        return NULL;
    }

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        return NULL;
    }

    ret = queue->first;
    queue->count--;
    if (queue->count == 0) {
        queue->first = NULL;
        queue->last = NULL;
    } else {
        queue->first = ret->next;
    }
    CM_MFENCE;
    cm_spin_unlock(&queue->lock);
    return ret;
}

void mes_free_msgitems(mes_msgitem_pool_t *pool, mes_msgqueue_t *msgitems)
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

void mes_send_proc(mes_msgitem_t *msgitem, uint32 work_idx)
{
    mes_message_head_t *head = msgitem->msg.head;
    int ret = MES_SEND_DATA(msgitem->msg.buffer);
    if (ret != 0) {
        LOG_RUN_ERR("[mes] mes_send_proc failed, cmd=%hhu, ruid=%llu, ruid->rid=%llu, ruid->rsn=%llu, src_inst=%u, "
                    "dst_inst=%u, size=%u, flag=%u, index=%u",
                    (head)->cmd, (uint64)head->ruid, (uint64)MES_RUID_GET_RID((head)->ruid),
                    (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size,
                    (head)->flags, work_idx);
    }

    mes_free_buf_item(msgitem->msg.buffer);
}

void mes_work_proc(mes_msgitem_t *msgitem, uint32 work_idx)
{
    mes_msg_t app_msg;
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    if (msgitem->msg.head->cmd == MES_CMD_SYNCH_ACK) {
        mes_notify_msg_recv(&msgitem->msg);
    } else {
        mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_GET_QUEUE, start_stat_time);
        mes_get_consume_time_start(&start_stat_time);
        app_msg.buffer = msgitem->msg.buffer + sizeof(mes_message_head_t);
        app_msg.size = msgitem->msg.head->size - (unsigned int)sizeof(mes_message_head_t);
        app_msg.src_inst = (unsigned int)msgitem->msg.head->src_inst;
        MES_GLOBAL_INST_MSG.proc(work_idx, msgitem->msg.head->ruid, &app_msg);

        mes_consume_with_time(msgitem->msg.head->cmd, MES_TIME_QUEUE_PROC, start_stat_time);
        mes_release_message_buf(&msgitem->msg);
    }
}

static bool32 mes_is_empty_queue_count(const mq_context_t *mq_ctx, mes_priority_t priority)
{
    const mes_task_priority_t *task_priority = &mq_ctx->priority.task_priority[priority];
    uint32 start_task_index = task_priority->start_task_idx;
    uint32 queue_num = task_priority->task_num > MES_PRIORITY_TASK_QUEUE_NUM ?
                       MES_PRIORITY_TASK_QUEUE_NUM : task_priority->task_num;
    uint32 end_task_index = start_task_index + queue_num;
    for (uint32 i = start_task_index; i < end_task_index; i++) {
        if (mq_ctx->tasks[i].queue.count > 0) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

void mes_task_proc(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    task_arg_t *arg = (task_arg_t *)thread->argument;
    uint32 my_task_index = arg->index;
    bool32 is_send = arg->is_send;
    mq_context_t *mq_ctx = arg->mq_ctx;
    mes_msgqueue_t finished_msgitem_queue;
    mes_msgitem_t *msgitem;
    mes_init_msgqueue(&finished_msgitem_queue);
    mes_msgqueue_t *my_queue = &mq_ctx->tasks[my_task_index].queue;
    mes_context_t *mes_ctx = (mes_context_t *)mq_ctx->mes_ctx;

    if (is_send) {
        PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_sender_%u", my_task_index));
    } else {
        PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_worker_%u", my_task_index));
    }
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (!is_send && cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_RUN_INF("[mes] mes_task_proc thread init callback: cb_thread_init done");
    }

    mes_task_priority_t *task_priority = mes_get_task_priority(my_task_index, is_send);
    mes_priority_t priority = task_priority->priority;
    bool32 need_serial = MES_GLOBAL_INST_MSG.profile.need_serial;
    uint32 start_task_idx = task_priority->start_task_idx;
    uint32 task_num = task_priority->task_num;
    uint32 loop = 0;
    uint32 queue_id = 0;
    bool32 is_empty = CM_FALSE;
    uint32 queue_num = task_num > MES_PRIORITY_TASK_QUEUE_NUM ? MES_PRIORITY_TASK_QUEUE_NUM : task_num;
    while (!thread->closed && mes_ctx->phase == SHUTDOWN_PHASE_NOT_BEGIN) {
        is_empty = mes_is_empty_queue_count(mq_ctx, priority);
        if (is_empty) {
            if (cm_event_timedwait(&arg->event, CM_SLEEP_1_FIXED) != CM_SUCCESS) {
                continue;
            }
        }

        if (!need_serial) {
            queue_id = task_priority->pop_cursor % queue_num;
            msgitem = mes_get_msgitem(&mq_ctx->tasks[queue_id + start_task_idx].queue);
            for (loop = 0; msgitem == NULL && loop < queue_num; loop++) {
                queue_id = (queue_id + 1) % queue_num;
                msgitem = mes_get_msgitem(&mq_ctx->tasks[queue_id + start_task_idx].queue);
            }
        } else {
            msgitem = mes_get_msgitem(my_queue);
        }

        if (msgitem == NULL) {
            continue;
        }
        task_priority->pop_cursor = queue_id + 1;
        mes_message_head_t *head = msgitem->msg.head;
        LOG_DEBUG_INF("[mes] mes_task_proc, cmd=%u, is_send=%u, ruid=%llu, ruid->rid=%llu, ruid->rsn=%llu, "
                      "src_inst=%u, dst_inst=%u, size=%u, flag=%u, index=%u, queue_count=%u, is_empty=%u",
                      (head)->cmd, is_send, (uint64)head->ruid, (uint64)MES_RUID_GET_RID((head)->ruid),
                      (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size,
                      (head)->flags, my_task_index, mq_ctx->tasks[queue_id + start_task_idx].queue.count, is_empty);
        if ((g_timer()->now - msgitem->enqueue_time) / MICROSECS_PER_MILLISEC >= MES_MSG_QUEUE_DISCARD_TIMEOUT) {
            LOG_DEBUG_WAR("[mes]proc wait timeout, message is discarded ");
            mes_release_message_buf(&msgitem->msg);
            continue;
        }
        if (is_send) {
            mes_send_proc(msgitem, my_task_index);
        } else {
            mes_work_proc(msgitem, my_task_index);
        }

        mes_put_msgitem_nolock(&finished_msgitem_queue, msgitem);
        if (MSG_ITEM_BATCH_SIZE == finished_msgitem_queue.count) {
            mes_free_msgitems(&mq_ctx->pool, &finished_msgitem_queue);
        }
    }

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (!is_send && cb_thread_deinit != NULL) {
        cb_thread_deinit();
        LOG_RUN_INF("[mes] mes_task_proc thread deinit callback: cb_thread_deinit done");
    }
    LOG_RUN_INF("[mes] work thread closed, tid:%lu, close:%u", thread->id, thread->closed);
}

status_t mes_start_task_dynamically(bool32 is_send, uint32 index)
{
    if (!is_send && ENABLE_MES_TASK_THREADPOOL) {
        return CM_SUCCESS;
    }
    
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    bool32 need_serial = MES_GLOBAL_INST_MSG.profile.need_serial;
    if (need_serial && !mq_ctx->work_thread_idx[index].is_start) {
        cm_spin_lock(&mq_ctx->work_thread_idx[index].lock, NULL);
        if (!mq_ctx->work_thread_idx[index].is_start) {
            if (cm_event_init(&mq_ctx->work_thread_idx[index].event) != CM_SUCCESS) {
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                LOG_RUN_ERR("[mes] create thread %u event failed, error code %d, is_send:%u.",
                            index, cm_get_os_error(), is_send);
                return CM_ERROR;
            }
            if (cm_create_thread(mes_task_proc, 0, (void *)&mq_ctx->work_thread_idx[index],
                                 &mq_ctx->tasks[index].thread) != CM_SUCCESS) {
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                LOG_RUN_ERR("[mes] create work thread %u failed, is_send:%u.", index, is_send);
                return CM_ERROR;
            }
            mq_ctx->work_thread_idx[index].is_start = CM_TRUE;
            LOG_RUN_INF("[mes] mes_start_task_dynamically, is_send:%u, index:%u", is_send, index);
        }
        cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
    }
    if (mq_ctx->work_thread_idx[index].is_start) {
        cm_event_notify(&mq_ctx->work_thread_idx[index].event);
    }
    return CM_SUCCESS;
}

status_t mes_alloc_channel_msg_queue(bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    uint32 alloc_size;
    char *temp_buf = NULL;
    uint32 i, j;
    mes_profile_t *profile = mq_ctx->profile;

    // alloc msgqueue
    alloc_size = (uint32)sizeof(mes_msgqueue_t *) * MES_MAX_INSTANCES +
            (uint32)sizeof(mes_msgqueue_t) * MES_MAX_INSTANCES * profile->channel_cnt;
    temp_buf = cm_malloc_prot(alloc_size);
    if (temp_buf == NULL) {
        CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "allocate mes_msgqueue_t failed, channel_num %u alloc size %u",
                          profile->channel_cnt, alloc_size);
        return CM_ERROR;
    }

    errno_t ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CM_FREE_PROT_PTR(temp_buf);
        return CM_ERROR;
    }

    mq_ctx->channel_private_queue = (mes_msgqueue_t **)temp_buf;
    temp_buf += (sizeof(mes_msgqueue_t *) * MES_MAX_INSTANCES);
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        mq_ctx->channel_private_queue[i] = (mes_msgqueue_t *)temp_buf;
        temp_buf += sizeof(mes_msgqueue_t) * profile->channel_cnt;
    }

    // init channel
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        for (j = 0; j < profile->channel_cnt; j++) {
            mes_init_msgqueue(&mq_ctx->channel_private_queue[i][j]);
        }
    }

    return CM_SUCCESS;
}

void mes_free_channel_msg_queue(bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    CM_FREE_PROT_PTR(mq_ctx->channel_private_queue);
}

int64 mes_get_mem_capacity_internal(mq_context_t *mq_ctx, mes_priority_t priority)
{
    if (mq_ctx == NULL) {
        return 0;
    }

    mes_profile_t *profile = mq_ctx->profile;
    mes_buffer_pool_attr_t buffer_pool_attr = profile->buffer_pool_attr[priority];

    int64 mem_capacity = 0;
    for (uint32 i = 0; i < buffer_pool_attr.pool_count; i++) {
        mes_buffer_attr_t buf_attr = buffer_pool_attr.buf_attr[i];
        mem_capacity += (buf_attr.count * buf_attr.size);
    }
    return mem_capacity;
}

long long mes_get_mem_capacity(bool8 is_send, mes_priority_t priority)
{
    if (SECUREC_UNLIKELY(priority >= MES_PRIORITY_CEIL)) {
        LOG_RUN_ERR("[mes] mes_get_mem_capacity invalid priority %u.", priority);
        return -1;
    }

    if (is_send) {
        return mes_get_mem_capacity_internal(&MES_GLOBAL_INST_MSG.send_mq, priority);
    }
    return mes_get_mem_capacity_internal(&MES_GLOBAL_INST_MSG.recv_mq, priority);
}

int mes_get_started_task_count(bool8 is_send)
{
    int count = 0;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    for (uint32 loop = 0; loop < mq_ctx->task_num; loop++) {
        if (mq_ctx->work_thread_idx[loop].is_start) {
            count++;
        }
    }
    return count;
}


int mes_put_buffer_list_queue(mes_bufflist_t *buff_list, bool32 is_send)
{
    int ret;
    char *buffer = NULL;
    uint32 pos = 0;
    uint32 total_len = 0;
    mes_message_head_t *head = (mes_message_head_t *)((void*)buff_list->buffers[0].buf);
    mes_priority_t priority = MES_PRIORITY(head->flags);
    uint8 enable_compress_priority = MES_GLOBAL_INST_MSG.profile.enable_compress_priority;
    bool32 send_directly = MES_GLOBAL_INST_MSG.profile.send_directly;
    compress_algorithm_t algorithm = MES_GLOBAL_INST_MSG.profile.algorithm;

    if (is_send && send_directly && (!cm_bitmap8_exist(&enable_compress_priority, priority) ||
        algorithm == COMPRESS_NONE || algorithm >= COMPRESS_CEIL || head->size == MES_MSG_HEAD_SIZE)) {
        return MES_SEND_BUFFLIST(buff_list);
    }

    total_len = head->size;
    if (is_send && cm_bitmap8_exist(&enable_compress_priority, priority) && algorithm > COMPRESS_NONE &&
        algorithm < COMPRESS_CEIL && head->size > MES_MSG_HEAD_SIZE) {
        // for compress reserved
        total_len += MES_BUFFER_RESV_SIZE;
    }

    inst_type inst_id = is_send ? head->dst_inst : head->src_inst;
    buffer = mes_alloc_buf_item(total_len, is_send, inst_id, priority);
    if (buffer == NULL) {
        LOG_DEBUG_ERR("[mes] mes_put_buffer_list_queue, alloc buf item failed, is_send:%u, src_inst:%u, dst_inst:%u, "
                      "priority:%u",
                      is_send, head->src_inst, head->dst_inst, priority);
        return ERR_MES_MALLOC_FAIL;
    }

    for (int i = 0; i < buff_list->cnt; i++) {
        ret = memcpy_s(buffer + pos, total_len - pos, buff_list->buffers[i].buf, buff_list->buffers[i].len);
        if (ret != EOK) {
            mes_free_buf_item(buffer);
            LOG_DEBUG_ERR("[mes] mes_put_buffer_list_queue, memcpy_s failed, is_send:%u, src_inst:%u, dst_inst:%u, "
                          "total_len:%u, priority:%u, ret:%d",
                          is_send, head->src_inst, head->dst_inst, total_len, priority, ret);
            return ERR_MES_MEMORY_COPY_FAIL;
        }
        pos += buff_list->buffers[i].len;
        if (total_len == pos) {
            break;
        }
    }

    mes_message_t msg;
    MES_MESSAGE_ATTACH(&msg, buffer);

    ret = mes_put_msg_queue(&msg, is_send);
    if (ret != CM_SUCCESS || (MES_GLOBAL_INST_MSG.profile.send_directly && is_send)) {
        mes_free_buf_item(buffer);
        return ret;
    }

    return ret;
}

status_t mes_check_send_head_info(const mes_message_head_t *head)
{
    if (SECUREC_UNLIKELY(head->size < sizeof(mes_message_head_t) ||
                         head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
        MES_LOG_ERR_HEAD_EX(head, "message head size invalid or message length excced");
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(head->dst_inst >= MES_MAX_INSTANCES || head->src_inst == head->dst_inst)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid instance id");
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(head->cmd >= MES_CMD_MAX)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid cmd");
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(MES_PRIORITY(head->flags) >= MES_PRIORITY_CEIL)) {
        MES_LOG_ERR_HEAD_EX(head, "invalid priority");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}