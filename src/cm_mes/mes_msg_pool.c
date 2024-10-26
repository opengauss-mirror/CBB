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

/*
 * introduction of msg pool.
 * when receive message, we need a buffer from receive msg pool to save message
 * so that the worker thread can process this message later.
 * when we enable send_directly and send message, we also need send msg pool to
 * find a buffer to save message so that the sender thread can send message later.
 * when we disable send_directly and send message, we do not need send msg pool
 * any more.
 *
 * 1.architecture
 * 1）use only single pool, not divived pool by instance
 * single_pool |--- buf_pool(buf1) |--- shared_pool
 *             |                   |--- private_pool |--- priority 0 pool
 *             |                                     |--- priority 1 pool
 *             |                                     |--- ...
 *             |
 *             |--- buf_pool(buf2) |--- shared_pool
 *             |                   |--- private_pool |--- priority 0 pool
 *             |                                     |--- priority 1 pool
 *             |                                     |--- ...
 *             |--- ...
 *
 * 2）enable inst dimension, divived pool by instance
 * inst_pool_set |---inst_pool(inst0) |--- buf_pool(buf0) |--- shared_pool
 *               |                    |                   |--- private_pool |--- priority 0 pool
 *               |                    |                                     |--- priority 1 pool
 *               |                    |                                     |--- ...
 *               |                    |
 *               |                    |--- buf_pool(buf1) ...
 *               |                    |--- ...
 *               |--- inst_pool(inst1) ....
 *
 * in order to unify the concept, we call single_pool and inst_pool msg_pool;
 * they use the same struct mes_msg_pool_t.
 *
 * 2.design concept
 * 1) priority pool has *appropriate amount* buffer, so most time we just use priority pool.
 *    these buffer only belong to this priority, can not used by other priority. we tag
 *    these buffer with *private*
 *      what is *appropriate amount* : 2 * worker-thread number
 *      the ability of process message depend of worker thread number and single message
 *      process time. under maximum load conditions, all the worker thread process together,
 *      we need at least worker-thread number buffer, consider proceess message need time
 *      and alloc-free competition problem, the number multiply 2
 *
 * 2) receive workload become bigger, if priority pool has no buffer, then we get buffer
 *    from shared pool. the buffer is tagged with shared.
 *    after the message proccessed and free this buffer, put this buffer to the priority
 *    pool. although the buffer is in priority pool, but it tag:shared not changed
 *
 * 3) because of some priority pool take up extra buffer (belong to shared pool), when
 *    receive other priority messages. the priority pool has not enough message, try to get
 *    buffer from shared_pool, however shared pool does not has enough buffer either.
 *    how to solve this problem
 *    1) receive thread need buffer to save message right now, so receive thread steal the
 *    buffer with *shared tag* from over-take priority pool.
 *    2) when shared pool available capacity touch the threshold (eg. 10% capacity), tag the
 *    buf_pool need recycle. when worker thread free buffer, find need-recycle tag and
 *    buffer tag is shared, put buffer backto shared pool until shared pool reach over
 *    threshold
 *
 * 3. how to find a buf_pool
 * *is_send* can distinguish send buffer_msg_pool and receive buffer_msg_pool
 * *enable_inst_dimension* can distinguish single_pool and inst_pool_set
 *      if enable_inst_dimension true, we also need *inst_id* to tell us which inst_pool
 * buf_pool_no or meessage len can find which buf_pool
 *
 * 4. alloc poilcy
 * find the correct buf_pool
 * 1) find buffer from priority_pool, if has return.
 * 2) find buffer from shared_pool, if has return.
 * 3) find buffer from other priority_pool,
 *      if buffer tagged with private, can not use this buffer, give back to priority_pool;
 *      if buffer tagged with shared, return
 * 4) wait and retry
 *
 * 5. free poilcy
 * 1) buffer tagged with private, give back to priority_pool.
 * 2) buffer tagged with shared, buf_pool need recycle, give back to shared_pool.
 * 3) buffer tagged with shared, no need recycle, put it into priority_pool.
 *
 */

#include "mes_msg_pool.h"
#include "mes_func.h"

#define RECV_MSG_POOL_FC_THRESHOLD 10
#define MSG_POOL_TEMP_STR_LEN 1000
#define MSG_POOL_SHORT_TEMP_STR_LEN 50
#define MSG_BUF_POOL_THRESHOLD_RATIO 0.1
#define MSG_PRIORITY_POOL_BUFFER_NUM_MAGNIFICATION 2

static int cmp_by_msg_buffer_pool_buf_size(const void *a, const void *b)
{
    mes_msg_buffer_pool_attr_t *mpa1 = (mes_msg_buffer_pool_attr_t*)a;
    mes_msg_buffer_pool_attr_t *mpa2 = (mes_msg_buffer_pool_attr_t*)b;
    return mpa1->buf_size - mpa2->buf_size;
}

static int mes_check_proportion_in_msg_pool_attr(mes_msg_pool_attr_t *msg_pool_attr)
{
    double actual_proportion = 0;
    for (uint8 buf_pool_no = 0; buf_pool_no < msg_pool_attr->buf_pool_count; buf_pool_no++) {
        if (msg_pool_attr->buf_pool_attr[buf_pool_no].proportion <= 0 ||
            msg_pool_attr->buf_pool_attr[buf_pool_no].proportion > 1) {
            LOG_RUN_ERR("[mes][msg pool] buf_pool_no:%u proportion:%f is not legal, legal scope is (0, 1]",
                buf_pool_no, msg_pool_attr->buf_pool_attr[buf_pool_no].proportion);
            return CM_ERROR;
        }
        actual_proportion += msg_pool_attr->buf_pool_attr[buf_pool_no].proportion;
    }

    if (fabs(actual_proportion - 1) > DBL_EPSILON) {
        LOG_RUN_ERR("[mes][msg pool] sum of proportion:%f, should be 1.",
            actual_proportion);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int mes_add_compress_size_in_check_msg_pool_attr(mes_profile_t *out_profile)
{
    bool8 add_compress_size[MES_MAX_BUFFPOOL_NUM] = { CM_FALSE };
    uint32 target_buf_size = 0;
    mes_msg_pool_attr_t *msg_pool_attr = &out_profile->msg_pool_attr;
    for (mes_priority_t prio = 0; prio < out_profile->priority_cnt; prio++) {
        if (msg_pool_attr->max_buf_size[prio] == 0) {
            LOG_RUN_ERR("[mes][msg pool] msg pool attribute has something wrong, "
                "priority:%u max buf size is zero.",
                prio);
            return CM_ERROR;
        }

        target_buf_size = msg_pool_attr->max_buf_size[prio] + sizeof(mes_message_head_t);
        bool8 find_target_buf = CM_FALSE;
        for (uint8 buf_pool_no = 0; buf_pool_no < msg_pool_attr->buf_pool_count; buf_pool_no++) {
            if (msg_pool_attr->buf_pool_attr[buf_pool_no].buf_size == target_buf_size) {
                if (!add_compress_size[buf_pool_no]) {
                    add_compress_size[buf_pool_no] = CM_TRUE;
                }
                find_target_buf = CM_TRUE;
            }
        }
        if (!find_target_buf) {
            LOG_RUN_ERR("[mes][msg pool] msg pool attribute has something wrong, "
                "priority:%u max buf size:%u can not find in msg pool attribute.",
                prio, msg_pool_attr->max_buf_size[prio]);
            return CM_ERROR;
        }
        msg_pool_attr->max_buf_size[prio] = target_buf_size + MES_BUFFER_RESV_SIZE;
    }

    for (uint8 buf_pool_no = 0; buf_pool_no < msg_pool_attr->buf_pool_count; buf_pool_no++) {
        if (add_compress_size[buf_pool_no]) {
            msg_pool_attr->buf_pool_attr[buf_pool_no].buf_size += MES_BUFFER_RESV_SIZE;
        }
    }
    return CM_SUCCESS;
}

int mes_check_msg_pool_attr(mes_profile_t *profile, mes_profile_t *out_profile, bool8 check_proportion,
    mes_msg_buffer_relation_t *buf_rel)
{
    int ret;
    mes_msg_pool_attr_t *input_msg_pool_attr = &profile->msg_pool_attr;
    mes_msg_pool_attr_t *msg_pool_attr = &out_profile->msg_pool_attr;
    *msg_pool_attr = *input_msg_pool_attr;
    if (msg_pool_attr->buf_pool_count == 0 || msg_pool_attr->buf_pool_count > MES_MAX_BUFFPOOL_NUM) {
        LOG_RUN_ERR("[mes][msg pool] buf_pool_count:%u is invalid, legal scope is [1, %u].",
            msg_pool_attr->buf_pool_count, MES_MAX_BUFFPOOL_NUM);
        return CM_ERROR;
    }

    if (buf_rel != NULL) {
        buf_rel->buf_count = msg_pool_attr->buf_pool_count;
    }

    if (check_proportion) {
        ret = mes_check_proportion_in_msg_pool_attr(msg_pool_attr);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }

    // add sizeof(mes_message_head_t)
    for (int buf_pool_no = 0; buf_pool_no < msg_pool_attr->buf_pool_count; buf_pool_no++) {
        mes_msg_buffer_pool_attr_t *buf_pool_attr = &msg_pool_attr->buf_pool_attr[buf_pool_no];
        if (buf_pool_attr->buf_size == 0) {
            LOG_RUN_ERR("[mes][msg pool] buf_pool_no:%u, buf_size should not be 0",
                buf_pool_no);
            return CM_ERROR;
        }

        if (buf_rel != NULL) {
            buf_rel->origin_buf_size[buf_pool_no] =
                msg_pool_attr->buf_pool_attr[buf_pool_no].buf_size;
        }
        buf_pool_attr->buf_size = buf_pool_attr->buf_size + sizeof(mes_message_head_t);
    
        for (mes_priority_t prio = 0; prio < profile->priority_cnt; prio++) {
            uint32 queue_num = buf_pool_attr->priority_pool_attr[prio].queue_num;
            if (queue_num == 0 || queue_num > MES_MAX_BUFFER_QUEUE_NUM) {
                LOG_RUN_ERR("[mes][msg pool] buf_pool_no:%u, priority:%u, "
                    "queue_num:%u is invalid, queue num legal scope is [1, %u].",
                    buf_pool_no, prio, queue_num, MES_MAX_BUFFER_QUEUE_NUM);
                return CM_ERROR;
            }
        }

        uint32 queue_num = buf_pool_attr->shared_pool_attr.queue_num;
        if (queue_num == 0 || queue_num > MES_MAX_BUFFER_QUEUE_NUM) {
            LOG_RUN_ERR("[mes][msg pool] buf_pool_no:%u, shared pool "
                "queue_num:%u is invalid, queue num legal scope is [1, %u].",
                buf_pool_no, queue_num, MES_MAX_BUFFER_QUEUE_NUM);
            return CM_ERROR;
        }
    }

    ret = mes_add_compress_size_in_check_msg_pool_attr(out_profile);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (buf_rel != NULL) {
        for (int buf_pool_no = 0; buf_pool_no < msg_pool_attr->buf_pool_count; buf_pool_no++) {
            buf_rel->changed_buf_size[buf_pool_no] =
                msg_pool_attr->buf_pool_attr[buf_pool_no].buf_size;
        }
    }

    // sort
    qsort(&msg_pool_attr->buf_pool_attr, msg_pool_attr->buf_pool_count, sizeof(mes_msg_buffer_pool_attr_t),
        cmp_by_msg_buffer_pool_buf_size);
    return CM_SUCCESS;
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

static void mes_init_msg_buffer_pool_queues(mes_msg_buffer_pool_t *buf_pool,
    bool8 is_shared, mes_priority_t priority, uint32 queue_num)
{
    mes_msg_buffer_inner_pool_t *inner_pool;
    if (is_shared) {
        inner_pool = &buf_pool->shared_pool;
    } else {
        inner_pool = &buf_pool->private_pool[priority];
    }

    for (int i = 0; i < queue_num; i++) {
        mes_buf_queue_t* queue = &inner_pool->queues[i];
        mes_init_buf_queue(queue);
        queue->queue_no = i;
        queue->buf_size = buf_pool->buf_size;
        queue->count = 0;
    }
}

static int mes_init_msg_shared_pool(mes_msg_buffer_pool_t *buf_pool, memory_chunk_t *mem_chunk,
    uint64 *actual_metadata_size, uint32 left_num)
{
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    mes_msg_buffer_pool_tag_t *pool_tag = &buf_pool->tag;
    uint8 buf_pool_no = pool_tag->buf_pool_no;
    uint32 shared_queue_num = mpa->buf_pool_attr[buf_pool_no].shared_pool_attr.queue_num;
    buf_pool->shared_pool.queue_num = shared_queue_num;
    mes_msg_buffer_inner_pool_t *shared_pool = &buf_pool->shared_pool;
    uint64 shared_queue_size = shared_queue_num * sizeof(mes_buf_queue_t);
    char* addr = cm_alloc_memory_from_chunk(mem_chunk, shared_queue_size);
    *actual_metadata_size += shared_queue_size;
    shared_pool->queues = (mes_buf_queue_t*)addr;
    int ret = memset_sp(shared_pool->queues, shared_queue_size, 0 , shared_queue_size);
    if (ret != EOK) {
        LOG_RUN_ERR("[mes][msg pool] init shared pool, memset_sp failed");
        return ret;
    }

    shared_pool->pop_cursor = 0;
    shared_pool->push_cursor = 0;
    mes_init_msg_buffer_pool_queues(buf_pool, CM_TRUE, 0, shared_queue_num);
    uint32 per_queue_buf_num = left_num / shared_queue_num;
    uint32 left_buf_num = left_num % shared_queue_num;
    for (int qn = 0; qn < shared_queue_num; qn++) {
        shared_pool->queues[qn].init_count = per_queue_buf_num;
        if (qn < left_buf_num) {
            shared_pool->queues[qn].init_count++;
        }
    }
    return CM_SUCCESS;
}

static int mes_init_msg_private_pool(mes_msg_buffer_pool_t *buf_pool, memory_chunk_t *mem_chunk,
    uint64* actual_metadata_size, uint32* alloc_buffer_num)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    *alloc_buffer_num = 0;
    mes_msg_buffer_pool_tag_t *pool_tag = &buf_pool->tag;
    uint8 buf_pool_no = buf_pool->tag.buf_pool_no;
    for (int prio = 0; prio < buf_pool->priority_cnt; prio++) {
        uint32 queue_num = mpa->buf_pool_attr[buf_pool_no].priority_pool_attr[prio].queue_num;
        mes_msg_buffer_inner_pool_t *prio_pool = &buf_pool->private_pool[prio];
        prio_pool->queue_num = queue_num;

        uint64 priority_queue_size = queue_num * sizeof(mes_buf_queue_t);
        char* addr = cm_alloc_memory_from_chunk(mem_chunk, priority_queue_size);
        *actual_metadata_size += priority_queue_size;
        prio_pool->queues = (mes_buf_queue_t*)addr;
        int ret = memset_sp(prio_pool->queues, priority_queue_size, 0, priority_queue_size);
        if (ret != EOK) {
            LOG_RUN_ERR("[mes][msg pool] init private pool, memset_sp failed");
            return ret;
        }
        mes_init_msg_buffer_pool_queues(buf_pool, CM_FALSE, prio, queue_num);

        prio_pool->pop_cursor = 0;
        uint32 prio_buf_num = 0;
        if (!pool_tag->is_send) {
            prio_buf_num = profile->work_task_count[prio] * MSG_PRIORITY_POOL_BUFFER_NUM_MAGNIFICATION;
        } else {
            prio_buf_num = profile->send_task_count[prio] * MSG_PRIORITY_POOL_BUFFER_NUM_MAGNIFICATION;
        }
        uint32 per_queue_buf_num = prio_buf_num / queue_num;
        uint32 left_buf_num = prio_buf_num % queue_num;
        for (int qn = 0; qn < queue_num; qn++) {
            prio_pool->queues[qn].init_count = per_queue_buf_num;
            if (qn < left_buf_num) {
                prio_pool->queues[qn].init_count++;
            }
        }
        prio_pool->push_cursor = left_buf_num;
        *alloc_buffer_num += prio_buf_num;
    }
    return CM_SUCCESS;
}

static int mes_init_msg_buffer_pool(uint8 buf_pool_no, memory_chunk_t *mem_chunk,
    mes_msg_buffer_pool_t** buf_pool_ptr, uint64 available_size,
    uint64 metadata_size, mes_msg_pool_tag_t *msg_pool_tag)
{
    uint64 actual_metadata_size = 0;
    char* addr = cm_alloc_memory_from_chunk(mem_chunk, sizeof(mes_msg_buffer_pool_t));
    actual_metadata_size += sizeof(mes_msg_buffer_pool_t);
    *buf_pool_ptr = (mes_msg_buffer_pool_t*)addr;
    mes_msg_buffer_pool_t *buf_pool = (mes_msg_buffer_pool_t*)addr;
    int ret = memset_sp(buf_pool, sizeof(mes_msg_buffer_pool_t), 0, sizeof(mes_msg_buffer_pool_t));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes][msg pool] init buf pool, memset_sp failed");
        return ret;
    }
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    mes_msg_buffer_pool_attr_t *buf_attr = &mpa->buf_pool_attr[buf_pool_no];
    
    buf_pool->tag.is_send = msg_pool_tag->is_send;
    buf_pool->tag.enable_inst_dimension = msg_pool_tag->enable_inst_dimension;
    buf_pool->tag.inst_id = msg_pool_tag->inst_id;
    buf_pool->tag.buf_pool_no = buf_pool_no;
    buf_pool->buf_size = buf_attr->buf_size;
    buf_pool->buf_num = available_size / (buf_attr->buf_size + sizeof(mes_buffer_item_t));
    buf_pool->priority_cnt = MES_GLOBAL_INST_MSG.profile.priority_cnt;
    
    uint32 alloc_buffer_num = 0;
    ret = mes_init_msg_private_pool(buf_pool, mem_chunk, &actual_metadata_size, &alloc_buffer_num);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (alloc_buffer_num > buf_pool->buf_num) {
        cm_panic_log(0, "[mes][msg pool] we already check pool whether enough and check pass, "
            "but now pool size is not enough. something unexpected happen, already alloc_buffer_num:%u, "
            "total num:%u",
            alloc_buffer_num, buf_pool->buf_num);
    }
    uint32 all_left_num = buf_pool->buf_num - alloc_buffer_num;
    ret = mes_init_msg_shared_pool(buf_pool, mem_chunk, &actual_metadata_size, all_left_num);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    CM_ASSERT(metadata_size == actual_metadata_size);
    buf_pool->mem_chunk.addr = cm_alloc_memory_from_chunk(mem_chunk, available_size);
    buf_pool->mem_chunk.offset = 0;
    buf_pool->mem_chunk.total_size = available_size;
    GS_INIT_SPIN_LOCK(buf_pool->mem_chunk_lock);
    buf_pool->pop_priority = 0;
    buf_pool->need_recycle = CM_FALSE;
    uint32 per_buf_count = buf_pool->shared_pool.queues[0].init_count;
    buf_pool->recycle_threshold = per_buf_count * MSG_BUF_POOL_THRESHOLD_RATIO;
    buf_pool->inited = CM_TRUE;
    LOG_DEBUG_INF("[mes][msg pool][buf pool] buf_pool_no:%d, buf_size:%u, buf_num:%u, "
        "buf_pool {metadata size:%llu, msg actual size:%llu}",
        buf_pool_no, buf_pool->buf_size, buf_pool->buf_num, metadata_size,
        available_size);
    return CM_SUCCESS;
}

static void mes_assemble_msg_pool_proportion_print_info_error_branch(char* buf)
{
    (void)snprintf_s(buf, MSG_POOL_TEMP_STR_LEN, MSG_POOL_TEMP_STR_LEN - 1,
        "%s", "assemble proportion info occur something wrong");
}

static void mes_assemble_msg_pool_proportion_print_info(char* buf)
{
    int ret;
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    for (uint8 i = 0; i < mpa->buf_pool_count; i++) {
        char temp_buf[MSG_POOL_SHORT_TEMP_STR_LEN] = { 0 };
        ret = snprintf_s(temp_buf, MSG_POOL_SHORT_TEMP_STR_LEN, MSG_POOL_SHORT_TEMP_STR_LEN - 1,
            "buf_pool_no:%u, proportion:%f;",
            i, mpa->buf_pool_attr[i].proportion);
        if (ret < 0) {
            mes_assemble_msg_pool_proportion_print_info_error_branch(buf);
            return;
        }
        ret = strcat_s(buf, MSG_POOL_TEMP_STR_LEN, temp_buf);
        if (ret != EOK) {
            mes_assemble_msg_pool_proportion_print_info_error_branch(buf);
            return;
        }
    }
}

static int mes_get_buffer_pool_minimum_size(mes_profile_t *profile, bool8 is_send,
    uint64 *buffer_pool_minimum_list)
{
    unsigned int all_task_count = 0;
    unsigned int *task_count = is_send ? profile->send_task_count : profile->work_task_count;

    for (int prio = 0; prio < profile->priority_cnt; prio++) {
        if (task_count[prio] > MES_MAX_TASK_NUM) {
            LOG_RUN_ERR("[mes][msg pool] %s thread count:%u, legal scope is [1, %u]",
                is_send ? "send" : "work",
                task_count[prio], MES_MAX_TASK_NUM);
            return CM_ERROR;
        }

        if (task_count[prio] == 0) {
            all_task_count += 1;
        } else {
            all_task_count += task_count[prio];
        }
    }

    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    for (int buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        uint32 buf_item_size = mpa->buf_pool_attr[buf_pool_no].buf_size + sizeof(mes_buffer_item_t);
        buffer_pool_minimum_list[buf_pool_no] = (uint64)buf_item_size *
            all_task_count * MSG_PRIORITY_POOL_BUFFER_NUM_MAGNIFICATION;
    }
    return CM_SUCCESS;
}

static uint64 mes_calculate_msg_pool_recommend_size(mes_msg_pool_attr_t *mpa, uint64 *buffer_pool_minimum_list,
    uint64 metadata_size)
{
    uint64 at_least_size = 0;
    uint64 tmp_size = 0;
    for (int buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        tmp_size = (uint64)((double)buffer_pool_minimum_list[buf_pool_no] /
            mpa->buf_pool_attr[buf_pool_no].proportion) + 1;
        if (tmp_size > at_least_size) {
            at_least_size = tmp_size;
        }
    }
    at_least_size += metadata_size;
    return at_least_size;
}

static int mes_check_msg_pool_size_whether_enough(bool8 is_send, uint64 metadata_size,
    uint64 pool_size, uint64 *recommend_size)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    if (pool_size < metadata_size) {
        LOG_RUN_ERR("[mes][msg pool] pool size is not enough. "
            "pool size is less than metadata size, pool_size:%llu, metadata_size:%llu.",
            pool_size, metadata_size);
        return CM_ERROR;
    }

    int ret = CM_SUCCESS;
    uint64 left_size = pool_size - metadata_size;
    uint64 buffer_pool_minimum_list[MES_MAX_BUFFPOOL_NUM] = { 0 };
    ret = mes_get_buffer_pool_minimum_size(profile, is_send, buffer_pool_minimum_list);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    for (int buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        uint64 actual_alloc = (uint64)(left_size * mpa->buf_pool_attr[buf_pool_no].proportion);
        if (actual_alloc < buffer_pool_minimum_list[buf_pool_no]) {
            ret = CM_ERROR;
            break;
        }
    }

    if (ret != CM_SUCCESS) {
        *recommend_size = mes_calculate_msg_pool_recommend_size(mpa, buffer_pool_minimum_list, metadata_size);
        return ret;
    }
    return ret;
}

static int mes_get_buffer_pool_metadata_size(mes_profile_t *profile, uint8 buf_pool_no)
{
    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    mes_msg_buffer_pool_attr_t *buf_attr = &mpa->buf_pool_attr[buf_pool_no];

    uint64 metadata_size = sizeof(mes_msg_buffer_pool_t);
    uint32 queue_num = 0;
    for (int i = 0; i < profile->priority_cnt; i++) {
        queue_num += buf_attr->priority_pool_attr[i].queue_num;
    }
    queue_num += buf_attr->shared_pool_attr.queue_num;
    metadata_size += queue_num * sizeof(mes_buf_queue_t);
    return metadata_size;
}

static uint64 mes_get_msg_pool_metadata_size(mes_profile_t *profile, uint64 *buf_pool_metadata)
{
    uint64 all_metadata_size = sizeof(mes_msg_pool_t);
    for (uint8 i = 0; i < profile->msg_pool_attr.buf_pool_count; i++) {
        uint64 buffer_pool_metadata = mes_get_buffer_pool_metadata_size(profile, i);
        buf_pool_metadata[i] = buffer_pool_metadata;
        all_metadata_size += buffer_pool_metadata;
    }
    return all_metadata_size;
}

int mes_init_msg_pool(mes_msg_pool_t **msg_pool_ptr, uint64 pool_size,
    mes_msg_pool_tag_t *tag)
{
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;

    char* addr = cm_malloc_prot(pool_size);
    if (addr == NULL) {
        LOG_RUN_ERR("[mes][msg pool] init msg pool, cm_malloc_prot failed");
        return CM_ERROR;
    }

    *msg_pool_ptr = (mes_msg_pool_t*)addr;
    mes_msg_pool_t *msg_pool = *msg_pool_ptr;
    int ret;
    ret = memset_sp(msg_pool, sizeof(mes_msg_pool_t), 0, sizeof(mes_msg_pool_t));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes][msg pool] init msg pool, memset_sp failed");
        return ret;
    }

    msg_pool->mem_chunk.addr = addr;
    msg_pool->mem_chunk.offset = sizeof(mes_msg_pool_t);
    msg_pool->mem_chunk.total_size = pool_size;
    msg_pool->tag = *tag;
    msg_pool->size = pool_size;
    msg_pool->buf_pool_count = mpa->buf_pool_count;
    uint64 metadata_size[MES_MAX_BUFFPOOL_NUM] = { 0 };
    uint64 all_metadata_size = mes_get_msg_pool_metadata_size(&MES_GLOBAL_INST_MSG.profile, metadata_size);

    uint64 all_left_size = pool_size - all_metadata_size;
    uint64 left_size = all_left_size;
    uint64 allowed_size = 0;
    for (uint8 buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        if (buf_pool_no == mpa->buf_pool_count - 1) {
            allowed_size = left_size; // reduce waste
        } else {
            allowed_size = all_left_size * mpa->buf_pool_attr[buf_pool_no].proportion;
        }
        uint32 buf_item_size = mpa->buf_pool_attr[buf_pool_no].buf_size + sizeof(mes_buffer_item_t);
        allowed_size = allowed_size - (allowed_size % buf_item_size);
        ret = mes_init_msg_buffer_pool(buf_pool_no, &msg_pool->mem_chunk, &msg_pool->buf_pool[buf_pool_no],
            allowed_size, metadata_size[buf_pool_no], &msg_pool->tag);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] init buf pool failed, buf_pool_no:%u",
                buf_pool_no);
            return ret;
        }
        left_size = left_size - allowed_size;
        msg_pool->buf_pool[buf_pool_no]->msg_pool = msg_pool;
    }
    return CM_SUCCESS;
}

void mes_deinit_msg_pool(mes_msg_pool_t **msg_pool)
{
    if (*msg_pool == NULL) {
        return;
    }
    cm_free_prot(*msg_pool);
    *msg_pool = NULL;
}

int mes_init_msg_single_pool(bool8 is_send)
{
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msg_pool_tag_t tag = {
        .is_send = is_send,
        .enable_inst_dimension = CM_FALSE,
        .inst_id = 0,
    };
    LOG_DEBUG_INF("[mes][msg pool] init single pool, is_send:%u", is_send);
    int ret = mes_init_msg_pool(&mq_ctx->single_pool, mpa->total_size, &tag);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes][msg pool] init single pool failed, is_send:%u", is_send);
        mes_deinit_msg_pool(&mq_ctx->single_pool);
        return ret;
    }
    LOG_DEBUG_INF("[mes][msg pool] init single pool success, is_send:%u", is_send);
    return ret;
}

int mes_init_msg_inst_pool_set(bool8 is_send)
{
    int ret = CM_SUCCESS;
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msg_pool_attr_t *mpa = &MES_GLOBAL_INST_MSG.profile.msg_pool_attr;
    mes_msg_inst_pool_set_t *pool_set = &mq_ctx->inst_pool_set;

    if (is_send) {
        pool_set->inst_pool_count = profile->inst_cnt - 1;
    } else {
        pool_set->inst_pool_count = profile->inst_cnt;
    }

    if (pool_set->inst_pool_count == 0 ) {
        pool_set->total_size = 0;
        pool_set->per_inst_pool_size = mpa->total_size;
        CM_ASSERT(is_send);
        LOG_DEBUG_INF("[mes][msg pool] init instance pool set, send message pool no need init, inst_cnt:%u",
            profile->inst_cnt);
        return CM_SUCCESS;
    } else {
        pool_set->total_size = mpa->total_size;
        pool_set->per_inst_pool_size = pool_set->total_size / pool_set->inst_pool_count;
    }

    int sz = sizeof(bool8) * MES_MAX_INSTANCES;
    ret = memset_sp(pool_set->inst_pool_inited, sz, 0, sz);
    if (ret != EOK) {
        LOG_RUN_ERR("[mes][msg pool] init inst pool set, memset_sp failed");
        return ret;
    }

    LOG_DEBUG_INF("[mes][msg pool] init instance pool set, is_send:%u", is_send);
    for (uint8 inst_id = 0; inst_id < pool_set->inst_pool_count; inst_id++) {
        if (is_send && inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
            pool_set->inst_pool[inst_id] = NULL;
            continue;
        }

        mes_msg_pool_tag_t tag = {
            .is_send = is_send,
            .enable_inst_dimension = CM_TRUE,
            .inst_id = inst_id,
        };
        LOG_DEBUG_INF("[mes][msg pool] init instance pool, inst_id:%u, is_send:%u",
            inst_id, is_send);
        ret = mes_init_msg_pool(&pool_set->inst_pool[inst_id], pool_set->per_inst_pool_size, &tag);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] init instance pool failed, inst_id:%u, is_send:%u",
                inst_id, is_send);
            for (int i = inst_id; i >= 0; i--) {
                mes_deinit_msg_pool(&pool_set->inst_pool[i]);
            }
            return ret;
        }
        LOG_DEBUG_INF("[mes][msg pool] init instance pool success, inst_id:%u, is_send:%u",
            inst_id, is_send);
        pool_set->inst_pool_inited[inst_id] = CM_TRUE;
    }
    return ret;
}

int mes_init_message_pool(bool8 is_send)
{
    int ret = CM_SUCCESS;
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;

    cm_spin_lock(&mq_ctx->msg_pool_init_lock, NULL);
    if (mq_ctx->msg_pool_inited) {
        cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
        LOG_DEBUG_INF("[mes][msg pool] no need to reinit message pool, already inited.");
        return CM_SUCCESS;
    }

    if (is_send && profile->send_directly &&
        (profile->enable_compress_priority == 0 || profile->algorithm == COMPRESS_NONE ||
        profile->algorithm >= COMPRESS_CEIL)) {
        // send_directly and disable compress
        cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
        LOG_RUN_INF("[mes][msg pool] no need to init send message pool, cause send directly and compress disable.");
        return CM_SUCCESS;
    }

    if (!mq_ctx->enable_inst_dimension) {
        ret = mes_init_msg_single_pool(is_send);
    } else {
        ret = mes_init_msg_inst_pool_set(is_send);
    }
    mq_ctx->msg_pool_inited = CM_TRUE;
    cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
    return ret;
}

void mes_deinit_message_pool(mq_context_t *mq_ctx)
{
    cm_spin_lock(&mq_ctx->msg_pool_init_lock, NULL);
    if (!mq_ctx->enable_inst_dimension) {
        mes_deinit_msg_pool(&mq_ctx->single_pool);
    } else {
        mes_msg_inst_pool_set_t *set = &mq_ctx->inst_pool_set;
        for (int i = 0; i < set->inst_pool_count; i++) {
            mes_deinit_msg_pool(&set->inst_pool[i]);
        }
    }
    mq_ctx->msg_pool_inited = CM_FALSE;
    cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
}

void mes_deinit_all_message_pool()
{
    mes_deinit_message_pool(&MES_GLOBAL_INST_MSG.send_mq);
    mes_deinit_message_pool(&MES_GLOBAL_INST_MSG.recv_mq);
}

mes_buffer_item_t* mes_get_buf_item_from_queue(mes_buf_queue_t *queue, uint32 *count)
{
    mes_buffer_item_t *buf_item = NULL;
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        buf_item = queue->first;
        queue->count--;
        if (queue->count == 0) {
            queue->first = NULL;
            queue->last = NULL;
        } else {
            queue->first = buf_item->next;
            CM_ASSERT(queue->first != NULL);
        }
        CM_ASSERT(buf_item != NULL);
        buf_item->next = NULL;
        cm_panic_log(buf_item->inqueue == CM_TRUE, "buf_item:%p should in queue but not. inqueue:%u. "
            "possible reason: thread1 repeat put same buffer to different queue concurrently, thread2 already "
            "get buffer from anthor queue, so this time buffer indicate not in queue.",
            buf_item, buf_item->inqueue);
        buf_item->inqueue = CM_FALSE;
    }

    if (count != NULL) {
        *count = queue->count;
    }
    cm_spin_unlock(&queue->lock);
    return buf_item;
}

static void mes_put_buf_item_to_queue(mes_buffer_item_t *buf_item, mes_buf_queue_t *queue,
    uint32 *count)
{
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count > 0) {
        queue->last->next = buf_item;
        queue->last = buf_item;
    } else {
        queue->first = buf_item;
        queue->last = buf_item;
    }
    buf_item->next = NULL;
    cm_panic_log(buf_item->inqueue == CM_FALSE, "buf_item:%p should not in queue but in. inqueue:%u. "
        "possible reason: thread repeat call mes_free_buf_item function with same buffer lead to repeat "
        "put buffer to queue, this is not allowed.",
        buf_item, buf_item->inqueue);
    buf_item->inqueue = CM_TRUE;
    queue->count++;

    if (count != NULL) {
        *count = queue->count;
    }
    cm_spin_unlock(&queue->lock);
    return;
}

static void mes_init_buffer_item_tag(mes_buffer_item_tag_t *tag, mes_msg_buffer_pool_tag_t *pool_tag,
    bool8 is_shared, mes_priority_t priority, uint8 queue_no)
{
    tag->is_send = pool_tag->is_send;
    tag->inst_id = pool_tag->inst_id;
    tag->buf_pool_no = pool_tag->buf_pool_no;
    tag->is_shared = is_shared;
    tag->priority = priority;
    tag->queue_no = queue_no;
}

static void mes_format_buf_for_queue(mes_buf_queue_t *queue, mes_msg_buffer_pool_t *buf_pool,
    bool8 is_shared, mes_priority_t priority)
{
    uint64 buf_item_size = buf_pool->buf_size + sizeof(mes_buffer_item_t);
    uint32 init_count = queue->init_count;
    if (init_count == 0) {
        queue->inited = CM_TRUE;
        return;
    }
    
    uint64 size = init_count * buf_item_size;
    cm_spin_lock(&buf_pool->mem_chunk_lock, NULL);
    char* addr = cm_alloc_memory_from_chunk(&buf_pool->mem_chunk, size);
    cm_spin_unlock(&buf_pool->mem_chunk_lock);

    mes_buffer_item_t *buf_item;
    mes_msg_buffer_pool_tag_t *pool_tag = &buf_pool->tag;
    for (uint32 i = 0; i < init_count; i++) {
        buf_item = (mes_buffer_item_t*)addr;
        mes_init_buffer_item_tag(&buf_item->tag, pool_tag, is_shared, priority, queue->queue_no);
        buf_item->inqueue = CM_FALSE;
        mes_put_buf_item_to_queue(buf_item, queue, NULL);
        addr += buf_item_size;
    }

    queue->inited = CM_TRUE;
    return;
}

static mes_buf_queue_t *mes_get_priority_private_queue(mes_msg_buffer_pool_t *buf_pool, mes_priority_t priority)
{
    mes_msg_buffer_inner_pool_t *priority_pool = &buf_pool->private_pool[priority];
    if (priority_pool->queue_num == 0) {
        cm_panic_log(0, "[mes] get priority:%u queue failed, queue_num is zero, buf_pool_no:%u.",
            priority, buf_pool->tag.buf_pool_no);
    }

    uint32 pop = priority_pool->pop_cursor++;
    mes_buf_queue_t *queue = &priority_pool->queues[pop % priority_pool->queue_num];
    if (!queue->inited) {
        cm_spin_lock(&queue->init_lock, NULL);
        if (!queue->inited) {
            mes_format_buf_for_queue(queue, buf_pool, CM_FALSE, priority);
        }
        cm_spin_unlock(&queue->init_lock);
    }
    return queue;
}

static mes_buffer_item_t* mes_get_buf_item_from_private_pool(mes_msg_buffer_pool_t *buf_pool, mes_priority_t priority)
{
    mes_buf_queue_t *queue = mes_get_priority_private_queue(buf_pool, priority);
    return mes_get_buf_item_from_queue(queue, NULL);
}

static mes_buffer_item_t* mes_get_buf_item_from_shared_pool(mes_msg_buffer_pool_t *buf_pool,
    bool8 enable_flow_control)
{
    mes_buffer_item_t *buf_item = NULL;
    mes_msg_buffer_inner_pool_t *shared_pool = &buf_pool->shared_pool;
    uint32 pop = shared_pool->pop_cursor++;
    mes_buf_queue_t *queue = &shared_pool->queues[pop % shared_pool->queue_num];

    if (!queue->inited) {
        cm_spin_lock(&queue->init_lock, NULL);
        if (!queue->inited) {
            mes_format_buf_for_queue(queue, buf_pool, CM_TRUE, 0);
        }
        cm_spin_unlock(&queue->init_lock);
    }

    uint32 buf_count = 0;
    if (enable_flow_control) {
        buf_count = queue->count;
        if (buf_count > 0 && queue->init_count / buf_count <= RECV_MSG_POOL_FC_THRESHOLD) {
            return NULL;
        }
    }

    buf_item = mes_get_buf_item_from_queue(queue, &buf_count);
    if (buf_count < buf_pool->recycle_threshold) {
        buf_pool->need_recycle = CM_TRUE;
        buf_pool->recycle_queue_no = pop % shared_pool->queue_num;
    }
    return buf_item;
}

static mes_buffer_item_t* mes_steal_buf_item_from_other_private_pool(mes_msg_buffer_pool_t *buf_pool,
    mes_priority_t priority)
{
    mes_buf_queue_t *queue;
    int32 pop_priority = cm_atomic32_inc(&buf_pool->pop_priority) % buf_pool->priority_cnt;
    if (pop_priority == priority) {
        // no need steal self
        return NULL;
    }

    queue = mes_get_priority_private_queue(buf_pool, pop_priority);
    if (queue == NULL) {
        return NULL;
    }

    mes_buffer_item_t *buf_item = mes_get_buf_item_from_queue(queue, NULL);
    if (buf_item != NULL && !buf_item->tag.is_shared) {
        mes_put_buf_item_to_queue(buf_item, queue, NULL);
        buf_item = NULL;
    }
    return buf_item;
}

static mes_msg_buffer_pool_t* mes_get_buf_pool_by_buf_tag(mes_buffer_item_tag_t *buf_tag)
{
    bool8 is_send = buf_tag->is_send;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    if (!mq_ctx->msg_pool_inited) {
        int ret = mes_init_message_pool(is_send);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] mes init msg pool failed, is_send:%u.",
                is_send);
            return NULL;
        }

        if (!mq_ctx->msg_pool_inited) {
            LOG_DEBUG_INF("[mes][msg pool] msg pool(is_send:%u) is not inited, "
                "so can not get buf_pool.",
                is_send);
            return NULL;
        }
    }

    if (!mq_ctx->enable_inst_dimension) {
        return mq_ctx->single_pool->buf_pool[buf_tag->buf_pool_no];
    }
    return mq_ctx->inst_pool_set.inst_pool[buf_tag->inst_id]->buf_pool[buf_tag->buf_pool_no];
}

static mes_msg_buffer_pool_t* mes_get_buf_pool(bool8 is_send, uint32 dst_inst, uint32 len)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    if (!mq_ctx->msg_pool_inited) {
        int ret = mes_init_message_pool(is_send);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] mes init msg pool failed, is_send:%u.",
                is_send);
            return NULL;
        }

        if (!mq_ctx->msg_pool_inited) {
            LOG_DEBUG_INF("[mes][msg pool] msg pool(is_send:%u) is not inited, "
                "so can not get buf_pool.",
                is_send);
            return NULL;
        }
    }

    if (!mq_ctx->enable_inst_dimension) {
        mes_msg_pool_t *single_pool = mq_ctx->single_pool;
        for (uint32 i = 0; i < single_pool->buf_pool_count; i++) {
            mes_msg_buffer_pool_t *buf_pool = single_pool->buf_pool[i];
            if (len <= buf_pool->buf_size) {
                return buf_pool;
            }
        }
        LOG_RUN_ERR("[mes] There is not long enough buffer for this message. "
            "message len:%u, is_send:%u, dst_inst:%u.",
            len, is_send, dst_inst);
        return NULL;
    }

    mes_msg_inst_pool_set_t *pool_set = &mq_ctx->inst_pool_set;
    if (!pool_set->inst_pool_inited[dst_inst]) {
        // occur when cluster add new instance
        cm_spin_lock(&mq_ctx->msg_pool_init_lock, NULL);
        if (!pool_set->inst_pool_inited[dst_inst]) {
            mes_msg_pool_tag_t tag = {
                .is_send = is_send,
                .enable_inst_dimension = CM_TRUE,
                .inst_id = dst_inst,
            };
            LOG_RUN_INF("[mes][msg pool] receive inst:%u message, this instance message pool not inited. "
                "now we init this message pool, is_send:%u",
                dst_inst, is_send);
            int ret = mes_init_msg_pool(&pool_set->inst_pool[dst_inst], pool_set->per_inst_pool_size, &tag);
            if (ret != CM_SUCCESS) {
                cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
                LOG_RUN_ERR("[mes][msg pool] init inst pool failed, "
                    "inst_id:%u, is_send:%u, enable_inst_dimension:%u",
                    dst_inst, is_send, CM_TRUE);
                mes_deinit_msg_pool(&pool_set->inst_pool[dst_inst]);
                return NULL;
            }
            LOG_RUN_INF("[mes][msg pool] init instance:%u message pool success, is_send:%u.",
                dst_inst, is_send);
            pool_set->total_size = pool_set->total_size + pool_set->per_inst_pool_size;
            pool_set->inst_pool_count++;
            pool_set->inst_pool_inited[dst_inst] = CM_TRUE;
        }
        cm_spin_unlock(&mq_ctx->msg_pool_init_lock);
    }

    mes_msg_pool_t *inst_pool = pool_set->inst_pool[dst_inst];
    for (int i = 0; i < inst_pool->buf_pool_count; i++) {
        mes_msg_buffer_pool_t *buf_pool = inst_pool->buf_pool[i];
        if (len <= buf_pool->buf_size) {
            return buf_pool;
        }
    }

    LOG_RUN_ERR("[mes] There is not long enough buffer for this message. "
        "message len:%u, is_send:%u, dst_inst:%u.",
        len, is_send, dst_inst);
    return NULL;
}

char* mes_alloc_buf_item_inner(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority,
    bool8 enable_flow_control)
{
    mes_buffer_item_t *buf_item = NULL;
    uint32 find_times = 0;

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[mes] mes_alloc_buf_item_inner fail, phase %u", MES_GLOBAL_INST_MSG.mes_ctx.phase);
        return NULL;
    }

    mes_msg_buffer_pool_t *buf_pool = mes_get_buf_pool(is_send, dst_inst, len);
    if (buf_pool == NULL) {
        LOG_RUN_ERR("[mes]: get buf_pool failed.");
        return NULL;
    }

    mes_msg_buffer_pool_t *begin_buf_pool = buf_pool;
    mes_msg_pool_t *msg_pool = NULL;
    do {
        do {
            buf_item = mes_get_buf_item_from_private_pool(buf_pool, priority);
            if (buf_item != NULL) {
                break;
            }

            buf_item = mes_get_buf_item_from_shared_pool(buf_pool, enable_flow_control);
            if (buf_item != NULL) {
                break;
            }

            buf_item = mes_steal_buf_item_from_other_private_pool(buf_pool, priority);
            if (buf_item != NULL) {
                break;
            }

            find_times++;
            if (find_times % buf_pool->private_pool[priority].queue_num == 0) {
                LOG_RUN_WAR_INHIBIT(LOG_INHIBIT_LEVEL5, "[mes]: There is no buffer, sleep and try again.");
                cm_sleep(1);
                break; // try anthor buf_pool
            }
        } while (buf_item == NULL);

        if (buf_item == NULL) {
            uint8 next_buf_pool_no = buf_pool->tag.buf_pool_no + 1;
            msg_pool = (mes_msg_pool_t*)buf_pool->msg_pool;
            if (next_buf_pool_no >= msg_pool->buf_pool_count) {
                buf_pool = begin_buf_pool;
            } else {
                buf_pool = msg_pool->buf_pool[next_buf_pool_no];
            }
        }
    } while (buf_item == NULL);
    return buf_item->data;
}

char *mes_alloc_buf_item(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority)
{
    return mes_alloc_buf_item_inner(len, is_send, dst_inst, priority, CM_FALSE);
}

char *mes_alloc_buf_item_fc(uint32 len, bool32 is_send, uint32 dst_inst, mes_priority_t priority)
{
    return mes_alloc_buf_item_inner(len, is_send, dst_inst, priority, CM_TRUE);
}

void mes_free_buf_item(char *buffer)
{
    if (buffer == NULL) {
        return;
    }

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return;
    }

    mes_buffer_item_t *buf_item = (mes_buffer_item_t*)(buffer - MES_BUFFER_ITEM_SIZE);
    mes_buffer_item_tag_t *buf_tag = &buf_item->tag;
    mes_msg_buffer_pool_t *buf_pool = mes_get_buf_pool_by_buf_tag(buf_tag);
    if (buf_pool == NULL) {
        return;
    }

    mes_buf_queue_t *queue = NULL;
    bool8 check_recycle = CM_FALSE;
    mes_msg_buffer_inner_pool_t *priority_pool;
    if (!buf_tag->is_shared) {
        priority_pool = &buf_pool->private_pool[buf_tag->priority];
        queue = &priority_pool->queues[buf_tag->queue_no];
    } else if (buf_pool->need_recycle) {
        queue = &buf_pool->shared_pool.queues[buf_tag->queue_no];
        check_recycle = CM_TRUE;
    } else {
        priority_pool = &buf_pool->private_pool[buf_tag->priority];
        uint32 push = priority_pool->push_cursor++;
        queue = &priority_pool->queues[push % priority_pool->queue_num];
    }

    uint16 cmd = ((mes_message_head_t *)buffer)->app_cmd;
    uint32 buf_count = 0;
    mes_put_buf_item_to_queue(buf_item, queue, &buf_count);

    if (check_recycle && buf_pool->need_recycle &&
        buf_item->tag.queue_no == buf_pool->recycle_queue_no) {
        if (buf_count > buf_pool->recycle_threshold) {
            buf_pool->need_recycle = CM_FALSE;
        }
    }
    mes_release_buf_stat(cmd);
    return;
}

uint32 mes_get_priority_max_msg_size(mes_priority_t priority)
{
    return MES_GLOBAL_INST_MSG.profile.msg_pool_attr.max_buf_size[priority];
}

static int mes_precheck_msg_pool_attr(mes_profile_t *profile)
{
    if (profile->inst_cnt > MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes][msg pool] precheck, inst_cnt:%u is invalid, legal scope is [1, %u].",
            profile->inst_cnt, MES_MAX_INSTANCES);
        return CM_ERROR;
    }

    if (profile->priority_cnt == 0 || profile->priority_cnt > MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[mes][msg pool] precheck, priority_cnt:%u is invalid, legal scope is [1, %u].",
            profile->priority_cnt, MES_PRIORITY_CEIL);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int mes_recheck_extra_size_whether_work(uint64 total_buf_pool_size, uint64 extra_size,
    double proportion, uint64 buf_pool_minimum_size)
{
    uint64 alloc = (uint64)((total_buf_pool_size + extra_size) * (proportion));
    if (alloc < buf_pool_minimum_size) {
        LOG_RUN_ERR("[mes][msg pool] calculate extra size to eliminate accuracy error failed, "
            "alloc size for this buf pool is less than minimum size. "
            "alloc_size:%llu, minimum_size:%llu, proportion:%f, total_buf_pool_size:%llu, "
            "extra_size:%llu.",
            alloc, buf_pool_minimum_size, proportion, total_buf_pool_size, extra_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int mes_calculate_extra_size_in_msg_pool_minimum_info(uint64 *buf_pool_size_list,
    uint32 buf_pool_count, uint64 *extra_size)
{
    int ret;
    uint64 max_extra = 0;
    uint64 temp_extra = 0;
    uint64 total_buf_pool_size = 0;
    for (uint8 buf_pool_no = 0; buf_pool_no < buf_pool_count; buf_pool_no++) {
        total_buf_pool_size += buf_pool_size_list[buf_pool_no];
    }

    double proportion_arr[MES_MAX_BUFFPOOL_NUM] = { 0 };
    for (uint8 buf_pool_no = 0; buf_pool_no < buf_pool_count; buf_pool_no++) {
        proportion_arr[buf_pool_no] = (double)buf_pool_size_list[buf_pool_no] / total_buf_pool_size;
        temp_extra = (uint64)(buf_pool_size_list[buf_pool_no] * DBL_EPSILON / proportion_arr[buf_pool_no]) + 1;
        if (temp_extra > max_extra) {
            max_extra = temp_extra;
        }

        ret = mes_recheck_extra_size_whether_work(total_buf_pool_size, max_extra,
            proportion_arr[buf_pool_no], buf_pool_size_list[buf_pool_no]);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] buf pool:%u recheck proportion failed.",
                buf_pool_no);
            return ret;
        }
    }

    double last_proportion_arr[MES_MAX_BUFFPOOL_NUM] = { 0 };
    double left_proportion = 1;
    for (uint8 tar_no = 0; tar_no < buf_pool_count; tar_no++) {
        left_proportion = 1;
        for (uint8 buf_pool_no = 0; buf_pool_no < buf_pool_count; buf_pool_no++) {
            if (tar_no == buf_pool_no) {
                continue;
            }
            left_proportion -= proportion_arr[buf_pool_no];
        }
        last_proportion_arr[tar_no] = left_proportion;
        if (left_proportion < 0) {
            LOG_RUN_ERR("[mes][msg pool] calculate extra size to eliminate accuracy error failed, "
                "buf_pool_no:%u left_proportion:%f is less than zero.",
                tar_no, left_proportion);
            return CM_ERROR;
        }
    }

    for (uint8 buf_pool_no = 0; buf_pool_no < buf_pool_count; buf_pool_no++) {
        temp_extra = (uint64)(buf_pool_size_list[buf_pool_no] * DBL_EPSILON / last_proportion_arr[buf_pool_no]) + 1;
        if (temp_extra > max_extra) {
            max_extra = temp_extra;
        }
        ret = mes_recheck_extra_size_whether_work(total_buf_pool_size, max_extra,
            last_proportion_arr[buf_pool_no], buf_pool_size_list[buf_pool_no]);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes][msg pool] buf pool:%u recheck proportion twice failed.",
                buf_pool_no);
            return ret;
        }
    }
    *extra_size = max_extra;
    return CM_SUCCESS;
}

void mes_get_message_pool_minimum_info_when_enable_inst_dimension(uint32 inst_cnt, bool8 is_send,
    mes_msg_pool_minimum_info_t *minimum_info, uint64 *extra_size)
{
    if (is_send) {
        minimum_info->metadata_size *= (inst_cnt - 1);
        for (uint8 buf_pool_no = 0; buf_pool_no < minimum_info->buf_pool_count; buf_pool_no++) {
            minimum_info->buf_pool_minimum_size[buf_pool_no] *= (inst_cnt - 1);
        }
        *extra_size *= (inst_cnt - 1);
    } else {
        minimum_info->metadata_size *= inst_cnt;
        for (uint8 buf_pool_no = 0; buf_pool_no < minimum_info->buf_pool_count; buf_pool_no++) {
            minimum_info->buf_pool_minimum_size[buf_pool_no] *= inst_cnt;
        }
        *extra_size *= inst_cnt;
    }
}

int mes_get_message_pool_minimum_info(mes_profile_t *profile, uint8 is_send,
    mes_msg_pool_minimum_info_t *minimum_info)
{
    mes_profile_t out_profile = *profile;
    mes_msg_buffer_relation_t buf_rel = { 0 };
    int ret;
    
    ret = mes_precheck_msg_pool_attr(profile);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = mes_check_msg_pool_attr(profile, &out_profile, CM_FALSE, &buf_rel);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    mes_msg_pool_attr_t *msg_pool_attr = &out_profile.msg_pool_attr;
    minimum_info->buf_pool_count = profile->msg_pool_attr.buf_pool_count;
    // metadata_size
    uint64 buf_pool_metadata[MES_MAX_BUFFPOOL_NUM] = { 0 };
    uint64 message_pool_metadata =
        mes_get_msg_pool_metadata_size(&out_profile, buf_pool_metadata);
    minimum_info->metadata_size = message_pool_metadata;

    uint64 buffer_pool_minimum_list[MES_MAX_BUFFPOOL_NUM] = { 0 };
    ret = mes_get_buffer_pool_minimum_size(&out_profile, is_send, buffer_pool_minimum_list);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    uint32 changed_size;
    bool8 found;
    for (uint8 buf_pool_no = 0; buf_pool_no < buf_rel.buf_count; buf_pool_no++) {
        changed_size = buf_rel.changed_buf_size[buf_pool_no];
        found = CM_FALSE;
        for (int i = 0; i < msg_pool_attr->buf_pool_count; i++) {
            if (msg_pool_attr->buf_pool_attr[i].buf_size == changed_size) {
                minimum_info->buf_pool_minimum_size[buf_pool_no] = buffer_pool_minimum_list[i];
                found = CM_TRUE;
                break;
            }
        }

        if (!found) {
            cm_panic_log(0, "[mes][msg pool] can not find buf_pool minimum size, which buf_size:%u.",
                buf_rel.origin_buf_size[buf_pool_no]);
        }
    }

    // add extra size to eliminate accuracy error
    uint64 extra_size = 0;
    ret = mes_calculate_extra_size_in_msg_pool_minimum_info(buffer_pool_minimum_list,
        minimum_info->buf_pool_count, &extra_size);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (msg_pool_attr->enable_inst_dimension) {
        uint32 inst_cnt = 0;
        if (profile->inst_cnt == 0) {
            inst_cnt = CM_MAX_INSTANCES;
        } else {
            inst_cnt = profile->inst_cnt;
        }
        mes_get_message_pool_minimum_info_when_enable_inst_dimension(inst_cnt, is_send,
            minimum_info, &extra_size);
    }
    
    minimum_info->buf_pool_total_size = 0;
    for (uint8 buf_pool_no = 0; buf_pool_no < buf_rel.buf_count; buf_pool_no++) {
        minimum_info->buf_pool_total_size += minimum_info->buf_pool_minimum_size[buf_pool_no];
    }

    minimum_info->total_minimum_size = minimum_info->buf_pool_total_size
        + minimum_info->metadata_size + extra_size;
    return CM_SUCCESS;
}

static int mes_check_message_pool_size_inner(mes_profile_t *profile, bool8 is_send, uint64 all_metadata_size)
{
    if (is_send && profile->send_directly &&
        (profile->enable_compress_priority == 0 || profile->algorithm == COMPRESS_NONE ||
        profile->algorithm >= COMPRESS_CEIL)) {
        // send_directly and disable compress means no need send message pool
        return CM_SUCCESS;
    }

    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    uint64 pool_size = profile->msg_pool_attr.total_size;
    uint64 each_pool_size = pool_size;
    bool8 pool_exist = CM_TRUE;
    int pool_count = 0;
    if (mpa->enable_inst_dimension) {
        pool_count = is_send ? (profile->inst_cnt - 1) : profile->inst_cnt;
        if (pool_count <= 0) {
            pool_exist = CM_FALSE;
        } else {
            each_pool_size = pool_size / pool_count;
        }
    }

    if (!pool_exist) {
        cm_panic_log(is_send, "[mes] receive message pool must exist, inst_cnt:%u",
            profile->inst_cnt);
    }

    uint64 recommend_size = 0;
    int ret = mes_check_msg_pool_size_whether_enough(is_send, all_metadata_size, each_pool_size, &recommend_size);
    if (ret != CM_SUCCESS) {
        if (recommend_size != 0) {
            char buf[MSG_POOL_TEMP_STR_LEN] = { 0 };
            mes_assemble_msg_pool_proportion_print_info(buf);
            if (mpa->enable_inst_dimension) {
                recommend_size *= pool_count;
            }
            LOG_RUN_ERR("[mes][msg pool] %s size is not enough. size:%llu. "
                "if keep the parameter unchanged(%s), msg_buffer_pool need at least size:%llu.",
                is_send ? "send message pool" : "receive message pool",
                pool_size, buf, recommend_size);
        }
        return ret;
    }
    return ret;
}

int mes_check_message_pool_size(mes_profile_t *profile)
{
    uint64 metadata_size[MES_MAX_BUFFPOOL_NUM] = { 0 };
    uint64 all_metadata_size = mes_get_msg_pool_metadata_size(profile, metadata_size);
    int ret = CM_SUCCESS;
    ret = mes_check_message_pool_size_inner(profile, CM_FALSE, all_metadata_size);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = mes_check_message_pool_size_inner(profile, CM_TRUE, all_metadata_size);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return ret;
}