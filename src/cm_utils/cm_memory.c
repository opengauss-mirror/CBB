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
 * cm_memory.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_memory.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_memory.h"
#include "cm_log.h"
#include "cm_num.h"

#ifndef WIN32
#include <execinfo.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TYPE_ALIGN(ALIGNVAL, BUF) (((uintptr_t)(BUF) + ((ALIGNVAL) - 1)) & ~((uintptr_t)((ALIGNVAL) -1)))
mem_pool_t g_buddy_pool;
spinlock_t g_mem_context_lock = 0;

void *buddy_pool_malloc_prot(memory_context_t *context, uint64 size)
{
    return cm_malloc_prot(size);
}

void buddy_pool_free_prot(void *pointer)
{
    return cm_free_prot(pointer);
}

// flag indicate block is left or right,0 represent left: 1 represent right
static mem_block_t *mem_block_init(mem_zone_t *mem_zone, void *p, uint64 size, uint32 flag, uint64 bitmap)
{
    mem_block_t *mem_block = (mem_block_t *)p;

    errno_t ret = memset_sp(mem_block, MEM_BLOCK_SIZE, 0, MEM_BLOCK_SIZE);
    if (ret != EOK) {
        return NULL;
    }
    mem_block->mem_zone = mem_zone;
    mem_block->size = size;
    mem_block->bitmap = bitmap;
    if (flag == MEM_BLOCK_LEFT) {
        mem_block->bitmap &= ~size;
    } else {
        mem_block->bitmap |= size;
    }
    CM_MAGIC_SET(mem_block, mem_block_t);
    return mem_block;
}

static inline uint32 cm_get_power_exp(uint64 power)
{
    uint64 val = 1;
    uint32 exp = 0;

    while (val < power) {
        val <<= 1;
        exp++;
    }
    return exp;
}

static inline bool32 cm_is_power_of_2(uint64 val)
{
    if (!val) {
        return 0;
    }
    return ((val & (val - 1)) == 0);
}

static bilist_t *mem_zone_get_list(mem_zone_t *mem_zone, uint64 size)
{
    bilist_t *mem_block_list = NULL;
    uint32 index;

    if (cm_is_power_of_2(size) && (size >= 64)) {
        index = cm_get_power_exp(size / 64);
        if (index < MEM_NUM_FREELISTS) {
            mem_block_list = &mem_zone->list[index];
        }
    }

    return mem_block_list;
}

static inline void mem_block_add(mem_block_t *mem_block)
{
    CM_MAGIC_CHECK(mem_block, mem_block_t);
    bilist_t *mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
    if (mem_block_list == NULL) {
        return;
    }
    cm_bilist_add_tail(&mem_block->link, mem_block_list);
}

static mem_zone_t *mem_zone_init(mem_pool_t *mem, uint64 size)
{
    mem_zone_t *mem_zone;
    mem_block_t *mem_block;

    ddes_memory_allocator_t *mem_allocator = &mem->mem_allocator;
    mem_zone = (mem_zone_t *)(mem_allocator->malloc_proc)(mem_allocator->context, (size_t)(sizeof(mem_zone_t) + size));
    if (mem_zone == NULL) {
        return NULL;
    }

    errno_t ret = memset_sp(mem_zone, sizeof(mem_zone_t), 0, sizeof(mem_zone_t));
    if (ret != EOK) {
       (mem_allocator->free_proc)(mem_zone);
        return NULL;
    }
    mem_zone->mem = mem;
    mem_zone->total_size = size;
    mem_zone->used_size = 0;
    CM_MAGIC_SET(mem_zone, mem_zone_t);
    mem_block = mem_block_init(mem_zone, (void *)(mem_zone + 1), size, MEM_BLOCK_LEFT, 0);
    if (mem_block == NULL) {
       (mem_allocator->free_proc)(mem_zone);
        return NULL;
    }
    mem_block_add(mem_block);

    mem->total_size += size;
    return mem_zone;
}

status_t buddy_pool_init(char *pool_name, uint64 init_size, uint64 max_size, mem_pool_t *mem)
{
    mem_zone_t *mem_zone;
    uint32 len = (uint32)strlen(pool_name);
    if (len > CM_MAX_NAME_LEN) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, len, CM_MAX_NAME_LEN);
        return CM_ERROR;
    }
    init_size = cm_get_next_2power(init_size);
    // modify init size val
    if (init_size > BUDDY_MAX_BLOCK_SIZE) {
        init_size = BUDDY_MAX_BLOCK_SIZE;
    } else if (init_size < BUDDY_MIN_BLOCK_SIZE) {
        init_size = BUDDY_MIN_BLOCK_SIZE;
    }

    if (max_size > BUDDY_MEM_POOL_MAX_SIZE) {
        max_size = BUDDY_MEM_POOL_MAX_SIZE;
    } else if (max_size < init_size) {
        max_size = init_size;
    }

    errno_t ret = memset_sp(mem, sizeof(mem_pool_t), 0, sizeof(mem_pool_t));
    MEMS_RETURN_IFERR(ret);
    ddes_memory_allocator_t mem_allocator = {
        .context = NULL,
        .malloc_proc = buddy_pool_malloc_prot,
        .free_proc = buddy_pool_free_prot };
    buddy_pool_set_mem_allocator(mem, &mem_allocator);
    CM_MAGIC_SET(mem, mem_pool_t);
    MEMS_RETURN_IFERR(strncpy_sp(mem->name, CM_NAME_BUFFER_SIZE, pool_name, len));
    mem->max_size = max_size;
    GS_INIT_SPIN_LOCK(mem->lock);
    cm_bilist_init(&mem->mem_zone_lst);
    if (cm_event_init(&mem->event) != CM_SUCCESS) {
        return CM_ERROR;
    }
    mem_zone = mem_zone_init(mem, init_size);
    if (mem_zone == NULL) {
        CM_THROW_ERROR(ERR_MEM_ZONE_INIT_FAIL, "");
        cm_event_destory(&mem->event);
        return CM_ERROR;
    }

    cm_bilist_add_tail(&mem_zone->link, &mem->mem_zone_lst);

    return CM_SUCCESS;
}

status_t buddy_pool_init_ext(char *pool_name, uint64 init_size, uint64 max_size, mem_pool_t *mem,
    ddes_memory_allocator_t* mem_allocator)
{
    CM_CHECK_NULL_PTR(mem_allocator);

    mem_zone_t *mem_zone;
    uint32 len = (uint32)strlen(pool_name);
    if (len > CM_MAX_NAME_LEN) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, len, CM_MAX_NAME_LEN);
        return CM_ERROR;
    }
    init_size = cm_get_next_2power(init_size);
    // modify init size val
    if (init_size > BUDDY_MAX_BLOCK_SIZE) {
        init_size = BUDDY_MAX_BLOCK_SIZE;
    } else if (init_size < BUDDY_MIN_BLOCK_SIZE) {
        init_size = BUDDY_MIN_BLOCK_SIZE;
    }

    if (max_size > BUDDY_MEM_POOL_MAX_SIZE) {
        max_size = BUDDY_MEM_POOL_MAX_SIZE;
    } else if (max_size < init_size) {
        max_size = init_size;
    }

    errno_t ret = memset_sp(mem, sizeof(mem_pool_t), 0, sizeof(mem_pool_t));
    MEMS_RETURN_IFERR(ret);
    buddy_pool_set_mem_allocator(mem, mem_allocator);
    CM_MAGIC_SET(mem, mem_pool_t);
    MEMS_RETURN_IFERR(strncpy_sp(mem->name, CM_NAME_BUFFER_SIZE, pool_name, len));
    mem->max_size = max_size;
    GS_INIT_SPIN_LOCK(mem->lock);
    cm_bilist_init(&mem->mem_zone_lst);
    if (cm_event_init(&mem->event) != CM_SUCCESS) {
        return CM_ERROR;
    }
    mem_zone = mem_zone_init(mem, init_size);
    if (mem_zone == NULL) {
        CM_THROW_ERROR(ERR_MEM_ZONE_INIT_FAIL, "");
        cm_event_destory(&mem->event);
        return CM_ERROR;
    }

    cm_bilist_add_tail(&mem_zone->link, &mem->mem_zone_lst);

    return CM_SUCCESS;
}

status_t buddy_pool_set_mem_allocator(mem_pool_t *mem, ddes_memory_allocator_t *mem_allocator)
{
    CM_CHECK_NULL_PTR(mem);
    CM_CHECK_NULL_PTR(mem_allocator);
    mem->mem_allocator = *mem_allocator;
    return CM_SUCCESS;
}

static mem_block_t *mem_get_block_low(mem_zone_t *mem_zone, uint64 size)
{
    bilist_t *mem_block_list;
    mem_block_t *mem_block;
    bilist_node_t *head;
    CM_MAGIC_CHECK(mem_zone, mem_zone_t);
    if (size > mem_zone->total_size - mem_zone->used_size) {
        return NULL;
    }

    mem_block_list = mem_zone_get_list(mem_zone, size);
    if (mem_block_list != NULL && !cm_bilist_empty(mem_block_list)) {
        head = cm_bilist_head(mem_block_list);
        cm_bilist_del_head(mem_block_list);

        mem_block = BILIST_NODE_OF(mem_block_t, head, link);
        CM_ASSERT(!mem_block->use_flag);
        CM_MAGIC_CHECK(mem_block, mem_block_t);
        return mem_block;
    } else {
        mem_block = mem_get_block_low(mem_zone, size * 2);
        if (mem_block == NULL) {
            return NULL;
        } else {
            mem_block_t *block_left;
            mem_block_t *block_right;
            uint64 bitmap = mem_block->bitmap;
            block_left = mem_block_init(mem_zone, (void *)mem_block, size, MEM_BLOCK_LEFT, bitmap);
            block_right = mem_block_init(mem_zone, (void *)((char *)mem_block + size), size, MEM_BLOCK_RIGHT, bitmap);

            mem_block_add(block_left);
            return block_right;
        }
    }
}

// obtain a block from memory zone
static inline mem_block_t *mem_alloc_block(mem_zone_t *mem_zone, uint64 size)
{
    if (mem_zone->total_size - mem_zone->used_size < size) {
        return NULL;
    }

    return mem_get_block_low(mem_zone, size);
}

static status_t mem_extend(mem_pool_t *mem, uint64 align_size)
{
    mem_zone_t *mem_zone;
    uint64 extend_size;

    extend_size = cm_get_next_2power(mem->total_size);
    extend_size = MAX(extend_size, align_size);
    extend_size = MIN(extend_size, BUDDY_MAX_BLOCK_SIZE);
    while (extend_size + mem->total_size > mem->max_size) {
        extend_size /= 2;
    }

    if (extend_size < align_size) {
        CM_THROW_ERROR(ERR_MEM_OUT_OF_MEMORY, align_size);
        return CM_ERROR;
    }

    mem_zone = mem_zone_init(mem, extend_size);
    if (mem_zone == NULL) {
        CM_THROW_ERROR(ERR_MEM_ZONE_INIT_FAIL, "");
        return CM_ERROR;
    }
    cm_bilist_add_head(&mem_zone->link, &mem->mem_zone_lst);

    return CM_SUCCESS;
}

static status_t mem_check_if_extend(mem_pool_t *mem, uint64 align_size)
{
    uint64 remain_size = cm_get_prev_2power(mem->max_size - mem->used_size);
    if (align_size > remain_size) {
        CM_THROW_ERROR(ERR_MEM_OUT_OF_MEMORY, align_size);
        return CM_ERROR;
    }

    if (align_size > mem->total_size - mem->used_size) {
        return mem_extend(mem, align_size);
    }

    return CM_SUCCESS;
}

void *galloc(uint64 size, mem_pool_t *mem)
{
    mem_zone_t *mem_zone;
    mem_block_t *mem_block = NULL;
    uint64 align_size;
    status_t status;
    CM_MAGIC_CHECK(mem, mem_pool_t);
    align_size = cm_get_next_2power(size + MEM_BLOCK_SIZE);
    if (SECUREC_UNLIKELY(align_size > BUDDY_MAX_BLOCK_SIZE)) {
        return NULL;
    }

    cm_spin_lock(&mem->lock, NULL);

    status = mem_check_if_extend(mem, align_size);
    if (status != CM_SUCCESS) {
        cm_spin_unlock(&mem->lock);
        return NULL;
    }

    bilist_node_t *node = cm_bilist_head(&mem->mem_zone_lst);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        mem_zone = BILIST_NODE_OF(mem_zone_t, node, link);
        mem_block = mem_alloc_block(mem_zone, align_size);
        if (mem_block != NULL) {
            break;
        }
    }

    if (mem_block == NULL) {
        status = mem_extend(mem, align_size);
        if (status != CM_SUCCESS) {
            cm_spin_unlock(&mem->lock);
            return NULL;
        }
        // extend zone always add list head
        node = cm_bilist_head(&mem->mem_zone_lst);
        mem_zone = BILIST_NODE_OF(mem_zone_t, node, link);
        mem_block = mem_alloc_block(mem_zone, align_size);
    }
    CM_ASSERT(mem_block != NULL);

    mem_block->actual_size = size;
    CM_ASSERT(mem_block->actual_size < mem_block->size);
    mem_block->use_flag = CM_TRUE;
    mem_block->mem_zone->used_size += mem_block->size;
    mem_block->mem_zone->mem->used_size += mem_block->size;
    cm_spin_unlock(&mem->lock);

    return mem_block->data;
}

#ifdef DB_DEBUG_VERSION
static void check_zone_list(mem_zone_t *mem_zone)
{
    for (int i = 0; i < MEM_NUM_FREELISTS; i++) {
        CM_ASSERT(mem_zone->list[i].count == 0);
    }
}
static void check_mem_double_free(mem_block_t *mem_block, mem_zone_t *mem_zone)
{
    char *left = (char *)mem_block;
    char *right = (char *)mem_block + mem_block->size;
    for (int i = 0; i < MEM_NUM_FREELISTS; i++) {
        bilist_node_t *node = cm_bilist_head(&mem_zone->list[i]);
        while (node) {
            mem_block_t *block_left = BILIST_NODE_OF(mem_block_t, node, link);
            if ((char *)block_left >= left && (char *)block_left < right) {
                CM_ASSERT(0);
            }
            char *block_right = (char *)block_left + block_left->size;
            if (block_right > left && block_right <= right) {
                CM_ASSERT(0);
            }

            if (left >= (char *)block_left && left < (char *)block_right) {
                CM_ASSERT(0);
            }

            if (right > (char *)block_left && right <= (char *)block_right) {
                CM_ASSERT(0);
            }
            node = BINODE_NEXT(node);
        }
    }
}
#endif

static void mem_recycle_low(mem_pool_t *mem, mem_block_t *mem_block)
{
    bilist_t *mem_block_list;
    mem_block_t *mem_block_bro;
    mem_block_t *mem_block_merge;
    uint8 block_type;

    CM_MAGIC_CHECK(mem_block, mem_block_t);
    if (mem_block->size == mem_block->mem_zone->total_size) {
#ifdef DB_DEBUG_VERSION
        check_zone_list(mem_block->mem_zone);
#endif
        mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
        if (mem_block_list == NULL) {
            return;
        }
        cm_bilist_add_head(&mem_block->link, mem_block_list);
        return;
    }

    block_type = (mem_block->bitmap & mem_block->size) == 0 ? MEM_BLOCK_LEFT : MEM_BLOCK_RIGHT;
    if (block_type == MEM_BLOCK_LEFT) {
        mem_block_bro = (mem_block_t *)((char *)mem_block + mem_block->size);
        mem_block_merge = mem_block;
    } else {
        mem_block_bro = (mem_block_t *)((char *)mem_block - mem_block->size);
        mem_block_merge = mem_block_bro;
    }
    CM_MAGIC_CHECK(mem_block_bro, mem_block_t);

    if (mem_block_bro->use_flag == CM_TRUE || mem_block->size != mem_block_bro->size) {
        mem_block_list = mem_zone_get_list(mem_block->mem_zone, mem_block->size);
        if (mem_block_list == NULL) {
            return;
        }
        cm_bilist_add_head(&mem_block->link, mem_block_list);
        return;
    }

    mem_block_list = mem_zone_get_list(mem_block_bro->mem_zone, mem_block_bro->size);
    if (mem_block_list == NULL) {
        return;
    }

    cm_bilist_del(&mem_block_bro->link, mem_block_list);
    mem_block_merge->size *= 2;
    mem_recycle_low(mem, mem_block_merge);
}

void *grealloc(void *p, uint64 size, mem_pool_t *mem)
{
    CM_ASSERT(p != NULL);
    mem_block_t *mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
    if (mem_block->size - MEM_BLOCK_SIZE >= size) {
        mem_block->actual_size = size;
        return p;
    }

    void *new_p = galloc(size, mem);
    if (new_p == NULL) {
        return NULL;
    }

    mem_block_t *new_block = (mem_block_t *)((char *)new_p - MEM_BLOCK_SIZE);
    if (memcpy_sp(new_p, (size_t)(new_block->size - MEM_BLOCK_SIZE), p, (size_t)mem_block->actual_size) != EOK) {
        gfree(new_p);
        return NULL;
    }

    gfree(p);

    return new_p;
}

void *galloc_timeout(uint64 size, mem_pool_t *mem, uint32 timeout_ms)
{
    while (timeout_ms > 0) {
        void *ptr = galloc(size, mem);
        if (ptr != NULL) {
            return ptr;
        }

        uint32 wait = MIN(timeout_ms, 100);
        if (cm_event_timedwait(&mem->event, wait) == CM_SUCCESS) {
            continue;
        }
        timeout_ms -= wait;
    }
    return NULL;
}

void gfree(void *p)
{
    mem_block_t *mem_block;
    mem_pool_t *mem;
    CM_ASSERT(p != NULL);

    mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
    mem = mem_block->mem_zone->mem;
    CM_MAGIC_CHECK(mem_block, mem_block_t);
    CM_MAGIC_CHECK(mem, mem_pool_t);
    CM_ASSERT(mem_block->use_flag);
    CM_ASSERT(mem_block->link.next == NULL);
    CM_ASSERT(mem_block->link.prev == NULL);

    cm_spin_lock(&mem->lock, NULL);
    mem_block = (mem_block_t *)((char *)p - MEM_BLOCK_SIZE);
#ifdef DB_DEBUG_VERSION
    check_mem_double_free(mem_block, mem_block->mem_zone);
#endif
    mem_block->use_flag = CM_FALSE;
    mem_block->actual_size = 0;
    mem_block->mem_zone->used_size -= mem_block->size;
    mem_block->mem_zone->mem->used_size -= mem_block->size;
    mem_recycle_low(mem, mem_block);
    cm_spin_unlock(&mem->lock);
    cm_event_notify(&mem->event);
}

void buddy_pool_deinit(mem_pool_t *mem)
{
    mem_zone_t *mem_zone;
    bilist_node_t *head;
    ddes_memory_allocator_t *mem_allocator = &mem->mem_allocator;

    while (!cm_bilist_empty(&mem->mem_zone_lst)) {
        head = cm_bilist_head(&mem->mem_zone_lst);
        cm_bilist_del(head, &mem->mem_zone_lst);
        mem_zone = BILIST_NODE_OF(mem_zone_t, head, link);
       (mem_allocator->free_proc)(mem_zone);
    }
}

void ddes_update_allocated_context_memory(memory_context_t *context, int64 size)
{
    memory_context_t *temp_context = context;
    while (temp_context != NULL) {
        if (size <= 0) {
            (void)cm_atomic_add((atomic_t *)&temp_context->allocated_size, size);
            CM_ASSERT(temp_context->allocated_size >= 0);
        } else {
            if (temp_context->allocated_size + size <= CM_MAX_INT64) {
                (void)cm_atomic_add((atomic_t *)&temp_context->allocated_size, size);
            }
        }
        temp_context = temp_context->parent;
    }
}

static bool8 memory_context_check_max_size(memory_context_t *context, int64 size)
{
    memory_context_t *temp_context = context;
    while (temp_context != NULL) {
        if (temp_context->used_size + size > temp_context->mem_max_size) {
            return CM_FALSE;
        }
        temp_context = temp_context->parent;
    }
    return CM_TRUE;
}

static void roll_back_add_used_context_memory(memory_context_t *context, int64 size, int32 level)
{
    memory_context_t *temp_context = context;
    while (level > 0 && temp_context != NULL) {
        cm_atomic_add((atomic_t *)&temp_context->used_size, -size);
        CM_ASSERT(temp_context->used_size >= 0);
        temp_context = temp_context->parent;
        level--;
    }
}

bool8 ddes_add_used_context_memory(memory_context_t *context, int64 size)
{
    bool8 updated = CM_TRUE;
    int64 cur_used = 0;
    int32 level = 0;
    if (memory_context_check_max_size(context, size) != CM_TRUE) {
        LOG_RUN_ERR("memory used has reached context max_mem_size");
        return CM_FALSE;
    }
    memory_context_t *temp_context = context;
    while (temp_context != NULL) {
        if (temp_context->used_size + size <= temp_context->mem_max_size) {
            cur_used = cm_atomic_add((atomic_t *)&temp_context->used_size, size);
            level++;
            if (cur_used > temp_context->mem_max_size) {
                roll_back_add_used_context_memory(context, size, level);
                updated = CM_FALSE;
                break;
            }
        } else {
            roll_back_add_used_context_memory(context, size, level);
            updated = CM_FALSE;
            break;
        }
        temp_context = temp_context->parent;
    }

    if (updated == CM_FALSE) {
        LOG_RUN_ERR("memory used has reached context max_mem_size");
    }
    return updated;
}

void ddes_sub_used_context_memory(memory_context_t *context, int64 size)
{
    memory_context_t *temp_context = context;
    while (temp_context != NULL) {
        cm_atomic_add((atomic_t *)&temp_context->used_size, -size);
        CM_ASSERT(temp_context->used_size >= 0);
        temp_context = temp_context->parent;
    }
}

memory_context_t* ddes_memory_context_create(memory_context_t *parent, uint64 max_size, char *name,
    cm_memory_allocator_t *mem_allocator)
{
    cm_memory_allocator_t memory_allocator_temp = {0};
    if (mem_allocator == NULL) {
        memory_allocator_temp.malloc_proc = malloc;
        memory_allocator_temp.free_proc = free;
        mem_allocator = &memory_allocator_temp;
    }
    cm_spin_lock(&g_mem_context_lock, NULL);
    int32 ret;
    uint64 size = sizeof(memory_context_t);
    memory_context_t *context = NULL;
    if (parent != NULL) {
        context = (memory_context_t *)ddes_alloc(parent, size);
    } else {
        context = (memory_context_t *)mem_allocator->malloc_proc(size);
    }
    if (context == NULL) {
        LOG_RUN_ERR("cm_memory: mem_context create failed, malloc failed");
        return NULL;
    }
    ret = memset_sp(context, sizeof(memory_context_t), 0, sizeof(memory_context_t));
    if (ret != EOK) {
        LOG_RUN_ERR("cm_memory: mem_context create failed, memset_sp failed");
        if (parent != NULL) {
            ddes_free(context);
        } else {
            mem_allocator->free_proc(context);
        }
        return NULL;
    }
    GS_INIT_SPIN_LOCK(context->lock);
    ret = strncpy_s(context->name, CM_NAME_BUFFER_SIZE, name, strlen(name));
    if (ret != EOK) {
        LOG_RUN_ERR("cm_memory: mem_context create failed, strncpy_sp failed");
        if (parent != NULL) {
            ddes_free(context);
        } else {
            mem_allocator->free_proc(context);
        }
        return NULL;
    }
    context->mem_max_size = max_size;
    if (parent == NULL) {
        context->allocated_size = size;
    }
    context->used_size = 0;
    context->firstchild = NULL;
    context->nextchild = NULL;
    context->prechild = NULL;
    context->parent = parent;
    if (parent != NULL) {
        context->nextchild = (memory_context_t *)parent->firstchild;
        if (parent->firstchild != NULL) {
            parent->firstchild->prechild = (memory_context_t *)context;
        }
        parent->firstchild = (memory_context_t *)context;
    }
    context->mem_allocator = *mem_allocator;
    context->is_init = CM_TRUE;
    cm_spin_unlock(&g_mem_context_lock);
    return (memory_context_t *)context;
}

void ddes_memory_context_destroy_self(memory_context_t *context)
{
    if (context->is_init == CM_FALSE) {
        return;
    }
    cm_spin_lock(&context->lock, NULL);
    cm_memory_allocator_t *mem_allocator = &context->mem_allocator;
    mem_context_block_t *block = context->blocks;
    while (block) {
        mem_context_block_t *next = block->next;
        CM_MAGIC_CHECK(block, mem_context_block_t);
        mem_allocator->free_proc(block);
        block = next;
    }
    context->blocks = NULL;
    cm_spin_unlock(&context->lock);
    context->allocated_size = 0;
    context->used_size = 0;
    context->is_init = CM_FALSE;
    if (context->parent != NULL && context->parent->firstchild == context) {
        context->parent->firstchild = context->nextchild;
    }
    if (context->nextchild != NULL) {
        context->nextchild->prechild = context->prechild;
    }
    if (context->prechild != NULL) {
        context->prechild->nextchild = context->nextchild;
    }
}

void ddes_memory_context_destroy_inner(memory_context_t *context)
{
    if (context->is_init == CM_FALSE) {
        return;
    }
    memory_context_t *child = context->firstchild;
    while (child) {
        ddes_memory_context_destroy_inner(child);
        child = child->nextchild;
    }
    ddes_memory_context_destroy_self(context);
}

void ddes_memory_context_destroy(memory_context_t *context)
{
   if (context == NULL || context->is_init == CM_FALSE) {
        return;
   }
    cm_spin_lock(&g_mem_context_lock, NULL);
    if (context->is_init == CM_FALSE) {
        cm_spin_unlock(&g_mem_context_lock);
        return;
    }
    ddes_sub_used_context_memory(context, context->used_size);
    ddes_update_allocated_context_memory(context, -context->allocated_size);
    ddes_memory_context_destroy_inner(context);
    cm_spin_unlock(&g_mem_context_lock);
    if (context->parent == NULL) {
        context->mem_allocator.free_proc(context);
    }
    LOG_RUN_INF("memory context destroy successful");
}

void *ddes_alloc(memory_context_t *context, uint64 size)
{
    if (context == NULL || !context->is_init) {
        LOG_RUN_ERR("context is not legal");
        return NULL;
    }
    if (ddes_add_used_context_memory(context, size) == CM_FALSE) {
        LOG_RUN_ERR("ddes_alloc failed, context mem used size has reached mem_max_size");
        return NULL;
    }
    cm_memory_allocator_t *mem_allocator = &context->mem_allocator;
    uint64 alloc_size = size + sizeof(ddes_buffer_head_t) + sizeof(mem_context_block_t);
    mem_context_block_t *block = (mem_context_block_t *)mem_allocator->malloc_proc(alloc_size);
    if (block == NULL) {
        ddes_sub_used_context_memory(context, size);
        return NULL;
    }
    block->size = alloc_size;
    cm_spin_lock(&context->lock, NULL);
    block->next = context->blocks;
    block->prev = NULL;
    if (context->blocks != NULL) {
        context->blocks->prev = block;
    }
    context->blocks = block;
    cm_spin_unlock(&context->lock);
    ddes_buffer_head_t *head = (ddes_buffer_head_t *)((char *)block + sizeof(mem_context_block_t));
    char *buf = (char*)((char *)head + sizeof(ddes_buffer_head_t));
    head->offset = (uint64)((char *)buf - (char *)block);
    head->context = context;
    head->size = size;
    ddes_update_allocated_context_memory(context, alloc_size);
    CM_MAGIC_SET(block, mem_context_block_t);
    CM_MAGIC_SET(head, ddes_buffer_head_t);
    return (void*)buf;
}

void *ddes_alloc_align(memory_context_t *context, uint32 alignment, uint64 size)
{
    if (context == NULL || !context->is_init) {
        LOG_RUN_ERR("context is not legal");
        return NULL;
    }
    if (ddes_add_used_context_memory(context, size) == CM_FALSE) {
        LOG_RUN_ERR("ddes_alloc failed, context mem used size has reached mem_max_size");
        return NULL;
    }
    cm_memory_allocator_t *mem_allocator = &context->mem_allocator;
    uint64 alloc_size = size + (alignment -1) + sizeof(ddes_buffer_head_t) + sizeof(mem_context_block_t);
    mem_context_block_t *block = (mem_context_block_t *)mem_allocator->malloc_proc(alloc_size);
    if (block == NULL) {
        ddes_sub_used_context_memory(context, size);
        return NULL;
    }
    block->size = alloc_size;
    cm_spin_lock(&context->lock, NULL);
    block->next = context->blocks;
    block->prev = NULL;
    if (context->blocks != NULL) {
        context->blocks->prev = block;
    }
    context->blocks = block;
    cm_spin_unlock(&context->lock);
    char *buf = (char*)TYPE_ALIGN(alignment, (char *)block + sizeof(mem_context_block_t) + sizeof(ddes_buffer_head_t));
    ddes_buffer_head_t *head = (ddes_buffer_head_t *)((char *)buf - sizeof(ddes_buffer_head_t));
    head->offset = (uint64)((char *)buf - (char *)block);
    head->context = context;
    head->size = size;
    ddes_update_allocated_context_memory(context, alloc_size);
    CM_MAGIC_SET(block, mem_context_block_t);
    CM_MAGIC_SET(head, ddes_buffer_head_t);
    return (void*)buf;
}

void ddes_free(void *ptr)
{
    ddes_buffer_head_t *head = (ddes_buffer_head_t *)((char *)ptr - sizeof(ddes_buffer_head_t));
    memory_context_t *context = head->context;
    ddes_sub_used_context_memory(context, head->size);
    mem_context_block_t *block = (mem_context_block_t *)((char *)ptr - head->offset);
    CM_MAGIC_CHECK(block, mem_context_block_t);
    CM_MAGIC_CHECK(head, ddes_buffer_head_t);
    cm_spin_lock(&context->lock, NULL);
    if (context->blocks == block) {
        context->blocks = block->next;
    }
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }

    if (block->prev != NULL) {
        block->prev->next = block->next;
    }
    cm_spin_unlock(&context->lock);
    ddes_update_allocated_context_memory(context, -block->size);
    cm_memory_allocator_t *mem_allocator = &context->mem_allocator;
    mem_allocator->free_proc(block);
}

#ifdef __cplusplus
}
#endif
