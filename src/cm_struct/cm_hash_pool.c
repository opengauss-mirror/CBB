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
 * cm_hash_pool.c
 *
 *
 * IDENTIFICATION
 *    src/cm_struct/cm_hash_pool.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_hash_pool.h"
#include "cm_log.h"

static cm_hash_item_t *find_in_hash_bucket(const cm_hash_pool_t *pool, const cm_hash_bucket_t *bucket, void *data,
                                           bool32 is_lock)
{
    cm_hash_item_t *item = bucket->first;
    while (item != NULL) {
        if (pool->profile.cb_match_data(data, item->data)) {
            if (is_lock) {
                cm_spin_lock(&item->lock, NULL);
            }
            break;
        }
        item = item->next;
    }
    return item;
}

static void add_to_hash_bucket_nolock(cm_hash_pool_t *pool, cm_hash_bucket_t *bucket, cm_hash_item_t *item)
{
    item->prev = NULL;
    item->next = bucket->first;
    if (bucket->first != NULL) {
        bucket->first->prev = item;
    }
    bucket->first = item;
    bucket->count++;
}

static void del_from_hash_bucket_nolock(cm_hash_pool_t *pool, cm_hash_bucket_t *bucket, cm_hash_item_t *item)
{
    if (item->prev != NULL) {
        item->prev->next = item->next;
    }

    if (item->next != NULL) {
        item->next->prev = item->prev;
    }

    if (bucket->first == item) {
        bucket->first = item->next;
    }

    bucket->count--;
    item->prev = item->next = NULL;
}

static void add_to_free_list_nolock(cm_hash_bucket_t *free_list, cm_hash_item_t *item)
{
    item->prev = NULL;
    item->next = free_list->first;
    if (free_list->first != NULL) {
        free_list->first->prev = item;
    }
    free_list->first = item;
    free_list->count++;
}

static status_t try_extend_free_list(cm_hash_pool_t *pool)
{
    cm_hash_item_t *extent = NULL;
    cm_hash_item_t *curr = NULL;
    cm_hash_item_t *next = NULL;
    cm_hash_bucket_t *free_list = &pool->free_list;
    if (pool->hwm >= HASH_MAX_SIZE) {
        LOG_DEBUG_ERR("too many objects, pool name: %s, max size:%u", HASH_NAME, HASH_MAX_SIZE);
        return CM_ERROR;
    }
    uint32 size = (uint32)((ENTRY_SIZE + HASH_ITEM_SIZE) * HASH_MEM_EXTENT_SIZE);
    extent = (cm_hash_item_t *)cm_malloc_prot(size);
    if (extent == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, pool->profile.name);
        return CM_ERROR;
    }
    errno_t ret = memset_sp(extent, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(extent);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    curr = extent;
    for (uint32 i = 0; i < HASH_MEM_EXTENT_SIZE - 1; i++) {
        next = (cm_hash_item_t *)((char *)curr + (ENTRY_SIZE + HASH_ITEM_SIZE));
        curr->next = next;
        next->prev = curr;
        curr = next;
    }

    free_list->first = extent;
    free_list->count = HASH_MEM_EXTENT_SIZE;
    pool->hwm += HASH_MEM_EXTENT_SIZE;
    pool->pages[pool->count++] = (char *)extent;

    return CM_SUCCESS;
}

static status_t remove_from_free_list(cm_hash_pool_t *pool, cm_hash_item_t **item)
{
    cm_hash_bucket_t *free_list = HASH_FREE_LIST;

    cm_spin_lock(&free_list->lock, NULL);
    if (free_list->count == 0) {
        if (try_extend_free_list(pool) != CM_SUCCESS) {
            cm_spin_unlock(&free_list->lock);
            return CM_ERROR;
        }
    }

    *item = free_list->first;
    free_list->first = (*item)->next;
    (*item)->next = NULL;
    if (free_list->first != NULL) {
        free_list->first->prev = NULL;
    }
    free_list->count--;
    cm_spin_unlock(&free_list->lock);

    return CM_SUCCESS;
}

static void add_to_free_list(cm_hash_bucket_t *free_list, cm_hash_item_t *item)
{
    cm_spin_lock(&free_list->lock, NULL);
    add_to_free_list_nolock(free_list, item);
    cm_spin_unlock(&free_list->lock);
}

status_t cm_hash_pool_create(cm_hash_profile_t *profile, cm_hash_pool_t *pool)
{
    CM_RETURN_ERR_IF_NULL_PTR(profile);
    MEMS_RETURN_IFERR(memset_sp(pool, sizeof(cm_hash_pool_t), 0, sizeof(cm_hash_pool_t)));
    MEMS_RETURN_IFERR(memcpy_sp(&pool->profile, sizeof(cm_hash_profile_t), (void *)profile, sizeof(cm_hash_profile_t)));

    uint32 mem_size = (uint32)(profile->bucket_num * sizeof(cm_hash_bucket_t));
    pool->buckets = (cm_hash_bucket_t *)cm_malloc_prot(mem_size);
    if (pool->buckets == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, mem_size, profile->name);
        return CM_ERROR;
    }
    errno_t ret = memset_sp(pool->buckets, mem_size, 0, mem_size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(pool->buckets);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    mem_size = (uint32)(CM_ALIGN_CEIL(HASH_MAX_SIZE, HASH_MEM_EXTENT_SIZE) * sizeof(char *));
    pool->pages = (char **)cm_malloc_prot(mem_size);
    if (pool->pages == NULL) {
        CM_FREE_PROT_PTR(pool->buckets);
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, mem_size, profile->name);
        return CM_ERROR;
    }

    ret = memset_sp(pool->pages, mem_size, 0, mem_size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(pool->buckets);
        CM_FREE_PROT_PTR(pool->pages);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    init_hash_bucket(&pool->free_list);
    return CM_SUCCESS;
}

void *cm_hash_pool_match_nolock(const cm_hash_pool_t *pool, void *data)
{
    void *match_data = NULL;
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];
    cm_hash_item_t *item = NULL;

    cm_spin_lock(&bucket->lock, NULL);
    item = find_in_hash_bucket(pool, bucket, data, CM_FALSE);
    if (item != NULL) {
        match_data = item->data;
    }
    cm_spin_unlock(&bucket->lock);

    return match_data;
}

void *cm_hash_pool_match_lock(const cm_hash_pool_t *pool, void *data)
{
    void *match_data = NULL;
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];
    cm_hash_item_t *item = NULL;

    cm_spin_lock(&bucket->lock, NULL);
    item = find_in_hash_bucket(pool, bucket, data, CM_TRUE);
    if (item != NULL) {
        match_data = item->data;
    }
    cm_spin_unlock(&bucket->lock);

    return match_data;
}

void *cm_hpool_match_key_lock(const cm_hash_pool_t *pool, void *data)
{
    void *match_data = NULL;
    cm_hash_item_t *item = NULL;
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];

    cm_spin_lock(&bucket->lock, NULL);
    item = find_in_hash_bucket(pool, bucket, data, CM_TRUE);
    if (item != NULL) {
        match_data = item->data;
    }

    return match_data;
}

void cm_hpool_bucket_unlock(const cm_hash_pool_t *pool, void *data)
{
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];
    cm_spin_unlock(&bucket->lock);
}

status_t cm_hpool_add_item_nolock(cm_hash_pool_t *pool, void *data, cm_hash_item_t **entry)
{
    cm_hash_item_t *item = NULL;
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];

    item = find_in_hash_bucket(pool, bucket, data, CM_FALSE);
    if (item != NULL) {
        return CM_ERROR;
    }

    if (remove_from_free_list(pool, &item) != CM_SUCCESS) {
        return CM_ERROR;
    }
    errno_t ret = memcpy_sp(item->data, ENTRY_SIZE, data, ENTRY_SIZE);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    add_to_hash_bucket_nolock(pool, bucket, item);
    *entry = item;
    return CM_SUCCESS;
}

status_t cm_hash_pool_add(cm_hash_pool_t *pool, void *data)
{
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];
    cm_hash_item_t *item = NULL;

    cm_spin_lock(&bucket->lock, NULL);
    item = find_in_hash_bucket(pool, bucket, data, CM_FALSE);
    if (item != NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }

    if (remove_from_free_list(pool, &item) != CM_SUCCESS) {
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }
    errno_t ret = memcpy_sp(item->data, ENTRY_SIZE, data, ENTRY_SIZE);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }

    add_to_hash_bucket_nolock(pool, bucket, item);
    cm_spin_unlock(&bucket->lock);

    return CM_SUCCESS;
}

void cm_hash_pool_del(cm_hash_pool_t *pool, void *data)
{
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];
    cm_hash_item_t *item = NULL;

    cm_spin_lock(&bucket->lock, NULL);
    item = find_in_hash_bucket(pool, bucket, data, CM_TRUE);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    del_from_hash_bucket_nolock(pool, bucket, item);
    cm_spin_unlock(&item->lock);
    add_to_free_list(&pool->free_list, item);
    cm_spin_unlock(&bucket->lock);

    return;
}

cm_hash_item_t *cm_hpool_del_from_bucket(cm_hash_pool_t *pool, void *data)
{
    cm_hash_item_t *item = NULL;
    uint32 hash_val = pool->profile.cb_hash_data(data);
    hash_val = hash_val % pool->profile.bucket_num;
    cm_hash_bucket_t *bucket = &pool->buckets[hash_val];

    item = find_in_hash_bucket(pool, bucket, data, CM_TRUE);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return item;
    }

    del_from_hash_bucket_nolock(pool, bucket, item);
    cm_spin_unlock(&item->lock);

    return item;
}

void cm_hpool_add_to_free_list(cm_hash_pool_t *pool, cm_hash_item_t *item)
{
    if (item == NULL) {
        return;
    }
    add_to_free_list(&pool->free_list, item);
}

void cm_hash_pool_destory(cm_hash_pool_t *pool)
{
    for (uint32 i = 0; i < pool->count; i++) {
        CM_FREE_PROT_PTR(pool->pages[i]);
    }
    CM_FREE_PROT_PTR(pool->buckets);
    CM_FREE_PROT_PTR(pool->pages);
    pool->count = 0;
    pool->hwm = 0;
    init_hash_bucket(&pool->free_list);
}
