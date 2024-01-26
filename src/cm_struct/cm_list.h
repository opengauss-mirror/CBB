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
 * cm_list.h
 *
 *
 * IDENTIFICATION
 *    src/cm_struct/cm_list.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LIST_H__
#define __CM_LIST_H__
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_debug.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LIST_EXTENT_SIZE 32

/* pointer list */
typedef struct st_ptlist {
    pointer_t *items;
    uint32 capacity;
    uint32 count;
} ptlist_t;

static inline void cm_ptlist_init(ptlist_t *list)
{
    list->items = NULL;
    list->capacity = 0;
    list->count = 0;
}

static inline void cm_ptlist_reset(ptlist_t *list)
{
    list->count = 0;
}

static inline void cm_destroy_ptlist(ptlist_t *list)
{
    if (list->items != NULL) {
        CM_FREE_PROT_PTR(list->items);
    }

    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static inline pointer_t cm_ptlist_get(ptlist_t *list, uint32 index)
{
    if (index >= list->capacity) {
        return NULL;
    }
    return list->items[index];
}

static inline void cm_ptlist_set(ptlist_t *list, uint32 index, pointer_t item)
{
    list->items[index] = item;
}

static inline status_t cm_ptlist_extend(ptlist_t *list, uint32 extent_size)
{
    pointer_t *new_items = NULL;
    uint32 buf_size;
    errno_t errcode;
    buf_size = (uint32)((list->capacity + extent_size) * sizeof(pointer_t));
    if (buf_size == 0 || (buf_size / sizeof(pointer_t) != list->capacity + extent_size)) {
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    new_items = (pointer_t *)cm_malloc_prot(buf_size);
    if (new_items == NULL) {
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    errcode = memset_sp(new_items, (size_t)buf_size, 0, (size_t)buf_size);
    if (errcode != EOK) {
        CM_FREE_PROT_PTR(new_items);
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    if (list->items != NULL) {
        if (list->capacity != 0) {
            errcode = memcpy_sp(new_items, (size_t)buf_size, list->items, (size_t)(list->capacity * sizeof(pointer_t)));
            if (errcode != EOK) {
                CM_FREE_PROT_PTR(new_items);
                LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
                return CM_ERROR;
            }
        }

        CM_FREE_PROT_PTR(list->items);
    }
    list->items = new_items;
    list->capacity += extent_size;

    return CM_SUCCESS;
}

static inline status_t cm_ptlist_add(ptlist_t *list, pointer_t item)
{
    if (list->count >= list->capacity) { /* extend the list */
        if (cm_ptlist_extend(list, LIST_EXTENT_SIZE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    list->items[list->count] = item;
    list->count++;
    return CM_SUCCESS;
}

static inline status_t cm_ptlist_insert(ptlist_t *list, uint32 index, pointer_t item)
{
    if (index >= list->capacity) { /* extend the list */
        if (cm_ptlist_extend(list, (index - list->capacity) + LIST_EXTENT_SIZE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    list->count++;
    list->items[index] = item;
    return CM_SUCCESS;
}

static inline status_t cm_ptlist_remove(ptlist_t *list, uint32 index)
{
    if (index >= list->capacity || list->count == 0) {
        LOG_DEBUG_ERR("cm_ptlist_remove failed");
        return CM_ERROR;
    }
    if (list->items[index] == NULL) {
        return CM_SUCCESS;
    }
    list->items[index] = NULL;
    list->count--;
    return CM_SUCCESS;
}

/** linked list below */
typedef struct st_linked_list {
    struct st_linked_list *next, *prev;
} linked_list_t;

static inline void cm_linked_list_init(linked_list_t *linkedList)
{
    CM_ASSERT(linkedList != NULL);
    linkedList->next = linkedList;
    linkedList->prev = linkedList;
}

static inline bool8 cm_linked_list_empty(const linked_list_t *linkedList)
{
    CM_ASSERT(linkedList != NULL);
    return linkedList->next == linkedList;
}

static inline bool8 cm_linked_list_is_head(const linked_list_t *linkedList, const linked_list_t *linkedListNode)
{
    CM_ASSERT(linkedList != NULL);
    return linkedList->next == linkedListNode;
}

static inline bool8 cm_linked_list_is_tail(const linked_list_t *linkedList, const linked_list_t *linkedListNode)
{
    CM_ASSERT(linkedList != NULL);
    return linkedList->prev == linkedListNode;
}

static inline void cm_linked_list_insert(linked_list_t *node, linked_list_t *newNode)
{
    CM_ASSERT(node != NULL);
    CM_ASSERT(newNode != NULL);
    newNode->prev = node->prev;
    newNode->next = node;
    newNode->prev->next = newNode;
    newNode->next->prev = newNode;
}

static inline void cm_linked_list_append(linked_list_t *node, linked_list_t *newNode)
{
    cm_linked_list_insert((linked_list_t *)node, newNode);
}

static inline void cm_linked_list_prepend(linked_list_t *node, linked_list_t *newNode)
{
    CM_ASSERT(node != NULL);
    CM_ASSERT(newNode != NULL);
    cm_linked_list_insert(node->next, newNode);
}

static inline void cm_linked_list_remove(const linked_list_t *node)
{
    CM_ASSERT(node != NULL);
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

static inline void cm_linked_list_remove_head(const linked_list_t *node)
{
    CM_ASSERT(node != NULL);
    cm_linked_list_remove(node->next);
}

static inline void cm_linked_list_remove_tail(const linked_list_t *node)
{
    CM_ASSERT(node != NULL);
    cm_linked_list_remove(node->prev);
}

static inline void cm_linked_list_add_tail(linked_list_t *destNode, const linked_list_t *srcNode)
{
    srcNode->next->prev = destNode->prev;
    destNode->prev->next = srcNode->next;
    srcNode->prev->next = destNode;
    destNode->prev = srcNode->prev;
}

#define LIST_ENTRY(linkedList, type, member) \
    ((type *)((char *)(linkedList) - (unsigned long)(&((type *)0)->member)))

#define LIST_HEAD(linkedList, type, member) \
    LIST_ENTRY((linkedList)->next, type, member)

#define LIST_NEXT(elem, member) \
    LIST_ENTRY((elem)->member.next, __typeof__(*(elem)), member)

#define LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, linkedList, member) \
    for ((pos) = LIST_HEAD((linkedList), __typeof__(*(pos)), member), (tmp) = LIST_NEXT((pos), member); \
        &(pos)->member != (linkedList); \
        pos = (tmp), (tmp) = LIST_NEXT((pos), member))

#ifdef __cplusplus
}
#endif

#endif
