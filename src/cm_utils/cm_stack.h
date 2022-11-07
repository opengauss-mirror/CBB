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
 * cm_stack.h
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_STACK_H__
#define __CM_STACK_H__
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_error.h"
#include <string.h>

// reserved size to save the last push_offset
// 8 bytes align
#define GS_PUSH_RESERVE_SIZE 8
#define GS_PUSH_OFFSET_POS 4
#define STACK_MAGIC_NUM (uint32)0x12345678

typedef struct st_stack {
    uint8 *buf;
    uint32 size;
    uint32 push_offset; /* top postion of the stack, begin from max_stack_size to 0  */
    uint32 heap_offset; /* bottom postion of the stack, begin from 0 to max_stack_size */
} cm_stack_t;

static inline void cm_stack_reset(cm_stack_t *stack)
{
    stack->push_offset = stack->size;
    stack->heap_offset = 0;
}

static inline void *cm_push(cm_stack_t *stack, uint32 size)
{
    uint32 last_offset;
    uint32 actual_size = CM_ALIGN8(size) + GS_PUSH_RESERVE_SIZE;
    uint8 *ptr = stack->buf + stack->push_offset - actual_size + GS_PUSH_RESERVE_SIZE;

    if (stack->push_offset < (uint64)stack->heap_offset + actual_size) {
        return NULL;
    }

    last_offset = stack->push_offset;
    stack->push_offset -= actual_size;
    *(uint32 *)(stack->buf + stack->push_offset + GS_PUSH_OFFSET_POS) = last_offset;

    return ptr;
}

static inline void cm_pop(cm_stack_t *stack)
{
    if (stack->push_offset == stack->size) {
        return;
    }

    stack->push_offset = *(uint32 *)(stack->buf + stack->push_offset + GS_PUSH_OFFSET_POS);
}

static inline void cm_pop_to(cm_stack_t *stack, uint32 push_offset)
{
    if (stack->push_offset >= push_offset) {
        return;
    }

    stack->push_offset = push_offset;
}

static inline status_t cm_stack_alloc(void *owner, uint32 size, void **ptr)
{
    cm_stack_t *stack = (cm_stack_t *)owner;
    uint32 actual_size = CM_ALIGN8(size);
    if ((uint64)stack->heap_offset + actual_size >= stack->push_offset) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY);
        return CM_ERROR;
    }

    *ptr = stack->buf + stack->heap_offset;
    stack->heap_offset += actual_size;
    return CM_SUCCESS;
}

static inline void *cm_stack_heap_head(cm_stack_t *stack)
{
    return (stack->buf + stack->heap_offset);
}

static inline void cm_stack_heap_reset(cm_stack_t *stack, void *to)
{
    stack->heap_offset = (uint32)((uint8 *)to - stack->buf);
}

static inline void cm_stack_init(cm_stack_t *stack, char *buf, uint32 buf_size)
{
    CM_ASSERT(stack != NULL);
    MEMS_RETVOID_IFERR(memset_sp(stack, sizeof(cm_stack_t), 0, sizeof(cm_stack_t)));

    stack->buf = (uint8 *)buf;
    stack->size = buf_size;
    cm_stack_reset(stack);
}

static inline void cm_keep_stack_variant(cm_stack_t *stack, char *buf)
{
    if (buf == NULL) {
        return;
    }
    if (buf < (char *)(stack->buf + stack->heap_offset) ||
        buf >= (char *)stack->buf + stack->push_offset + GS_PUSH_RESERVE_SIZE) {
        return;
    }

    stack->push_offset = (uint32)(buf - (char *)stack->buf - GS_PUSH_RESERVE_SIZE);
}

#endif
