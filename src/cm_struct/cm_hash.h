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
 * cm_hash.h
 *
 *
 * IDENTIFICATION
 *    src/cm_struct/cm_hash.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HASH_H__
#define __CM_HASH_H__

#include "cm_defs.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    uint64 u64;
    struct {
        uint32 u32p0;
        uint32 u32p1;
    };
} u64shape_t;

typedef union {
    uint8 bytes[4]; /* used for handling different endian */
    uint32 value;
} endian_t;

#define CM_HASH_INIT(key, len) (0x9E735650 + (len))
#define HASH_BYTE_BATCH 12
#define HASH_DIM_BATCH 3
#define HASH_WORD_SIZE 4
#define HASH_DIM_INDEX_0 0
#define HASH_DIM_INDEX_1 1
#define HASH_DIM_INDEX_2 2
#define BIT_NUM_INT32 32

typedef union {
    uint8 bytes[HASH_BYTE_BATCH];
    uint32 dim[HASH_DIM_BATCH];
    endian_t e[HASH_DIM_BATCH];
} hash_helper_t;

#define HASH_RESULT(hs) ((hs)->e[2].value)

/** left rotate u32 by n bits */
static inline uint32 cm_crol(uint32 u32, uint32 n)
{
#ifdef WIN32
    u64shape_t shape;
    shape.u64 = ((uint64)u32) << n;
    return shape.u32p0 | shape.u32p1;
#else
    /* In GCC or Linux, this following codes can be optimized by merely
     * one instruction, i.e.: rol  eax, cl */
    return (u32 >> (UINT32_BITS - n)) | (u32 << n);
#endif
}

#define INFINITE_HASH_RANGE (uint32)0
#define HASH_PRIME          (uint32)0x01000193
#define HASH_SEED           (uint32)0x811c9dc5
#define BACKWARD_MAPPING(hs, i, j, k, n) \
((hs)->dim[i] = (((hs)->dim[i] ^ (hs)->dim[j]) - cm_crol((hs)->dim[j], ((n) + (k) - (j)))))

static inline void cm_init_hash_helper(const uint8 *key, uint32 len, hash_helper_t *hs)
{
    uint32 init_val = CM_HASH_INIT(key, len);
    hs->dim[HASH_DIM_INDEX_0] = init_val;
    hs->dim[HASH_DIM_INDEX_1] = init_val;
    hs->dim[HASH_DIM_INDEX_2] = init_val;
}

static inline void cm_backward_transform(hash_helper_t *hs)
{
    BACKWARD_MAPPING(hs, 2, 1, 0, 15);
    BACKWARD_MAPPING(hs, 0, 2, 1, 12);
    BACKWARD_MAPPING(hs, 1, 0, 2, 23);
    BACKWARD_MAPPING(hs, 2, 1, 0, 17);
    BACKWARD_MAPPING(hs, 0, 2, 1, 5);
    BACKWARD_MAPPING(hs, 1, 0, 2, 12);
    BACKWARD_MAPPING(hs, 2, 1, 0, 25);
}

static inline uint32 cm_hash_uint32(uint32 i32, uint32 range)
{
    uint32 hval = i32 * HASH_SEED;
    if (range != INFINITE_HASH_RANGE) {
        return hval % range;
    }
    return hval;
}

uint32 cm_hash_bytes(const uint8 *bytes, uint32 size, uint32 range);
uint32 cm_hash_uint32_shard(uint32 val);

typedef struct st_hash_node {
    struct st_hash_node *next;
} hash_node_t;

typedef status_t (*f_malloc_t)(void *ctx, uint32 size, void **buf);
typedef void (*f_free_t)(void *ctx, void *buf);
typedef struct st_cm_allocator_t {
    f_malloc_t f_alloc;
    f_free_t f_free;
    void *mem_ctx;
}cm_allocator_t;

typedef bool32 (*hash_equal_t)(void *lkey, void *rkey);
typedef uint32 (*hash_func_t)(void *key);
typedef void *(*hash_key_t)(hash_node_t *node);

typedef struct st_hash_funcs {
    hash_key_t f_key;
    hash_equal_t f_equal;
    hash_func_t f_hash;
} hash_funcs_t;

typedef struct st_hash_map {
    hash_node_t **buckets;
    uint32 bucket_num;
} hash_map_t;

static inline status_t cm_hmap_init(hash_map_t *hmap, cm_allocator_t *alloc, uint32 buckets)
{
    uint32 size = (uint32)sizeof(hash_node_t *) * buckets;
    CM_RETURN_IFERR(alloc->f_alloc(alloc->mem_ctx, size, (void **)&hmap->buckets));
    MEMS_RETURN_IFERR(memset_s(hmap->buckets, size, 0, size));
    hmap->bucket_num = buckets;
    return CM_SUCCESS;
}

bool32 cm_hmap_insert(hash_map_t *hmap, hash_funcs_t *hfuncs, hash_node_t *node);
hash_node_t *cm_hmap_find(hash_map_t *hmap, hash_funcs_t *hfuncs, void *key);
hash_node_t *cm_hmap_delete(hash_map_t *hmap, hash_funcs_t *hfuncs, void *key);
void cm_hmap_begin(hash_map_t *hmap, hash_node_t **beg);
void cm_hmap_next(hash_map_t *hmap, hash_funcs_t *hfuncs, hash_node_t **curr);

#ifdef __cplusplus
}
#endif

#endif
