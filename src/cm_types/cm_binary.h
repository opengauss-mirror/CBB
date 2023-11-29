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
 * cm_binary.h
 *
 *
 * IDENTIFICATION
 *    src/cm_types/cm_binary.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BINARY_H_
#define __CM_BINARY_H_

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_BITMAP_8        (uint8)8
#define CM_BITMAP_64       (uint8)64

typedef struct st_binary {
    uint8 *bytes;
    uint32 size;
} binary_t;

extern const uint8 g_hex2byte_map[];
extern const char g_hex_map[];

static inline uint8 cm_hex2int8(uchar c)
{
    return g_hex2byte_map[c];
}

static inline void cm_rtrim0_binary(binary_t *bin)
{
    while (bin->size > 0 && (bin->bytes[bin->size - 1] == 0)) {
        --bin->size;
    }
}

static inline void cm_bitmap8_set(uint8 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_8);
    *bitmap |= ((uint8)1 << num);
}

static inline void cm_bitmap8_clear(uint8 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_8);
    *bitmap &= (~((uint8)1 << num));
}

static inline bool32 cm_bitmap8_exist(const uint8 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_8);
    return ((*bitmap) & ((uint8)1 << num)) != 0;
}

static inline uint32 cm_bitmap64_count(uint64 bitmap)
{
    uint32 count = 0;
    while (bitmap != 0) {
        bitmap = bitmap & (bitmap - 1);
        count++;
    }
    return count;
}

static inline void cm_bitmap64_set(uint64 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_64);
    *bitmap |= ((uint64)1 << num);
}

static inline void cm_bitmap64_clear(uint64 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_64);
    *bitmap &= (~((uint64)1 << num));
}

static inline bool32 cm_bitmap64_exist(const uint64 *bitmap, uint8 num)
{
    CM_ASSERT(num < CM_BITMAP_64);
    return ((*bitmap) & ((uint64)1 << num)) != 0;
}

static inline uint64 cm_bitmap64_create(const uint8 *inst_id, uint8 inst_count)
{
    uint64 inst_map = 0;
    for (uint8 i = 0; i < inst_count; i++) {
        inst_map |= ((uint64)1 << inst_id[i]);
    }
    return inst_map;
}

static inline uint64 cm_bitmap64_minus(uint64 bitmap1, uint64 bitmap2)
{
    return bitmap1 & (~bitmap2);
}

static inline uint64 cm_bitmap64_union(uint64 bitmap1, uint64 bitmap2)
{
    return bitmap1 | bitmap2;
}

/*
 * if all bits in bitmap2 are also in bitmap1, return true
 * bitmap1 = 1101, bitmap2 = 1001 return true
 * bitmap1 = 1101, bitmap2 = 1011 return false
 */
static inline bool32 cm_bitmap64_include(uint64 bitmap1, uint64 bitmap2)
{
    return (bitmap2 & (~bitmap1)) == 0;
}

/*
 * if there is bit in bitmap2 is also in bitmap1, return true
 * bitmap1 = 1101, bitmap2 = 0010 return false
 * bitmap1 = 1101, bitmap2 = 0011 return true
 */
static inline bool32 cm_bitmap64_exist_ex(uint64 bitmap1, uint64 bitmap2)
{
    return (bitmap1 & bitmap2) != 0;
}

static inline uint64 cm_bitmap64_intersect(uint64 bitmap1, uint64 bitmap2)
{
    return bitmap1 & bitmap2;
}

status_t cm_verify_hex_string(const text_t *text);
status_t cm_bin2str(const binary_t *bin, bool32 hex_prefix, char *str, uint32 buf_len);
status_t cm_bin2text(const binary_t *bin, bool32 hex_prefix, text_t *text);
status_t cm_str2bin(const char *str, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
status_t cm_text2bin(const text_t *text, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
int32 cm_compare_bin(const binary_t *left, const binary_t *right);
status_t cm_concat_bin(binary_t *bin, uint32 bin_len, const binary_t *part);
status_t cm_hex2int64(const char *str, uint32 strlen, int64 *res);

#ifdef __cplusplus
}
#endif

#endif
