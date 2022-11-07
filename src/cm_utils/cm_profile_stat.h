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
 * cm_profile_stat.h
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_profile_stat.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CBB_CM_PROFILE_STAT_H__
#define __CBB_CM_PROFILE_STAT_H__

#include <cm_error.h>
#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "cm_date_to_text.h"
#include "cm_date.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "cm_file.h"


#define MAX_ITEM_COUNT 100
#define STAT_TABLE_SIZE 2
#define STAT_ITEM_WIDTH 21
#define STAT_ITEM_NAME_MAX_LEN 20

#define STAT_INDICATOR_ACC 0x00000001
#define STAT_INDICATOR_AVG 0x00000002
#define STAT_INDICATOR_MAX 0x00000004
#define STAT_INDICATOR_MIN 0x00000010

typedef enum stat_unit {
    STAT_UNIT_DEFAULT = 0,
    STAT_UNIT_US,
    STAT_UNIT_MS,
    STAT_UNIT_S,
    STAT_UNIT_BYTES,
    STAT_UNIT_KB,
    STAT_UNIT_MB,
    STAT_UNIT_GB,
    STAT_UNIT_CEIL
} stat_unit_t;

typedef int64 (*cb_get_value_func_t)(uint32 stat_id);
typedef struct stat_item_attr {
    char name[STAT_ITEM_NAME_MAX_LEN];
    stat_unit_t unit;
    uint32 indicator;
    cb_get_value_func_t func;
} stat_item_attr_t;
#define MAX_STAT_ITEM_SIZE (128)
#define DEFAULT_ITEM_NUM_ALINE (7)
typedef struct stat_item {
    uint32 id;
    uint64 count;
    uint64 value;
    double avg_value;
    uint64 max;
    uint64 min;
} stat_item_t;

typedef struct stat_item_result {
    uint32 id;
    latch_t latch;
    uint32 is_valid;
    double value;
    double avg_value;
    double max;
    double min;
} stat_item_result_t;

typedef struct stat_result {
    latch_t latch;
    stat_item_result_t result_cache[MAX_STAT_ITEM_SIZE];
} stat_result_t;


status_t cm_profile_stat_init(void);
void cm_profile_stat_uninit(void);
// if print callback function value, need set value_func cb
status_t cm_register_stat_item(uint32 stat_item_id, const char *name, stat_unit_t unit, uint32 indicator,
    cb_get_value_func_t value_func);
void cm_stat_record(uint32 stat_item_id, uint64 value);
void cm_set_stat_item_null(void);


#endif
