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
 * cm_profile_stat.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_profile_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_profile_stat.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_STAT_INTERVAL 3
#define MAX_LINES_PRINT_HEAD 50
#define STAT_THREAD_SLEEP_TIME 100

static thread_t g_profile_stat_thread;
static bool32 g_profile_stat_init = CM_FALSE;
static stat_item_t *g_stat_table[STAT_TABLE_SIZE][MAX_STAT_ITEM_SIZE][MAX_ITEM_COUNT] = {{{0}}};
static uint32 g_stat_count[STAT_TABLE_SIZE][MAX_STAT_ITEM_SIZE] = { {0} };
spinlock_t g_lock;
static thread_local_var stat_item_t *stat_item_local[STAT_TABLE_SIZE][MAX_STAT_ITEM_SIZE] = {{0}};
atomic_t g_stat_table_id;
static stat_result_t g_stat_result;
static const char *g_stat_unit_str[STAT_UNIT_CEIL] = {"", "us", "ms", "s", "byte", "KB", "MB", "GB"};
static stat_item_attr_t g_stat_item_attrs[MAX_STAT_ITEM_SIZE];
static uint32 g_stat_item_count;

status_t cm_register_stat_item(uint32 stat_item_id, const char *name, stat_unit_t unit, uint32 indicator,
    cb_get_value_func_t value_func)
{
    if (CM_IS_EMPTY_STR(name)) {
        return CM_ERROR;
    }
    if (stat_item_id >= MAX_STAT_ITEM_SIZE) {
        return CM_ERROR;
    }
    MEMS_RETURN_IFERR(strcpy_s(g_stat_item_attrs[stat_item_id].name, STAT_ITEM_NAME_MAX_LEN + 1, name));
    g_stat_item_attrs[stat_item_id].unit = unit;
    g_stat_item_attrs[stat_item_id].indicator = indicator;
    g_stat_item_attrs[stat_item_id].func = value_func;
    for (uint32 i = 0; i < stat_item_id; i++) {
        if (CM_IS_EMPTY_STR(g_stat_item_attrs[stat_item_id].name)) {
            return CM_ERROR;
        }
    }
    g_stat_item_count++;
    return CM_SUCCESS;
}

void cm_stat_record(uint32 stat_item_id, uint64 value)
{
    if (!LOG_PROFILE_ON || !g_profile_stat_init) {
        return;
    }
    int64 table_id = cm_atomic_get(&g_stat_table_id);
    stat_item_t *item_local = stat_item_local[table_id][stat_item_id];
    if (item_local == NULL) {
        cm_spin_lock(&g_lock, NULL);
        uint32 cnt = g_stat_count[table_id][stat_item_id];
        if (cnt >= MAX_ITEM_COUNT) {
            cm_spin_unlock(&g_lock);
            return;
        }
        item_local = (stat_item_t *)cm_malloc_prot(sizeof(stat_item_t));
        if (item_local == NULL) {
            cm_spin_unlock(&g_lock);
            return;
        }
        stat_item_local[table_id][stat_item_id] = item_local;
        g_stat_count[table_id][stat_item_id]++;
        cm_spin_unlock(&g_lock);

        item_local->count = 0;
        item_local->value = 0;
        item_local->avg_value = 0;
        item_local->max = 0;
        item_local->min = CM_MAX_UINT64;
        item_local->id = stat_item_id;
        g_stat_table[table_id][stat_item_id][cnt] = item_local;
    }

    item_local->value += value;
    item_local->count++;
    if (g_stat_item_attrs[stat_item_id].indicator & STAT_INDICATOR_MAX) {
        item_local->max = MAX(value, item_local->max);
    }
    if (g_stat_item_attrs[stat_item_id].indicator & STAT_INDICATOR_MIN) {
        item_local->min = MIN(value, item_local->min);
    }
}
static inline int get_cal_table_id(void)
{
    return (int)((uint64)cm_atomic_get(&g_stat_table_id) ^ 1);
}
static inline void cal_item_result_by_ratio(const stat_item_t *stat_item, stat_item_result_t *result, double ratio)
{
    result->id = stat_item->id;
    if (g_stat_item_attrs[stat_item->id].func != NULL) {
        result->value = (double)stat_item->value * ratio;
        return;
    }
    result->value = (double)stat_item->value * ratio / DEFAULT_STAT_INTERVAL;
    result->avg_value = stat_item->avg_value * ratio;
    result->max = (double)stat_item->max * ratio;
    result->min = (double)stat_item->min * ratio;
}

static void transform_unit(stat_item_t *stat_item, stat_item_result_t *result)
{
    uint32 unit = g_stat_item_attrs[stat_item->id].unit;
    result->is_valid = stat_item->count != 0;
    switch (unit) {
        case STAT_UNIT_DEFAULT:
        case STAT_UNIT_BYTES:
        case STAT_UNIT_US:
            cal_item_result_by_ratio(stat_item, result, 1.0);
            break;
        case STAT_UNIT_MS:
            cal_item_result_by_ratio(stat_item, result, 1.0 / MICROSECS_PER_MILLISEC);
            break;
        case STAT_UNIT_S:
            cal_item_result_by_ratio(stat_item, result, 1.0 / MICROSECS_PER_SECOND);
            break;
        case STAT_UNIT_MB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_M(1));
            break;
        case STAT_UNIT_KB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_K(1));
            break;
        case STAT_UNIT_GB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_G(1));
            break;
        default:
            break;
    }
}

static void stat_agg_items(stat_item_t *stat_item)
{
    int cal_table_id = get_cal_table_id();
    if (g_stat_item_attrs[stat_item->id].func != NULL) {
        stat_item->count = 1;
        stat_item->value = (uint64)g_stat_item_attrs[stat_item->id].func(stat_item->id);
        stat_item->avg_value = (double)stat_item->value;
        stat_item->max = stat_item->value;
        stat_item->min = stat_item->value;
        return;
    }
    uint32 item_count_total = g_stat_count[cal_table_id][stat_item->id];
    for (uint32 item_count = 0; item_count < item_count_total; item_count++) {
        stat_item_t *tmp = g_stat_table[cal_table_id][stat_item->id][item_count];
        if (tmp == NULL) {
            continue;
        }
        stat_item->value += tmp->value;
        stat_item->count += tmp->count;
        stat_item->max = ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_MAX) &&
                          (tmp->max > stat_item->max)) ? tmp->max : stat_item->max;
        stat_item->min = ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_MIN)
                          && (tmp->min < stat_item->min)) ? tmp->min : stat_item->min;
        tmp->count = 0;
        tmp->value = 0;
        tmp->max = 0;
        tmp->min = CM_MAX_UINT64;
    }
    if ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_AVG) && stat_item->count != 0) {
        stat_item->avg_value = (double)stat_item->value / (1.0 * (double)stat_item->count);
    }
}

static void stat_calculate(void)
{
    if (!cm_atomic_cas(&g_stat_table_id, 0, 1)) {
        (void)cm_atomic_cas(&g_stat_table_id, 1, 0);
    }
    cm_latch_x(&g_stat_result.latch, 0, NULL);
    for (uint32 i = 0; i < g_stat_item_count; i++) {
        stat_item_t stat_item = { i, 0, 0, 0, 0, CM_MAX_UINT64 };
        stat_agg_items(&stat_item);
        transform_unit(&stat_item, &g_stat_result.result_cache[i]);
    }
    cm_unlatch(&g_stat_result.latch, NULL);
}

static inline status_t build_item_head(const char *item_name, const char *suffix, const char *item_unit, char *item_buf)
{
    item_buf[0] = '\0';
    MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, item_name, strlen(item_name)));
    MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, suffix, strlen(suffix)));
    if (item_unit != NULL && strlen(item_unit) != 0) {
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, "(", 1));
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, item_unit, strlen(item_unit)));
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, ")", 1));
    }
    for (uint32 i = (uint32)strlen(item_buf); i < STAT_ITEM_WIDTH; i++) {
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, " ", 1));
    }
    return CM_SUCCESS;
}

static status_t stat_build_head(char *buf, uint32 begin, uint32 end)
{
    char tmp_buf[STAT_ITEM_WIDTH + 1] =  { 0 };
    for (uint32 i = (uint32)begin; i < (uint32)end; i++) {
        stat_unit_t unit = g_stat_item_attrs[i].unit;
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_ACC) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_AVG) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Avg", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MAX) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Max", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MIN) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Min", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
    }
    return CM_SUCCESS;
}
static status_t stat_concat_content_format(char *buf, double value, bool32 need_converted)
{
    char tmp_buf[STAT_ITEM_WIDTH + 1] = { 0 };
    if (need_converted) {
        PRTS_RETURN_IFERR(
            snprintf_s(tmp_buf, STAT_ITEM_WIDTH + 1, STAT_ITEM_WIDTH, "%-*llu", STAT_ITEM_WIDTH, (uint64)(value)));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(tmp_buf, STAT_ITEM_WIDTH + 1, STAT_ITEM_WIDTH, "%-*.3f", STAT_ITEM_WIDTH, value));
    }
    MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
    return CM_SUCCESS;
}
static status_t stat_build_content(char *buf, uint32 begin, uint32 end)
{
    for (uint32 i = (uint32)begin; i < (uint32)end; i++) {
        bool32 need_converted = g_stat_item_attrs[i].unit == STAT_UNIT_DEFAULT ||
            g_stat_item_attrs[i].unit == STAT_UNIT_US || g_stat_item_attrs[i].unit == STAT_UNIT_BYTES;
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_ACC) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].value, need_converted));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_AVG) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].avg_value, 0));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MAX) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].max, need_converted));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MIN) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].min, need_converted));
        }
    }
    return CM_SUCCESS;
}

// print item content range: [begin, end)
static void stat_print_range(bool8 head_off, uint32 begin, uint32 end)
{
    if (begin > end) {
        return;
    }
    if (end > g_stat_item_count) {
        end = g_stat_item_count;
    }
    char buf[CM_MAX_LOG_CONTENT_LENGTH] = { 0 };
    status_t ret;
    if (!head_off) {
        ret = stat_build_head(buf, begin, end);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[STAT] profile stat build head failed , retcode=%d, error code=%d, error info=%s", ret,
                cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return;
        } else {
            LOG_PROFILE("[STAT] %s", buf);
            buf[0] = '\0';
        }
    }
    cm_latch_s(&g_stat_result.latch, 0, CM_FALSE, NULL);
    ret = stat_build_content(buf, begin, end);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[STAT] profile stat build content failed , retcode=%d, error code=%d, error info=%s", ret,
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
    }
    cm_unlatch(&g_stat_result.latch, NULL);
    LOG_PROFILE("[STAT] %s", buf);
}

static void stat_print(void)
{
    uint32 max_num_aline = DEFAULT_ITEM_NUM_ALINE;
    uint32 i;
    for (i = 0; i < g_stat_item_count; i += max_num_aline) {
        stat_print_range(CM_FALSE, i, i + max_num_aline);
    }
    if (i < g_stat_item_count) {
        stat_print_range(CM_FALSE, i, g_stat_item_count);
    }
}

static void stat_free(void)
{
    for (uint32 table_id = 0; table_id < STAT_TABLE_SIZE; table_id++) {
        for (int item_id = 0; item_id < MAX_STAT_ITEM_SIZE; item_id++) {
            uint32 item_count_total = g_stat_count[table_id][item_id];
            for (uint32 item_count = 0; item_count < item_count_total; item_count++) {
                if (g_stat_table[table_id][item_id][item_count] != NULL) {
                    CM_FREE_PROT_PTR(g_stat_table[table_id][item_id][item_count]);
                    g_stat_table[table_id][item_id][item_count] = NULL;
                }
            }
        }
    }
}

static void cm_profile_stat_entry(thread_t *thread)
{
    cm_set_thread_name("cm_profile_stat");

    date_t last_check_time = g_timer()->now;

    while (!thread->closed) {
        cm_sleep(STAT_THREAD_SLEEP_TIME);
        if (!LOG_PROFILE_ON) {
            continue;
        }
        date_t now = g_timer()->now;
        if (now - last_check_time >= DEFAULT_STAT_INTERVAL * MICROSECS_PER_SECOND) {
            last_check_time = now;
            stat_calculate();
            stat_print();
        }
    }
}

status_t cm_profile_stat_init(void)
{
    if (g_profile_stat_init) {
        return CM_SUCCESS;
    }

    (void)cm_atomic_set(&g_stat_table_id, 0);
    cm_latch_init(&g_stat_result.latch);
    g_stat_item_count = 0;

    status_t ret = cm_create_thread(cm_profile_stat_entry, 0, NULL, &g_profile_stat_thread);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    g_profile_stat_init = CM_TRUE;
    return CM_SUCCESS;
}

void cm_profile_stat_uninit(void)
{
    if (g_profile_stat_init) {
        cm_close_thread(&g_profile_stat_thread);
        stat_free();
    }
    g_profile_stat_init = CM_FALSE;
}

void cm_set_stat_item_null(void)
{
    for (uint32 i = 0; i < STAT_TABLE_SIZE; i++) {
        for (uint32 j = 0; j < MAX_STAT_ITEM_SIZE; j++) {
            stat_item_local[i][j] = NULL;
        }
    }
}

#ifdef __cplusplus
}
#endif