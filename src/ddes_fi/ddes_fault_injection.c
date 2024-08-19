/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * ddes_fault_injection.c
 *
 * Fault categories:
 * - Network
 *   - packet loss
 *   - network latency
 * - CPU
 *   - process latency
 *   - process exit
 * - Customized
 *   - inject customized logic at any location, such as conditional triggering
 *
 * -------------------------------------------------------------------------
 */
#include "ddes_fault_injection.h"
#include <float.h>
#include <stdarg.h>
#include "cm_defs.h"
#include "cm_encrypt.h"
#include "cm_log.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined _DEBUG

static thread_local_var int32 ddes_packet_loss_triggered = CM_FALSE;
static thread_local_var int32 ddes_custom_triggered = CM_FALSE;
static ddes_fi_run_ctx_t *g_ddes_fi_run_ctx = NULL;

int ddes_fi_get_context_size(void)
{
    return sizeof(ddes_fi_run_ctx_t);
}

static void ddes_fi_init_tpe_map(
    ddes_fi_type_mapping_t *ddes_fi_type_map, int fi_type, unsigned int fi_flag, ddes_fi_config_t *config)
{
    ddes_fi_type_map->fi_type = fi_type;
    ddes_fi_type_map->fi_flag = fi_flag;
    ddes_fi_type_map->config = config;
}

void ddes_fi_set_and_init_context(void *context)
{
    if (context == NULL) {
        LOG_DEBUG_ERR("[ddes_fi] Not init the fun ctx");
        return;
    }

    g_ddes_fi_run_ctx  = (ddes_fi_run_ctx_t *)context;
    (void)memset_s(g_ddes_fi_run_ctx, sizeof(ddes_fi_run_ctx_t), 0x00, sizeof(ddes_fi_run_ctx_t));

    ddes_fi_init_tpe_map(&g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_PACKET_LOSS], DDES_FI_TYPE_PACKET_LOSS,
        DDES_FI_PACKET_LOSS_FLAG, &g_ddes_fi_run_ctx->ddes_fi_ctx.ss_fi_packet_loss);

    ddes_fi_init_tpe_map(&g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_NET_LATENCY], DDES_FI_TYPE_NET_LATENCY,
        DDES_FI_NET_LATENCY_FLAG, &g_ddes_fi_run_ctx->ddes_fi_ctx.ss_fi_net_latency);

    ddes_fi_init_tpe_map(&g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_CPU_LATENCY], DDES_FI_TYPE_CPU_LATENCY,
        DDES_FI_CPU_LATENCY_FLAG, &g_ddes_fi_run_ctx->ddes_fi_ctx.ss_fi_cpu_latency);

    ddes_fi_init_tpe_map(&g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_PROCESS_FAULT], DDES_FI_TYPE_PROCESS_FAULT,
        DDES_FI_PROCESS_FAULT_FLAG, &g_ddes_fi_run_ctx->ddes_fi_ctx.ss_fi_process_fault);

    ddes_fi_init_tpe_map(&g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_CUSTOM_FAULT], DDES_FI_TYPE_CUSTOM_FAULT,
        DDES_FI_CUSTOM_FAULT_FLAG, &g_ddes_fi_run_ctx->ddes_fi_ctx.ss_fi_custom_fault);

    LOG_DEBUG_INF("[ddes_fi] init the fun ctx");
}

void ddes_fi_set_context(void *context)
{
    if (context == NULL) {
        LOG_DEBUG_ERR("[ddes_fi] Not init the fun ctx");
        return;
    }

    g_ddes_fi_run_ctx  = (ddes_fi_run_ctx_t *)context;
    LOG_DEBUG_INF("[ddes_fi] init the fun ctx");
}

static inline bool32 ddes_fi_entry_type_active(const ddes_fi_entry_t *entry, int type)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return CM_FALSE;
    }
    unsigned int flag = g_ddes_fi_run_ctx->ddes_fi_type_map[type].fi_flag;
    return entry->faultFlags & flag;
}

static void ddes_fi_inject_network_latency(const ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    if (ddes_fi_entry_type_active(entry, DDES_FI_TYPE_NET_LATENCY)) {
        LOG_DEBUG_INF("[ddes_fi]entry:%d triggers network latency", entry->pointId);
        cm_sleep(g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_NET_LATENCY].config->fault_value);
    }
}

static void ddes_fi_inject_cpu_latency(const ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    if (ddes_fi_entry_type_active(entry, DDES_FI_TYPE_CPU_LATENCY)) {
        LOG_DEBUG_INF("[ddes_fi]entry:%d triggers cpu latency", entry->pointId);
        cm_sleep(g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_CPU_LATENCY].config->fault_value);
    }
}

static void ddes_fi_inject_process_fault(const ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    if (ddes_fi_entry_type_active(entry, DDES_FI_TYPE_PROCESS_FAULT)) {
        uint32 rand = cm_random(DDES_FI_PROB_ALWAYS);
        uint32 prob = g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_PROCESS_FAULT].config->fault_value;
        if (rand < prob) {
            LOG_RUN_INF("[ddes_fi]entry:%d triggers proc fault exit, %d in %d", entry->pointId, rand, prob);
            cm_exit(0);
        }
    }
}

static void ddes_fi_inject_pack_loss(const ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    if (ddes_fi_entry_type_active(entry, DDES_FI_TYPE_PACKET_LOSS)) {
        uint32 rand = cm_random(DDES_FI_PROB_ALWAYS);
        uint32 prob = g_ddes_fi_run_ctx->ddes_fi_type_map[DDES_FI_TYPE_PACKET_LOSS].config->fault_value;
        if (rand < prob) {
            va_list apcopy;
            va_copy(apcopy, args);
            unsigned int cmd = (unsigned int)va_arg(apcopy, unsigned int);
            LOG_DEBUG_INF("[ddes_fi]triggers packloss cmd:%u, %d in %d", cmd, rand, prob);
            ddes_packet_loss_triggered = CM_TRUE;
            va_end(apcopy);
        }
    }
}

static void ddes_fi_inject_custom_fault(ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    if (ddes_fi_entry_type_active(entry, DDES_FI_TYPE_CUSTOM_FAULT)) {
        LOG_DEBUG_INF("[ddes_fi]entry:%d triggers cust fault", entry->pointId);
        va_list apcopy;
        va_copy(apcopy, args);
        ddes_fi_callback_func_t callback = (ddes_fi_callback_func_t)va_arg(apcopy, ddes_fi_callback_func_t);
        entry->func = callback;
        entry->func(entry, apcopy);
        va_end(apcopy);
    }
}

static void ddes_fi_common_injection(ddes_fi_entry_t *entry, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    ddes_fi_inject_network_latency(entry, args);
    ddes_fi_inject_cpu_latency(entry, args);
    ddes_fi_inject_pack_loss(entry, args);
    ddes_fi_inject_process_fault(entry, args);
    ddes_fi_inject_custom_fault(entry, args);
}

void ddes_fi_call(unsigned int point, ...)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    ddes_fi_entry_t *entry = ddes_fi_get_entry(point);
    if (entry != NULL && entry->faultFlags) {
        entry->calledCount++;
        va_list args;
        va_start(args, point);
        ddes_fi_common_injection(entry, args);
        va_end(args);
    }
}

void ddes_fi_call_ex(unsigned int point, va_list args)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    ddes_fi_entry_t *entry = ddes_fi_get_entry(point);
    if (entry != NULL && entry->faultFlags) {
        entry->calledCount++;
        ddes_fi_common_injection(entry, args);
    }
}

int ddes_fi_parse_entry_list(char *value, uint32 *entry_list, uint32 *count)
{
    text_t text = {0};
    text_t entry = {0};
    int32 id = 0;
    *count = 0;
    cm_str2text(value, &text);
    if (text.len == 0 || cm_text_str_equal_ins(&text, "NULL")) {
        return CM_SUCCESS;
    }
    while (cm_fetch_text(&text, ',', '\0', &entry)) {
        if (entry.len == 0) {
            continue;
        }
        cm_trim_text(&entry);
        if (entry.len == 0) {
            continue;
        }
        if (cm_text2int(&entry, &id) != CM_SUCCESS || id < 0 || id >= DDES_FI_ENTRY_END) {
            LOG_DEBUG_ERR("[ddes_fi] entry:%s invalid", entry.str);
            return CM_ERROR;
        }
        if (*count >= DDES_FI_ENTRY_COUNT_PER_TYPE) {
            LOG_DEBUG_ERR("[ddes_fi] entry count:%d too much", *count);
            return CM_ERROR;
        }

        // filter the same id
        for (uint32 i = 0; i < *count; i++) {
            if (entry_list[i] == (uint32)id) {
                LOG_DEBUG_ERR("[ddes_fi] duplicate id:%u", (uint32)id);
                return CM_ERROR;
            }
        }
        entry_list[*count] = (uint32)id;
        *count = *count + 1;
    }
    return CM_SUCCESS;
}

static int is_valid_entry_point(unsigned int point)
{
    return (point < DDES_FI_ENTRY_END);
}

ddes_fi_entry_t *ddes_fi_get_entry(unsigned int point)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return NULL;
    }
    if (!is_valid_entry_point(point)) {
        return NULL;
    }
    return (ddes_fi_entry_t *)&g_ddes_fi_run_ctx->ddes_fi_entry[point];
}

int ddes_fi_get_tls_trigger(void)
{
    return ddes_packet_loss_triggered;
}

void ddes_fi_set_tls_trigger(int val)
{
    ddes_packet_loss_triggered = val;
}

int ddes_fi_get_tls_trigger_custom(void)
{
    return ddes_custom_triggered;
}

void ddes_fi_set_tls_trigger_custom(int val)
{
    ddes_custom_triggered = val;
}

static int ddes_fi_set_type_entries(unsigned int type, unsigned int *entries, unsigned int count)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return CM_ERROR;
    }
    unsigned int *elist = g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->entries;
    unsigned int *elist_count = &(g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->count);
    unsigned int flag = g_ddes_fi_run_ctx->ddes_fi_type_map[type].fi_flag;
    for (unsigned int i = 0; i < count; i++) {
        if (!is_valid_entry_point(entries[i])) {
            LOG_DEBUG_ERR("[ddes_fi] entry idx %u invalid:%u", i, entries[i]);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("[ddes_fi] entry %u activated, flag %u", entries[i], flag);
        DDES_FAULT_INJECTION_ACTIVATE(entries[i], flag);
        elist[i] = entries[i];
    }
    *elist_count = count;
    LOG_DEBUG_INF("[ddes_fi] set entries for type:%u", type);
    return CM_SUCCESS;
}

static void ddes_fi_reset_type_entries(unsigned int type)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return;
    }
    unsigned int *elist = g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->entries;
    unsigned int count = g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->count;
    for (unsigned int i = 0; i < count; ++i) {
        DDES_FAULT_INJECTION_INACTIVE(elist[i], g_ddes_fi_run_ctx->ddes_fi_type_map[type].fi_flag);
    }
    errno_t ret =
        memset_s(elist, sizeof(int) * DDES_FI_ENTRY_COUNT_PER_TYPE, 0, sizeof(int) * DDES_FI_ENTRY_COUNT_PER_TYPE);
    securec_check_panic(ret);
}

int ddes_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count)
{
    if (g_ddes_fi_run_ctx == NULL) {
        LOG_DEBUG_ERR("[ddes_fi] Not init the fun ctx");
        return CM_ERROR;
    }
    if (type >= DDES_FI_TYPE_END) {
        LOG_DEBUG_ERR("[ddes_fi] wrong type");
        return CM_ERROR;
    }
    ddes_fi_reset_type_entries(type);
    return ddes_fi_set_type_entries(type, entries, count);
}

int ddes_fi_parse_and_set_entry_list(unsigned int type, char *value)
{
    if (g_ddes_fi_run_ctx == NULL) {
        LOG_DEBUG_ERR("[ddes_fi] Not init the fun ctx");
        return CM_ERROR;
    }
    uint32 entry_list[DDES_FI_ENTRY_COUNT_PER_TYPE] = {0};
    uint32 count = 0;
    if (value == NULL) {
        LOG_DEBUG_ERR("[ddes_fi] parse NULL entry list fail");
        return CM_ERROR;
    }

    if (ddes_fi_parse_entry_list(value, entry_list, &count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[ddes_fi] parse entry list:[%s] fail", value);
        return CM_ERROR;
    }

    if (ddes_fi_set_entries(type, entry_list, count)) {
        LOG_DEBUG_ERR("[ddes_fi] set entry list fail");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int ddes_fi_set_entry_value(unsigned int type, unsigned int value)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return CM_ERROR;
    }
    if (type >= DDES_FI_TYPE_END) {
        LOG_DEBUG_ERR("[ddes_fi] wrong type");
        return CM_ERROR;
    }
    if (type == DDES_FI_TYPE_PACKET_LOSS || type == DDES_FI_TYPE_PROCESS_FAULT) {
        if (value > DDES_FI_PROB_ALWAYS) {
            LOG_DEBUG_ERR("[ddes_fi] wrong prob value");
            return CM_ERROR;
        }
    }

    unsigned int *var_ptr = &(g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->fault_value);
    *var_ptr = value;
    LOG_DEBUG_INF("[ddes_fi] set type %u fault value %u", type, value);
    return CM_SUCCESS;
}

unsigned int ddes_fi_get_entry_value(unsigned int type)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return 0;
    }
    if (type < DDES_FI_TYPE_END) {
        return g_ddes_fi_run_ctx->ddes_fi_type_map[type].config->fault_value;
    }
    return 0;
}

bool8 ddes_fi_entry_custom_valid(unsigned int point)
{
    if (g_ddes_fi_run_ctx == NULL) {
        return CM_FALSE;
    }
    ddes_fi_entry_t *entry = ddes_fi_get_entry(point);
    return entry != NULL && ddes_fi_entry_type_active(entry, DDES_FI_TYPE_CUSTOM_FAULT);
}

#else
int ddes_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count)
{
    return CM_SUCCESS;
}

int ddes_fi_parse_and_set_entry_list(unsigned int type, char *value)
{
    return CM_SUCCESS;
}

int ddes_fi_set_entry_value(unsigned int type, unsigned int value)
{
    return 0;
}

unsigned int ddes_fi_get_entry_value(unsigned int type)
{
    return 0;
}

ddes_fi_entry_t *ddes_fi_get_entry(unsigned int fi_entry)
{
    return NULL;
}

int ddes_fi_get_tls_trigger()
{
    return 0;
}

void ddes_fi_set_tls_trigger(int val)
{}

int ddes_fi_get_tls_trigger_custom()
{
    return 0;
}

void ddes_fi_set_tls_trigger_custom(int val)
{}

void ddes_fi_call(unsigned int point, ...)
{}

void ddes_fi_call_ex(unsigned int point, va_list args)
{}

bool8 ddes_fi_entry_custom_valid(unsigned int point)
{
    return CM_FALSE;
}

#endif

#ifdef __cplusplus
}
#endif