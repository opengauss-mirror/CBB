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
 * ddes_fault_injection.h
 * the ways to perform fault injection:
 * compile DEBUG, which registers all FI triggers at set_ddes_fi
 *
 * -------------------------------------------------------------------------
 */
#ifndef DDES_FAULT_INJECTION_H
#define DDES_FAULT_INJECTION_H

#include "cm_types.h"
#include "cm_config.h"
#include "ddes_fault_injection_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct ddes_fi_config {
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    unsigned int fault_value;
} ddes_fi_config_t;

typedef struct st_fi_context {
    ddes_fi_config_t ss_fi_packet_loss;
    ddes_fi_config_t ss_fi_net_latency;
    ddes_fi_config_t ss_fi_cpu_latency;
    ddes_fi_config_t ss_fi_process_fault;
    ddes_fi_config_t ss_fi_custom_fault;
} ddes_fi_context_t;

typedef int (*ddes_fi_callback_func_t)(const void *ddes_fi_entry, va_list args);

typedef struct st_ddes_fi_entry {
    int pointId;
    unsigned int faultFlags;
    int calledCount;
    ddes_fi_callback_func_t func;
} ddes_fi_entry_t;

// begin: SHOULD call these by caller to init fi context before using other interfaces
DDES_DECLARE int ddes_fi_get_context_size(void);
DDES_DECLARE void ddes_fi_set_and_init_context(void *context);
DDES_DECLARE void ddes_fi_set_context(void *context);
// end: SHOULD call these by caller to init fi context before using other interfaces

DDES_DECLARE int ddes_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count);
DDES_DECLARE int ddes_fi_parse_and_set_entry_list(unsigned int type, char *value);
DDES_DECLARE unsigned int ddes_fi_get_entry_value(unsigned int type);
DDES_DECLARE int ddes_fi_set_entry_value(unsigned int type, unsigned int value);
DDES_DECLARE int ddes_fi_get_tls_trigger(void);
DDES_DECLARE void ddes_fi_set_tls_trigger(int val);
DDES_DECLARE int ddes_fi_get_tls_trigger_custom(void);
DDES_DECLARE void ddes_fi_set_tls_trigger_custom(int val);
DDES_DECLARE void ddes_fi_call(unsigned int point, ...);
DDES_DECLARE void ddes_fi_call_ex(unsigned int point, va_list args);
DDES_DECLARE bool8 ddes_fi_entry_custom_valid(unsigned int point);

ddes_fi_entry_t *ddes_fi_get_entry(unsigned int fi_entry);

#if defined _DEBUG

#define DDES_FI_PROB_NEVER 0
#define DDES_FI_PROB_ALWAYS 100
#define DDES_FI_NORMAL_FLAG 0
#define DDES_FI_PACKET_LOSS_FLAG 1
#define DDES_FI_NET_LATENCY_FLAG 2
#define DDES_FI_CPU_LATENCY_FLAG 4
#define DDES_FI_PROCESS_FAULT_FLAG 8
#define DDES_FI_CUSTOM_FAULT_FLAG 0x10

typedef struct st_fi_type_map {
    int fi_type;
    unsigned int fi_flag;
    ddes_fi_config_t *config;
} ddes_fi_type_mapping_t;

typedef struct st_fi_run_ctx {
    ddes_fi_entry_t ddes_fi_entry[DDES_FI_ENTRY_END];
    ddes_fi_context_t ddes_fi_ctx;
    ddes_fi_type_mapping_t ddes_fi_type_map[DDES_FI_TYPE_END];
} ddes_fi_run_ctx_t;

#define DDES_FAULT_INJECTION_ACTIVATE(point, flag)         \
    do {                                                   \
        ddes_fi_entry_t *entry = ddes_fi_get_entry(point); \
        if (entry != NULL) {                               \
            entry->faultFlags |= flag;                     \
            entry->pointId = point;                        \
        }                                                  \
    } while (0)

#define DDES_FAULT_INJECTION_INACTIVE(point, flag)         \
    do {                                                   \
        ddes_fi_entry_t *entry = ddes_fi_get_entry(point); \
        if (entry != NULL) {                               \
            entry->faultFlags &= (~flag);                  \
        }                                                  \
    } while (0)

#define DDES_FAULT_INJECTION_ACTION_TRIGGER(action)                           \
    do {                                                                      \
        if (ddes_fi_get_tls_trigger() == CM_TRUE) {                           \
            ddes_fi_set_tls_trigger(CM_FALSE);                                \
            LOG_DEBUG_INF("[ddes_fi] fi action happens at %s", __FUNCTION__); \
            action;                                                           \
        }                                                                     \
    } while (0)

#define DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(point, action)                                   \
    do {                                                                                            \
        if (ddes_fi_entry_custom_valid(point) && ddes_fi_get_tls_trigger_custom() == CM_TRUE) {     \
            ddes_fi_set_tls_trigger_custom(CM_FALSE);                                               \
            LOG_DEBUG_INF("[ddes_fi] fi cust action happens at %s", __FUNCTION__);                  \
            action;                                                                                 \
        }                                                                                           \
    } while (0)

#define DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM_ALWAYS(point, action)            \
    do {                                                                            \
        if (ddes_fi_entry_custom_valid(point)) {                                    \
            LOG_DEBUG_INF("[ddes_fi] fi cust action happens at %s", __FUNCTION__);  \
            action                                                                  \
        }                                                                           \
    } while (0)

#define DDES_FAULT_INJECTION_CALL(point, ...)              \
    do {                                                   \
        ddes_fi_entry_t *entry = ddes_fi_get_entry(point); \
        if (entry != NULL && entry->faultFlags) {          \
            ddes_fi_call(point, ##__VA_ARGS__);            \
        }                                                  \
    } while (0)

#else

#define DDES_FAULT_INJECTION_ACTIVATE(point, flag)
#define DDES_FAULT_INJECTION_INACTIVE(point, flag)
#define DDES_FAULT_INJECTION_ACTION_TRIGGER(action)
#define DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(point, action)
#define DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM_ALWAYS(point, action)
#define DDES_FAULT_INJECTION_CALL(point, ...)

#endif

#ifdef __cplusplus
}
#endif

#endif  // DDES_FAULT_INJECTION_H