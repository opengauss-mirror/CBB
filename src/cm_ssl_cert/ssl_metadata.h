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
 * ssl_metadata.h
 *
 *
 * IDENTIFICATION
 *    src/cm_ssl_cert/ssl_metadata.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SSL_METADATA_H__
#define __SSL_METADATA_H__

#include "cm_types.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_latch.h"
#include "cm_list.h"
#include "cm_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif


#define CERT_SSL_NOTI_TIME_MIN   7
#define CERT_SSL_NOTI_TIME_MAX   180
#define CERT_MAX_CHAR_ARRAY_LEN 256

typedef enum en_cert_param {
    CERT_PARAM_UNKNOWN = 0,
    CERT_PARAM_SER_SSL_CA,
    CERT_PARAM_SER_SSL_KEY,
    CERT_PARAM_SER_SSL_CERT,
    CERT_PARAM_SER_SSL_CRL,
    CERT_PARAM_SER_SSL_CERT_NOTIFY_TIME,
    CERT_PARAM_CLI_SSL_CA,
    CERT_PARAM_CLI_SSL_KEY,
    CERT_PARAM_CLI_SSL_CERT,
    CERT_PARAM_CLI_SSL_CRL,
    CERT_PARAM_CLI_SSL_CERT_NOTIFY_TIME,
    CERT_PARAM_CEIL,
} cert_param_t;

typedef union un_cert_param_value {
    uint32 v_uint32;
    uint32 ser_ssl_cert_notify_time;
    char v_char_array[CERT_MAX_CHAR_ARRAY_LEN];
    char ser_ssl_ca[CM_FULL_PATH_BUFFER_SIZE];
    char ser_ssl_key[CM_FULL_PATH_BUFFER_SIZE];
    char ser_ssl_cert[CM_FULL_PATH_BUFFER_SIZE];
    char ser_ssl_crl[CM_FULL_PATH_BUFFER_SIZE];
    uint32 cli_ssl_cert_notify_time;
    char cli_ssl_ca[CM_FULL_PATH_BUFFER_SIZE];
    char cli_ssl_key[CM_FULL_PATH_BUFFER_SIZE];
    char cli_ssl_cert[CM_FULL_PATH_BUFFER_SIZE];
    char cli_ssl_crl[CM_FULL_PATH_BUFFER_SIZE];
} cert_param_value_t;

typedef enum en_cert_param_val_type {
    CERT_PARAM_STRING,
    CERT_PARAM_UINT32,
    CERT_PARAM_UNKNOW
} cert_param_val_type_t;

typedef status_t (*cert_param_get_t)(cert_param_t param_type, const char *param_value, cert_param_value_t *out_value);
typedef struct st_cert_param_item {
    char *name; // param name
    cert_param_value_t value;
    cert_param_get_t get_param;
    char *range;
    cert_param_val_type_t val_type;
} cert_param_item_t;

status_t get_cert_ssl_notify_time(cert_param_t param_type, const char *param_value, cert_param_value_t *out_value);
status_t get_cert_param_string(cert_param_t param_type, const char *param_value, cert_param_value_t *out_value);
status_t ssl_chk_md_param(const char *param_name, const char *param_value,
                          cert_param_t *param_type, cert_param_value_t *out_value);
status_t ssl_set_md_param(cert_param_t param_type, const cert_param_value_t* param_value);
status_t ssl_md_get_param(cert_param_t param_type, cert_param_value_t* param_value);

#ifdef __cplusplus
}
#endif

#endif