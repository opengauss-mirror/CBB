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
 * mes_metadata.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_metadata.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_METADATA_H__
#define __MES_METADATA_H__

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


#define CM_SSL_NOTI_TIME_MIN   7
#define CM_SSL_NOTI_TIME_MAX   180
#define CM_MAX_CHAR_ARRAY_LEN 256

typedef enum en_cbb_param {
    CBB_PARAM_UNKNOWN = 0,
    CBB_PARAM_SSL_CA,
    CBB_PARAM_SSL_KEY,
    CBB_PARAM_SSL_CRL,
    CBB_PARAM_SSL_CERT,
    CBB_PARAM_SSL_GM_KEY,
    CBB_PARAM_SSL_GM_CERT,
    CBB_PARAM_SSL_CIPHER,
    CBB_PARAM_SSL_PWD_PLAINTEXT,
    CBB_PARAM_SSL_PWD_CIPHERTEXT,
    CBB_PARAM_SSL_CERT_NOTIFY_TIME,
    CBB_PARAM_CEIL,
} cbb_param_t;


typedef union un_param_value {
    uint32 v_uint32;
    char v_char_array[CM_MAX_CHAR_ARRAY_LEN];
    uint32 ssl_cert_notify_time;
    char ssl_ca[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_key[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_crl[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_cert[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_gm_key[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_gm_cert[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_cipher[CM_MAX_SSL_CIPHER_LEN];
    char ext_pwd[CM_MAX_SSL_PWD_CIPHER_LEN];
    cipher_t inter_pwd;
} param_value_t;

typedef enum en_param_val_type {
    PARAM_STRING,
    PARAM_UINT32,
    PARAM_UNKNOW
} param_val_type_t;

typedef status_t (*param_get_t)(cbb_param_t param_type, const char *param_value, param_value_t *out_value);
typedef struct st_param_item {
    char *name; // param name
    param_value_t value;
    param_get_t get_param;
    char *range;
    param_val_type_t val_type;
} param_item_t;

status_t get_param_string(cbb_param_t param_type, const char *param_value, param_value_t *out_value);
status_t get_param_ssl_notify_time(cbb_param_t param_type, const char *param_value, param_value_t *out_value);
status_t get_param_password(cbb_param_t param_type, const char *param_value, param_value_t *out_value);
status_t mes_chk_md_param(const char *param_name, const char *param_value,
                          cbb_param_t *param_type, param_value_t *out_value);
status_t mes_set_md_param(cbb_param_t param_type, const param_value_t* param_value);
status_t mes_md_get_param(cbb_param_t param_type, param_value_t* param_value);
status_t mes_get_md_param_by_name(const char *param_name, char *param_value, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif
