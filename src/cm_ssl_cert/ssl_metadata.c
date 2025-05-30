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
 * mes_metadata.c
 *
 *
 * IDENTIFICATION
 *    src/cm_ssl_cert/ssl_certification.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cm_text.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "ssl_metadata.h"

static cert_param_item_t g_parameters[] = {
    [CERT_PARAM_SER_SSL_CA] = {"SER_SSL_CA", {.ser_ssl_ca = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_SER_SSL_KEY] = {"SER_SSL_KEY", {.ser_ssl_key = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_SER_SSL_CERT] = {"SER_SSL_CERT", {.ser_ssl_cert = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_SER_SSL_CERT_NOTIFY_TIME] = {"SER_SSL_CERT_NOTIFY_TIME", {.ser_ssl_cert_notify_time = 30},
                                             get_cert_ssl_notify_time, "[7,180]", CERT_PARAM_UINT32},
    [CERT_PARAM_CLI_SSL_CA] = {"CLI_SSL_CA", {.cli_ssl_ca = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_CLI_SSL_KEY] = {"CLI_SSL_KEY", {.cli_ssl_key = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_CLI_SSL_CERT] = {"CLI_SSL_CERT", {.cli_ssl_cert = ""}, get_cert_param_string, "", CERT_PARAM_STRING},
    [CERT_PARAM_CLI_SSL_CERT_NOTIFY_TIME] = {"CLI_SSL_CERT_NOTIFY_TIME", {.cli_ssl_cert_notify_time = 30},
                                             get_cert_ssl_notify_time, "[7,180]", CERT_PARAM_UINT32}
};

status_t get_cert_ssl_notify_time(cert_param_t param_type, const char *param_value, cert_param_value_t *out_value)
{
    uint32 val;
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (val < CM_MIN_SSL_EXPIRE_THRESHOLD || val > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        return CM_ERROR;
    }
    out_value->v_uint32 = val;
    return CM_SUCCESS;
}

status_t get_cert_param_string(cert_param_t param_type, const char *param_value, cert_param_value_t *out_value)
{
    errno_t errcode = EOK;
    CM_CHECK_NULL_PTR(param_value);
    switch (param_type) {
        case CERT_PARAM_SER_SSL_CA:
            errcode = strncpy_s(out_value->ser_ssl_ca, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CERT_PARAM_SER_SSL_KEY:
            errcode = strncpy_s(out_value->ser_ssl_key, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CERT_PARAM_SER_SSL_CERT:
            errcode = strncpy_s(out_value->ser_ssl_cert, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CERT_PARAM_CLI_SSL_CA:
            errcode = strncpy_s(out_value->cli_ssl_ca, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CERT_PARAM_CLI_SSL_KEY:
            errcode = strncpy_s(out_value->cli_ssl_key, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CERT_PARAM_CLI_SSL_CERT:
            errcode = strncpy_s(out_value->cli_ssl_cert, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        default:
            return CM_ERROR;
    }
    return errcode == EOK ? CM_SUCCESS : CM_ERROR;
}

static status_t get_cert_param_id_by_name(const char *param_name, uint32 *param_name_id)
{
    uint32 count = ELEMENT_COUNT(g_parameters);
    for (uint32 i = 0; i < count; i++) {
        if (g_parameters[i].name == NULL) {
            continue;
        }
        if (cm_str_equal(param_name, g_parameters[i].name)) {
            *param_name_id = i;
            return CM_SUCCESS;
        }
    }

    return CM_ERROR;
}

status_t ssl_md_get_param(cert_param_t param_type, cert_param_value_t *param_value)
{
    if (param_type >= CERT_PARAM_CEIL) {
        return CM_ERROR;
    }
    *param_value = g_parameters[param_type].value;
    return CM_SUCCESS;
}

status_t ssl_set_md_param(cert_param_t param_type, const cert_param_value_t *param_value)
{
    if (param_value == NULL) {
        return CM_ERROR;
    }
    g_parameters[param_type].value = *param_value;
    return CM_SUCCESS;
}

status_t ssl_chk_md_param(const char *param_name, const char *param_value, cert_param_t *param_type,
    cert_param_value_t *out_value)
{
    status_t ret;
    uint32 param_name_id;
    ret = get_cert_param_id_by_name(param_name, &param_name_id);
    if (ret == CM_ERROR || g_parameters[param_name_id].get_param == NULL) {
        LOG_RUN_ERR("[mes] get paramid failed. param_name:%s, param_value:%s", param_name, param_value);
        return CM_ERROR;
    }
    *param_type = (cert_param_t)param_name_id;
    ret = g_parameters[param_name_id].get_param((cert_param_t)param_name_id, param_value, out_value);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] get param failed. param_name:%s, param_value:%s", param_name, param_value);
    }
    return ret;
}