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
 *    src/cm_mes/mes_metadata.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_metadata.h"
#include "cm_defs.h"
#include "cm_text.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "mes_func.h"

static param_item_t g_parameters[] = {
    [CBB_PARAM_SSL_CA] = {"SSL_CA", {.ssl_ca = ""}, get_param_string, "", PARAM_STRING},
    [CBB_PARAM_SSL_KEY] = {"SSL_KEY", {.ssl_key = ""}, get_param_string, "", PARAM_STRING},
    [CBB_PARAM_SSL_CRL] = {"SSL_CRL", {.ssl_crl = ""}, get_param_string, "", PARAM_STRING},
    [CBB_PARAM_SSL_CERT] = {"SSL_CERT", {.ssl_cert = ""}, get_param_string, "", PARAM_STRING},
    [CBB_PARAM_SSL_CIPHER] = {"SSL_CIPHER", {.ssl_cipher = ""}, get_param_string, "", PARAM_STRING},
    [CBB_PARAM_SSL_PWD_PLAINTEXT] = {"SSL_PWD_PLAINTEXT", {0}, get_param_password, "", PARAM_STRING},
    [CBB_PARAM_SSL_PWD_CIPHERTEXT] = {"SSL_PWD_CIPHERTEXT", {.ext_pwd = ""}, get_param_string, "",
                                      PARAM_STRING},
    [CBB_PARAM_SSL_CERT_NOTIFY_TIME] = {"SSL_CERT_NOTIFY_TIME", {.ssl_cert_notify_time = 30},
                                        get_param_ssl_notify_time, "[7,180]", PARAM_UINT32}
};

static status_t get_param_id_by_name(const char *param_name, uint32 *param_name_id)
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

static status_t get_param_by_name(const char *param_name, char *param_value, unsigned int size)
{
    uint32 len;
    uint32 param_id;
    errno_t errcode = EOK;
    int32 ret;
    CM_RETURN_IFERR(get_param_id_by_name(param_name, &param_id));

    if (param_id >= CBB_PARAM_CEIL) {
        return CM_ERROR;
    }
    param_value_t out_value = g_parameters[param_id].value;

    switch (g_parameters[param_id].val_type) {
        case PARAM_UINT32:
            if (size < sizeof(uint32)) {
                LOG_RUN_ERR("[param] the output buffer is small");
                return CM_ERROR;
            }
            ret = sprintf_s(param_value, size, "%u", out_value.v_uint32);
            PRTS_RETURN_IFERR(ret);
            break;
        case PARAM_STRING:
            len = (uint32)strlen(out_value.v_char_array);
            if (size < len) {
                LOG_RUN_ERR("[param] the output buffer is small");
                return CM_ERROR;
            }
            errcode = memcpy_sp(param_value, len, out_value.v_char_array, len);
            securec_check_ret(errcode);
            break;
        case PARAM_UNKNOW:
            return CM_ERROR;
    }
    return CM_SUCCESS;
}
status_t mes_get_md_param_by_name(const char *param_name, char *param_value, unsigned int size)
{
    status_t ret = get_param_by_name(param_name, param_value, size);
    return ret;
}

status_t get_param_ssl_notify_time(cbb_param_t param_type, const char *param_value, param_value_t *out_value)
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

status_t get_param_string(cbb_param_t param_type, const char *param_value, param_value_t *out_value)
{
    errno_t errcode = EOK;
    CM_CHECK_NULL_PTR(param_value);
    switch (param_type) {
        case CBB_PARAM_SSL_CA:
            errcode = strncpy_s(out_value->ssl_ca, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CBB_PARAM_SSL_KEY:
            errcode = strncpy_s(out_value->ssl_key, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CBB_PARAM_SSL_CRL:
            errcode = strncpy_s(out_value->ssl_crl, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CBB_PARAM_SSL_CERT:
            errcode = strncpy_s(out_value->ssl_cert, CM_FULL_PATH_BUFFER_SIZE, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CBB_PARAM_SSL_CIPHER:
            errcode = strncpy_s(out_value->ssl_cipher, CM_MAX_SSL_CIPHER_LEN, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        case CBB_PARAM_SSL_PWD_CIPHERTEXT:
            if (g_parameters[CBB_PARAM_SSL_PWD_PLAINTEXT].value.inter_pwd.cipher_len > 0) {
                LOG_DEBUG_ERR("ssl key password has already been set");
                return CM_ERROR;
            }
            errcode = strncpy_s(out_value->ext_pwd, CM_MAX_SSL_PWD_CIPHER_LEN, (const char *)param_value,
                strlen((const char *)param_value));
            break;
        default:
            return CM_ERROR;
    }
    return errcode == EOK ? CM_SUCCESS : CM_ERROR;
}

status_t get_param_password(cbb_param_t param_type, const char *param_value, param_value_t *out_value)
{
    param_value_t *param_val = &g_parameters[CBB_PARAM_SSL_PWD_CIPHERTEXT].value;
    if (!CM_IS_EMPTY_STR(param_val->ext_pwd)) {
        LOG_RUN_ERR("ssl key password has already been set");
        return CM_ERROR;
    }
    return cm_encrypt_pwd((uchar *)param_value, (uint32)strlen(param_value), &out_value->inter_pwd);
}

status_t md_get_param(cbb_param_t param_type, param_value_t *param_value)
{
    if (param_type >= CBB_PARAM_CEIL) {
        return CM_ERROR;
    }
    *param_value = g_parameters[param_type].value;
    return CM_SUCCESS;
}

status_t mes_set_md_param(cbb_param_t param_type, const param_value_t *param_value)
{
    if (param_value == NULL) {
        return CM_ERROR;
    }
    g_parameters[param_type].value = *param_value;
    return CM_SUCCESS;
}

status_t mes_chk_md_param(const char *param_name, const char *param_value, cbb_param_t *param_type,
    param_value_t *out_value)
{
    status_t ret;
    uint32 param_name_id;
    ret = get_param_id_by_name(param_name, &param_name_id);
    if (ret == CM_ERROR || g_parameters[param_name_id].get_param == NULL) {
        LOG_RUN_ERR("[mes] get paramid failed. param_name:%s, param_value:%s", param_name, param_value);
        return CM_ERROR;
    }
    *param_type = (cbb_param_t)param_name_id;
    ret = g_parameters[param_name_id].get_param((cbb_param_t)param_name_id, param_value, out_value);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] get param failed. param_name:%s, param_value:%s", param_name, param_value);
    }
    return ret;
}
