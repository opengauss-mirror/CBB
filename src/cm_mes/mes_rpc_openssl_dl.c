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
 * mes_rpc_openssl_dl.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_openssl_dl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_log.h"
#include "cm_utils.h"
#include "cm_file.h"
#include "mes_rpc_openssl_dl.h"

typedef int (*SetOpensslLibPath)(const char *ssl, const char *crypto);

#define SSL_SO_NAME     "libssl.so"
#define CRYPTO_SO_NAME  "libcrypto.so"
#define OPENSSL_DL_SO_NAME  "libopenssl_dl.so"
#define PATH_LENGTH PATH_MAX


int OpensslDlopenAndSet(const char* path)
{
    char opensslPath[PATH_LENGTH] = {0};
    char* opensslPathPtr = opensslPath;
    int ret = snprintf_s(opensslPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", path, OPENSSL_DL_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct opensslPath failed, ret %d.", ret);
        return DL_OPENSSL_ERROR;
    }
    char ockSslPath[PATH_LENGTH] = {0};
    ret = snprintf_s(ockSslPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", path, SSL_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct ockSslPath failed, ret %d.", ret);
        return DL_OPENSSL_ERROR;
    }
    char ockCryptoPath[PATH_LENGTH] = {0};
    ret = snprintf_s(ockCryptoPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", path, CRYPTO_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct ockCryptoPath failed, ret %d.", ret);
        return DL_OPENSSL_ERROR;
    }
    
    void* opensslDl;
    ret = cm_open_dl(&opensslDl, opensslPathPtr);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlopen openssl_dl error, path(%s)", opensslPathPtr);
        return DL_OPENSSL_ERROR;
    }

    SetOpensslLibPath setPath;
    ret = cm_load_symbol(opensslDl, "SetOpensslDLopenLibPath", (void**)&setPath);
    if (ret != CM_SUCCESS) {
        cm_close_dl(opensslDl);
        LOG_RUN_ERR("dlsym SetOpensslDLopenLibPath error");
        return DL_OPENSSL_ERROR;
    }

    ret = setPath(ockSslPath, ockCryptoPath);
    if (ret != DL_OPENSSL_OK) {
        cm_close_dl(opensslDl);
        LOG_RUN_ERR("call SetOpensslDLopenLibPath error");
        return DL_OPENSSL_ERROR;
    }

    cm_close_dl(opensslDl);
    return DL_OPENSSL_OK;
}