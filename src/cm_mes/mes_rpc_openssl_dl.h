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
 * mes_rpc_openssl_dl.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_openssl_dl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OCK_OPENSSL_DL_H
#define OCK_OPENSSL_DL_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static const int DL_OPENSSL_ERROR = -1;
static const int DL_OPENSSL_OK = 1;

/**
 * @brief get the path of libssl.so and libctypto.so of special version of OPENSSL (1.1.1k)
 *
 * @param path the folder path where libopenssl.so is located
 *
 * @return DL_OPENSSL_OK for success, DL_OPENSSL_ERROR for failed.
 */
int OpensslDlopenAndSet(const char* path);

/**
 * @brief get the path of libssl.so and libctypto.so of special version of OPENSSL (1.1.1k)
 *
 * @param ssl the path of libssl.so
 * @param crypto the path of libcrypto.so
 *
 * @return DL_OPENSSL_OK for success, DL_OPENSSL_ERROR for failed.
 */
int SetOpensslDLopenLibPath(const char *ssl, const char *crypto);


#ifdef __cplusplus
}
#endif

#endif