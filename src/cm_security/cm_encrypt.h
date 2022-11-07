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
 * cm_encrypt.h
 *
 *
 * IDENTIFICATION
 *    src/cm_security/cm_encrypt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_ENCRYPT_H__
#define __CM_ENCRYPT_H__

#include "cm_text.h"
#include "openssl/evp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_ENCRYPTION_SIZE 512

uint32 cm_base64_encode_len(uint32 src_len);
uint32 cm_base64_decode_len(const char *src);

status_t cm_base64_encode(uchar *src, uint32 src_len, char *cipher, uint32 *cipher_len);
uint32 cm_base64_decode(const char *src, uint32 src_len, uchar *dest_data, uint32 buff_len);

status_t cm_rand(uchar *buf, uint32 len);

#ifdef __cplusplus
}
#endif

#endif
