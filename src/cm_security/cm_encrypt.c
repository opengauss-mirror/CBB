/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
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
 * cm_encrypt.c
 *    DCF API
 *
 * IDENTIFICATION
 *    src/cm_security/cm_encrypt.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_encrypt.h"
#include "cm_log.h"
#include "cm_file.h"
#include "openssl/x509.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#ifdef WIN32
#include <wincrypt.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* returns base64 encoded string length, include null term */
uint32 cm_base64_encode_len(uint32 len)
{
    uint32 ret;

    switch (len % 3) {
        case 1:
            len += 2;
            break;
        case 2:
            len += 1;
            break;
        default:
            break;
    }

    ret = (len / 3) * 4 + 1;

    return ret;
}

uint32 cm_base64_decode_len(const char *src)
{
    uint32 ret = 0;
    size_t length;

    if (src == NULL) {
        return ret;
    }
    length = (uint32)strlen(src);
    if (length == 0) {
        return ret;
    }

    ret = (uint32)((length / 4) * 3 + 1);
    if (length > 2) {
        if (*(src + length - 1) == '=') {
            ret--;
        }
        if (*(src + length - 2) == '=') {
            ret--;
        }
    }

    return ret;
}

static char cm_base2char(uchar n)
{
    char ret_char;

    n &= 0x3F;
    if (n < 26) {
        ret_char = (char)(n + 'A');
    } else if (n < 52) {
        ret_char = (char)((n - 26) + 'a');
    } else if (n < 62) {
        ret_char = (char)((n - 52) + '0');
    } else if (n == 62) {
        ret_char = '+';
    } else {
        ret_char = '/';
    }

    return ret_char;
}

static uchar cm_char2base(char ch)
{
    uchar ret;

    if ((ch >= 'A') && (ch <= 'Z')) {
        ret = (uchar)(ch - 'A');
    } else if ((ch >= 'a') && (ch <= 'z')) {
        ret = (uchar)((ch - 'a') + 26);
    } else if ((ch >= '0') && (ch <= '9')) {
        ret = (uchar)((ch - '0') + 52);
    } else if (ch == '+') {
        ret = 62;
    } else if (ch == '/') {
        ret = 63;
    } else {
        ret = 64;
    }

    return ret;
}

static status_t cm_base64_encode_inside(char *dest, uint32 *buf_len, uchar *src, uint32 src_len)
{
    uint32 ret;
    uint32 i;
    uchar c_temp = '\0';

    ret = cm_base64_encode_len(src_len);
    if (ret > *buf_len) {
        LOG_DEBUG_ERR("String buffer for base64 encoding is too short, buffer: %u, required: %u", *buf_len, ret);
        return CM_ERROR;
    }

    do {
        for (i = 0; i < src_len; i++) {
            switch (i % 3) {
                case 0:
                    *dest++ = cm_base2char((uchar)(*src) >> 2);
                    c_temp = ((((uchar)(*src++)) << 4) & 0x3F);
                    break;
                case 1:
                    *dest++ = cm_base2char(c_temp | ((uchar)(*src) >> 4));
                    c_temp = ((((uchar)(*src++)) << 2) & 0x3F);
                    break;
                case 2:
                    *dest++ = cm_base2char(c_temp | ((uchar)(*src) >> 6));
                    *dest++ = cm_base2char((uchar)*src++);
                    break;
                default:
                    break;
            }
        }
        if (src_len % 3 != 0) {
            *dest++ = cm_base2char(c_temp);

            if (src_len % 3 == 1) {
                *dest++ = '=';
            }
            *dest++ = '=';
        }
        *dest = '\0'; //  aDest is an ASCIIZ string
    } while (0);

    *buf_len = ret - 1;
    return CM_SUCCESS;
}

static uint32 cm_base64_decode_inside(uchar *dest, uint32 buf_len, const char *src, uint32 src_len)
{
    uint32 ret;
    uint32 i;
    uchar temp_src = '\0';
    uchar char_temp = '\0';

    ret = cm_base64_decode_len(src);
    if (ret == 0) {
        return ret;
    }

    do {
        if ((dest == NULL) || (ret > buf_len)) {
            break;
        }

        for (i = 0; i < src_len; ++i) {
            if (*src == '=') {
                break;
            }

            do {
                temp_src = ((*src) ? (cm_char2base((char)(*src++))) : (uchar)(65));
            } while (temp_src == 64);

            if (temp_src == 65) {
                break;
            }

            switch (i % 4) {
                case 0:
                    char_temp = (uchar)(temp_src << 2);
                    break;
                case 1:
                    *dest++ = (char)(char_temp | (temp_src >> 4));
                    char_temp = (uchar)(temp_src << 4);
                    break;
                case 2:
                    *dest++ = (char)(char_temp | (temp_src >> 2));
                    char_temp = (uchar)(temp_src << 6);
                    break;
                case 3:
                    *dest++ = (char)(char_temp | temp_src);
                    break;
                default:
                    break;
            }
        }
        *dest = '\0';
    } while (0);

    return (ret - 1);
}

status_t cm_base64_encode(uchar *src, uint32 src_len, char *cipher, uint32 *cipher_len)
{
    if ((src == NULL) || (src_len == 0) || (cipher == NULL) || (*cipher_len == 0)) {
        return CM_ERROR;
    }

    return cm_base64_encode_inside(cipher, cipher_len, src, src_len);
}

uint32 cm_base64_decode(const char *src, uint32 src_len, uchar *dest_data, uint32 buff_len)
{
    uint32 dest_len;

    if (src == NULL || dest_data == NULL || buff_len == 0) {
        return 0;
    }

    dest_len = cm_base64_decode_len(src);
    if (dest_len == 0 || buff_len < dest_len) {
        return 0;
    }

    return cm_base64_decode_inside(dest_data, dest_len, src, src_len);
}

status_t cm_rand(uchar *buf, uint32 len)
{
    if (buf == NULL || len == 0) {
        return CM_ERROR;
    }

    if (RAND_priv_bytes(buf, (int)len) != 1) {
        LOG_DEBUG_ERR("cm_rand generate random failed");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
