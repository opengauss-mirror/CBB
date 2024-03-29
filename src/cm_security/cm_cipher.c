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
 * cm_cipher.c
 *
 *
 * IDENTIFICATION
 *    src/cm_security/cm_cipher.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_cipher.h"
#include "cm_log.h"
#include "securec.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/asn1.h"
#include "openssl/hmac.h"

/* get_evp_cipher_by_id: if you need to be use,you can add some types */
static const EVP_CIPHER *get_evp_cipher_by_id(uint32 alg_id)
{
    const EVP_CIPHER *cipher = NULL;
    switch (alg_id & 0xFFFF) {
        case NID_aes_128_cbc:
            cipher = EVP_aes_128_cbc();
            break;
        case NID_aes_256_cbc:
            cipher = EVP_aes_256_cbc();
            break;
        case NID_undef:
            cipher = EVP_enc_null();
            break;
        default:
            LOG_DEBUG_ERR("invalid algorithm for cipher");
            break;
    }
    return cipher;
}

static status_t evp_set_padding(EVP_CIPHER_CTX *ctx, uchar *plain_text, uint32 plain_len, uint32 *block_size,
    uint32 *buffer_len, uchar **buffer)
{
    /* open padding mode */
    (void)EVP_CIPHER_CTX_set_padding(ctx, CM_TRUE);

    /* handling the last block */
    *block_size = (uint32)EVP_CIPHER_CTX_block_size(ctx);
    if (*block_size == 0) {
        LOG_DEBUG_ERR("EVP_CIPHER_CTX_block_size invalid block size");
        return CM_ERROR;
    }

    *buffer = (uchar *)OPENSSL_malloc(*block_size);
    if (*buffer == NULL) {
        LOG_DEBUG_ERR("OPENSSL_malloc %u failed", *block_size);
        return CM_ERROR;
    }

    if (memset_s(*buffer, *block_size, 0, *block_size) != EOK) {
        OPENSSL_free(*buffer);
        LOG_DEBUG_ERR("memset_s failed");
        return CM_ERROR;
    }

    *buffer_len = plain_len % (*block_size);
    if (memcpy_s(*buffer, *block_size, plain_text + (plain_len - (*buffer_len)), *buffer_len) != EOK) {
        OPENSSL_free(*buffer);
        LOG_DEBUG_ERR("memcpy_s failed");
        return CM_ERROR;
    }

    /* the first byte uses "0x80" to padding ,and the others uses "0x00" */
    (*buffer)[*buffer_len] = 0x80;
    /* close padding mode, default padding method of OPENSSL is forbidden */
    (void)EVP_CIPHER_CTX_set_padding(ctx, CM_FALSE);
    return CM_SUCCESS;
}

static status_t evp_encrypt(EVP_CIPHER_CTX *ctx, uchar *buffer, uint32 buffer_len, uint32 block_size, uchar *plain_text,
    uint32 plain_len, cipher_t *cipher)
{
    uint32 enc_num = 0;
    if (!EVP_EncryptUpdate(ctx, cipher->cipher_text, (int32 *)&enc_num, plain_text, (int32)(plain_len - buffer_len))) {
        LOG_DEBUG_ERR("EVP_EncryptUpdate for plain text failed");
        return CM_ERROR;
    }
    cipher->cipher_len = enc_num;
    if (!EVP_EncryptUpdate(ctx, cipher->cipher_text + cipher->cipher_len, (int32 *)&enc_num, buffer,
        (int32)block_size)) {
        LOG_DEBUG_ERR("EVP_EncryptUpdate for padding text failed");
        return CM_ERROR;
    }

    cipher->cipher_len += enc_num;
    if (!EVP_EncryptFinal(ctx, cipher->cipher_text + cipher->cipher_len, (int32 *)&enc_num)) {
        LOG_DEBUG_ERR("EVP_EncryptFinal failed");
        return CM_ERROR;
    }
    cipher->cipher_len += enc_num;
    return CM_SUCCESS;
}

/*
 * @Brief        : GS_UINT32 CRYPT_encrypt()
 * @Description  : encrypts plain text to cipher text using encryption algorithm.
 *		  It creates symmetric context by creating algorithm object, padding object,
 *		  opmode object.After encryption, symmetric context needs to be freed.
 * @return       : success: 0, failed: 1.
 *
 * @Notes	: the last block is not full. so here need to padding the last block.(the block size is an algorithm-related
 * parameter) 1.here *ISO/IEC 7816-4* padding method is adoptted: the first byte uses "0x80" to padding ,and the others
 * uses "0x00". Example(in the following example the block size is 8 bytes): when the last block is not full: The last
 * block has 4 bytes, so four bytes need to be filled
 *	 	 	 	 ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
 *			when the last block is full: here need to add a new block
 *				 ... | DD DD DD DD DD DD DD DD | 80 00 00 00 00 00 00 00 |
 *		  2.Default padding method of OPENSSL(this method is closed at here): Each byte is filled with the number of
 * remaining bytes Example(in the following example the block size is 8 bytes): when the last block is not full:The last
 * block has 4 bytes, so four bytes need to be filled
 *                                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 04 04 04 04 |
 *                       when the last block is full: here need to add a new block
 *                                ... | DD DD DD DD DD DD DD DD | 08 08 08 08 08 08 08 08 |
 */
static status_t CRYPT_encrypt(uint32 alg_id, const uchar *key, uint32 key_len, uchar *plain_text, uint32 plain_len,
    cipher_t *cipher)
{
    uchar *buffer = NULL;
    uint32 buffer_len, block_size;

    const EVP_CIPHER *cipher_alg = get_evp_cipher_by_id(alg_id);
    if (cipher_alg == NULL) {
        return CM_ERROR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_DEBUG_ERR("EVP_CIPHER_CTX_new failed");
        return CM_ERROR;
    }

    (void)EVP_CipherInit_ex(ctx, cipher_alg, NULL, key, cipher->IV, CM_TRUE);

    if (evp_set_padding(ctx, plain_text, plain_len, &block_size, &buffer_len, &buffer) != CM_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }

    status_t status = evp_encrypt(ctx, buffer, buffer_len, block_size, plain_text, plain_len, cipher);

    OPENSSL_free(buffer);
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

/*
 * @Brief        : GS_UINT32 CRYPT_decrypt()
 * @Description  : decrypts cipher text to plain text using decryption algorithm.
 *		  It creates symmetric context by creating algorithm object, padding object,
 *		  opmode object. After decryption, symmetric context needs to be freed.
 * @return       : success: 0, failed: 1.
 *
 * @Notes        : the last block is not full. so here need to padding the last block.(the block size is an
 * algorithm-related parameter) 1.here *ISO/IEC 7816-4* padding method is adoptted:the first byte uses "0x80" to padding
 * ,and the others uses "0x00". Example(in the following example the block size is 8 bytes): when the last block is not
 * full: The last block has 4 bits,so padding is required for 4 bytes
 *                                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
 *                       when the last block is full: here need to add a new block
 *                                ... | DD DD DD DD DD DD DD DD | 80 00 00 00 00 00 00 00 |
 */
static status_t CRYPT_decrypt(uint32 alg_id, const uchar *key, uint32 key_len, cipher_t *cipher, uchar *plain_text,
    uint32 *plain_len)
{
    const EVP_CIPHER *cipher_alg = get_evp_cipher_by_id(alg_id);
    if (cipher_alg == NULL) {
        return CM_ERROR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_DEBUG_ERR("EVP_CIPHER_CTX_new failed");
        return CM_ERROR;
    }
    (void)EVP_CipherInit_ex(ctx, cipher_alg, NULL, key, cipher->IV, CM_FALSE);

    (void)EVP_CIPHER_CTX_set_padding(ctx, CM_FALSE);

    uint32 dec_num = 0;
    if (!EVP_DecryptUpdate(ctx, plain_text, (int32 *)&dec_num, cipher->cipher_text, (int32)cipher->cipher_len)) {
        LOG_DEBUG_ERR("EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }

    *plain_len = dec_num;
    if (!EVP_DecryptFinal(ctx, plain_text + dec_num, (int32 *)&dec_num)) {
        LOG_DEBUG_ERR("EVP_DecryptFinal failed");
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }

    *plain_len += dec_num;
    /* padding bytes of the last block need to be removed */
    uint32 block_size = (uint32)EVP_CIPHER_CTX_block_size(ctx);
    uint32 pwd_len = (*plain_len) - 1;
    while (*(plain_text + pwd_len) == 0) {
        pwd_len--;
    }

    if (pwd_len < ((*plain_len) - block_size) || *(plain_text + pwd_len) != 0x80) {
        LOG_DEBUG_ERR("invalid plain text");
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }
    (*plain_len) = pwd_len;
    plain_text[pwd_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return CM_SUCCESS;
}

status_t cm_get_component(char *buff, uint32 buff_size)
{
    char init_vector[32] = {
        (char)0x72, (char)0xA1, (char)0x8D, (char)0x39,
        (char)0xBC, (char)0x46, (char)0xEF, (char)0x53,
        (char)0x91, (char)0x6B, (char)0x2C, (char)0xF7,
        (char)0xDA, (char)0x43, (char)0x98, (char)0xCE,
        (char)0x5F, (char)0xE8, (char)0x33, (char)0xD6,
        (char)0xC4, (char)0x79, (char)0xB2, (char)0x54,
        (char)0xF, (char)0x9A, (char)0x28, (char)0x13,
        (char)0x67, (char)0x25, (char)0xAF, (char)0xDB,
    };
    init_vector[0] = (char)init_vector[25] + (char)init_vector[2];
    init_vector[1] = (char)init_vector[7] | (char)init_vector[11];
    init_vector[2] = (char)init_vector[17] ^ (char)init_vector[29];
    init_vector[3] = (char)init_vector[5] << (char)init_vector[22];
    init_vector[4] = (char)init_vector[0] | (char)init_vector[18];
    init_vector[5] = (char)init_vector[21] & (char)init_vector[12];
    init_vector[6] = (char)init_vector[9] << (char)init_vector[31];
    init_vector[7] = (char)init_vector[8] ^ (char)init_vector[6];
    init_vector[8] = (char)init_vector[15] | (char)init_vector[28];
    init_vector[9] = (char)init_vector[30] + (char)init_vector[4];
    init_vector[10] = (char)init_vector[16] & (char)init_vector[30];
    init_vector[11] = (char)init_vector[1] - (char)init_vector[24];
    init_vector[12] = (char)init_vector[28] << (char)init_vector[19];
    init_vector[13] = (char)init_vector[13] ^ (char)init_vector[3];
    init_vector[14] = (char)init_vector[14] | (char)init_vector[10];
    init_vector[15] = (char)init_vector[27] ^ (char)init_vector[15];
    init_vector[16] = (char)init_vector[23] << (char)init_vector[20];
    init_vector[17] = (char)init_vector[18] + (char)init_vector[26];
    init_vector[18] = (char)init_vector[4] << (char)init_vector[17];
    init_vector[19] = (char)init_vector[11] | (char)init_vector[22];
    init_vector[20] = (char)init_vector[18] & (char)init_vector[2];
    init_vector[21] = (char)init_vector[26] + (char)init_vector[16];
    init_vector[22] = (char)init_vector[15] - (char)init_vector[28];
    init_vector[23] = (char)init_vector[2] + (char)init_vector[17];
    init_vector[24] = (char)init_vector[20] | (char)init_vector[16];
    init_vector[25] = (char)init_vector[7] & (char)init_vector[15];
    init_vector[26] = (char)init_vector[19] + (char)init_vector[29];
    init_vector[27] = (char)init_vector[14] - (char)init_vector[9];
    init_vector[28] = (char)init_vector[31] | (char)init_vector[10];
    init_vector[29] = (char)init_vector[28] + (char)init_vector[1];
    init_vector[30] = (char)init_vector[25] & (char)init_vector[12];
    init_vector[31] = (char)init_vector[6] ^ (char)init_vector[18];
    MEMS_RETURN_IFERR(memcpy_sp(buff, (size_t)buff_size, init_vector, sizeof(init_vector)));
    return CM_SUCCESS;
}

status_t cm_get_actual_component(char *component, uint32 component_len, char *component1)
{
    char src_component[RANDOM_LEN + 1] = { 0 };
    if (cm_get_component(src_component, RANDOM_LEN) != CM_SUCCESS) {
        LOG_DEBUG_ERR("get component failed");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < RANDOM_LEN; i++) {
        src_component[i] = src_component[i] ^ component1[i];
    }
    MEMS_RETURN_IFERR(memcpy_sp(component, (size_t)component_len, src_component, RANDOM_LEN));
    return CM_SUCCESS;
}

status_t cm_encrypt_pwd(uchar *plain_text, uint32 plain_len, cipher_t *cipher)
{
    if (plain_len > CM_PASSWD_MAX_LEN) {
        LOG_DEBUG_ERR("passwd length %u is more than max %d", plain_len, CM_PASSWD_MAX_LEN);
        return CM_ERROR;
    }

    if (RAND_priv_bytes(cipher->rand, RANDOM_LEN) != 1) {
        LOG_DEBUG_ERR("cm_encrypt_pwd generate rand key failed");
        return CM_ERROR;
    }

    if (RAND_priv_bytes(cipher->salt, RANDOM_LEN) != 1) {
        LOG_DEBUG_ERR("cm_encrypt_pwd generate salt key failed");
        return CM_ERROR;
    }

    uchar key[RANDOM_LEN] = { 0 };
    char component[RANDOM_LEN + 1] = { 0 };
    if (cm_get_actual_component(component, RANDOM_LEN, (char *)cipher->rand) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Get component failed when encrypt pwd");
        return CM_ERROR;
    }
    /* use PKCS5 HMAC sha256 to dump the key for encryption */
    int32 ret = PKCS5_PBKDF2_HMAC((const char *)component, RANDOM_LEN, cipher->salt, RANDOM_LEN, ITERATE_TIMES,
        EVP_sha256(), RANDOM_LEN, key);
    if (ret != 1) {
        LOG_DEBUG_ERR("PKCS5_PBKDF2_HMAC generate the derived key failed, errcode:%d", ret);
        return CM_ERROR;
    }
    if (RAND_priv_bytes(cipher->IV, RANDOM_LEN) != 1) {
        LOG_DEBUG_ERR("cm_encrypt_pwd generate IV key failed");
        return CM_ERROR;
    }

    if (CRYPT_encrypt(NID_aes_256_cbc, key, RANDOM_LEN, plain_text, plain_len, cipher) != CM_SUCCESS) {
        return CM_ERROR;
    }
    errno_t errcode = memset_s(key, RANDOM_LEN, 0, RANDOM_LEN);
    if (errcode != EOK) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cm_decrypt_pwd(cipher_t *cipher, uchar *plain_text, uint32 *plain_len)
{
    uchar key[RANDOM_LEN] = { 0 };
    char component[RANDOM_LEN + 1] = { 0 };
    if (cm_get_actual_component(component, RANDOM_LEN, (char *)cipher->rand) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Get component failed when decrypt pwd");
        return CM_ERROR;
    }
    /* get the decrypt key value */
    int32 ret = PKCS5_PBKDF2_HMAC((const char *)component, RANDOM_LEN, cipher->salt, RANDOM_LEN, ITERATE_TIMES,
        EVP_sha256(), RANDOM_LEN, key);
    if (ret != 1) {
        LOG_DEBUG_ERR("PKCS5_PBKDF2_HMAC generate the derived key failed, errcode:%d", ret);
        return CM_ERROR;
    }

    /* decrypt the cipher */
    if (CRYPT_decrypt(NID_aes_256_cbc, key, RANDOM_LEN, cipher, plain_text, plain_len) != CM_SUCCESS) {
        (void)memset_s(plain_text, *plain_len, 0, *plain_len);
        LOG_DEBUG_ERR("CRYPT_decrypt failed");
        return CM_ERROR;
    }
    errno_t errcode = memset_s(key, RANDOM_LEN, 0, RANDOM_LEN);
    if (errcode != EOK) {
        (void)memset_s(plain_text, *plain_len, 0, *plain_len);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
