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
#include "cm_utils.h"
#include "securec.h"
#ifndef WIN32
#include <unistd.h>
#endif
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

/*
 * Per-instance cipher component file.
 * When configured via cm_cipher_set_component_file(), its RANDOM_LEN random bytes replace the
 * built-in component below, so the PBKDF2 password source is no longer recoverable from the
 * binary image. When not configured, the legacy built-in component is used to stay compatible
 * with ciphertexts produced before the file was introduced.
 */
static char g_component_file[CM_FILE_NAME_BUFFER_SIZE] = { 0 };
static bool8 g_builtin_component_warned = CM_FALSE;

#ifndef WIN32
static status_t cm_check_component_file_stat(const char *real_path)
{
    struct stat stat_buf;
    if (stat(real_path, &stat_buf) != 0) {
        LOG_DEBUG_ERR("stat cipher component file \"%s\" failed, errno %d", real_path, errno);
        return CM_ERROR;
    }
    if (!S_ISREG(stat_buf.st_mode)) {
        LOG_DEBUG_ERR("cipher component file \"%s\" is not a regular file", real_path);
        return CM_ERROR;
    }
    if (stat_buf.st_size != (off_t)RANDOM_LEN) {
        LOG_DEBUG_ERR("cipher component file \"%s\" size must be exactly %d bytes", real_path, RANDOM_LEN);
        return CM_ERROR;
    }
    if ((stat_buf.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        LOG_DEBUG_ERR("cipher component file \"%s\" must not be accessible by group or others", real_path);
        return CM_ERROR;
    }
    if (stat_buf.st_uid != geteuid()) {
        LOG_DEBUG_ERR("cipher component file \"%s\" must be owned by the current user", real_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
#endif

static status_t cm_load_component_file(const char *file_path, char *buff, uint32 buff_size)
{
#ifndef WIN32
    char real_path[CM_FILE_NAME_BUFFER_SIZE] = { 0 };
    CM_RETURN_IFERR(realpath_file(file_path, real_path, CM_FILE_NAME_BUFFER_SIZE));
    if (cm_check_component_file_stat(real_path) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (buff_size < RANDOM_LEN) {
        LOG_DEBUG_ERR("cipher component buffer size %u is too small", buff_size);
        return CM_ERROR;
    }
    int32 fd = open(real_path, O_RDONLY);
    if (fd < 0) {
        LOG_DEBUG_ERR("open cipher component file \"%s\" failed, errno %d", real_path, errno);
        return CM_ERROR;
    }
    uint32 offset = 0;
    while (offset < RANDOM_LEN) {
        ssize_t read_len = read(fd, buff + offset, (size_t)(RANDOM_LEN - offset));
        if (read_len > 0) {
            offset += (uint32)read_len;
            continue;
        }
        if (read_len < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    (void)close(fd);
    if (offset != RANDOM_LEN) {
        LOG_DEBUG_ERR("read cipher component file \"%s\" failed, got %u of %d bytes", real_path, offset, RANDOM_LEN);
        return CM_ERROR;
    }
    return CM_SUCCESS;
#else
    LOG_DEBUG_ERR("cipher component file is not supported on windows");
    return CM_ERROR;
#endif
}

status_t cm_cipher_set_component_file(const char *file_path)
{
    if (file_path == NULL || file_path[0] == '\0') {
        LOG_DEBUG_ERR("cipher component file path is empty");
        return CM_ERROR;
    }
    if (strlen(file_path) >= CM_FILE_NAME_BUFFER_SIZE) {
        LOG_DEBUG_ERR("cipher component file path is too long");
        return CM_ERROR;
    }
    /* validate eagerly so misconfiguration is reported at startup instead of first use */
    char probe[RANDOM_LEN] = { 0 };
    if (cm_load_component_file(file_path, probe, (uint32)sizeof(probe)) != CM_SUCCESS) {
        (void)memset_s(probe, sizeof(probe), 0, sizeof(probe));
        LOG_DEBUG_ERR("cipher component file \"%s\" is invalid", file_path);
        return CM_ERROR;
    }
    (void)memset_s(probe, sizeof(probe), 0, sizeof(probe));
    MEMS_RETURN_IFERR(strcpy_s(g_component_file, sizeof(g_component_file), file_path));
    return CM_SUCCESS;
}

/* legacy built-in component: public constant, kept only for backward compatibility */
static status_t cm_get_builtin_component(char *buff, uint32 buff_size)
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
    (void)memset_s(init_vector, sizeof(init_vector), 0, sizeof(init_vector));
    return CM_SUCCESS;
}

status_t cm_get_component(char *buff, uint32 buff_size)
{
    /* a configured per-instance component file always takes precedence and fails closed */
    if (g_component_file[0] != '\0') {
        return cm_load_component_file(g_component_file, buff, buff_size);
    }
    if (!g_builtin_component_warned) {
        LOG_RUN_WAR("cipher component file is not configured, the built-in public component is used and "
            "encrypted data is only obfuscated. Call cm_cipher_set_component_file() with a per-instance "
            "random file for real confidentiality.");
        g_builtin_component_warned = CM_TRUE;
    }
    return cm_get_builtin_component(buff, buff_size);
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

/* derive the component from the legacy built-in constant, used only for backward-compatible decrypt */
static status_t cm_get_legacy_actual_component(char *component, uint32 component_len, char *component1)
{
    char src_component[RANDOM_LEN + 1] = { 0 };
    if (cm_get_builtin_component(src_component, RANDOM_LEN) != CM_SUCCESS) {
        LOG_DEBUG_ERR("get built-in component failed");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < RANDOM_LEN; i++) {
        src_component[i] = src_component[i] ^ component1[i];
    }
    MEMS_RETURN_IFERR(memcpy_sp(component, (size_t)component_len, src_component, RANDOM_LEN));
    (void)memset_s(src_component, sizeof(src_component), 0, sizeof(src_component));
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

static status_t cm_decrypt_pwd_with_component(cipher_t *cipher, const char *component, uchar *plain_text,
    uint32 *plain_len)
{
    uchar key[RANDOM_LEN] = { 0 };
    /* get the decrypt key value */
    int32 ret = PKCS5_PBKDF2_HMAC(component, RANDOM_LEN, cipher->salt, RANDOM_LEN, ITERATE_TIMES,
        EVP_sha256(), RANDOM_LEN, key);
    if (ret != 1) {
        (void)memset_s(key, RANDOM_LEN, 0, RANDOM_LEN);
        LOG_DEBUG_ERR("PKCS5_PBKDF2_HMAC generate the derived key failed, errcode:%d", ret);
        return CM_ERROR;
    }
    /* decrypt the cipher */
    status_t status = CRYPT_decrypt(NID_aes_256_cbc, key, RANDOM_LEN, cipher, plain_text, plain_len);
    (void)memset_s(key, RANDOM_LEN, 0, RANDOM_LEN);
    return status;
}

status_t cm_decrypt_pwd(cipher_t *cipher, uchar *plain_text, uint32 *plain_len)
{
    char component[RANDOM_LEN + 1] = { 0 };
    if (cm_get_actual_component(component, RANDOM_LEN, (char *)cipher->rand) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Get component failed when decrypt pwd");
        return CM_ERROR;
    }
    status_t status = cm_decrypt_pwd_with_component(cipher, component, plain_text, plain_len);
    (void)memset_s(component, sizeof(component), 0, sizeof(component));
    /*
     * Backward compatibility: ciphertexts produced before a component file was configured were
     * derived with the built-in component. Retry with it when decryption with the configured
     * component fails.
     */
    if (status != CM_SUCCESS && g_component_file[0] != '\0') {
        char legacy_component[RANDOM_LEN + 1] = { 0 };
        if (cm_get_legacy_actual_component(legacy_component, RANDOM_LEN, (char *)cipher->rand) == CM_SUCCESS) {
            status = cm_decrypt_pwd_with_component(cipher, legacy_component, plain_text, plain_len);
        }
        (void)memset_s(legacy_component, sizeof(legacy_component), 0, sizeof(legacy_component));
    }
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("CRYPT_decrypt failed");
    }
    return status;
}
