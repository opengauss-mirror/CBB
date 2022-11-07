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
 * cs_packet.h
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cs_packet.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CS_PACKET_H__
#define __CS_PACKET_H__
#include "cm_base.h"
#ifndef WIN32
#include <string.h>
#endif

#include "cm_num.h"
#include "cm_debug.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum en_cs_minor_version {
    MIN_VERSION_0 = 0,
} cs_minor_version_t;

typedef enum en_cs_major_version {
    MJR_VERSION_0 = 0,
} cs_major_version_t;


#define CS_PROTOCOL_MAJOR(v)    ((v) >> 16)
#define CS_PROTOCOL_MINOR(v)    ((v) & 0x0000ffff)
#define CS_PROTOCOL(m, n)        (((m) << 16) | (n))


#define CS_LOCAL_VERSION (uint32) CS_PROTOCOL(MJR_VERSION_0, MIN_VERSION_0)

#define CS_CMD_UNKONOW       (uint8)0
#define CS_CMD_HANDSHAKE     (uint8)1 /* process before login, added since v2.0; for SSL only since v9.0 */
#define CS_CMD_AUTH_INIT     (uint8)2 /* request for user auth info, added since v9.0 */
#define CS_CMD_LOGIN         (uint8)3
#define CS_CMD_LOGOUT        (uint8)4
#define CS_CMD_CEIL          (uint8)5 /* the ceil of cmd */


/* every option use one bit of flags in cs_packet_head_t */
#define CS_FLAG_NONE                 0x0000
#define CS_FLAG_MORE_DATA            0x0001  // continue to recv more data
#define CS_FLAG_END_DATA             0x0002  // end to last packet
#define CS_FLAG_PEER_CLOSED          0x0004
#define CS_FLAG_COMPRESS             0x0008
#define CS_FLAG_PRIV_LOW             0x0010
#define CS_FLAG_BATCH                0x0020


#define CS_ALIGN_SIZE 4

#define CS_WAIT_FOR_READ 1
#define CS_WAIT_FOR_WRITE 2

typedef enum en_cs_option {
    CSO_DIFFERENT_ENDIAN = 0x00000001,
    CSO_BUFF_IN_QUEUE    = 0x00000002,
    CSO_SUPPORT_SSL      = 0x00000004,  // support SSL
} cs_option_t;

#define CS_DIFFERENT_ENDIAN(options) ((options) & CSO_DIFFERENT_ENDIAN)
#define CS_MORE_DATA(flag) ((flag) & CS_FLAG_MORE_DATA)
#define CS_END_DATA(flag) ((flag) & CS_FLAG_END_DATA)
#define CS_COMPRESS(flag) ((flag) & CS_FLAG_COMPRESS)
#define CS_PRIV_LOW(flag) ((flag) & CS_FLAG_PRIV_LOW)
#define CS_BATCH(flag) ((flag) & CS_FLAG_BATCH)

typedef struct st_cs_packet_head {
    uint32 size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint32 version;
    uint32 serial_number;
} cs_packet_head_t;

typedef struct tagcs_packet {
    uint32 offset;  // for reading
    uint32 options; // options
    cs_packet_head_t *head;
    uint32 max_buf_size; // MAX_ALLOWED_PACKET
    uint32 buf_size;
    char *buf;
    char init_buf[CM_INIT_PACKET_SIZE];
} cs_packet_t;

static inline char *cs_write_addr(const cs_packet_t *pack)
{
    return (pack->buf + pack->head->size);
}

static inline char *cs_read_addr(const cs_packet_t *pack)
{
    return (pack->buf + pack->offset);
}

static inline bool32 cs_has_remain(const cs_packet_t *pack, uint32 sz)
{
    return ((sz < pack->buf_size) && (pack->head->size + sz <= pack->buf_size));
}

static inline bool32 cs_has_recv_remain(const cs_packet_t *pack, uint32 sz)
{
    return ((sz < pack->head->size) && (pack->offset + sz <= pack->head->size));
}

static inline int32 cs_remain_size(const cs_packet_t *pack)
{
    return (int32)(pack->buf_size - pack->head->size);
}

static inline uint32 cs_reverse_int32(uint32 value)
{
    uint32 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[3];
    r_bytes[1] = v_bytes[2];
    r_bytes[2] = v_bytes[1];
    r_bytes[3] = v_bytes[0];
    return result;
}

static inline uint32 cs_reverse_uint32(uint32 value)
{
    return cs_reverse_int32(value);
}

static inline uint16 cs_reverse_int16(uint16 value)
{
    uint16 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[1];
    r_bytes[1] = v_bytes[0];
    return result;
}

static inline uint64 cs_reverse_int64(uint64 value)
{
    uint64 result;
    uint32 *v_int32, *r_int32;

    v_int32 = (uint32 *)&value;
    r_int32 = (uint32 *)&result;
    r_int32[1] = cs_reverse_int32(v_int32[0]);
    r_int32[0] = cs_reverse_int32(v_int32[1]);
    return result;
}

static inline double cs_reverse_real(double value)
{
    double tmp_value, result;
    uint16 *v_int16 = (uint16 *)&value;
    uint16 *tmp_int16 = (uint16 *)&tmp_value;
    uint16 *r_int16 = (uint16 *)&result;
    uint32 *tmp_int32 = (uint32 *)&tmp_value;

    tmp_int16[0] = v_int16[0];
    tmp_int16[1] = v_int16[3];
    tmp_int16[2] = v_int16[1];
    tmp_int16[3] = v_int16[2];

    tmp_int32[0] = cs_reverse_int32(tmp_int32[0]);
    tmp_int32[1] = cs_reverse_int32(tmp_int32[1]);

    r_int16[0] = tmp_int16[0];
    r_int16[3] = tmp_int16[1];
    r_int16[1] = tmp_int16[2];
    r_int16[2] = tmp_int16[3];

    return result;
}

static inline void cs_init_pack(cs_packet_t *pack, uint32 options, uint32 max_buf_size)
{
    CM_ASSERT(pack != NULL);
    pack->offset = 0;
    pack->buf = pack->init_buf;
    pack->buf_size = CM_INIT_PACKET_SIZE;
    pack->max_buf_size = max_buf_size;
    pack->head = (cs_packet_head_t *)pack->buf;
    pack->options = options;
}

static inline void cs_try_free_packet_buffer(cs_packet_t *pack)
{
    if (pack->buf != NULL && pack->buf != pack->init_buf) {
        CM_FREE_PTR(pack->buf);
        pack->buf_size = CM_INIT_PACKET_SIZE;
        pack->buf = pack->init_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }
}

static inline void cs_init_get(cs_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    pack->offset = (uint32)sizeof(cs_packet_head_t);
}

static inline void cs_init_set(cs_packet_t *pack, uint32 call_version)
{
    CM_ASSERT(pack != NULL);
    pack->head->size = (uint32)sizeof(cs_packet_head_t);
    pack->head->result = 0;
    pack->head->flags = 0;
    pack->head->version = call_version;
}

/*
 * check the send-buffer size, extend the buffer dynamicly if need.
 * default buffer size is GS_MAX_PACKET_SIZE;
 * if max_buf_size == buf_size == GS_MAX_PACKET_SIZE, use default buffer, not extend;
 * Hint : remember to free the buf if it's extended dynamicly by malloc;
 */
static inline uint32 cm_realloc_send_pack_size(const cs_packet_t *pack, uint32 len)
{
    return (pack->head->size + CM_ALIGN_8K(len));
}

static status_t cs_try_realloc_send_pack(cs_packet_t *pack, uint32 expect_size)
{
    errno_t errcode = 0;
    if (!cs_has_remain(pack, expect_size)) {
        if (CM_MAX_UINT32 - pack->head->size < (uint32)CM_ALIGN_8K(expect_size)) {
            CM_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
            return CM_ERROR;
        }
        // extend memory align 8K
        if (CM_MAX_UINT32 - pack->head->size < CM_ALIGN_8K(expect_size)) {
            CM_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
            return CM_ERROR;
        }

        if (pack->head->size + expect_size > pack->max_buf_size) {
            CM_THROW_ERROR(ERR_FULL_PACKET, "send", pack->head->size + expect_size, pack->max_buf_size);
            return CM_ERROR;
        }
        uint32 send_size = cm_realloc_send_pack_size(pack, expect_size);
        uint32 new_buf_size = MIN(send_size, pack->max_buf_size);
        if (new_buf_size == 0) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "invalid buffer size");
            return CM_ERROR;
        }

        char *new_buf = (char *)malloc(new_buf_size);
        if (new_buf == NULL) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_buf_size, "large packet buffer");
            return CM_ERROR;
        }
        errcode = memcpy_s(new_buf, new_buf_size, pack->buf, pack->head->size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            CM_FREE_PTR(new_buf);
            return CM_ERROR;
        }
        if (pack->buf != pack->init_buf) {
            CM_FREE_PTR(pack->buf);
        }

        pack->buf_size = new_buf_size;
        pack->buf = new_buf;
        pack->head = (cs_packet_head_t *)pack->buf;
    }

    return CM_SUCCESS;
}

static inline status_t cs_put_data(cs_packet_t *pack, const void *data, uint32 size)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(data != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, CM_ALIGN4(size)));
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(cs_write_addr(pack), cs_remain_size(pack), data, size));
    }
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t cs_put_int64(cs_packet_t *pack, uint64 value)
{
    CM_ASSERT(pack != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, sizeof(uint64)));

    *(uint64 *)cs_write_addr(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(value) : value;
    pack->head->size += (uint32)sizeof(uint64);
    return CM_SUCCESS;
}

static inline status_t cs_put_int32(cs_packet_t *pack, uint32 value)
{
    CM_ASSERT(pack != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, sizeof(uint32)));

    *(uint32 *)cs_write_addr(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int32(value) : value;
    pack->head->size += (uint32)sizeof(uint32);
    return CM_SUCCESS;
}

static inline status_t cs_put_int16(cs_packet_t *pack, uint16 value)
{
    CM_ASSERT(pack != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, CS_ALIGN_SIZE));

    *(uint16 *)cs_write_addr(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16(value) : value;
    pack->head->size += CS_ALIGN_SIZE;
    return CM_SUCCESS;
}

static inline status_t cs_put_real(cs_packet_t *pack, double value)
{
    CM_ASSERT(pack != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, sizeof(double)));

    *(double *)cs_write_addr(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(value) : value;
    pack->head->size += (uint32)sizeof(double);
    return CM_SUCCESS;
}

static inline status_t cs_put_text(cs_packet_t *pack, const text_t *text)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, sizeof(uint32) + CM_ALIGN4(text->len)));
    /* put the length of text */
    (void)cs_put_int32(pack, text->len);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    MEMS_RETURN_IFERR(memcpy_s(cs_write_addr(pack), cs_remain_size(pack), text->str, text->len));
    pack->head->size += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

static inline status_t cs_get_data(cs_packet_t *pack, uint32 size, void **buf)
{
    int64 len;
    char *temp_buf = NULL;
    CM_ASSERT(pack != NULL);
    len = (int64)CM_ALIGN4(size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    if (!cs_has_recv_remain(pack, (uint32)len)) {
        CM_THROW_ERROR(ERR_PACKET_READ, pack->head->size, pack->offset, (uint32)len);
        return CM_ERROR;
    }
    temp_buf = cs_read_addr(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (size > 0) ? (void *)temp_buf : NULL;
    }
    return CM_SUCCESS;
}

static inline status_t cs_get_int64(cs_packet_t *pack, int64 *value)
{
    int64 temp_value;
    CM_ASSERT(pack != NULL);
    if (!cs_has_recv_remain(pack, sizeof(int64))) {
        CM_THROW_ERROR(ERR_PACKET_READ, pack->head->size, pack->offset, sizeof(int64));
        return CM_ERROR;
    }
    temp_value = *(int64 *)cs_read_addr(pack);
    temp_value = (int64)(CS_DIFFERENT_ENDIAN(pack->options) ?
        cs_reverse_int64((uint64)temp_value) : temp_value);
    pack->offset += (uint32)sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t cs_get_int32(cs_packet_t *pack, int32 *value)
{
    int32 temp_value;
    CM_ASSERT(pack != NULL);
    if (!cs_has_recv_remain(pack, sizeof(int32))) {
        CM_THROW_ERROR(ERR_PACKET_READ, pack->head->size, pack->offset, sizeof(int32));
        return CM_ERROR;
    }
    temp_value = *(int32 *)cs_read_addr(pack);
    pack->offset += (uint32)sizeof(int32);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ?
        (int32)(cs_reverse_int32((uint32)temp_value)) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

/* need keep 4-byte align by the caller */
static inline status_t cs_get_int16(cs_packet_t *pack, int16 *value)
{
    int16 temp_value;
    CM_ASSERT(pack != NULL);
    if (!cs_has_recv_remain(pack, CS_ALIGN_SIZE)) {
        CM_THROW_ERROR(ERR_PACKET_READ, pack->head->size, pack->offset, CS_ALIGN_SIZE);
        return CM_ERROR;
    }

    temp_value = *(int16 *)cs_read_addr(pack);
    pack->offset += CS_ALIGN_SIZE;
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16((uint16)temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t cs_get_real(cs_packet_t *pack, double *value)
{
    double temp_value;
    CM_ASSERT(pack != NULL);
    if (!cs_has_recv_remain(pack, sizeof(double))) {
        CM_THROW_ERROR(ERR_PACKET_READ, pack->head->size, pack->offset, sizeof(double));
        return CM_ERROR;
    }
    temp_value = *(double *)cs_read_addr(pack);
    pack->offset += (uint32)sizeof(double);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t cs_get_text(cs_packet_t *pack, text_t *text)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *)&text->len));
    return cs_get_data(pack, text->len, (void **)&(text->str));
}

static inline status_t cs_copy_packet(const cs_packet_t *src, cs_packet_t *dst)
{
    uint32 copy_len = src->head->size;
    dst->offset = src->offset;
    dst->options = src->options;
    // set dst max_extend size
    dst->max_buf_size = src->max_buf_size;

    // copy src packet to dst packet
    dst->head->size = 0; // reset write offset
    CM_RETURN_IFERR(cs_try_realloc_send_pack(dst, copy_len));
    MEMS_RETURN_IFERR(memcpy_s(dst->buf, dst->buf_size, src->buf, copy_len));
    return CM_SUCCESS;
}

static inline status_t cs_reserve_space(cs_packet_t *pack, uint32 size, uint32 *offset)
{
    char *temp_buf = NULL;
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, CM_ALIGN4(size)));

    temp_buf = pack->buf + pack->head->size;
    pack->head->size += CM_ALIGN4(size);

    if (offset != NULL) {
        *offset = (uint32)(temp_buf - pack->buf);
    }

    return CM_SUCCESS;
}

static inline uint32 cs_get_version(const cs_packet_t *pack)
{
    return pack->head->version;
}

#ifdef __cplusplus
}
#endif

#endif
