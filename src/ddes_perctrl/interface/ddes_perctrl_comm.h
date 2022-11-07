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
 * ddes_perctrl_comm.h
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/interface/ddes_perctrl_comm.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_PERCTRL_COMM_H__
#define __DDES_PERCTRL_COMM_H__

#ifdef WIN32
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include "cm_debug.h"
#include "cm_error.h"
#include "cm_num.h"
#include "cm_text.h"
#include "cm_types.h"
#include "cm_spinlock.h"

#define MAX_PACKET_LEN 2048
#define MAX_FD_LEN 128

#define PERCTRL_STD_INPUT 0
#define PERCTRL_STD_OUTPUT 1

typedef union st_pipe {
    struct {
        int32 rfd;
        int32 wfd;
    };
    int32 fds[2];
} pipe_t;

typedef struct st_perctrl_pipes {
    pipe_t req_pipe; // for sending request
    pipe_t res_pipe; // for receiving response
    pid_t pid;
} perctrl_pipes_t;

typedef enum {
    PERCTRL_CMD_REGISTER,
    PERCTRL_CMD_UNREGISTER,
    PERCTRL_CMD_REVERSE,
    PERCTRL_CMD_RELEASE,
    PERCTRL_CMD_CLEAR,
    PERCTRL_CMD_PREEMPT,
    PERCTRL_CMD_CAW,
    PERCTRL_CMD_READ,
    PERCTRL_CMD_WRITE,
    PERCTRL_CMD_INQL,
    PERCTRL_CMD_RKEYS,
    PERCTRL_CMD_RRES,
    PERCTRL_CMD_EXIT,
    PERCTRL_CMD_END // must be the last item
} perctrl_cmd_e;

typedef struct st_perctrl_cmd_head {
    uint32 size;
    perctrl_cmd_e cmd;
    int32 result;
} perctrl_cmd_head_t;

typedef struct st_perctrl_packet {
    uint32 offset;
    perctrl_cmd_head_t *head;
    char *buf;
    char buf_init[MAX_PACKET_LEN];
} perctrl_packet_t;

#define DDES_WRITE_ADDR(pack) ((pack)->buf + (pack)->head->size)
#define DDES_REMAIN_SIZE(pack) (MAX_PACKET_LEN - ((pack)->head->size))
#define DDES_READ_ADDR(pack) ((pack)->buf + (pack)->offset)

status_t ddes_put_text(perctrl_packet_t *pack, text_t *text);
status_t init_req_and_ack(perctrl_packet_t *req, perctrl_packet_t *ack);

static inline void ddes_init_get(perctrl_packet_t *pack)
{
    if (pack == NULL) {
        return;
    }
    pack->offset = (uint32)sizeof(perctrl_cmd_head_t);
}

static inline status_t ddes_put_int64(perctrl_packet_t *pack, uint64 value)
{
    CM_ASSERT(pack != NULL);

    *(uint64 *)DDES_WRITE_ADDR(pack) = value;
    pack->head->size += (uint32)sizeof(uint64);
    return CM_SUCCESS;
}

static inline status_t ddes_put_int32(perctrl_packet_t *pack, uint32 value)
{
    CM_ASSERT(pack != NULL);

    *(uint32 *)DDES_WRITE_ADDR(pack) = value;
    pack->head->size += (uint32)sizeof(uint32);
    return CM_SUCCESS;
}

static inline status_t ddes_put_str(perctrl_packet_t *pack, const char *str)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    uint32 size = (uint32)strlen(str);
    if (size != 0) {
        errno_t errcode = memcpy_s(DDES_WRITE_ADDR(pack), DDES_REMAIN_SIZE(pack), str, size);
        MEMS_RETURN_IFERR(errcode);
    }
    DDES_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CM_SUCCESS;
}

static inline status_t ddes_put_data(perctrl_packet_t *pack, const void *data, uint32 size)
{
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(data != NULL);

    if (size != 0) {
        errcode = memcpy_s(DDES_WRITE_ADDR(pack), DDES_REMAIN_SIZE(pack), data, size);
        MEMS_RETURN_IFERR(errcode);
    }
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t ddes_get_data(perctrl_packet_t *pack, uint32 size, void **buf)
{
    CM_ASSERT(pack != NULL);
    int64 len = (int64)CM_ALIGN4(size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    char *temp_buf = DDES_READ_ADDR(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (void *)temp_buf;
    }
    return CM_SUCCESS;
}

static inline status_t ddes_get_str(perctrl_packet_t *pack, char **buf)
{
    CM_ASSERT(pack != NULL);

    char *str = DDES_READ_ADDR(pack);
    size_t str_len = strlen(str) + 1;

    int64 len = (int64)CM_ALIGN4(str_len);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    pack->offset += (uint32)len;
    if (buf != NULL) {
        *buf = str;
    }
    return CM_SUCCESS;
}

static inline status_t ddes_get_int64(perctrl_packet_t *pack, int64 *value)
{
    int64 temp_value;
    CM_ASSERT(pack != NULL);
    temp_value = *(int64 *)DDES_READ_ADDR(pack);
    pack->offset += (uint32)sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t ddes_get_int32(perctrl_packet_t *pack, int32 *value)
{
    int32 temp_value;
    CM_ASSERT(pack != NULL);
    temp_value = *(int32 *)DDES_READ_ADDR(pack);
    pack->offset += (uint32)sizeof(int32);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t ddes_get_text(perctrl_packet_t *pack, text_t *text)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    CM_RETURN_IFERR(ddes_get_int32(pack, (int32 *)&text->len));
    return ddes_get_data(pack, text->len, (void **)&(text->str));
}

#define ddes_malloc(size) (ddes_malloc_ex(size, __LINE__, __FILE_NAME__))

static inline void *ddes_malloc_ex(uint32 size, uint32 line, char *file)
{
    CM_ASSERT(size != 0);
    // To do some je_malloc
    uint8 *p = (uint8 *)malloc(size);
    return (void *)p;
}

static inline void *ddes_malloc_align(uint32 alignment, uint32 size)
{
#ifndef WIN32
    int ret;
    void *memptr;
    ret = posix_memalign(&memptr, alignment, size);
    if (ret == 0) {
        return memptr;
    } else {
        return NULL;
    }
#else
    return ddes_malloc(size);
#endif
}

#endif
