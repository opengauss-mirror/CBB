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
 * mes_type.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_type.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_TYPE_H__
#define __MES_TYPE_H__

#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef unsigned __int64 uint64;
#else
#ifndef HAVE_UINT64
#define HAVE_UINT64
typedef unsigned long long uint64;
#endif
#endif

#define MES_MAX_BUFFERLIST ((int)4) /* Number of buffers supported by the bufferlist */
#define MES_MSGHEAD_RESERVED (28)

typedef struct st_mes_message_head {
    unsigned int version;
    unsigned char cmd;         // mes command
    unsigned short app_cmd;    // upper application command
    unsigned char unused;
    unsigned int  flags;
    unsigned int  caller_tid;
    unsigned long long ruid;
    unsigned int src_inst; // from instance
    unsigned int dst_inst; // to instance
    unsigned int size;
    unsigned char reserved[MES_MSGHEAD_RESERVED];
} mes_message_head_t;

/*
 * MES_CMD_CONNECT=0, MES_CMD_CONNECT=254, max=255
 */
typedef enum en_mes_cmd {
    MES_CMD_CONNECT = 0,
    MES_CMD_HEARTBEAT = 1,
    MES_CMD_ASYNC_MSG = 2,
    MES_CMD_SYNCH_REQ = 3,
    MES_CMD_SYNCH_ACK = 4,
    MES_CMD_FORWARD_REQ = 5,
    MES_CMD_MAX,
} mes_cmd_t;

#define MES_MSG_HEAD_SIZE sizeof(mes_message_head_t)

typedef struct st_mes_message {
    mes_message_head_t *head;
    char *buffer;
} mes_message_t;

typedef struct st_mes_buffer {
    char *buf;  /* data buffer */
    unsigned int len; /* buffer length */
} mes_buffer_t;

/* room unique id */
typedef struct st_ruid {
    union {
        struct {
            unsigned long long room_id : 16;
            unsigned long long rsn : 48;
        };
        unsigned long long ruid;
    };
} ruid_t;

typedef struct st_mes_bufflist {
    unsigned short cnt;
    mes_buffer_t buffers[MES_MAX_BUFFERLIST];
} mes_bufflist_t;

#ifndef WIN32
#define MES_CURR_TID (syscall(__NR_gettid))
#else
#define MES_CURR_TID (GetCurrentThreadId())
#endif

#define MES_INIT_MESSAGE_HEAD(head, v_version, v_cmd, v_flags, v_src_inst, v_dst_inst, v_ruid, v_size)      \
    do {                                                                                                    \
        (head)->cmd = (uint32)(v_cmd);                                                                      \
        (head)->app_cmd = 0;                                                                                \
        (head)->unused = 0;                                                                                 \
        (head)->version = (uint32)(v_version);                                                              \
        (head)->flags = (uint32)(v_flags);                                                                  \
        (head)->src_inst = (uint32)(v_src_inst);                                                            \
        (head)->dst_inst = (uint32)(v_dst_inst);                                                            \
        (head)->ruid = (uint64)(v_ruid);                                                                    \
        (head)->size = (uint32)(v_size);                                                                    \
        (head)->caller_tid = (uint32)MES_CURR_TID;                                                          \
        securec_check_panic(memset_s((head)->reserved, MES_MSGHEAD_RESERVED, 0, MES_MSGHEAD_RESERVED));     \
    } while (0)

#define MES_MESSAGE_BODY(msg) ((msg)->buffer + sizeof(mes_message_head_t))


#ifdef __cplusplus
}
#endif

#endif
