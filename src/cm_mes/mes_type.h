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

#include "cs_pipe.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_MAX_BUFFERLIST ((int)4) /* Number of buffers supported by the bufferlist */
#define MES_MAX_BUFFPOOL_NUM ((int)8)

typedef enum en_mes_task_group_id_t {
    MES_TASK_GROUP_ZERO = 0,
    MES_TASK_GROUP_ONE,
    MES_TASK_GROUP_TWO,
    MES_TASK_GROUP_THREE,
    MES_TASK_GROUP_ALL
} mes_task_group_id_t;

typedef enum en_mes_time_stat {
    MES_TIME_TEST_SEND = 0,
    MES_TIME_SEND_IO,
    MES_TIME_TEST_RECV,
    MES_TIME_TEST_MULTICAST,
    MES_TIME_TEST_MULTICAST_AND_WAIT,
    MES_TIME_TEST_WAIT_AND_RECV,
    MES_TIME_GET_BUF,
    MES_TIME_READ_MES,
    MES_TIME_PROC_FUN,
    MES_TIME_PUT_QUEUE,
    MES_TIME_GET_QUEUE,
    MES_TIME_QUEUE_PROC,
    MES_TIME_PUT_BUF,
    MES_TIME_CEIL
} mes_time_stat_t;

typedef struct st_mes_addr {
    char ip[CM_MAX_IP_LEN];
    uint16 port;
    uint8 reserved[2];
} mes_addr_t;

typedef struct st_mes_buffer_attr {
    uint32 size;
    uint32 count;
} mes_buffer_attr_t;

typedef struct st_mes_buffer_pool_attr {
    uint32 pool_count;
    uint32 queue_count;
    mes_buffer_attr_t buf_attr[MES_MAX_BUFFPOOL_NUM];
} mes_buffer_pool_attr_t;

typedef struct st_mes_profile {
    uint32 inst_id;
    uint32 inst_cnt;
    cs_pipe_type_t pipe_type;
    mes_buffer_pool_attr_t buffer_pool_attr;
    uint32 channel_cnt;
    uint32 work_thread_cnt;
    bool32 mes_elapsed_switch;
    mes_addr_t inst_net_addr[CM_MAX_INSTANCES];
    uint32 task_group[MES_TASK_GROUP_ALL];
    uint32 conn_created_during_init : 1; // Indicates whether to connected to other instances during MES initialization
    uint32 reserved : 31;
} mes_profile_t;

typedef struct st_mes_message_head {
    uint8 cmd; // command
    uint8 flags;
    uint8 src_inst; // from instance
    uint8 dst_inst; // to instance
    uint16 src_sid; // from session
    uint16 dst_sid; // to session
    uint16 size;
    uint8 unused[2];
    uint32 rsn;
} mes_message_head_t;

typedef struct st_mes_message {
    mes_message_head_t *head;
    char *buffer;
} mes_message_t;

typedef struct st_mes_buffer {
    char *buf;  /* data buffer */
    uint32 len; /* buffer length */
} mes_buffer_t;

typedef struct st_mes_bufflist {
    uint16 cnt;
    mes_buffer_t buffers[MES_MAX_BUFFERLIST];
} mes_bufflist_t;

#define MES_INIT_MESSAGE_HEAD(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid) \
    do {                                                                                          \
        (head)->cmd = v_cmd;                                                                      \
        (head)->flags = v_flags;                                                                  \
        (head)->src_inst = v_src_inst;                                                            \
        (head)->dst_inst = v_dst_inst;                                                            \
        (head)->src_sid = v_src_sid;                                                              \
        (head)->dst_sid = v_dst_sid;                                                              \
    } while (0)

#define MES_MESSAGE_BODY(msg) ((msg)->buffer + sizeof(mes_message_head_t))

typedef void (*mes_message_proc_t)(uint32 work_thread, mes_message_t *message);

#ifdef __cplusplus
}
#endif

#endif
