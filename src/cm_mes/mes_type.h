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
#define MES_MAX_BUFFPOOL_NUM ((int)8)
#define MES_MAX_INSTANCES            (unsigned int)64
#define MES_MAX_IP_LEN 64
#define MES_MAX_LOG_PATH 4096

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

typedef enum en_mes_pipe_type {
    MES_TYPE_TCP = 1,
    MES_TYPE_IPC = 2,
    MES_TYPE_DOMAIN_SCOKET = 3,
    MES_TYPE_SSL = 4,
    MES_TYPE_EMBEDDED = 5, /* embedded mode, reserved */
    MES_TYPE_DIRECT = 6,   /* direct mode, reserved */
    MES_TYPE_RDMA = 7,     /* direct mode, reserved */
    MES_TYPE_CEIL
} mes_pipe_type_t;

typedef struct st_mes_addr {
    char ip[MES_MAX_IP_LEN];
    unsigned short port;
    unsigned char reserved[2];
} mes_addr_t;

typedef struct st_mes_buffer_attr {
    unsigned int size;
    unsigned int count;
} mes_buffer_attr_t;

typedef struct st_mes_buffer_pool_attr {
    unsigned int pool_count;
    unsigned int queue_count;
    mes_buffer_attr_t buf_attr[MES_MAX_BUFFPOOL_NUM];
} mes_buffer_pool_attr_t;

typedef struct st_mes_profile {
    unsigned int inst_id;
    unsigned int inst_cnt;
    mes_pipe_type_t pipe_type;
    mes_buffer_pool_attr_t buffer_pool_attr;
    unsigned int channel_cnt;
    unsigned int work_thread_cnt;
    unsigned int mes_elapsed_switch;
    unsigned char rdma_rpc_use_busypoll;    // busy poll need to occupy the cpu core
    unsigned char rdma_rpc_is_bind_core;
    unsigned char rdma_rpc_bind_core_start;
    unsigned char rdma_rpc_bind_core_end;
    char ock_log_path[MES_MAX_LOG_PATH];
    mes_addr_t inst_net_addr[MES_MAX_INSTANCES];
    unsigned int task_group[MES_TASK_GROUP_ALL];
    // Indicates whether to connected to other instances during MES initialization
    unsigned int conn_created_during_init : 1;
    unsigned int reserved : 31;
} mes_profile_t;

typedef struct st_mes_message_head {
    unsigned int version;
    unsigned int cmd; // command
    unsigned char flags;
    unsigned char src_inst; // from instance
    unsigned char dst_inst; // to instance
    unsigned char unused1;
    unsigned short src_sid; // from session
    unsigned short dst_sid; // to session
    unsigned short size;
    unsigned short tickets;
    unsigned int unused2;
    unsigned long long rsn;
    unsigned int cluster_ver;
} mes_message_head_t;

#define MES_MSG_HEAD_SIZE sizeof(mes_message_head_t)

typedef struct st_mes_message {
    mes_message_head_t *head;
    char *buffer;
} mes_message_t;

typedef struct st_mes_buffer {
    char *buf;  /* data buffer */
    unsigned int len; /* buffer length */
} mes_buffer_t;

typedef struct st_mes_bufflist {
    unsigned short cnt;
    mes_buffer_t buffers[MES_MAX_BUFFERLIST];
} mes_bufflist_t;

#define MES_INIT_MESSAGE_HEAD(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid) \
    do {                                                                                          \
        (head)->version = (uint32)0;                                                                \
        (head)->cmd = (uint32)(v_cmd);                                                              \
        (head)->flags = (uint8)(v_flags);                                                           \
        (head)->src_inst = (uint8)(v_src_inst);                                                     \
        (head)->dst_inst = (uint8)(v_dst_inst);                                                     \
        (head)->unused1 = (uint8)0;                                                                 \
        (head)->src_sid = (uint16)(v_src_sid);                                                      \
        (head)->dst_sid = (uint16)(v_dst_sid);                                                      \
        (head)->tickets = (uint32)0;                                                                \
        (head)->unused2 = (uint32)0;                                                                \
    } while (0)

#define MES_MESSAGE_BODY(msg) ((msg)->buffer + sizeof(mes_message_head_t))

typedef void (*mes_message_proc_t)(unsigned int work_thread, mes_message_t *message);
typedef int(*usr_cb_decrypt_pwd_t)(const char *cipher, unsigned int len, char *plain, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif
