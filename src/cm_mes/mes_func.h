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
 * mes_func.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_func.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_FUNC_H__
#define __MES_FUNC_H__
#include "cm_utils.h"
#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_error.h"
#include "cm_timer.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "mes_queue.h"
#include "mes_tcp.h"
#include "mes_type.h"
#include "mes_msg_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define MES_INST_SENT_SUCCESS(bits, id) ((bits) |= (0x1 << (id)))
#define MEG_GET_BUF_ID(msg_buf) (*(uint32 *)((char *)(msg_buf) - sizeof(uint32)))
#define MES_MESSAGE_TINY_SIZE (64)
#define MES_MESSAGE_BUFFER_SIZE \
    (uint32)(SIZE_K(32) + MES_MESSAGE_TINY_SIZE) /* biggest: pcr page ack: head + ack + page */
#define MES_MIN_TASK_NUM (1)
#define MES_MAX_TASK_NUM (128)
#define MES_WAIT_TIMEOUT (5) // ms

#define MES_LOG_WAR_HEAD_EX(head, message)                                                             \
    do {                                                                                               \
        LOG_RUN_WAR("[mes]%s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u.",  \
            (char *)__func__, (message), (head)->cmd, (head)->rsn, (head)->src_inst, (head)->dst_inst, \
            (head)->src_sid, (head)->dst_sid);                                                         \
    } while (0);

#define MES_LOG_ERR_HEAD_EX(head, message)                                                             \
    do {                                                                                               \
        LOG_RUN_ERR("[mes]%s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u.",  \
            (char *)__func__, (message), (head)->cmd, (head)->rsn, (head)->src_inst, (head)->dst_inst, \
            (head)->src_sid, (head)->dst_sid);                                                         \
    } while (0);

#ifdef WIN32
typedef HANDLE mes_mutex_t;
#else
typedef pthread_mutex_t mes_mutex_t;
#endif

#define MES_MESSAGE_ATTACH(msg, buf)               \
    do {                                           \
        (msg)->buffer = buf;                       \
        (msg)->head = (mes_message_head_t *)(buf); \
    } while (0);

#define MES_MESSAGE_DETACH(msg) \
    do {                        \
        (msg)->buffer = NULL;   \
        (msg)->head = NULL;     \
    } while (0);

typedef int (*mes_connect_t)(uint32 inst_id);

typedef void (*mes_disconnect_t)(uint32 inst_id);

typedef int (*mes_send_data_t)(const void *msg_data);

typedef int (*mes_send_bufflist_t)(mes_bufflist_t *buff_list);

typedef void (*mes_release_buf_t)(const char *buffer);

typedef bool32 (*mes_connection_ready_t)(uint32 inst_id);

typedef mes_msgitem_t *(*mes_alloc_msgitem_t)(mes_msgqueue_t *queue);

typedef struct st_mes_lsnr {
    tcp_lsnr_t tcp;
} mes_lsnr_t;

typedef struct st_mes_waiting_room {
    mes_mutex_t mutex;           // msg ack wake up mes_recv
    mes_mutex_t broadcast_mutex; // broadcast acks wake up mes_wait_acks
    spinlock_t lock;             // protect rsn
    void *msg_buf;
    void *broadcast_msg[CM_MAX_INSTANCES];
    uint32 err_code;
    atomic32_t req_count;
    atomic32_t ack_count;
    volatile uint32 rsn; // requestion sequence number
    volatile uint32 check_rsn;
    volatile bool8 broadcast_flag;
    char res[3];
} mes_waiting_room_t;

typedef struct st_mes_conn {
    thread_lock_t lock;
    bool8 is_connect;
} mes_conn_t;

typedef struct st_mes_pool {
    uint32 count;
    mes_buf_chunk_t chunk[MES_MAX_BUFFPOOL_NUM];
} mes_pool_t;

typedef struct st_mes_context {
    mes_lsnr_t lsnr;
    mes_channel_t **channels;
    mes_pool_t msg_pool;
    mes_conn_t conn_arr[CM_MAX_INSTANCES];
    mes_waiting_room_t waiting_rooms[CM_MAX_MES_ROOMS];
    uint32 work_thread_idx[CM_MES_MAX_TASK_NUM];

    uint32 startLsnr : 1;
    uint32 startChannelsTh : 1;
    uint32 creatMsgPool : 1;
    uint32 creatWaitRoom : 1;
    uint32 startWorkTh : 1;
    uint32 reserve : 27;
} mes_context_t;

typedef struct st_mes_instance {
    mes_profile_t profile;
    mes_context_t mes_ctx;
    mq_context_t mq_ctx;
    mes_message_proc_t proc;
    bool32 is_enqueue[CM_MAX_MES_MSG_CMD];
} mes_instance_t;


typedef struct timeval cm_timeval;

static __inline uint64 db_rdtsc(void)
{
#ifdef WIN32
    return __rdtsc();
#else
    uint32 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64)hi << 32) | lo);
#endif
}

typedef struct st_mes_callback {
    mes_connect_t connect_func;
    mes_disconnect_t disconnect_func;
    mes_send_data_t send_func;
    mes_send_bufflist_t send_bufflist_func;
    mes_release_buf_t release_buf_func;
    mes_connection_ready_t conn_ready_func;
    mes_alloc_msgitem_t alloc_msgitem_func;
} mes_callback_t;

// Do not modify
extern mes_instance_t g_cbb_mes;
#define MES_GLOBAL_INST_MSG g_cbb_mes

void mes_process_message(mes_msgqueue_t *my_queue, uint32 recv_idx, mes_message_t *msg);

typedef struct st_mes_commond_stat {
    uint32 cmd;
    int64 send_count;
    int64 recv_count;
    int64 local_count;
    atomic32_t occupy_buf;
    spinlock_t lock;
} mes_commond_stat_t;

typedef struct st_mes_time_consume {
    uint32 cmd; // command
    uint64 time[MES_TIME_CEIL];
    int64 count[MES_TIME_CEIL];
    spinlock_t lock[MES_TIME_CEIL];
} mes_time_consume_t;

typedef struct st_mes_elapsed_stat {
    bool32 mes_elapsed_switch;
    mes_time_consume_t time_consume_stat[CM_MAX_MES_MSG_CMD];
} mes_elapsed_stat_t;

typedef struct st_mes_stat {
    bool32 mes_elapsed_switch;
    mes_commond_stat_t mes_commond_stat[CM_MAX_MES_MSG_CMD];
} mes_stat_t;

extern mes_elapsed_stat_t g_mes_elapsed_stat;
extern mes_stat_t g_mes_stat;
uint64 cm_get_time_usec(void);

void mes_local_stat(uint32 cmd);

static inline void mes_get_consume_time_start(uint64 *stat_time)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        *stat_time = cm_get_time_usec();
    }
    return;
}

static inline void mes_consume_with_time(uint32 cmd, mes_time_stat_t type, uint64 start_time)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        uint64 elapsed_time = cm_get_time_usec() - start_time;
        cm_spin_lock(&(g_mes_elapsed_stat.time_consume_stat[cmd].lock[type]), NULL);
        g_mes_elapsed_stat.time_consume_stat[cmd].time[type] += elapsed_time;
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].count[type]));
        cm_spin_unlock(&(g_mes_elapsed_stat.time_consume_stat[cmd].lock[type]));
    }
    return;
}

static inline void mes_elapsed_stat(uint32 cmd, mes_time_stat_t type)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        cm_spin_lock(&(g_mes_elapsed_stat.time_consume_stat[cmd].lock[type]), NULL);
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].count[type]));
        cm_spin_unlock(&(g_mes_elapsed_stat.time_consume_stat[cmd].lock[type]));
    }
    return;
}

#ifdef __cplusplus
}
#endif

#endif
