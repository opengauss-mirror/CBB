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
#include "mes_rdma_rpc.h"
#include "cm_rwlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define MES_INST_SENT_SUCCESS(bits, id) ((bits) |= ((uint64)0x1 << (id)))
#define MEG_GET_BUF_ID(msg_buf) (*(uint32 *)((char *)(msg_buf) - sizeof(uint32)))
#define MES_MESSAGE_TINY_SIZE (64)
#define MES_MESSAGE_BUFFER_SIZE \
    (uint32)(SIZE_K(32) + MES_MESSAGE_TINY_SIZE) /* biggest: pcr page ack: head + ack + page */
#define MES_MIN_TASK_NUM (1)
#define MES_MAX_TASK_NUM (128)
#define MES_WAIT_TIMEOUT (5) // ms

#define MES_LOG_WAR_HEAD_EX(head, message)                                                             \
    do {                                                                                               \
        LOG_RUN_ERR("[mes]%s: %s. cmd=%hhu, rsn=%llu, src_inst=%hhu, dst_inst=%hhu, src_sid=%hu, dst_sid=%hu.",  \
            (char *)__func__, (message), (head)->cmd, (head)->rsn, (head)->src_inst, (head)->dst_inst, \
            (head)->src_sid, (head)->dst_sid);                                                         \
    } while (0);

#define MES_LOG_ERR_HEAD_EX(head, message)                                                             \
    do {                                                                                               \
        LOG_RUN_ERR("[mes]%s: %s. cmd=%hhu, rsn=%llu, src_inst=%hhu, dst_inst=%hhu, src_sid=%hu, dst_sid=%hu.",  \
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

typedef void (*mes_disconnect_t)(uint32 inst_id, bool32 wait);

typedef int (*mes_send_data_t)(const void *msg_data);

typedef int (*mes_send_bufflist_t)(mes_bufflist_t *buff_list);

typedef void (*mes_release_buf_t)(const char *buffer);

typedef bool32 (*mes_connection_ready_t)(uint32 inst_id);

typedef mes_msgitem_t *(*mes_alloc_msgitem_t)(mes_msgqueue_t *queue);

typedef struct rdma_rpc_lsnr_t {
    OckRpcServer server_handle;
    rwlock_t server_lock;
} rdma_rpc_lsnr_t;

typedef struct st_mes_lsnr {
    tcp_lsnr_t tcp;
    rdma_rpc_lsnr_t rdma;
} mes_lsnr_t;

typedef struct st_mes_channel {
    rwlock_t recv_lock;
    rwlock_t send_lock;
    cs_pipe_t send_pipe;
    cs_pipe_t recv_pipe;
    rdma_rpc_client_t rdma_client;
    thread_t thread;
    uint16 id;
    volatile bool8 recv_pipe_active;
    volatile bool8 send_pipe_active;
    atomic_t send_count;
    atomic_t recv_count;
    mes_msgqueue_t msg_queue;
    date_t last_send_time;
} mes_channel_t;

typedef struct st_mes_waiting_room {
    mes_mutex_t mutex;           // msg ack wake up mes_recv
    mes_mutex_t broadcast_mutex; // broadcast acks wake up mes_wait_acks
    spinlock_t lock;             // protect rsn
    void *msg_buf;
    void *broadcast_msg[CM_MAX_INSTANCES];
    uint32 err_code;
    atomic32_t req_count;
    atomic32_t ack_count;
    volatile uint64 rsn; // requestion sequence number
    volatile uint64 check_rsn;
    volatile bool8 broadcast_flag;
    char res[3];
    uint64 succ_insts;
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
    ssl_ctx_t  *ssl_acceptor_fd;
    ssl_ctx_t  *ssl_connector_fd;
} mes_instance_t;

#define INST_ID_MOVE_LEFT_BIT_CNT 8
// for ssl
extern bool32 g_ssl_enable;
extern usr_cb_decrypt_pwd_t usr_cb_decrypt_pwd;

typedef struct timeval cm_timeval;

static __inline uint64 db_rdtsc(void)
{
#ifdef WIN32
    return __rdtsc();
#else
    uint32 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64)hi << UINT32_BITS) | lo);
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
#define MES_SESSION_TO_CHANNEL_ID(sid) (uint8)((sid) % MES_GLOBAL_INST_MSG.profile.channel_cnt)

bool32 mes_connection_ready(uint32 inst_id);
int mes_send_bufflist(mes_bufflist_t *buff_list);

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

typedef struct st_mes_global_ptr {
    mes_instance_t* g_cbb_mes_ptr;
    mes_stat_t* g_mes_stat_ptr;
    mes_elapsed_stat_t* g_mes_elapsed_stat;
} mes_global_ptr_t;

uint64 cm_get_time_usec(void);

void mes_local_stat(uint32 cmd);

status_t mes_verify_ssl_key_pwd(ssl_config_t *ssl_cfg, char *plain, uint32 size);

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

void mes_get_wait_event(unsigned int cmd, unsigned long long *event_cnt, unsigned long long *event_time);
#ifdef __cplusplus
}
#endif

#endif
