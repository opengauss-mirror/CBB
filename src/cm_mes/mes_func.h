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
#include "cm_bilist.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "mes_queue.h"
#include "mes_tcp.h"
#include "mes_msg_pool.h"
#include "mes_rdma_rpc.h"
#include "cm_rwlock.h"
#include "mes_interface.h"
#include "mes_type.h"
#include "mes_stat.h"
#include "mes_task_threadpool_interface.h"
#include "cm_system.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define MES_INST_SENT_SUCCESS(bits, id) ((bits) |= ((uint64)0x1 << (id)))
#define MEG_GET_BUF_ID(msg_buf) (*(uint32 *)((char *)(msg_buf) - sizeof(uint32)))
#define MES_MESSAGE_TINY_SIZE (256) /* app head(64) + mes head(64) + reserved(128) */
#define MES_BUFFER_RESV_SIZE     (SIZE_K(2))
#define MES_MESSAGE_BUFFER_SIZE(profile) \
    (uint64)((profile)->frag_size + MES_MESSAGE_TINY_SIZE) /* heads + data */
#define MES_CHANNEL_MAX_SEND_BUFFER_SIZE(profile) MES_MESSAGE_BUFFER_SIZE(profile)
#define MES_WAIT_TIMEOUT (5) // ms

#define MES_ROOM_ID_TO_FREELIST_ID(rid) ((rid) / CM_MES_ROOMS_PER_FREELIST)
#define MES_INVLD_RUID (0)
#define MES_FIRST_RUID (1)
#define MES_RUID_GET_RSN(ruid) (((ruid_t *)&(ruid))->rsn)
#define MES_RUID_GET_RID(ruid) (((ruid_t *)&(ruid))->room_id)
#define MES_RUID_IS_INVALID(ruid) ((ruid) == MES_INVLD_RUID)
#define MES_RUID_IS_ILLEGAL(ruid) (MES_RUID_GET_RID(ruid) >= CM_MAX_MES_ROOMS)

#define MES_LOG_WAR_HEAD_EX(head, message, room)                                                              \
    do {                                                                                                      \
        LOG_RUN_WAR("[mes]%s: %s. cmd=%u, ruid->rid=%llu, ruid->rsn=%llu, "                                   \
            "room-rsn=%llu, src_inst=%u, dst_inst=%u, size=%u, flags=%u.",                                    \
            (char *)__func__, (message), (head)->cmd, (uint64)MES_RUID_GET_RID((head)->ruid),                 \
            (uint64)MES_RUID_GET_RSN((head)->ruid), (uint64)(room)->rsn, (head)->src_inst, (head)->dst_inst,  \
            (head)->size, (head)->flags);                                                                     \
    } while (0);

#define MES_LOG_ERR_HEAD_EX(head, message)                                                                     \
    do {                                                                                                       \
        LOG_RUN_ERR("[mes]%s: %s. cmd=%u, ruid->rid=%llu, ruid->rsn=%llu, src_inst=%u, dst_inst=%u, size=%u, " \
            "flags=%u.",                                                                                       \
            (char *)__func__, (message), (head)->cmd, (uint64)MES_RUID_GET_RID((head)->ruid),                  \
            (uint64)MES_RUID_GET_RSN((head)->ruid), (head)->src_inst, (head)->dst_inst, (head)->size,          \
            (head)->flags);                                                                                    \
    } while (0);

#define MES_RETURN_IF_BAD_RUID(ruid)                                                            \
    do {                                                                                        \
        if (MES_RUID_IS_ILLEGAL(ruid) || MES_RUID_IS_INVALID(ruid)) {                           \
            LOG_DEBUG_ERR("[mes] invalid ruid %llu(rid=%llu, rsn=%llu)",                        \
                (uint64)(ruid), (uint64)MES_RUID_GET_RID(ruid), (uint64)MES_RUID_GET_RSN(ruid));  \
            return ERR_MES_PARAM_INVALID;                                                        \
        }                                                                                       \
    } while (0);

#define MES_RETURN_IF_BAD_INST_COUNT(inst_count)                                                \
    do {                                                                                        \
        if ((inst_count) > MES_MAX_INSTANCES || (inst_count) == 0) {                                 \
            LOG_DEBUG_ERR("[mes] invalid inst_count=%d", inst_count);                           \
            return ERR_MES_PARAM_INVALID;                                                        \
        }                                                                                       \
    } while (0);

#define MES_RETURN_IF_BAD_MSG_COUNT(count)                                                      \
    do {                                                                                        \
        if ((count) > CM_INVALID_ID16 || (count) == 0) {                                            \
            LOG_DEBUG_ERR("[mes] message body count=%d", count);                                \
            return ERR_MES_PARAM_INVALID;                                                        \
        }                                                                                       \
    } while (0);

#ifdef WIN32
typedef HANDLE mes_mutex_t;
#else
typedef pthread_mutex_t mes_mutex_t;
#endif

/* external msg ptr attach to internal message. */
#define MES_MSG_ATTACH(msg, buf)                                                            \
    do {                                                                                    \
        (msg)->buffer = (char *)(buf) + sizeof(mes_message_head_t);                                   \
        (msg)->size = (((mes_message_head_t *)(buf))->size - sizeof(mes_message_head_t));   \
        (msg)->src_inst = ((unsigned int)((mes_message_head_t *)(buf))->src_inst);          \
    } while (0);

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

typedef void (*mes_connect_t)(uintptr_t pipePtr);

typedef void (*mes_heartbeat_t)(uintptr_t channelPtr);

typedef void (*mes_disconnect_t)(uint32 inst_id, bool32 wait);

typedef int (*mes_send_data_t)(const void *msg_data);

typedef int (*mes_send_bufflist_t)(mes_bufflist_t *buff_list);

typedef void (*mes_release_buf_t)(const char *buffer);

typedef mes_msgitem_t *(*mes_alloc_msgitem_t)(mes_msgqueue_t *queue, bool32 is_send);

typedef void (*mes_stop_channels_t)(void);

typedef struct rdma_rpc_lsnr_t {
    OckRpcServer server_handle;
    rwlock_t server_lock;
} rdma_rpc_lsnr_t;

typedef struct st_mes_lsnr {
    tcp_lsnr_t tcp;
    rdma_rpc_lsnr_t rdma;
} mes_lsnr_t;

typedef struct st_mes_pipe {
    rwlock_t recv_lock;
    rwlock_t send_lock;
    cs_pipe_t send_pipe;
    cs_pipe_t recv_pipe;
    rdma_rpc_client_t rdma_client;
    thread_t thread;
    volatile bool8 recv_pipe_active;
    volatile bool8 send_pipe_active;
    atomic_t send_count;
    atomic_t recv_count;
    uint64 last_send_time;
    mes_priority_t priority;
    struct st_mes_channel *channel;
    char *msgbuf;
    uint32 send_version;
    uint32 recv_version;
} mes_pipe_t;

typedef struct st_mes_channel {
    uint16 id;
    union
    {
        mes_pipe_t pipe[MES_PRIORITY_CEIL];
        mes_pipe_t rpc_pipe;
    };
} mes_channel_t;

typedef struct st_mes_waiting_room {
    bilist_node_t node;
    mes_mutex_t mutex;           // msg ack wake up mes_recv
    mes_mutex_t broadcast_mutex; // broadcast acks wake up mes_wait_acks
    spinlock_t lock;             // protect rsn
    void *msg_buf;
    uint32 err_code;
    atomic32_t req_count;
    atomic32_t ack_count;
    volatile uint64 rsn; // requestion sequence number
    volatile uint64 check_rsn;
    volatile char room_status;
    unsigned short room_index;
    char res;
    uint64 succ_insts;
} mes_waiting_room_t;

typedef enum en_bcast_flag {
    STATUS_FREE_ROOM = 0,
    STATUS_BCAST_SENDING,
    STATUS_BCAST_SENT,
    STATUS_PTP_SENT,
} bcast_flag_e;

typedef enum en_shutdown_phase {
    SHUTDOWN_PHASE_NOT_BEGIN = 0,
    SHUTDOWN_PHASE_INPROGRESS,
    SHUTDOWN_PHASE_DONE
} shutdown_phase_t;

typedef struct st_mes_conn {
    thread_lock_t lock;
    thread_t thread;
    cm_event_t event;
    bool8 is_connect; // Indicates whether the instance has triggered connect and heartbeat.
    bool8 is_start;   // Indicates whether the instance has started the thread for connect and heartbeat.
} mes_conn_t;

typedef struct st_room_freelist {
    uint32 list_id;
    spinlock_t lock;
    bilist_t list;
} mes_room_freelist_t;

typedef struct st_mes_waiting_room_pool {
    uint32 next_freelist;
    mes_waiting_room_t waiting_rooms[CM_MAX_MES_ROOMS];
    mes_room_freelist_t room_freelists[CM_MAX_ROOM_FREELIST_NUM];
    void **broadcast_msg[MES_MAX_INSTANCES];
    spinlock_t inst_broadcast_msg_lock;
} mes_waiting_room_pool_t;

typedef void (*mes_event_proc_t)(uint16 channel_id, uint16 priority, uint32 version, uint32 event);
typedef struct st_receiver {
    uint32 priority;
    uint32 id;
    mes_event_proc_t proc;
    int epfd;
    thread_t thread;
} receiver_t;

typedef struct st_mes_context {
    mes_lsnr_t lsnr;
    mes_channel_t **channels;
    spinlock_t inst_channel_lock;
    mes_conn_t conn_arr[MES_MAX_INSTANCES];
    mes_waiting_room_pool_t wr_pool;
    receiver_t sender_monitor;

    shutdown_phase_t phase;
    uint32 startLsnr : 1;
    uint32 startChannelsTh : 1;
    uint32 creatWaitRoom : 1;
    uint32 reserve : 29;
} mes_context_t;

typedef struct st_mes_instance {
    mes_profile_t profile;
    mes_context_t mes_ctx;
    mq_context_t send_mq;
    mq_context_t recv_mq;
    mes_message_proc_t proc;
    ssl_ctx_t *ssl_acceptor_fd;
    ssl_ctx_t *ssl_connector_fd;
    mes_task_threadpool_t task_tpool;
} mes_instance_t;

typedef struct st_mes_global_ptr {
    mes_instance_t* mes_ptr;
    mes_stat_t* cmd_count_stats_ptr;
    mes_elapsed_stat_t* cmd_time_stats_ptr;
    mes_msg_size_stats_t* cmd_size_stats_ptr;
} mes_global_ptr_t;

#define CHANNEL_ID_BITS (8)
#define CHANNEL_ID_MASK (((unsigned)1 << CHANNEL_ID_BITS) - 1)
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
    mes_heartbeat_t heartbeat_func;
    mes_disconnect_t disconnect_func;
    mes_send_data_t send_func;
    mes_send_bufflist_t send_bufflist_func;
    mes_release_buf_t release_buf_func;
    mes_alloc_msgitem_t alloc_msgitem_func;
} mes_callback_t;

// Do not modify
extern mes_instance_t g_cbb_mes;
extern mes_callback_t g_cbb_mes_callback;
#define MES_GLOBAL_INST_MSG g_cbb_mes
#define MES_CALLER_TID_TO_CHANNEL_ID(tid) (uint8)((tid) % MES_GLOBAL_INST_MSG.profile.channel_cnt)
#define MES_MY_ID (MES_GLOBAL_INST_MSG.profile.inst_id)
#define MES_SEND_DATA(msg_data) g_cbb_mes_callback.send_func(msg_data)
#define MES_SEND_BUFFLIST(buff_list) g_cbb_mes_callback.send_bufflist_func(buff_list)

#define MES_WAITING_ROOM_POOL MES_GLOBAL_INST_MSG.mes_ctx.wr_pool
#define MES_TASK_THREADPOOL &MES_GLOBAL_INST_MSG.task_tpool
#define ENABLE_MES_TASK_THREADPOOL (MES_GLOBAL_INST_MSG.profile.tpool_attr.enable_threadpool == CM_TRUE)
#define MES_BROADCAST_MSG MES_WAITING_ROOM_POOL.broadcast_msg

bool32 mes_connection_ready(uint32 inst_id);
int mes_send_bufflist(mes_bufflist_t *buff_list);
void mes_process_message(mes_msgqueue_t *my_queue, mes_message_t *msg);

void mes_mutex_destroy(mes_mutex_t *mutex);
int mes_mutex_create(mes_mutex_t *mutex);
#ifndef WIN32
void mes_get_timespec(struct timespec *tim, uint32 timeout);
#endif
bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout);
void mes_mutex_unlock(mes_mutex_t *mutex);
void mes_protect_when_timeout(mes_waiting_room_t *room);
void mes_protect_when_brcast_timeout(mes_waiting_room_t *room);

mes_waiting_room_t *mes_ruid_get_room(unsigned long long ruid);
bool8 ruid_matches_room_rsn(unsigned long long *ruid, unsigned long long room_rsn);

int mes_alloc_channels(void);
void mes_heartbeat(mes_pipe_t *pipe);

int mes_connect(inst_type inst_id);
void mes_disconnect_nowait(inst_type inst_id);
void mes_disconnect(inst_type inst_id);
void mes_release_message_buf(mes_message_t *msg_buf);
void mes_notify_msg_recv(mes_message_t *msg);
void mes_close_channel(mes_channel_t *channel);
void mes_close_send_pipe(mes_pipe_t *pipe);
void mes_close_send_pipe_nolock(mes_pipe_t *pipe);
void mes_close_recv_pipe(mes_pipe_t *pipe);
void mes_close_recv_pipe_nolock(mes_pipe_t *pipe);
status_t mes_get_inst_net_add_index(inst_type inst_id, uint32 *index);
int mes_connect_single(inst_type inst_id);
mes_channel_t *mes_get_active_send_channel(uint32 dest_id, uint32 caller_tid, uint32 flags);
void mes_destroy_all_broadcast_msg();
int mes_init_single_inst_broadcast_msg(unsigned int inst_id);
int mes_ensure_inst_channel_exist(unsigned int inst_id);
status_t mes_verify_ssl_key_pwd(ssl_config_t *ssl_cfg, char *plain, uint32 size);

#ifdef __cplusplus
}
#endif

#endif
