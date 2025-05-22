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
 * mes_func.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_func.c
 *
 * -------------------------------------------------------------------------
 */
#include <float.h>
#include <math.h>
#include "mes_func.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_spinlock.h"
#include "cs_tcp.h"
#include "mes_tcp.h"
#include "cm_date_to_text.h"
#include "mes_rpc_dl.h"
#include "cm_defs.h"
#include "mes_metadata.h"
#include "mes_interface.h"
#include "mec_type.h"
#include "mes_recv.h"
#include "mes_stat.h"
#include "mec_adapter.h"
#include "cm_system.h"

mes_instance_t g_cbb_mes = {0};
mes_callback_t g_cbb_mes_callback;
static spinlock_t g_profile_lock;

static mes_global_ptr_t g_mes_ptr = {
    .mes_ptr = &g_cbb_mes,
    .cmd_count_stats_ptr = &g_mes_stat,
    .cmd_time_stats_ptr = &g_mes_elapsed_stat,
    .cmd_size_stats_ptr = &g_mes_msg_size_stat
};

#define MES_CONNECT(pipe) g_cbb_mes_callback.connect_func(pipe)
#define MES_HEARTBEAT(pipe) g_cbb_mes_callback.heartbeat_func(pipe)
#define MES_DISCONNECT(inst_id, wait) g_cbb_mes_callback.disconnect_func(inst_id, wait)
#define MES_RELEASE_BUFFER(buffer) g_cbb_mes_callback.release_buf_func(buffer)
#define MES_CONNETION_READY(inst_id, ready_count) g_cbb_mes_callback.conn_ready_func(inst_id, ready_count)
#define MES_ALLOC_MSGITEM(queue, is_send) g_cbb_mes_callback.alloc_msgitem_func(queue, is_send)

#define MES_CONNECT_TIMEOUT (3000)

// for ssl
bool32 g_ssl_enable = CM_FALSE;
usr_cb_decrypt_pwd_t usr_cb_decrypt_pwd = NULL;

static inline void mes_clean_recv_broadcast_msg(mes_waiting_room_t *room)
{
    mes_message_t msg;
    for (uint32 inst_id = 0; inst_id < MES_MAX_INSTANCES; ++inst_id) {
        if (MES_BROADCAST_MSG[inst_id] == NULL) {
            continue;
        }
        if (MES_BROADCAST_MSG[inst_id][room->room_index] != NULL) {
            MES_MESSAGE_ATTACH(&msg, MES_BROADCAST_MSG[inst_id][room->room_index]);
            mes_release_message_buf(&msg);
            MES_BROADCAST_MSG[inst_id][room->room_index] = NULL;
        }
    }
}

#ifdef WIN32
void mes_mutex_destroy(mes_mutex_t *mutex)
{
    (void)CloseHandle(*mutex);
}

int mes_mutex_create(mes_mutex_t *mutex)
{
    *mutex = CreateSemaphore(NULL, 0, CM_MAX_MES_ROOMS, NULL);
    if (*mutex == NULL) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    uint32 code = WaitForSingleObject(*mutex, timeout);
    return (code == WAIT_OBJECT_0);
}

void mes_mutex_unlock(mes_mutex_t *mutex)
{
    ReleaseSemaphore(*mutex, 1, NULL);
}

void mes_protect_when_timeout(mes_waiting_room_t *room)
{
    return;
}

void mes_protect_when_brcast_timeout(mes_waiting_room_t *room)
{
    return;
}

#else
void mes_mutex_destroy(mes_mutex_t *mutex)
{
    (void)pthread_mutex_destroy(mutex);
}

int mes_mutex_create(mes_mutex_t *mutex)
{
    if (pthread_mutex_init(mutex, NULL) != 0) {
        return CM_ERROR;
    }

    (void)pthread_mutex_lock(mutex);
    return CM_SUCCESS;
}

void mes_get_timespec(struct timespec *tim, uint32 timeout)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_REALTIME, &tv);

    tim->tv_sec = tv.tv_sec + timeout / MILLISECS_PER_SECOND;
    tim->tv_nsec = tv.tv_nsec + ((long)timeout % (long)MILLISECS_PER_SECOND) * NANOSECS_PER_MILLISECS_LL;
    if (tim->tv_nsec >= NANOSECS_PER_SECOND_LL) {
        tim->tv_sec++;
        tim->tv_nsec -= NANOSECS_PER_SECOND_LL;
    }
}

bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    struct timespec ts;
    mes_get_timespec(&ts, timeout);

    return (pthread_mutex_timedlock(mutex, &ts) == 0);
}

void mes_mutex_unlock(mes_mutex_t *mutex)
{
    (void)pthread_mutex_unlock(mutex);
}

void mes_protect_when_timeout(mes_waiting_room_t *room)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_inc((atomic_t *)(&room->rsn));
    if (!pthread_mutex_trylock(&room->mutex)) { // trylock to avoid mutex has been unlocked.
        if (room->msg_buf != NULL) {
            LOG_RUN_ERR("[mes]%s: mutex has unlock, rsn=%llu, room rsn=%llu.", (char *)__func__,
                (uint64)((ruid_t *)(&((mes_message_head_t *)room->msg_buf)->ruid))->rsn, room->rsn);
            mes_free_buf_item((char *)room->msg_buf);
        }
    }
    cm_spin_unlock(&room->lock);
}

void mes_protect_when_brcast_timeout(mes_waiting_room_t *room)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_inc((atomic_t *)(&room->rsn));
    cm_spin_unlock(&room->lock);
    (void)pthread_mutex_trylock(&room->broadcast_mutex);
    mes_clean_recv_broadcast_msg(room);
}

#endif

static inline void mes_stop_lsnr(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        cs_stop_tcp_lsnr(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp);
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        stop_rdma_rpc_lsnr();
    }
    return;
}

static void mes_clean_session_mutex(uint32 ceil)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom) {
        return;
    }

    for (uint32 i = 0; i < ceil; i++) {
        mes_mutex_destroy(&MES_GLOBAL_INST_MSG.mes_ctx.wr_pool.waiting_rooms[i].mutex);
        mes_mutex_destroy(&MES_GLOBAL_INST_MSG.mes_ctx.wr_pool.waiting_rooms[i].broadcast_mutex);
    }
    MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom = CM_FALSE;
}

static int mes_set_addr(uint32 index, const mes_addr_t *inst_net_addr)
{
    errno_t ret;
    inst_type inst_id = inst_net_addr->inst_id;
    char *ip = (char *)inst_net_addr->ip;
    char *secondary_ip = (char *)inst_net_addr->secondary_ip;
    unsigned short port = inst_net_addr->port;
    unsigned char need_connect = inst_net_addr->need_connect;

    if (!CM_IS_EMPTY_STR(ip) && cm_check_ip_valid(ip)) {
        ret = strncpy_s(MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].ip, CM_MAX_IP_LEN, ip, strlen(ip));
        if (ret != EOK) {
            LOG_DEBUG_ERR("[mes] mes_set_addr, strncpy_s ip failed, inst_id:%u, ip:%s, port:%u", inst_id, ip, port);
            return ERR_MES_STR_COPY_FAIL;
        }
    } else {
        ret = memset_sp(MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].ip, CM_MAX_IP_LEN, 0, CM_MAX_IP_LEN);
        if (ret != EOK) {
            LOG_DEBUG_ERR("[mes] mes_set_addr, memset_sp ip failed, inst_id:%u", inst_id);
            return ERR_MES_STR_COPY_FAIL;
        }
    }

    if (!CM_IS_EMPTY_STR(secondary_ip) && cm_check_ip_valid(secondary_ip)) {
        ret = strncpy_s(MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].secondary_ip, CM_MAX_IP_LEN,
                        secondary_ip, strlen(secondary_ip));
        if (ret != EOK) {
            LOG_DEBUG_ERR("[mes] mes_set_addr, strncpy_s secondary_ip failed, inst_id:%u, secondary_ip:%s, port:%u",
                          inst_id, secondary_ip, port);
            return ERR_MES_STR_COPY_FAIL;
        }
    } else {
        ret = memset_sp(MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].secondary_ip, CM_MAX_IP_LEN, 0, CM_MAX_IP_LEN);
        if (ret != EOK) {
            LOG_DEBUG_ERR("[mes] mes_set_addr, memset_sp ip failed, inst_id:%u", inst_id);
            return ERR_MES_STR_COPY_FAIL;
        }
    }

    MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].port = port;
    MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].inst_id = inst_id;
    MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].need_connect = need_connect;
    return CM_SUCCESS;
}

static int mes_set_instance_info(inst_type inst_id, uint32 inst_cnt, const mes_addr_t *inst_net_addrs)
{
    int ret;
    uint32 i;
    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] inst_id %u is invalid, exceed max instance num %u.", inst_id, MES_MAX_INSTANCES);
        return ERR_MES_PARAM_INVALID;
    }

    if (inst_cnt > MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] inst_count %u is invalid, exceed max instance num %u.", inst_cnt, MES_MAX_INSTANCES);
        return ERR_MES_PARAM_INVALID;
    }

    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    cm_spin_lock(&g_profile_lock, NULL);
    profile->inst_id = inst_id;
    profile->inst_cnt = 0;

    ret = memset_sp(profile->inst_net_addr, (sizeof(mes_addr_t) * MES_MAX_INSTANCES), 0,
                    (sizeof(mes_addr_t) * MES_MAX_INSTANCES));
    if (ret != EOK) {
        cm_spin_unlock(&g_profile_lock);
        LOG_RUN_ERR("[mes] mes_set_instance_info, memset_sp failed.");
        return ERR_MES_MEMORY_SET_FAIL;
    }
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        profile->inst_net_addr[i].inst_id = MES_MAX_INSTANCES;
    }

    for (i = 0; i < inst_cnt; i++) {
        ret = mes_set_addr(i, &inst_net_addrs[i]);
        if (ret != CM_SUCCESS) {
            cm_spin_unlock(&g_profile_lock);
            LOG_RUN_ERR("[mes] mes_set_instance_info, mes_set_addr failed.");
            return ret;
        }
    }

    profile->inst_cnt = inst_cnt;
    cm_spin_unlock(&g_profile_lock);
    return CM_SUCCESS;
}

static void mes_set_priority_num(uint32 priority_cnt)
{
    if (priority_cnt < MES_MIN_PRIORITY_NUM) {
        MES_GLOBAL_INST_MSG.profile.priority_cnt = MES_MIN_PRIORITY_NUM;
        LOG_RUN_WAR("[mes] min priority num is %u.", MES_MIN_PRIORITY_NUM);
    } else if (priority_cnt > MES_MAX_PRIORITY_NUM) {
        MES_GLOBAL_INST_MSG.profile.priority_cnt = MES_MAX_PRIORITY_NUM;
        LOG_RUN_WAR("[mes] max priority num is %u.", MES_MAX_PRIORITY_NUM);
    } else {
        MES_GLOBAL_INST_MSG.profile.priority_cnt = priority_cnt;
    }

    LOG_RUN_INF("[mes] set priority num %u.", MES_GLOBAL_INST_MSG.profile.priority_cnt);
}

static int mes_set_priority_task_worker_num(mes_priority_t priority, uint32 task_num, bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    mes_task_priority_t *task_priority = &mq_ctx->priority.task_priority[priority];

    if (task_num == 0) {
        LOG_RUN_WAR("[mes] priority %u set task_num 0, is_send:%u.", priority, is_send);
        return CM_SUCCESS;
    }

    if (task_priority->is_set) {
        LOG_RUN_ERR("[mes] priority %u has been set already, is_send:%u.", priority, is_send);
        return ERR_MES_THE_PRIORITY_SETED;
    }

    if ((mq_ctx->priority.assign_task_idx + task_num) > mq_ctx->task_num) {
        LOG_RUN_ERR("[mes] priority %u task num %u has exceed total task num, is_send:%u.",
                    priority, task_num, is_send);
        return ERR_MES_PARAM_INVALID;
    }

    task_priority->push_cursor = 0;
    task_priority->pop_cursor = 0;
    task_priority->is_set = CM_TRUE;
    task_priority->task_num = (uint8)task_num;
    task_priority->start_task_idx = (uint8)mq_ctx->priority.assign_task_idx;
    task_priority->priority = priority;
    task_priority->finished_msgitem_num = 0;
    task_priority->inqueue_msgitem_num = 0;
    task_priority->total_cost_time = 0;
    mq_ctx->priority.assign_task_idx += task_num;

    LOG_RUN_INF("[mes] set priority %u start_task_idx %hhu task num %u, is_send:%u.",
                priority, task_priority->start_task_idx, task_num, is_send);

    return CM_SUCCESS;
}

int mes_set_msg_pool(mes_profile_t *profile)
{
    int ret = mes_check_msg_pool_attr(profile, &MES_GLOBAL_INST_MSG.profile, CM_TRUE, NULL);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = mes_check_message_pool_size(profile);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return ret;
}

void mes_set_specified_priority_enable_compress(mes_priority_t priority, bool8 enable_compress)
{
    if (SECUREC_UNLIKELY(priority >= MES_PRIORITY_CEIL)) {
        LOG_RUN_ERR("[mes] invalid priority %u.", priority);
        return;
    }

    uint8 enable_compress_priority = MES_GLOBAL_INST_MSG.profile.enable_compress_priority;
    if (enable_compress) {
        cm_bitmap8_set(&enable_compress_priority, (uint8)priority);
    } else {
        cm_bitmap8_clear(&enable_compress_priority, (uint8)priority);
    }
    MES_GLOBAL_INST_MSG.profile.enable_compress_priority = enable_compress_priority;
    LOG_RUN_INF("[mes] set set specified priority %u enable_compress %u.", priority, enable_compress);
}

void mes_set_compress_algorithm(compress_algorithm_t algorithm)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    if (algorithm == profile->algorithm) {
        return;
    }

    if (algorithm == COMPRESS_NONE || algorithm >= COMPRESS_CEIL) {
        profile->algorithm = COMPRESS_NONE;
    } else {
        profile->algorithm = algorithm;
    }
    LOG_RUN_INF("[mes] set compress algorithm %u.", profile->algorithm);
}

void mes_set_compress_level(uint32 level)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    if (level == profile->compress_level) {
        return;
    }

    if (level < MES_DEFAULT_COMPRESS_LEVEL || level > MES_MAX_COMPRESS_LEVEL) {
        profile->compress_level = MES_DEFAULT_COMPRESS_LEVEL;
    } else {
        profile->compress_level = level;
    }
    LOG_RUN_INF("[mes] set compress algorithm level %u.", profile->compress_level);
}

static void mes_set_channel_num(uint32 channel_cnt)
{
    if (channel_cnt < CM_MES_MIN_CHANNEL_NUM) {
        MES_GLOBAL_INST_MSG.profile.channel_cnt = CM_MES_MIN_CHANNEL_NUM;
        LOG_RUN_WAR("[mes] min channel num is %u.", CM_MES_MIN_CHANNEL_NUM);
    } else if (channel_cnt > CM_MES_MAX_CHANNEL_NUM) {
        MES_GLOBAL_INST_MSG.profile.channel_cnt = CM_MES_MAX_CHANNEL_NUM;
        LOG_RUN_WAR("[mes] max channel num is %u.", CM_MES_MAX_CHANNEL_NUM);
    } else {
        MES_GLOBAL_INST_MSG.profile.channel_cnt = channel_cnt;
    }

    LOG_RUN_INF("[mes] set channel num %u.", MES_GLOBAL_INST_MSG.profile.channel_cnt);
    return;
}

static status_t mes_check_task_threadpool_attr(mes_profile_t *profile)
{
    if (!profile->tpool_attr.enable_threadpool) {
        LOG_RUN_INF("[mes][MES TASK THREADPOOL] work threadpool is off");
        MES_GLOBAL_INST_MSG.profile.tpool_attr.enable_threadpool = CM_FALSE;
        return CM_SUCCESS;
    }

    bool8 work_task_count_all_zero = CM_TRUE;
    for (int i = 0; i < MES_PRIORITY_CEIL; i++) {
        if (profile->work_task_count[i] > 0 ) {
            work_task_count_all_zero = CM_FALSE;
            break;
        }
    }

    if (profile->tpool_attr.enable_threadpool && !work_task_count_all_zero) {
        LOG_RUN_WAR("[mes][MES TASK THREADPOOL] work threadpool is on and work_task_count is not zero, "
            "which is not allowed. so we turn off work threadpool");
        profile->tpool_attr.enable_threadpool = CM_FALSE;
        MES_GLOBAL_INST_MSG.profile.tpool_attr.enable_threadpool = CM_FALSE;
        return CM_SUCCESS;
    }
    
    mes_task_threadpool_attr_t *tpool_attr = &profile->tpool_attr;
    if (tpool_attr->group_num > MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] group_num large than MES_PRIORITY_CEIL");
        return CM_ERROR;
    }

    if (tpool_attr->min_cnt < MES_MIN_TASK_NUM) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] min_cnt less than MES_MIN_TASK_NUM, min_cnt:%u, MES_MIN_TASK_NUM:%u",
            tpool_attr->min_cnt, MES_MIN_TASK_NUM);
        return CM_ERROR;
    }

    if (tpool_attr->max_cnt > MES_MAX_TASK_NUM) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] max_cnt large than MES_MAX_TASK_NUM, max_cnt:%u, MES_MAX_TASK_NUM:%u",
            tpool_attr->max_cnt, MES_MAX_TASK_NUM);
        return CM_ERROR;
    }

    unsigned int total_min = 0;
    unsigned int total_max = 0;
    for (int i = 0; i < tpool_attr->group_num; i++) {
        mes_task_threadpool_group_attr_t *group_attr = &tpool_attr->group_attr[i];
        if (group_attr->enabled) {
            if (group_attr->min_cnt > group_attr->max_cnt) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group min_cnt large than max_cnt "
                    "group_id:%u, min_cnt:%u, max_cnt:%u",
                    group_attr->group_id, group_attr->min_cnt, group_attr->max_cnt);
                return CM_ERROR;
            }
            if (group_attr->min_cnt < MES_MIN_TASK_NUM) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group min_cnt less than MES_MIN_TASK_NUM "
                    "group_id:%u, min_cnt:%u, MES_MIN_TASK_NUM:%u",
                    group_attr->group_id, group_attr->min_cnt, MES_MIN_TASK_NUM);
                return CM_ERROR;
            }
            if (group_attr->max_cnt > MES_MAX_TASK_NUM) {
                LOG_RUN_ERR("[MES TASK THREADPOOL] group max_cnt large than MES_MAX_TASK_NUM "
                    "group_id:%u, max_cnt:%u, MES_MAX_TASK_NUM:%u",
                    group_attr->group_id, group_attr->max_cnt, MES_MAX_TASK_NUM);
                return CM_ERROR;
            }
            total_min += group_attr->min_cnt;
            total_max += group_attr->max_cnt;
        }
    }

    if (total_min != tpool_attr->min_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] min_cnt not equal to sum of group min_cnt "
            "min_cnt:%u, sum of group:%u",
            tpool_attr->min_cnt, total_min);
        return CM_ERROR;
    }

    if (total_max != tpool_attr->max_cnt) {
        LOG_RUN_ERR("[MES TASK THREADPOOL] max_cnt not equal to sum of group max_cnt "
            "max_cnt:%u, sum of group:%u",
            tpool_attr->max_cnt, total_max);
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes][MES TASK THREADPOOL] work threadpool is on");
    MES_GLOBAL_INST_MSG.profile.tpool_attr = profile->tpool_attr;
    return CM_SUCCESS;
}

static int mes_set_profile(mes_profile_t *profile)
{
    int ret;
    GS_INIT_SPIN_LOCK(g_profile_lock);
    ret = mes_set_instance_info(profile->inst_id, profile->inst_cnt, profile->inst_net_addr);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: mes_set_instance_info failed.");
        return ret;
    }

    MES_GLOBAL_INST_MSG.profile.pipe_type = profile->pipe_type;
    MES_GLOBAL_INST_MSG.profile.conn_created_during_init = profile->conn_created_during_init;
    MES_GLOBAL_INST_MSG.profile.frag_size = profile->frag_size;
    MES_GLOBAL_INST_MSG.profile.max_wait_time =
        profile->max_wait_time == 0 ? CM_INVALID_INT32 : profile->max_wait_time;
    MES_GLOBAL_INST_MSG.profile.connect_timeout =
        profile->connect_timeout == 0 ? CM_INVALID_INT32 : profile->connect_timeout;
    MES_GLOBAL_INST_MSG.profile.socket_timeout =
        profile->socket_timeout == 0 ? CM_INVALID_INT32 : profile->socket_timeout;
    MES_GLOBAL_INST_MSG.profile.need_serial = profile->need_serial;
    MES_GLOBAL_INST_MSG.profile.send_directly = profile->send_directly;
    MES_GLOBAL_INST_MSG.profile.disable_request = profile->disable_request;
    mes_set_channel_num(profile->channel_cnt);
    mes_set_priority_num(profile->priority_cnt);
    MES_GLOBAL_INST_MSG.profile.enable_compress_priority = profile->enable_compress_priority;
    mes_set_compress_algorithm(profile->algorithm);
    mes_set_compress_level(profile->compress_level);

    ret = memcpy_sp(MES_GLOBAL_INST_MSG.profile.send_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.send_task_count), profile->send_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.send_task_count));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes]: set send_task_count failed.");
        return ERR_MES_MEMORY_COPY_FAIL;
    }
    ret = memcpy_sp(MES_GLOBAL_INST_MSG.profile.recv_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.recv_task_count), profile->recv_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.recv_task_count));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes]: set recv_task_count failed.");
        return ERR_MES_MEMORY_COPY_FAIL;
    }

    ret = memcpy_sp(MES_GLOBAL_INST_MSG.profile.work_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.work_task_count), profile->work_task_count,
                    sizeof(MES_GLOBAL_INST_MSG.profile.work_task_count));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes]: set work_task_count failed.");
        return ERR_MES_MEMORY_COPY_FAIL;
    }

    ret = mes_set_msg_pool(profile);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: set msg pool failed.");
        return ret;
    }

    // pipe work method and bind core
    MES_GLOBAL_INST_MSG.profile.rdma_rpc_use_busypoll = profile->rdma_rpc_use_busypoll;
    MES_GLOBAL_INST_MSG.profile.rdma_rpc_is_bind_core = profile->rdma_rpc_is_bind_core;
    MES_GLOBAL_INST_MSG.profile.rdma_rpc_bind_core_start = profile->rdma_rpc_bind_core_start;
    MES_GLOBAL_INST_MSG.profile.rdma_rpc_bind_core_end = profile->rdma_rpc_bind_core_end;
    ret = strncpy_sp(MES_GLOBAL_INST_MSG.profile.ock_log_path, MES_MAX_LOG_PATH, profile->ock_log_path,
                     MES_MAX_LOG_PATH - 1);
    if (ret != EOK) {
        LOG_RUN_ERR("[mes]: copy ock_log_path failed.");
        return ERR_MES_MEMORY_COPY_FAIL;
    }

    ret = mes_check_task_threadpool_attr(profile);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: init threadpool attr failed.");
        return ret;
    }

    LOG_RUN_INF("[mes]: set profile finish.");
    return CM_SUCCESS;
}

int mes_init_single_inst_broadcast_msg(unsigned int inst_id)
{
    size_t alloc_size = sizeof(void *) * CM_MAX_MES_ROOMS;
    char *temp_buf = (char *)cm_malloc_prot(alloc_size);
    if (temp_buf == NULL) {
        LOG_RUN_ERR("allocate broadcast failed, inst_id %u alloc size %zu", inst_id, alloc_size);
        return ERR_MES_MALLOC_FAIL;
    }
    int ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(temp_buf);
        return ERR_MES_MEMORY_SET_FAIL;
    }
    MES_WAITING_ROOM_POOL.broadcast_msg[inst_id] = (void **)temp_buf;
    return CM_SUCCESS;
}

static int mes_init_broadcast_msg()
{
    GS_INIT_SPIN_LOCK(MES_WAITING_ROOM_POOL.inst_broadcast_msg_lock);
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; ++i) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        CM_RETURN_IFERR(mes_init_single_inst_broadcast_msg(inst_id));
    }
    return CM_SUCCESS;
}

static int mes_init_session_room(void)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    if (profile->disable_request) {
        LOG_RUN_INF("[mes]no need init mes session room");
        return CM_SUCCESS;
    }
    uint32 i;
    uint32 freelist_idx;
    mes_waiting_room_t *room = NULL;
    mes_room_freelist_t *wr_freelist = NULL;
    MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom = CM_TRUE;
    mes_waiting_room_pool_t *wrpool = &MES_WAITING_ROOM_POOL;

    MEMS_RETURN_IFERR(memset_s(wrpool, sizeof(mes_waiting_room_pool_t), 0, sizeof(mes_waiting_room_pool_t)));

    for (i = 0; i < CM_MAX_ROOM_FREELIST_NUM; i++) {
        wr_freelist = &wrpool->room_freelists[i];
        wr_freelist->list_id = i;
        wr_freelist->lock = 0;
        cm_bilist_init(&wr_freelist->list);
    }

    for (i = 0; i < CM_MAX_MES_ROOMS; i++) {
        room = &wrpool->waiting_rooms[i];

        if (mes_mutex_create(&room->mutex) != CM_SUCCESS) {
            mes_clean_session_mutex(i);
            LOG_RUN_ERR("mes_mutex_create %u failed.", i);
            return ERR_MES_CREAT_MUTEX_FAIL;
        }

        if (mes_mutex_create(&room->broadcast_mutex) != CM_SUCCESS) {
            mes_clean_session_mutex(i);
            LOG_RUN_ERR("mes_mutex_create %u failed.", i);
            return ERR_MES_CREAT_MUTEX_FAIL;
        }

        GS_INIT_SPIN_LOCK(room->lock);

        room->rsn = MES_FIRST_RUID;
        room->check_rsn = MES_INVLD_RUID;
        room->room_index = (uint16)i;
        freelist_idx = MES_ROOM_ID_TO_FREELIST_ID(i);
        cm_bilist_add_tail(&room->node, (bilist_t *)&wrpool->room_freelists[freelist_idx].list);
    }

    int ret = mes_init_broadcast_msg();
    if (ret != CM_SUCCESS) {
        mes_destroy_all_broadcast_msg();
        mes_clean_session_mutex(CM_MAX_MES_ROOMS);
        LOG_RUN_ERR("mes_init_broadcast_msg failed.");
        return ret;
    }
    return CM_SUCCESS;
}

static int mes_register_func(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        g_cbb_mes_callback.connect_func = mes_tcp_try_connect;
        g_cbb_mes_callback.heartbeat_func = mes_tcp_heartbeat_channel;
        g_cbb_mes_callback.disconnect_func = mes_tcp_disconnect;
        g_cbb_mes_callback.send_func = mes_tcp_send_data;
        g_cbb_mes_callback.send_bufflist_func = mes_tcp_send_bufflist;
        g_cbb_mes_callback.alloc_msgitem_func = mes_alloc_msgitem;
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        g_cbb_mes_callback.connect_func = mes_rdma_rpc_try_connect;
        g_cbb_mes_callback.heartbeat_func = mes_rdma_rpc_heartbeat_channel;
        g_cbb_mes_callback.disconnect_func = mes_rdma_rpc_disconnect_handle;
        g_cbb_mes_callback.send_func = mes_rdma_rpc_send_data;
        g_cbb_mes_callback.send_bufflist_func = mes_rdma_rpc_send_bufflist;
        g_cbb_mes_callback.alloc_msgitem_func = mes_alloc_msgitem;
    }
    return CM_SUCCESS;
}

static int mes_init_conn(void)
{
    mes_conn_t *conn = NULL;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_TCP &&
        MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_RDMA) {
        return ERR_MES_CONNTYPE_ERR;
    }

    for (uint32 i = 0; i < MES_MAX_INSTANCES; i++) {
        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[i];
        conn->is_connect = CM_FALSE;
        conn->is_start = CM_FALSE;
        cm_init_thread_lock(&conn->lock);
        if (cm_event_init(&conn->event) != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] instance %u init event failed, error code %d.", i, cm_get_os_error());
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static int mes_init_pipe_resource(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        return mes_init_tcp_resource();
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        return mes_init_rdma_rpc_resource();
    }
    return CM_ERROR;
}

static int mes_init_priority_task(bool32 is_send)
{
    int ret;
    uint32 loop;
    uint32 task_num = 0;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    uint32 *task_priority =
            is_send ? MES_GLOBAL_INST_MSG.profile.send_task_count : MES_GLOBAL_INST_MSG.profile.work_task_count;
    uint32 priority_cnt = MES_GLOBAL_INST_MSG.profile.priority_cnt;

    if (!is_send && ENABLE_MES_TASK_THREADPOOL) {
        return CM_SUCCESS;
    }

    for (loop = 0; loop < priority_cnt; loop++) {
        if (task_priority[loop] == 0) {
            task_priority[loop] = 1;
        }
        task_num += task_priority[loop];
    }

    if (task_num > MES_MAX_TASK_NUM) {
        return CM_ERROR;
    }
    mq_ctx->task_num = task_num;

    for (loop = 0; loop < priority_cnt; loop++) {
        if (task_priority[loop] < MES_MIN_TASK_NUM) {
            if (is_send && MES_GLOBAL_INST_MSG.profile.send_directly) {
                continue;
            }
            LOG_RUN_ERR("[mes] init priority task failed, priority %u task num is zero, is_send:%u", loop, is_send);
            return CM_ERROR;
        }
        ret = mes_set_priority_task_worker_num((mes_priority_t)loop, task_priority[loop], is_send);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}

static int mes_start_work_thread_statically(bool32 is_send)
{
    bool32 need_serial = MES_GLOBAL_INST_MSG.profile.need_serial;
    bool32 send_directly = MES_GLOBAL_INST_MSG.profile.send_directly;
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;

    if (is_send && send_directly) {
        return CM_SUCCESS;
    }

    if (!is_send && ENABLE_MES_TASK_THREADPOOL) {
        return CM_SUCCESS;
    }

    for (uint32 loop = 0; loop < mq_ctx->task_num; loop++) {
        GS_INIT_SPIN_LOCK(mq_ctx->work_thread_idx[loop].lock);
        mq_ctx->work_thread_idx[loop].is_send = is_send;
        mq_ctx->work_thread_idx[loop].mq_ctx = mq_ctx;
        mq_ctx->work_thread_idx[loop].index = loop;
        mq_ctx->work_thread_idx[loop].tid = CM_INVALID_ID32;
        mq_ctx->work_thread_idx[loop].is_active = CM_FALSE;
        mq_ctx->work_thread_idx[loop].priority = CM_INVALID_ID32;
        mq_ctx->work_thread_idx[loop].get_msgitem_time = CM_INVALID_ID64;
        mq_ctx->work_thread_idx[loop].msg_ruid = CM_INVALID_ID64;
        mq_ctx->work_thread_idx[loop].msg_src_inst = CM_INVALID_ID32;
        mq_ctx->work_thread_idx[loop].longest_cost_time = 0;
        mq_ctx->work_thread_idx[loop].longest_get_msgitem_time = CM_INVALID_ID32;
        if (memset_s(&mq_ctx->work_thread_idx[loop].data, sizeof(mq_ctx->work_thread_idx[loop].data), 0,
            sizeof(mq_ctx->work_thread_idx[loop].data)) != EOK) {
            LOG_RUN_ERR("[mes] memset failed.");
            return CM_ERROR;
        }
        if (memset_s(&mq_ctx->work_thread_idx[loop].longest_data, sizeof(mq_ctx->work_thread_idx[loop].longest_data), 0,
            sizeof(mq_ctx->work_thread_idx[loop].longest_data)) != EOK) {
            LOG_RUN_ERR("[mes] memset failed.");
            return CM_ERROR;
        }

        if (need_serial) {
            mq_ctx->work_thread_idx[loop].is_start = CM_FALSE;
            continue;
        }
        if (cm_event_init(&mq_ctx->work_thread_idx[loop].event) != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] create thread %u event failed, error code %d, is_send:%u.",
                        loop, cm_get_os_error(), is_send);
            return CM_ERROR;
        }
        if (cm_create_thread(mes_task_proc, 0, &mq_ctx->work_thread_idx[loop], &mq_ctx->tasks[loop].thread) !=
            CM_SUCCESS) {
            LOG_RUN_ERR("[mes] create work thread %u failed, is_send:%u.", loop, is_send);
            return ERR_MES_WORK_THREAD_FAIL;
        }
        mq_ctx->work_thread_idx[loop].is_start = CM_TRUE;
        LOG_RUN_INF("[mes] mes_start_work_thread_statically, is_send:%u, index:%u", is_send, loop);
    }

    return CM_SUCCESS;
}

static int mes_init_mq_instance(bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    
    LOG_RUN_INF("[mes] mes_init_mq_instance begin, is_send:%u.", is_send);
    int ret;
    for (uint32 loop = 0; loop < MES_MAX_TASK_NUM; loop++) {
        mq_ctx->tasks[loop].choice = 0;
        mes_init_msgqueue(&mq_ctx->tasks[loop].queue);
    }

    mes_init_msgitem_pool(&mq_ctx->pool);

    mq_ctx->priority.assign_task_idx = 0;
    ret = mes_init_priority_task(is_send);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes set send priority task num failed, is_send:%u.", is_send);
        return ret;
    }

    mq_ctx->enable_inst_dimension = MES_GLOBAL_INST_MSG.profile.msg_pool_attr.enable_inst_dimension;
    mq_ctx->msg_pool_inited = CM_FALSE;
    GS_INIT_SPIN_LOCK(mq_ctx->msg_pool_init_lock);
    ret = mes_init_message_pool(is_send);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes][msg pool] mes init message pool failed, is_send:%u.",
            is_send);
        return ret;
    }

    ret = mes_start_work_thread_statically(is_send);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes start work thread statically failed, is_send:%u.", is_send);
        return ret;
    }

    LOG_RUN_INF("[mes] mes_init_mq_instance end, is_send:%u.", is_send);
    return CM_SUCCESS;
}

static int mes_init_mq()
{
    int ret;
    mq_context_t *send_mq = &MES_GLOBAL_INST_MSG.send_mq;
    mq_context_t *recv_mq = &MES_GLOBAL_INST_MSG.recv_mq;

    ret = memset_s(send_mq, sizeof(mq_context_t), 0, sizeof(mq_context_t));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes] mes_init_mq memset send_mq failed.");
        return CM_ERROR;
    }
    ret = memset_s(recv_mq, sizeof(mq_context_t), 0, sizeof(mq_context_t));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes] mes_init_mq memset recv_mq failed.");
        return CM_ERROR;
    }

    send_mq->profile = &MES_GLOBAL_INST_MSG.profile;
    send_mq->mes_ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    recv_mq->profile = &MES_GLOBAL_INST_MSG.profile;
    recv_mq->mes_ctx = &MES_GLOBAL_INST_MSG.mes_ctx;

    ret = mes_init_mq_instance(CM_TRUE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] init send mq instance failed.");
        return ret;
    }

    ret = mes_init_mq_instance(CM_FALSE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] init receive mq instance failed.");
        return ret;
    }
    return CM_SUCCESS;
}

static int mes_init_resource(void)
{
    int ret;

    LOG_RUN_INF("start to init mq");
    ret = mes_init_mq();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes init mq failed.");
        return ret;
    }
    LOG_RUN_INF("end to init mq");

    (void)mes_register_func();

    ret = mes_init_conn();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes init conn failed.");
        return ret;
    }

    ret = mes_init_session_room();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_init_session_room failed.");
        return ret;
    }

    ret = mes_init_pipe_resource();
    if (ret != CM_SUCCESS) {
        mes_destroy_all_broadcast_msg();
        mes_clean_session_mutex(CM_MAX_MES_ROOMS);
        LOG_RUN_ERR("[mes] mes_init_pipe_room failed.");
        return ret;
    }

    return CM_SUCCESS;
}

static void mes_destroy_msgitem_pool(void)
{
    mes_free_msgitem_pool(&MES_GLOBAL_INST_MSG.send_mq.pool);
    mes_init_msgitem_pool(&MES_GLOBAL_INST_MSG.send_mq.pool);
    mes_free_msgitem_pool(&MES_GLOBAL_INST_MSG.recv_mq.pool);
    mes_init_msgitem_pool(&MES_GLOBAL_INST_MSG.recv_mq.pool);
}

static inline void mes_close_libdl(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        FinishOckRpcDl();
    }
}

static void mes_destroy_resource(void)
{
    mes_free_channel_msg_queue(CM_TRUE);
    mes_free_channel_msg_queue(CM_FALSE);
    mes_free_channels();
    mes_clean_session_mutex(CM_MAX_MES_ROOMS);
    mes_close_libdl();
    return;
}

mes_waiting_room_t *mes_ruid_get_room(unsigned long long ruid)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_ruid_get_room");
        return NULL;
    }
    unsigned long long rid = ((ruid_t *)(&ruid))->room_id;
    if (rid >= CM_MAX_MES_ROOMS) {
        LOG_RUN_ERR("[mes]invalid rid = %llu, room = NULL", rid);
        return NULL;
    }
    return &MES_GLOBAL_INST_MSG.mes_ctx.wr_pool.waiting_rooms[rid];
}

bool8 ruid_matches_room_rsn(unsigned long long *ruid, unsigned long long room_rsn)
{
    return ((ruid_t *)ruid)->rsn == room_rsn;
}

static bool8 inline mes_check_msg_recv(mes_message_t *msg, mes_waiting_room_t *room)
{
    CM_ASSERT(room->room_status != STATUS_BCAST_SENDING);
    bool8 bcast_check = room->room_status != STATUS_BCAST_SENT ||
        MES_BROADCAST_MSG[msg->head->src_inst][room->room_index] == NULL;
    bool8 rsn_check = ruid_matches_room_rsn(&msg->head->ruid, room->rsn) &&
        ((ruid_t *)&(msg->head->ruid))->rsn > room->check_rsn;
    return bcast_check && rsn_check;
}

void mes_ensure_inst_broadcast_msg_exist(unsigned int inst_id)
{
    if (MES_BROADCAST_MSG[inst_id] == NULL) {
        cm_spin_lock(&MES_WAITING_ROOM_POOL.inst_broadcast_msg_lock, NULL);
        if (MES_BROADCAST_MSG[inst_id] == NULL) {
            if (mes_init_single_inst_broadcast_msg(inst_id) != CM_SUCCESS) {
                cm_spin_unlock(&MES_WAITING_ROOM_POOL.inst_broadcast_msg_lock);
                cm_panic(0);
            }
        }
        cm_spin_unlock(&MES_WAITING_ROOM_POOL.inst_broadcast_msg_lock);
    }
}

void mes_notify_msg_recv(mes_message_t *msg)
{
    if (msg == NULL || msg->buffer == NULL || MES_RUID_IS_ILLEGAL(msg->head->ruid) ||
        MES_RUID_IS_INVALID(msg->head->ruid)) {
        LOG_RUN_ERR("[mes]: mes notify msg recv failed");
        mes_release_message_buf(msg);
        return;
    }

    mes_waiting_room_t *room = mes_ruid_get_room(msg->head->ruid);
    CM_ASSERT(room != NULL);
    while (room->room_status == STATUS_BCAST_SENDING) {
        cm_usleep(1);
    }

    cm_spin_lock(&room->lock, NULL);
    LOG_DEBUG_INF("[mes]mes_notify_msg_recv ruid=%llu(%llu-%llu), cmd=%d, room:%llu-%llu, rstatus:%d",
        (uint64)msg->head->ruid, (uint64)MES_RUID_GET_RID(msg->head->ruid), (uint64)MES_RUID_GET_RSN(msg->head->ruid),
        (int32)msg->head->cmd, (uint64)room->room_index, (uint64)room->rsn, (int32)room->room_status);
    mes_ensure_inst_broadcast_msg_exist(msg->head->src_inst);
    if (mes_check_msg_recv(msg, room)) {
        if (room->room_status == STATUS_PTP_SENT) {
            room->msg_buf = msg->buffer;
            room->check_rsn = ((ruid_t *)&(msg->head->ruid))->rsn;
            mes_mutex_unlock(&room->mutex);
        } else if (room->room_status == STATUS_BCAST_SENT) {
            MES_BROADCAST_MSG[msg->head->src_inst][room->room_index] = msg->buffer;
            (void)cm_atomic32_inc(&room->ack_count);
            if (room->ack_count >= room->req_count) {
                room->check_rsn = ((ruid_t *)&(msg->head->ruid))->rsn;
                mes_mutex_unlock(&room->broadcast_mutex);
            }
        } else {
            LOG_RUN_ERR("[mes]:mes notify msg recv cmd=%d, ruid=%llu(%llu-%llu) matched wrong rstatus:%d",
                (int32)msg->head->cmd, (uint64)msg->head->ruid, (uint64)MES_RUID_GET_RID(msg->head->ruid),
                (uint64)MES_RUID_GET_RSN(msg->head->ruid), (int32)room->room_status);
            mes_release_message_buf(msg);
        }
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg", room);
        LOG_DEBUG_WAR("[mes]discard msg, room->rid=%llu, rsn=%llu, crsn=%llu, ruid=%llu(%llu-%llu), rstatus=%d",
            (uint64)room->room_index, room->rsn, room->check_rsn, (uint64)msg->head->ruid,
            (uint64)MES_RUID_GET_RID(msg->head->ruid), (uint64)MES_RUID_GET_RSN(msg->head->ruid),
            room->room_status);
        mes_release_message_buf(msg);
    }
    return;
}

void mes_process_message(mes_msgqueue_t *my_queue, mes_message_t *msg)
{
    if (mes_decompress(msg) != CM_SUCCESS) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes] decompress msg failed, src:%u, dst:%u, size:%u, flag:%u.",
                    msg->head->src_inst, msg->head->dst_inst, msg->head->size, msg->head->flags);
        return;
    }

    uint64 start_time = cm_get_time_usec();
    mes_msgitem_t *msgitem = NULL;

    mes_recv_message_stat(msg);

    /* message is sychronous ack, need to push notification */
    if (msg->head->cmd == MES_CMD_SYNCH_ACK) {
        mes_notify_msg_recv(msg);
        return;
    }

    msgitem = MES_ALLOC_MSGITEM(my_queue, CM_FALSE);
    if (msgitem == NULL) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes]: alloc msgitem failed.");
        return;
    }

    msgitem->msg.head = msg->head;
    msgitem->msg.buffer = msg->buffer;
    msgitem->enqueue_time = cm_get_time_usec();

    if (ENABLE_MES_TASK_THREADPOOL) {
        mes_put_msgitem_to_threadpool(msgitem);
        return;
    }

    uint32 work_index = 0;
    mes_put_msgitem_enqueue(msgitem, CM_FALSE, &work_index);
    mes_consume_with_time(msg->head->app_cmd, MES_TIME_PUT_QUEUE, start_time);
    if (work_index == CM_INVALID_ID32 || work_index >= MES_MAX_TASK_NUM) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes] mes_process_message, get work index failed.");
        return;
    }

    // need_serial = CM_TRUE, will start task dynamically
    // else will event notify
    if (mes_start_task_dynamically(CM_FALSE, work_index) != CM_SUCCESS) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes] mes_process_message, start task failed.");
        return;
    }

    return;
}

static int mes_start_listen_thread(void)
{
    int ret;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        ret = mes_start_lsnr();
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes]mes_init failed.");
            return ret;
        }
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        ret = mes_start_rdma_rpc_lsnr();
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes]mes start rdma rpc lsnr failed, ret: %d", ret);
            return ret;
        }
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startLsnr = CM_TRUE;
    return CM_SUCCESS;
}

static void mes_close_listen_thread(void)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.startLsnr) {
        return;
    }

    mes_stop_lsnr();
    MES_GLOBAL_INST_MSG.mes_ctx.startLsnr = CM_FALSE;
    return;
}

static void mes_close_work_thread(bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    for (uint32 loop = 0; loop < mq_ctx->task_num; loop++) {
        if (mq_ctx->work_thread_idx[loop].is_start) {
            cm_close_thread(&mq_ctx->tasks[loop].thread);
            cm_event_destory(&mq_ctx->work_thread_idx[loop].event);
            mq_ctx->work_thread_idx[loop].is_start = CM_FALSE;
            mes_init_msgqueue(&mq_ctx->tasks[loop].queue);
        }
    }
    LOG_RUN_INF("[mes] mes_close_work_thread end");
    return;
}

static int mes_connect_by_profile(void)
{
    int ret;
    if (!MES_GLOBAL_INST_MSG.profile.conn_created_during_init) {
        return CM_SUCCESS;
    }

    // channel connect
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
            continue;
        }

        ret = mes_connect(inst_id);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] connect to instance %u failed.", inst_id);
            return ret;
        }
    }

    return CM_SUCCESS;
}

status_t mes_verify_ssl_key_pwd(ssl_config_t *ssl_cfg, char *plain, uint32 size)
{
    param_value_t keypwd;

    // check password which encrypted by CBB
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_PWD_PLAINTEXT, &keypwd));
    if (keypwd.inter_pwd.cipher_len > 0) {
        CM_RETURN_IFERR(cm_decrypt_pwd(&keypwd.inter_pwd, (uchar *)plain, &size));
        ssl_cfg->key_password = plain;
        return CM_SUCCESS;
    }

    // check password which encrypted by RSM
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_PWD_CIPHERTEXT, &keypwd));
    if (!CM_IS_EMPTY_STR(keypwd.ext_pwd)) {
        if (usr_cb_decrypt_pwd == NULL) {
            LOG_RUN_ERR("[mes] user decrypt function has not registered");
            return CM_ERROR;
        }
        CM_RETURN_IFERR(usr_cb_decrypt_pwd(keypwd.ext_pwd, (unsigned int)strlen(keypwd.ext_pwd), plain, size));
        ssl_cfg->key_password = plain;
    }
    return CM_SUCCESS;
}

static void mes_deinit_ssl(void)
{
    if (MES_GLOBAL_INST_MSG.ssl_acceptor_fd != NULL) {
        cs_ssl_free_context(MES_GLOBAL_INST_MSG.ssl_acceptor_fd);
        MES_GLOBAL_INST_MSG.ssl_acceptor_fd = NULL;
    }

    if (MES_GLOBAL_INST_MSG.ssl_connector_fd != NULL) {
        cs_ssl_free_context(MES_GLOBAL_INST_MSG.ssl_connector_fd);
        MES_GLOBAL_INST_MSG.ssl_connector_fd = NULL;
    }

    g_ssl_enable = CM_FALSE;
    usr_cb_decrypt_pwd = NULL;
}

static status_t mes_create_ssl_fd(ssl_config_t *ssl_cfg)
{
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};

    // verify ssl key password and KMC module
    if (mes_verify_ssl_key_pwd(ssl_cfg, plain, sizeof(plain) - 1) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        return CM_ERROR;
    }

    // create acceptor fd
    MES_GLOBAL_INST_MSG.ssl_acceptor_fd = cs_ssl_create_acceptor_fd(ssl_cfg);
    if (MES_GLOBAL_INST_MSG.ssl_acceptor_fd == NULL) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[mes] create ssl acceptor context failed");
        return CM_ERROR;
    }

    // check cert expire
    if (mes_chk_ssl_cert_expire() != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[mes] check ssl cert failed");
        return CM_ERROR;
    }

    // check crl expire
    if (mes_chk_ssl_crl_expire() != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[mes] check ssl crl failed");
        return CM_ERROR;
    }

    // create connector fd
    MES_GLOBAL_INST_MSG.ssl_connector_fd = cs_ssl_create_connector_fd(ssl_cfg);
    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
    if (MES_GLOBAL_INST_MSG.ssl_connector_fd == NULL) {
        LOG_RUN_ERR("[mes] create ssl connector context failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t mes_init_ssl(void)
{
    ssl_config_t ssl_cfg = {0};
    param_value_t ca, key, crl, cert, cipher, gm_key, gm_cert;

    // Required parameters
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CA, &ca));
    ssl_cfg.ca_file = ca.ssl_ca;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_KEY, &key));
    ssl_cfg.key_file = key.ssl_key;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CERT, &cert));
    ssl_cfg.cert_file = cert.ssl_cert;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_GM_KEY, &gm_key));
    ssl_cfg.gm_key_file = gm_key.ssl_gm_key;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_GM_CERT, &gm_cert));
    ssl_cfg.gm_cert_file = gm_cert.ssl_gm_cert;

    if (CM_IS_EMPTY_STR(ssl_cfg.cert_file) || CM_IS_EMPTY_STR(ssl_cfg.key_file) || CM_IS_EMPTY_STR(ssl_cfg.ca_file)) {
        LOG_RUN_WAR("[mes] SSL disabled: certificate file or private key file or CA certificate is not available.");
        LOG_ALARM(WARN_SSL_DIASBLED, "}");
        return CM_SUCCESS;
    }

    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        if (mes_ockrpc_init_ssl() != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] init ockrpc ssl failed");
            return CM_ERROR;
        }
    }

    // Optional parameters
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CRL, &crl));
    ssl_cfg.crl_file = crl.ssl_crl;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CIPHER, &cipher));
    ssl_cfg.cipher = cipher.ssl_cipher;

    /* Require no public access to key file */
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.ca_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.key_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.cert_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.crl_file));
    // create fd
    if (mes_create_ssl_fd(&ssl_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }

    g_ssl_enable = CM_TRUE;
    LOG_RUN_INF("[mes] mes_init_ssl, ssl enable is %u.", (uint32)g_ssl_enable);
    return CM_SUCCESS;
}

static void mes_stop_channels(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        mes_tcp_stop_channels();
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        mes_rdma_stop_channels();
    }
}

void mes_heartbeat(mes_pipe_t *pipe)
{
    if (g_timer()->monotonic_now - pipe->last_send_time < MES_HEARTBEAT_INTERVAL * MICROSECS_PER_SECOND) {
        return;
    }
    pipe->last_send_time = g_timer()->monotonic_now;

    uint32 version = CM_INVALID_ID32;
    if (mes_get_pipe_version(&pipe->send_pipe, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[mes] mes_heartbeat, mes_get_send_pipe_version failed, channel_id %d, priority %d",
                      MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
        return;
    }
    if (is_old_mec_version(version)) {
        return;
    }

    /* dst_inst and caller_tid used to get current channel in mes_send_data */
    mes_message_head_t head = {0};
    head.cmd = MES_CMD_HEARTBEAT;
    head.src_inst = MES_GLOBAL_INST_MSG.profile.inst_id;
    head.dst_inst = MES_INSTANCE_ID(pipe->channel->id);
    head.caller_tid = MES_CHANNEL_ID(pipe->channel->id);
    head.size = (uint32)sizeof(mes_message_head_t);
    MES_SET_PRIORITY_FLAG(head.flags, pipe->priority);
    int ret = MES_SEND_DATA((void *)&head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_heartbeat failed, src:%u, dst:%u, flags:%u, ret:%u, channel_id:%u, priority:%u",
                    head.src_inst, head.dst_inst, head.flags, ret, MES_CHANNEL_ID(pipe->channel->id), pipe->priority);
    }
}

static void mes_heartbeat_entry(thread_t *thread)
{
    inst_type inst_id = (inst_type)(uint64)thread->argument;
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_heartbeat_%u", inst_id));
    cm_set_thread_name(thread_name);
    cm_block_sighup_signal();

    mes_context_t *mes_ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    uint64 periods = 0;
    while (!thread->closed && mes_ctx->phase == SHUTDOWN_PHASE_NOT_BEGIN) {
        mes_conn_t *conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];
        if (conn->is_connect) {
            for (unsigned int channel_id = 0; channel_id < MES_GLOBAL_INST_MSG.profile.channel_cnt; channel_id++) {
                mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
                MES_HEARTBEAT((uintptr_t)channel);
            }
        }

        if (periods == SECONDS_PER_DAY && g_ssl_enable) {
            periods = 0;
            (void)mes_chk_ssl_cert_expire();
            (void)mes_chk_ssl_crl_expire();
        }
        periods++;

        (void)cm_event_timedwait(&conn->event, CM_1000X_FIXED);
    }
    LOG_RUN_INF("[mes] heartbeat thread closed, inst_id:%u, close:%u", inst_id, thread->closed);
}

int mes_start_heartbeat_thread()
{
    mes_conn_t *conn = NULL;
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
            continue;
        }
        if (!MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].need_connect) {
            LOG_RUN_INF("[mes] no need to connect instance %u", inst_id);
            continue;
        }
        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];
        cm_thread_lock(&conn->lock);
        if (conn->is_start) {
            cm_thread_unlock(&conn->lock);
            LOG_RUN_WAR("[mes] dst instance %u thread has started.", inst_id);
            continue;
        }

        // wait last thread close finish
        cm_close_thread(&conn->thread);
        if (cm_create_thread(mes_heartbeat_entry, 0, (void *)(uint64)inst_id, &conn->thread) != CM_SUCCESS) {
            cm_thread_unlock(&conn->lock);
            LOG_RUN_ERR("[mes] start instance %u heartbeat thread failed, os error %d", inst_id, cm_get_os_error());
            return CM_ERROR;
        }
        conn->is_start = CM_TRUE;
        cm_thread_unlock(&conn->lock);
        LOG_RUN_INF("[mes] mes_start_heartbeat_thread, inst_id %u start thread success", inst_id);
    }
    return CM_SUCCESS;
}

void mes_stop_heartbeat_thread()
{
    mes_conn_t *conn = NULL;
    for (uint32 i = 0; i < MES_MAX_INSTANCES; i++) {
        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[i];
        cm_thread_lock(&conn->lock);
        cm_close_thread_nowait(&conn->thread);
        cm_event_notify(&conn->event);
        cm_close_thread(&conn->thread);
        cm_event_destory(&conn->event);
        conn->is_start = CM_FALSE;
        cm_thread_unlock(&conn->lock);
    }
    LOG_RUN_INF("[mes] mes_stop_heartbeat_thread end");
}

void mes_destroy_all_broadcast_msg()
{
    for (uint32 inst_id = 0; inst_id < MES_MAX_INSTANCES; ++inst_id) {
        CM_FREE_PROT_PTR(MES_WAITING_ROOM_POOL.broadcast_msg[inst_id]);
    }
}

void mes_uninit(void)
{
    LOG_RUN_INF("[mes] mes_uninit start");
    MES_GLOBAL_INST_MSG.mes_ctx.phase = SHUTDOWN_PHASE_INPROGRESS;
    mes_stop_heartbeat_thread();
    mes_close_listen_thread();
    mes_stop_receivers();
    mes_stop_sender_monitor();
    mes_close_work_thread(CM_TRUE);
    mes_close_work_thread(CM_FALSE);
    if (ENABLE_MES_TASK_THREADPOOL) {
        mes_task_threadpool_uninit();
    }
    mes_destroy_msgitem_pool();
    mes_deinit_all_message_pool();
    mes_stop_channels();
    mes_destroy_resource();
    mes_destroy_all_broadcast_msg();
    mes_deinit_ssl();
    MES_GLOBAL_INST_MSG.mes_ctx.phase = SHUTDOWN_PHASE_DONE;
    (void)memset_s(&MES_GLOBAL_INST_MSG, sizeof(mes_instance_t), 0, sizeof(mes_instance_t));

#ifndef WIN32
    delete_compress_thread_key();
#endif

    LOG_RUN_INF("[mes] mes_uninit success");
    return;
}

int mes_init(mes_profile_t *profile)
{
    int ret;

    if (profile == NULL) {
        LOG_RUN_ERR("[mes] profile is NULL, init failed.");
        return ERR_MES_PARAM_NULL;
    }
    LOG_RUN_INF("[mes] mes_init start");

#ifndef WIN32
    if (create_compress_ctx() != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif

    mes_init_stat(profile);

    MES_GLOBAL_INST_MSG.mes_ctx.phase = SHUTDOWN_PHASE_NOT_BEGIN;
    do {
        ret = cm_start_timer(g_timer());
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_set_profile(profile);
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = (int)mes_init_ssl();
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_init_resource();
        if (ret != CM_SUCCESS) {
            break;
        }

        if (profile->tpool_attr.enable_threadpool) {
            ret = mes_task_threadpool_init(&profile->tpool_attr);
            if (ret != CM_SUCCESS) {
                break;
            }
        }

        ret = mes_start_receivers(profile->priority_cnt, profile->recv_task_count, mes_recv_pipe_event_proc);
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_start_sender_monitor();
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_start_listen_thread();
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_start_heartbeat_thread();
        if (ret != CM_SUCCESS) {
            break;
        }
        
        ret = mes_connect_by_profile();
    } while (0);

    if (ret != CM_SUCCESS) {
        mes_uninit();
        return ret;
    }

    LOG_RUN_INF("[mes] mes_init success.");
    return ret;
}

void mes_register_proc_func(mes_message_proc_t proc)
{
    MES_GLOBAL_INST_MSG.proc = proc;
    return;
}

// connect interface
int mes_connect_thread_start(uint32 inst_id)
{
    if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
        LOG_RUN_INF("[mes] mes_connect_thread_start, not need to be connected to itself %u", inst_id);
        return CM_SUCCESS;
    }
    mes_conn_t *conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];
    conn->is_connect = CM_TRUE;
    if (!conn->is_start) {
        // wait last thread close finish
        cm_close_thread(&conn->thread);
        if (cm_create_thread(mes_heartbeat_entry, 0, (void *)(uint64)inst_id, &conn->thread) != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] start instance %u heartbeat thread failed, os error %d", inst_id, cm_get_os_error());
            return CM_ERROR;
        }
        conn->is_start = CM_TRUE;
        LOG_RUN_INF("[mes] mes_connect_thread_start, inst_id %u start thread success", inst_id);
    }
    cm_event_notify(&conn->event);
    LOG_DEBUG_INF("[mes] mes_connect_thread_start, inst_id=%u, event_notify to try connect", inst_id);
    return CM_SUCCESS;
}

int mes_ensure_inst_channel_exist(unsigned int inst_id)
{
    if (MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] == NULL) {
        cm_spin_lock(&MES_GLOBAL_INST_MSG.mes_ctx.inst_channel_lock, NULL);
        if (MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] == NULL) {
            if (mes_init_single_inst_channel(inst_id) != CM_SUCCESS) {
                cm_spin_unlock(&MES_GLOBAL_INST_MSG.mes_ctx.inst_channel_lock);
                return CM_ERROR;
            }
        }
        cm_spin_unlock(&MES_GLOBAL_INST_MSG.mes_ctx.inst_channel_lock);
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

int mes_connect(inst_type inst_id)
{
    int ret;
    mes_conn_t *conn;

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_RUN_ERR("[mes] mes_connect, phase(%d) not begin, inst_id %u", MES_GLOBAL_INST_MSG.mes_ctx.phase, inst_id);
        return CM_ERROR;
    }

    if ((inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) || (inst_id >= MES_MAX_INSTANCES)) {
        LOG_RUN_ERR("[mes]: connect inst_id %u failed, current inst_id %u.",
                    inst_id, MES_GLOBAL_INST_MSG.profile.inst_id);
        return ERR_MES_PARAM_INVALID;
    }

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id) {
            if(!MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].need_connect) {
                LOG_RUN_WAR("[mes] do not need create connection, inst_id %u", inst_id);
                return CM_SUCCESS;
            }
            break;
        }
    }

    conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];

    cm_thread_lock(&conn->lock);
    if (MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
        cm_thread_unlock(&conn->lock);
        LOG_RUN_WAR("[mes] dst instance %u has trigger connect.", inst_id);
        return CM_SUCCESS;
    }

    ret = mes_connect_thread_start(inst_id);
    if (ret != CM_SUCCESS) {
        cm_thread_unlock(&conn->lock);
        LOG_RUN_ERR("[mes]: mes_connect_thread_start failed, inst_id:%u.", inst_id);
        return ret;
    }

    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_TRUE;
    cm_thread_unlock(&conn->lock);

    LOG_RUN_INF("[mes]: connect to instance %u.", inst_id);

    return CM_SUCCESS;
}

static int mes_stop_old_secondary_ip_lsnr(tcp_lsnr_t *lsnr, char *old_secondary_ip)
{
    uint32 i, j;
    inst_type inst_id;
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        char *ip = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].ip;
        char *secondary_ip = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].secondary_ip;
        if (CM_IS_EMPTY_STR(ip) && !CM_IS_EMPTY_STR(secondary_ip) && cm_check_ip_valid(secondary_ip)) {
            for (j = 0; j < MES_GLOBAL_INST_MSG.profile.channel_cnt; j++) {
                mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][j];
                mes_close_channel(channel);
            }
        }
    }

    LOG_DEBUG_INF("[mes] mes_stop_old_secondary_ip_lsnr:old_secondary_ip %s", old_secondary_ip);

    // stop lsnr
    if (CM_IS_EMPTY_STR(lsnr->host[1])) {
        LOG_DEBUG_INF("[mes] old host is already closed");
        return CM_SUCCESS;
    }
    LOG_DEBUG_INF("[mes] mes_stop_old_secondary_ip_lsnr old_secondary_ip:%s, old host:%s",
                  old_secondary_ip, lsnr->host[1]);
    if (CM_STR_EQUAL(lsnr->host[1], old_secondary_ip)) {
        int32 slot_id = lsnr->slots[1];
        int fd = (int)lsnr->socks[slot_id];
        LOG_DEBUG_INF("[mes] try to epoll ctl del, lsnr efd:%u, slot_id:%d, socks fd:%u", lsnr->epoll_fd, slot_id, fd);
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) {
            LOG_RUN_ERR("[mes] remove socket from lsnr epoll failed, err code %u", cm_get_sock_error());
            return CM_ERROR;
        }
        cs_close_one_lsnr_sock(lsnr, slot_id);
        lsnr->host[1][0] = '\0';
        LOG_DEBUG_INF("[mes] old secondary ip %s closed success", old_secondary_ip);
    }
    return CM_SUCCESS;
}

static int mes_update_secondary_ip_lsnr(unsigned int inst_cnt, const mes_addr_t *inst_net_addrs)
{
    uint32 cur_node_id = MES_MY_ID;
    uint32 index = 0;
    char *old_secondary_ip = NULL;
    for (index = 0; index < MES_GLOBAL_INST_MSG.profile.inst_cnt; index++) {
        if (MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].inst_id == cur_node_id) {
            break;
        }
    }
    if (index != MES_GLOBAL_INST_MSG.profile.inst_cnt) {
        old_secondary_ip = MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].secondary_ip;
    }
    char *new_secondary_ip = NULL;
    for (uint32 i = 0; i < inst_cnt; i++) {
        if (inst_net_addrs[i].inst_id == cur_node_id) {
            new_secondary_ip = (char *)inst_net_addrs[i].secondary_ip;
            break;
        }
    }

    tcp_lsnr_t *lsnr = (tcp_lsnr_t *)&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp;
    if (lsnr == NULL) {
        LOG_DEBUG_ERR("[mes] mes_update_secondary_ip_lsnr lsnr is null");
        return CM_ERROR;
    }
    if (!CM_IS_EMPTY_STR(old_secondary_ip) && !CM_IS_EMPTY_STR(new_secondary_ip) &&
        cm_str_equal(old_secondary_ip, new_secondary_ip)) {
        LOG_DEBUG_INF("[mes] old_secondary_ip:%s, new_secondary_ip:%s is equal, does not need update",
                      old_secondary_ip, new_secondary_ip);
        return CM_SUCCESS;
    }

    LOG_RUN_INF("[mes] old_secondary_ip:%s, new_secondary_ip:%s",
                CM_IS_EMPTY_STR(old_secondary_ip) ? "NULL" : old_secondary_ip,
                CM_IS_EMPTY_STR(new_secondary_ip) ? "NULL" : new_secondary_ip);
    if (!CM_IS_EMPTY_STR(old_secondary_ip)) {
        CM_RETURN_IFERR(mes_stop_old_secondary_ip_lsnr(lsnr, old_secondary_ip));
    }

    // create new socks
    if (!CM_IS_EMPTY_STR(new_secondary_ip)) {
        int32 slot_id;
        if (cs_create_one_lsnr_sock(lsnr, new_secondary_ip, &slot_id) != CM_SUCCESS) {
            cs_close_one_lsnr_sock(lsnr, slot_id);
            LOG_DEBUG_ERR("[mes] create one lsnr sock failed, err code:%u", cm_get_os_error());
            return CM_ERROR;
        }
        lsnr->slots[1] = slot_id;
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = (int)(lsnr->socks[slot_id]);
        LOG_DEBUG_INF("[mes] try to epoll ctl add, lsnr efd:%u, slot_id:%u, socks fd:%u",
                      lsnr->epoll_fd, slot_id, ev.data.fd);
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) != 0) {
            cs_close_one_lsnr_sock(lsnr, slot_id);
            LOG_DEBUG_ERR("[mes] add socket to lsnr epool fd failed, err code:%u", cm_get_os_error());
            return CM_ERROR;
        }
        MEMS_RETURN_IFERR(strncpy_s(lsnr->host[1], CM_MAX_IP_LEN, new_secondary_ip, strlen(new_secondary_ip)));
    }
    return CM_SUCCESS;
}

int mes_add_instance(const mes_addr_t *inst_net_addr)
{
    int ret;
    uint32 i = 0;
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    inst_type dst_inst = inst_net_addr->inst_id;

    if (dst_inst >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] mes_add_instance, invalid instance id %u", dst_inst);
        return CM_ERROR;
    }

    cm_spin_lock(&g_profile_lock, NULL);
    for (i = 0; i < profile->inst_cnt; i++) {
        if (profile->inst_net_addr[i].inst_id == dst_inst) {
            break;
        }
    }
    if (i == profile->inst_cnt && i >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] inst_count %u is invalid, exceed max instance num %u.", i, MES_MAX_INSTANCES);
        return ERR_MES_PARAM_INVALID;
    }
    ret = mes_set_addr(i, inst_net_addr);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        cm_spin_unlock(&g_profile_lock);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        LOG_RUN_ERR("[mes] mes_add_instance, mes_set_addr failed inst_id:%u.", dst_inst);
        return ret;
    }
    if (i == profile->inst_cnt) {
        profile->inst_cnt++;
    }
    if (mes_ensure_inst_channel_exist(dst_inst) != CM_SUCCESS) {
        cm_spin_unlock(&g_profile_lock);
        return CM_ERROR;
    }
    cm_spin_unlock(&g_profile_lock);

    if (MES_GLOBAL_INST_MSG.profile.inst_id == dst_inst) {
        ret = mes_update_secondary_ip_lsnr(profile->inst_cnt, profile->inst_net_addr);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] mes_add_instance, update secondary ip failed inst %u", dst_inst);
            return ret;
        }
    }

    return mes_connect_single(dst_inst);
}

status_t mes_get_inst_net_add_index(inst_type inst_id, uint32 *index)
{
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id == inst_id) {
            *index = i;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

int mes_connect_instance(inst_type inst_id)
{
    uint32 index;
    if (mes_get_inst_net_add_index(inst_id, &index) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_connect_instance, invalid inst_id %u", inst_id);
        return CM_ERROR;
    }
    MES_GLOBAL_INST_MSG.profile.inst_net_addr[index].need_connect = CM_TRUE;
    return mes_connect_single(inst_id);
}

int mes_del_instance(inst_type inst_id)
{
    int ret;
    uint32 i, j;
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;
    mes_addr_t *inst_net_addrs = profile->inst_net_addr;
    cm_spin_lock(&g_profile_lock, NULL);
    for (i = 0; i < profile->inst_cnt; i++) {
        if (inst_net_addrs[i].inst_id == inst_id) {
            break;
        }
    }
    if (i == profile->inst_cnt) {
        cm_spin_unlock(&g_profile_lock);
        LOG_DEBUG_WAR("[mes] the instance %u to be deleted does not exist.", i);
        return CM_SUCCESS;
    }

    for (j = i; j < profile->inst_cnt - 1; j++) {
        ret = mes_set_addr(j, &inst_net_addrs[j+1]);
        if (ret != CM_SUCCESS) {
            cm_spin_unlock(&g_profile_lock);
            LOG_RUN_ERR("[mes] mes_del_instance, mes_set_addr failed.");
            return ret;
        }
    }

    ret = memset_sp(&inst_net_addrs[profile->inst_cnt - 1], sizeof(mes_addr_t), 0, sizeof(mes_addr_t));
    if (ret != EOK) {
        cm_spin_unlock(&g_profile_lock);
        LOG_RUN_ERR("[mes] mes_del_instance, memset_sp failed.");
        return ERR_MES_MEMORY_SET_FAIL;
    }
    profile->inst_cnt--;
    cm_spin_unlock(&g_profile_lock);

    mes_disconnect_nowait(inst_id);
    return CM_SUCCESS;
}

int mes_disconnect_instance(inst_type inst_id)
{
    mes_disconnect_nowait(inst_id);
    return CM_SUCCESS;
}

void mes_disconnect_nowait(inst_type inst_id)
{
    mes_conn_t *conn;

    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_WAR("[mes]: mes_disconnect: inst_id %u invalid.", inst_id);
        return;
    }

    if (!MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
        LOG_RUN_WAR("[mes]: mes_disconnect: inst_id %u already disconnect.", inst_id);
        return;
    }

    conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];

    cm_thread_lock(&conn->lock);

    MES_DISCONNECT(inst_id, CM_FALSE);

    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_FALSE;

    cm_thread_unlock(&conn->lock);

    LOG_RUN_INF("[mes]: disconnect node %u.", inst_id);
}

void mes_disconnect(inst_type inst_id)
{
    mes_conn_t *conn;

    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_WAR("[mes]: mes_disconnect: inst_id %u invalid.", inst_id);
        return;
    }

    if (!MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
        LOG_RUN_WAR("[mes]: mes_disconnect: inst_id %u already disconnect.", inst_id);
        return;
    }

    conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];

    cm_thread_lock(&conn->lock);

    MES_DISCONNECT(inst_id, CM_TRUE);

    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_FALSE;

    cm_thread_unlock(&conn->lock);

    LOG_RUN_INF("[mes]: disconnect node %u.", inst_id);
}

static inline bool32 is_node_in_new_profile(inst_type inst_id)
{
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static inline bool32 is_node_in_old_insts(inst_type inst_id, const uint32 *old_insts, uint32 old_node_count)
{
    for (uint32 i = 0; i < old_node_count; i++) {
        if (inst_id == old_insts[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

int mes_update_instance(unsigned int inst_cnt, const mes_addr_t *inst_net_addrs)
{
    uint32 i;
    uint32 old_insts[MES_MAX_INSTANCES];
    uint32 old_node_count = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    if (inst_cnt > MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] inst_count %u is invalid, exceed max instance num %u.", inst_cnt, MES_MAX_INSTANCES);
        return ERR_MES_PARAM_INVALID;
    }
    int ret = mes_update_secondary_ip_lsnr(inst_cnt, inst_net_addrs);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes update cross ip lsnr failed.");
        return ret;
    }
    for (i = 0; i < old_node_count; i++) {
        old_insts[i] = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
    }
    ret = mes_set_instance_info(MES_GLOBAL_INST_MSG.profile.inst_id, inst_cnt, inst_net_addrs);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_update_instance_info failed.");
        return ret;
    }
    LOG_RUN_INF("[mes] update profile inst ok. old_node_count=%u, inst_count=%u",
                old_node_count, MES_GLOBAL_INST_MSG.profile.inst_cnt);

    /* connect added instance's pipe */
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        uint32 new_inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (is_node_in_old_insts(new_inst_id, old_insts, old_node_count) == CM_FALSE) {
            LOG_DEBUG_INF("[mes] update profile, connect to new node %u", new_inst_id);
            if (new_inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) {
                continue;
            }
            CM_RETURN_IFERR(mes_ensure_inst_channel_exist(new_inst_id));
            if (mes_connect(new_inst_id) != CM_SUCCESS) {
                LOG_DEBUG_INF("[mes] update profile, connect to new node %u failed", new_inst_id);
                return CM_ERROR;
            }
        }
    }

    /* close removed instance's pipe */
    if (old_node_count > inst_cnt) {
        for (i = 0; i < old_node_count; i++) {
            if (is_node_in_new_profile(old_insts[i]) == CM_FALSE) {
                mes_disconnect_nowait(old_insts[i]);
            }
        }
    }
    return CM_SUCCESS;
}

int mes_send_bufflist(mes_bufflist_t *buff_list)
{
    return MES_SEND_BUFFLIST(buff_list);
}

void mes_release_msg(mes_msg_t *mes_msg)
{
    if (mes_msg == NULL || mes_msg->buffer == NULL) {
        return;
    }

    char *buffer = (char *)(mes_msg->buffer - MES_MSG_HEAD_SIZE);
    mes_free_buf_item(buffer);
    mes_msg->buffer = NULL;
    return;
}

void mes_release_msg_list(mes_msg_list_t* message_list)
{
    for (uint32 i = 0; i < message_list->count; i++) {
        mes_release_msg(&message_list->messages[i]);
    }
}

void mes_release_message_buf(mes_message_t *msg_buf)
{
    if (msg_buf == NULL || msg_buf->buffer == NULL) {
        return;
    }

    mes_free_buf_item((char *)msg_buf->buffer);
    msg_buf->buffer = NULL;
    return;
}

int mes_register_decrypt_pwd(usr_cb_decrypt_pwd_t proc)
{
    usr_cb_decrypt_pwd = proc;
    return CM_SUCCESS;
}

void mes_init_log(void)
{
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = MAX_LOG_LEVEL;
}

void mes_register_log_output(mes_usr_cb_log_output_t cb_func)
{
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_write = cb_func;
}

static status_t mes_set_ssl_cipher_param(const char *ssl_cipher)
{
    size_t cipher_len = strlen(ssl_cipher);
    char *ssl_cipher_tmp = NULL;
    char *sign = NULL;
    ssl_cipher_tmp  = (char *) cm_malloc_prot(cipher_len + 1);
    if(ssl_cipher_tmp == NULL) {
	LOG_RUN_ERR("[mes]:allocate memory ssl_cipher_tmp failed");
	return CM_ERROR;
    }
    size_t i;
    for(i = 0; i < cipher_len; i++) {
        ssl_cipher_tmp[i] = ssl_cipher[i];
    }
    ssl_cipher_tmp[i] = '\0';
    while ((sign = strchr(ssl_cipher_tmp, ';')) != NULL) {
        *sign = ':';
    }
    cbb_param_t param_type;
    param_value_t out_value;
    if(mes_chk_md_param("SSL_CIPHER", (const char *) ssl_cipher_tmp, &param_type, &out_value) != CM_SUCCESS) {
	CM_FREE_PROT_PTR(ssl_cipher_tmp);
	return CM_ERROR;
    }

    if(mes_set_md_param(param_type, &out_value) != CM_SUCCESS) {
    	CM_FREE_PROT_PTR(ssl_cipher_tmp);
        return CM_ERROR;
    }
    LOG_RUN_INF("[mes]:mes_set_ssl_cipher_param success,ssl cipher=%s", ssl_cipher_tmp);
    CM_FREE_PROT_PTR(ssl_cipher_tmp);
    return CM_SUCCESS;
}

int mes_set_param(const char *param_name, const char *param_value)
{
    status_t ret = CM_ERROR;
    if (param_name == NULL) {
        LOG_RUN_ERR("[mes] param_name is null");
        return CM_ERROR;
    }

    if (cm_str_equal(param_name, "SSL_PWD_PLAINTEXT") || cm_str_equal(param_name, "SSL_PWD_CIPHERTEXT")) {
        LOG_RUN_INF("[mes] set ssl param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_RUN_INF("[mes] set ssl param, param_name=%s param_value=%s", param_name, param_value);
    }

    if(cm_str_equal(param_name, "SSL_CIPHER")) {
        ret = mes_set_ssl_cipher_param(param_value);
        return ret;
    }

    cbb_param_t param_type;
    param_value_t out_value;
    CM_RETURN_IFERR(mes_chk_md_param(param_name, param_value, &param_type, &out_value));
    CM_RETURN_IFERR(mes_set_md_param(param_type, &out_value));

    return CM_SUCCESS;
}

int mes_chk_ssl_cert_expire(void)
{
    param_value_t cert_notify;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CERT_NOTIFY_TIME, &cert_notify));
    ssl_ca_cert_expire(MES_GLOBAL_INST_MSG.ssl_acceptor_fd, (int32)cert_notify.ssl_cert_notify_time);
    return CM_SUCCESS;
}

int mes_chk_ssl_crl_expire(void)
{
    param_value_t crl_notify;
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CERT_NOTIFY_TIME, &crl_notify));
    (void)ssl_crl_expire(MES_GLOBAL_INST_MSG.ssl_acceptor_fd, (int32)crl_notify.ssl_cert_notify_time);
    return CM_SUCCESS;
}

void* mes_get_global_inst(void)
{
    return &g_mes_ptr;
}

void mes_discard_response(ruid_type ruid)
{
    if (SECUREC_UNLIKELY(MES_GLOBAL_INST_MSG.profile.disable_request)) {
        LOG_RUN_ERR("[mes]disable_request = 1, no support send request and get response, func:mes_discard_response");
        return;
    }
    mes_waiting_room_t *room = mes_ruid_get_room(*(unsigned long long *)(&ruid));
    CM_ASSERT(room != NULL);
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == ((ruid_t *)(&ruid))->rsn && room->check_rsn != ((ruid_t *)(&ruid))->rsn) {
        room->rsn = (uint64)cm_atomic_inc((atomic_t *)(&room->rsn));
        room->msg_buf = NULL;
        room->check_rsn = ((ruid_t *)(&ruid))->rsn;
        mes_mutex_unlock(&room->mutex);
    }
    cm_spin_unlock(&room->lock);
}

int mes_is_different_endian(inst_type dst_inst)
{
    if (SECUREC_UNLIKELY(dst_inst >= MES_MAX_INSTANCES)) {
        LOG_RUN_ERR("[mes] mes_is_different_endian, invalid dst_inst: %u.", dst_inst);
        return CM_FALSE;
    }
    if (MES_GLOBAL_INST_MSG.mes_ctx.channels[dst_inst] == NULL) {
        return CM_FALSE;
    }
    int channel_id = MES_CALLER_TID_TO_CHANNEL_ID((uint32)MES_CURR_TID);
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[dst_inst][channel_id];
    if (channel == NULL) {
        return CM_FALSE;
    }
    return CS_DIFFERENT_ENDIAN(channel->pipe[MES_PRIORITY_ZERO].send_pipe.options);
}

bool32 mes_connection_ready_with_count(uint32 inst_id, uint32 *ready_count)
{
    uint32 i, j;
    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("check tcp connection is failed, inst id:%u", inst_id);
        return CM_FALSE;
    }
    if (MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] == NULL) {
        LOG_RUN_ERR("check tcp connection is failed, inst id:%u channel is not exist", inst_id);
        return CM_FALSE;
    }

    *ready_count = 0;
    mes_channel_t *channel = NULL;
    mes_pipe_t *pipe = NULL;
    bool32 check_ready = 0;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
            channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
            for (j = 0; j < MES_GLOBAL_INST_MSG.profile.priority_cnt; j++) {
                pipe = &channel->pipe[j];
                if (pipe->recv_pipe_active && pipe->send_pipe_active) {
                    (*ready_count)++;
                }
            }
        }
        check_ready = (*ready_count == MES_GLOBAL_INST_MSG.profile.channel_cnt * MES_GLOBAL_INST_MSG.profile.priority_cnt);
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        for (i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; i++) {
            channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
            pipe = &channel->rpc_pipe;
            if (pipe->recv_pipe_active && pipe->send_pipe_active) {
                (*ready_count)++;
            }
        }
        check_ready = (*ready_count == MES_GLOBAL_INST_MSG.profile.channel_cnt);        
    }

    return check_ready;
}

unsigned int mes_connection_ready(uint32 inst_id)
{
    uint32 ready_count;
    return mes_connection_ready_with_count(inst_id, &ready_count);
}

int mes_connect_single(inst_type inst_id)
{
    if (inst_id >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes]: currently not support id=%u > 255.", inst_id);
        return ERR_MES_PARAM_INVALID;
    }

    if (MES_GLOBAL_INST_MSG.profile.inst_id == inst_id) {
        return CM_SUCCESS;
    }

    int ret = mes_connect(inst_id);
    if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
        LOG_RUN_ERR("[mes] failed to create mes channel to instance %u", inst_id);
        return ret;
    }

    uint32 wait_time = 0;
    uint32 ready_count = 0;
    uint32 pre_ready_count = 0;
    while (!mes_connection_ready_with_count(inst_id, &ready_count)) {
        const uint8 once_wait_time = 10;
        cm_sleep(once_wait_time);
        if (ready_count == pre_ready_count) {
            wait_time += once_wait_time;
        }
        pre_ready_count = ready_count;

        if (wait_time > MES_CONNECT_TIMEOUT) {
            LOG_RUN_INF("[mes] connect to instance %u timeout.", inst_id);
            return ERR_MES_CONNECT_TIMEOUT;
        }
    }
    LOG_DEBUG_INF("[mes] reconnect to node %u success", inst_id);
    return CM_SUCCESS;
}

mes_channel_t *mes_get_active_send_channel(uint32 dest_id, uint32 caller_tid, uint32 flags)
{
    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(caller_tid);
    mes_priority_t priority = MES_PRIORITY(flags);
    mes_instance_t *mes = &MES_GLOBAL_INST_MSG;
    mes_channel_t *channel = &mes->mes_ctx.channels[dest_id][channel_id];
    if (mes->profile.need_serial) {
        return channel;
    } else {
        /*
         * try to get active send channel,
         * if original choosed channel is inactive,
         * we iterate from tail to head to find an active channel (
         * because heartbeat thread construct channel from head to tail),
         * if all is inactive, we still use the original choosed channel.
         */
        uint32 channel_cnt = mes->profile.channel_cnt;
        uint32 index = channel_id;
        uint32 times = 0;
        while (times++ <= channel_cnt) {
            channel = &mes->mes_ctx.channels[dest_id][index];
            if (channel->pipe[priority].send_pipe_active) {
                break;
            }
            index = (index == 0) ? (channel_cnt - 1) : (index - 1);
        }
        return channel;
    }
}

static void mes_get_timer_thread(mes_thread_set_t *mes_thread_set)
{
    gs_timer_t *timer = g_timer();
    if (!timer->init) {
        return;
    }

    if (mes_thread_set->thread_count >= MAX_MES_THREAD_NUM) {
        return;
    }
    errno_t err = sprintf_s(mes_thread_set->threads[mes_thread_set->thread_count].thread_name,
                MES_MAX_NAME_LEN, "mes timer");
    PRTS_RETVOID_IFERR(err);
    mes_thread_set->threads[mes_thread_set->thread_count].thread_info = (void *)&timer->thread;
    mes_thread_set->thread_count++;
}

static void mes_get_specified_thread(
    mes_thread_set_t *mes_thread_set, bool8 is_send, char *format)
{
    mq_context_t *mq_ctx = is_send ? &MES_GLOBAL_INST_MSG.send_mq : &MES_GLOBAL_INST_MSG.recv_mq;
    int count = mes_get_started_task_count(is_send);
    errno_t err;
    for (int i = 0; i < count; i++) {
        if (mes_thread_set->thread_count >= MAX_MES_THREAD_NUM) {
            return;
        }
        err = sprintf_s(mes_thread_set->threads[mes_thread_set->thread_count].thread_name,
                MES_MAX_NAME_LEN, format, i);
        PRTS_RETVOID_IFERR(err);
        mes_thread_set->threads[mes_thread_set->thread_count].thread_info = (void *)&mq_ctx->tasks[i].thread;
        mes_thread_set->thread_count++;
    }
}

static inline void mes_get_task_thread(mes_thread_set_t *mes_thread_set)
{
    char recv_format[] = "mes proc task : recv queue %d";
    char send_format[] = "mes proc task : send queue %d";
    mes_get_specified_thread(mes_thread_set, CM_FALSE, recv_format);
    mes_get_specified_thread(mes_thread_set, CM_TRUE, send_format);
}

static void mes_get_tcp_lsnr_thread(mes_thread_set_t *mes_thread_set)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_TCP) {
        return;
    }

    if (mes_thread_set->thread_count >= MAX_MES_THREAD_NUM) {
        return;
    }

    errno_t err = sprintf_s(mes_thread_set->threads[mes_thread_set->thread_count].thread_name,
                MES_MAX_NAME_LEN, "mes tcp lsnr");
    PRTS_RETVOID_IFERR(err);
    mes_thread_set->threads[mes_thread_set->thread_count].thread_info =
        (void *)&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp.thread;
    mes_thread_set->thread_count++;
}

static void mes_get_heartbeat_thread(mes_thread_set_t *mes_thread_set)
{
    uint32 inst_cnt = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    uint32 src_inst_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    uint32 conn_inst_id;
    mes_conn_t *conn;
    errno_t err;
    for (uint32 i = 0; i < inst_cnt; i++) {
        conn_inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (conn_inst_id == src_inst_id) {
            continue;
        }

        if (!MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].need_connect) {
            continue;
        }

        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[conn_inst_id];
        if (!conn->is_start) {
            continue;
        }

        if (mes_thread_set->thread_count >= MAX_MES_THREAD_NUM) {
            return;
        }
        err = sprintf_s(mes_thread_set->threads[mes_thread_set->thread_count].thread_name,
                MES_MAX_NAME_LEN, "mes heartbeat %u to %u : %u", src_inst_id, conn_inst_id, i);
        PRTS_RETVOID_IFERR(err);
        mes_thread_set->threads[mes_thread_set->thread_count].thread_info =
            (void *)&conn->thread;
        mes_thread_set->thread_count++;
    }
}

void mes_get_all_threads(mes_thread_set_t *mes_thread_set)
{
    mes_get_timer_thread(mes_thread_set);
    mes_get_task_thread(mes_thread_set);
    mes_get_receiver_thread(mes_thread_set);
    mes_get_tcp_lsnr_thread(mes_thread_set);
    mes_get_heartbeat_thread(mes_thread_set);
}

// channel
int mes_alloc_channels(void)
{
    errno_t ret;
    size_t alloc_size;
    char *temp_buf;

    if (MES_GLOBAL_INST_MSG.profile.channel_cnt == 0) {
        LOG_RUN_ERR("channel_cnt %u is invalid", MES_GLOBAL_INST_MSG.profile.channel_cnt);
        return ERR_MES_PARAM_INVALID;
    }

    // alloc channel pointer array
    alloc_size = sizeof(mes_channel_t *) * MES_MAX_INSTANCES;
    temp_buf = (char *)cm_malloc_prot(alloc_size);
    if (temp_buf == NULL) {
        LOG_RUN_ERR("allocate mes_channel_t pointer array failed, channel_cnt %u alloc size %zu",
                    MES_GLOBAL_INST_MSG.profile.channel_cnt, alloc_size);
        return ERR_MES_MALLOC_FAIL;
    }
    ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(temp_buf);
        return ERR_MES_MEMORY_SET_FAIL;
    }
    MES_GLOBAL_INST_MSG.mes_ctx.channels = (mes_channel_t **)temp_buf;

    // alloc channel
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; ++i) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        CM_RETURN_IFERR(mes_init_single_inst_channel(inst_id));
    }
    GS_INIT_SPIN_LOCK(MES_GLOBAL_INST_MSG.mes_ctx.inst_channel_lock);
    return CM_SUCCESS;
}

int mes_init_single_inst_channel(unsigned int inst_id)
{
    size_t alloc_size = sizeof(mes_channel_t) * MES_GLOBAL_INST_MSG.profile.channel_cnt;
    char *temp_buf = (char *)cm_malloc_prot(alloc_size);
    if (temp_buf == NULL) {
        LOG_RUN_ERR("allocate mes_channel_t failed, inst_id %u alloc size %zu", inst_id, alloc_size);
        return ERR_MES_MALLOC_FAIL;
    }
    int ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_FREE_PROT_PTR(temp_buf);
        return ERR_MES_MEMORY_SET_FAIL;
    }
    MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] = (mes_channel_t *)temp_buf;
    // init channel
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; ++i) {
        mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        channel->id = (inst_id << CHANNEL_ID_BITS) | i;
        if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
            mes_tcp_init_channels_param((uintptr_t)channel);
        } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
            mes_rdma_rpc_init_channels_param((uintptr_t)channel);
        }
    }
    return CM_SUCCESS;
}