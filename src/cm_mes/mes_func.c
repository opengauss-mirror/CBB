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
#include "mes_func.h"
#include "mes.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_spinlock.h"
#include "cs_tcp.h"
#include "cm_date_to_text.h"
#include "mes_rpc_dl.h"
#include "mes_rpc_ulog4c.h"
#include "cm_defs.h"
#include "mes_metadata.h"

mes_instance_t g_cbb_mes;
static mes_callback_t g_cbb_mes_callback;
mes_elapsed_stat_t g_mes_elapsed_stat;
mes_stat_t g_mes_stat;

static mes_global_ptr_t g_mes_ptr = {
    .g_cbb_mes_ptr = &g_cbb_mes,
    .g_mes_stat_ptr = &g_mes_stat,
    .g_mes_elapsed_stat = &g_mes_elapsed_stat
};

#define MES_CONNECT(inst_id) g_cbb_mes_callback.connect_func(inst_id)
#define MES_DISCONNECT(inst_id, wait) g_cbb_mes_callback.disconnect_func(inst_id, wait)
#define MES_SEND_DATA(data) g_cbb_mes_callback.send_func(data)
#define MES_SEND_BUFFLIST(buff_list) g_cbb_mes_callback.send_bufflist_func(buff_list)
#define MES_RELEASE_BUFFER(buffer) g_cbb_mes_callback.release_buf_func(buffer)
#define MES_CONNETION_READY(inst_id) g_cbb_mes_callback.conn_ready_func(inst_id)
#define MES_ALLOC_MSGITEM(queue) g_cbb_mes_callback.alloc_msgitem_func(queue)

// for ssl
bool32 g_ssl_enable = CM_FALSE;
usr_cb_decrypt_pwd_t usr_cb_decrypt_pwd = NULL;

static inline void mes_clean_recv_broadcast_msg(mes_waiting_room_t *room, uint64 success_inst)
{
    uint32 i;
    mes_message_t msg;
    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        if (MES_IS_INST_SEND(success_inst, i) && room->broadcast_msg[i] != NULL) {
            MES_MESSAGE_ATTACH(&msg, room->broadcast_msg[i]);
            mes_release_message_buf(&msg);
            room->broadcast_msg[i] = NULL;
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

static inline void mes_protect_when_timeout(mes_waiting_room_t *room)
{
    return;
}

static inline void mes_protect_when_brcast_timeout(mes_waiting_room_t *room, uint64 success_inst)
{
    return;
}

#else
static void mes_mutex_destroy(mes_mutex_t *mutex)
{
    (void)pthread_mutex_destroy(mutex);
}

static int mes_mutex_create(mes_mutex_t *mutex)
{
    if (pthread_mutex_init(mutex, NULL) != 0) {
        return CM_ERROR;
    }

    (void)pthread_mutex_lock(mutex);
    return CM_SUCCESS;
}

static void mes_get_timespec(struct timespec *tim, uint32 timeout)
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

static bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    struct timespec ts;
    mes_get_timespec(&ts, timeout);

    return (pthread_mutex_timedlock(mutex, &ts) == 0);
}

static void mes_mutex_unlock(mes_mutex_t *mutex)
{
    (void)pthread_mutex_unlock(mutex);
}

static inline void mes_protect_when_timeout(mes_waiting_room_t *room)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_inc((atomic_t *)(&room->rsn));
    if (!pthread_mutex_trylock(&room->mutex)) { // trylock to avoid mutex has been unlocked.
        mes_free_buf_item((char *)room->msg_buf);
        LOG_RUN_ERR("[mes]%s: mutex has unlock, rsn=%llu, room rsn=%llu.", (char *)__func__,
            ((mes_message_head_t *)room->msg_buf)->rsn, room->rsn);
    }
    cm_spin_unlock(&room->lock);
}

static inline void mes_protect_when_brcast_timeout(mes_waiting_room_t *room, uint64 success_inst)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_inc((atomic_t *)(&room->rsn));
    cm_spin_unlock(&room->lock);
    (void)pthread_mutex_trylock(&room->broadcast_mutex);
    if (success_inst != 0) {
        mes_clean_recv_broadcast_msg(room, success_inst);
    }
}

#endif

static void mes_consume_time_init(const mes_profile_t *profile)
{
    for (uint32 j = 0; j < CM_MAX_MES_MSG_CMD; j++) {
        g_mes_elapsed_stat.time_consume_stat[j].cmd = j;
        for (int i = 0; i < MES_TIME_CEIL; i++) {
            g_mes_elapsed_stat.time_consume_stat[j].time[i] = 0;
            g_mes_elapsed_stat.time_consume_stat[j].count[i] = 0;
            GS_INIT_SPIN_LOCK(g_mes_elapsed_stat.time_consume_stat[j].lock[i]);
        }
    }
    g_mes_elapsed_stat.mes_elapsed_switch = profile->mes_elapsed_switch;
    return;
}

static void mes_init_stat(const mes_profile_t *profile)
{
    g_mes_stat.mes_elapsed_switch = profile->mes_elapsed_switch;
    for (uint32 i = 0; i < CM_MAX_MES_MSG_CMD; i++) {
        g_mes_stat.mes_commond_stat[i].cmd = i;
        g_mes_stat.mes_commond_stat[i].send_count = 0;
        g_mes_stat.mes_commond_stat[i].recv_count = 0;
        g_mes_stat.mes_commond_stat[i].local_count = 0;
        g_mes_stat.mes_commond_stat[i].occupy_buf = 0;
        GS_INIT_SPIN_LOCK(g_mes_stat.mes_commond_stat[i].lock);
    }
    mes_consume_time_init(profile);
    return;
}

static inline void mes_send_stat(uint32 cmd)
{
    if (g_mes_stat.mes_elapsed_switch) {
        cm_spin_lock(&(g_mes_stat.mes_commond_stat[cmd].lock), NULL);
        (void)cm_atomic_inc(&(g_mes_stat.mes_commond_stat[cmd].send_count));
        cm_spin_unlock(&(g_mes_stat.mes_commond_stat[cmd].lock));
    }
    return;
}

void mes_local_stat(uint32 cmd)
{
    if (g_mes_stat.mes_elapsed_switch) {
        cm_spin_lock(&(g_mes_stat.mes_commond_stat[cmd].lock), NULL);
        (void)cm_atomic_inc(&(g_mes_stat.mes_commond_stat[cmd].local_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_commond_stat[cmd].occupy_buf));
        cm_spin_unlock(&(g_mes_stat.mes_commond_stat[cmd].lock));
    }
    return;
}

static inline void mes_recv_message_stat(const mes_message_t *msg)
{
    if (g_mes_stat.mes_elapsed_switch) {
        cm_spin_lock(&(g_mes_stat.mes_commond_stat[msg->head->cmd].lock), NULL);
        (void)cm_atomic_inc(&(g_mes_stat.mes_commond_stat[msg->head->cmd].recv_count));
        (void)cm_atomic32_inc(&(g_mes_stat.mes_commond_stat[msg->head->cmd].occupy_buf));
        cm_spin_unlock(&(g_mes_stat.mes_commond_stat[msg->head->cmd].lock));
    }
    return;
}

static inline void mes_stop_lsnr(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        cs_stop_tcp_lsnr(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.tcp);
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        stop_rdma_rpc_lsnr();
    }
    return;
}

static inline void mes_copy_recv_broadcast_msg(mes_waiting_room_t *room, uint64 success_inst,
    char *recv_msg[MES_MAX_INSTANCES])
{
    uint32 i;
    for (i = 0; i < MES_MAX_INSTANCES; i++) {
        if (MES_IS_INST_SEND(success_inst, i)) {
            recv_msg[i] = room->broadcast_msg[i];
            room->broadcast_msg[i] = NULL;
        }
    }
}

static int mes_send_inter_buffer_list(mes_bufflist_t *buff_list)
{
    int ret;
    mes_message_t msg;
    char *buffer;
    uint32 pos = 0;
    uint32 total_len = 0;

    for (int i = 0; i < buff_list->cnt; i++) {
        total_len += buff_list->buffers[i].len;
    }

    buffer = mes_alloc_buf_item(total_len);
    if (buffer == NULL) {
        return ERR_MES_MALLOC_FAIL;
    }

    for (int i = 0; i < buff_list->cnt; i++) {
        ret = memcpy_s(buffer + pos, total_len - pos, buff_list->buffers[i].buf, buff_list->buffers[i].len);
        if (ret != EOK) {
            mes_free_buf_item(buffer);
            return ERR_MES_MEMORY_COPY_FAIL;
        }
        pos += buff_list->buffers[i].len;
    }

    MES_MESSAGE_ATTACH(&msg, buffer);

    ret = mes_put_inter_msg(&msg);
    if (ret != CM_SUCCESS) {
        mes_free_buf_item(buffer);
        LOG_RUN_ERR("[mes] send inner failed.");
        return ret;
    }

    return CM_SUCCESS;
}

static inline void mes_append_bufflist(mes_bufflist_t *buff_list, const void *buff, uint32 len)
{
    buff_list->buffers[buff_list->cnt].buf = (char *)buff;
    buff_list->buffers[buff_list->cnt].len = len;
    buff_list->cnt = buff_list->cnt + 1;
}

static void mes_clean_session_mutex(uint32 ceil)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom) {
        return;
    }

    for (uint32 i = 0; i < ceil; i++) {
        mes_mutex_destroy(&MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[i].mutex);
        mes_mutex_destroy(&MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[i].broadcast_mutex);
    }
    MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom = CM_FALSE;
}

static inline int mes_set_addr(uint32 inst_id, const char *ip, uint16 port)
{
    errno_t ret = strncpy_s(MES_GLOBAL_INST_MSG.profile.inst_net_addr[inst_id].ip, CM_MAX_IP_LEN, ip, strlen(ip));
    if (ret != EOK) {
        return ERR_MES_STR_COPY_FAIL;
    }
    MES_GLOBAL_INST_MSG.profile.inst_net_addr[inst_id].port = port;
    return CM_SUCCESS;
}

static int mes_set_instance_info(uint32 inst_id, uint32 inst_cnt, const mes_addr_t *inst_net_addr)
{
    int ret;
    if (inst_id >= CM_MAX_INSTANCES) {
        LOG_RUN_ERR("inst_id %u is invalid, exceed max instance num %u.", inst_id, CM_MAX_INSTANCES);
        return ERR_MES_PARAM_INVAIL;
    }

    if (inst_cnt > CM_MAX_INSTANCES) {
        LOG_RUN_ERR("instinst_count_id %u is invalid, exceed max instance num %u.", inst_cnt, CM_MAX_INSTANCES);
        return ERR_MES_PARAM_INVAIL;
    }

    MES_GLOBAL_INST_MSG.profile.inst_id = inst_id;
    MES_GLOBAL_INST_MSG.profile.inst_cnt = inst_cnt;

    ret = memset_sp(MES_GLOBAL_INST_MSG.profile.inst_net_addr, (sizeof(mes_addr_t) * CM_MAX_INSTANCES), 0,
        (sizeof(mes_addr_t) * CM_MAX_INSTANCES));
    if (ret != EOK) {
        return ERR_MES_MEMORY_SET_FAIL;
    }

    for (uint32 i = 0; i < inst_cnt; i++) {
        ret = mes_set_addr(i, inst_net_addr[i].ip, inst_net_addr[i].port);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("mes_set_addr failed.");
            return ret;
        }
    }
    return CM_SUCCESS;
}

static int mes_set_group_task_num(mes_task_group_id_t group_id, uint32 task_num)
{
    mes_task_group_t *task_group = &MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[group_id];

    if (task_num == 0) {
        LOG_RUN_WAR("[mes]: group_id %u set task_num 0.", group_id);
        return CM_SUCCESS;
    }

    if (task_group->is_set) {
        LOG_RUN_ERR("[mes]: group_id %u has been set already.", group_id);
        return ERR_MES_THE_GROUP_SETED;
    }

    if ((MES_GLOBAL_INST_MSG.mq_ctx.group.assign_task_idx + task_num) > MES_GLOBAL_INST_MSG.mq_ctx.task_num) {
        LOG_RUN_ERR("[mes]: group %u task num %u has excced total task num.", group_id, task_num);
        return ERR_MES_PARAM_INVAIL;
    }

    task_group->push_cursor = 0;
    task_group->pop_cursor = 0;
    task_group->group_id = group_id;
    task_group->task_num = (uint8)task_num;
    task_group->start_task_idx = (uint8)MES_GLOBAL_INST_MSG.mq_ctx.group.assign_task_idx;
    MES_GLOBAL_INST_MSG.mq_ctx.group.assign_task_idx += task_num;
    task_group->is_set = CM_TRUE;

    LOG_RUN_INF("[mes]: set group %u start_task_idx %hhu task num %u.", group_id, task_group->start_task_idx, task_num);

    return CM_SUCCESS;
}

static int mes_send_inter_msg(const void *msg_data)
{
    int ret;
    mes_message_t msg;
    char *buffer;
    mes_message_head_t *msgdata = (mes_message_head_t *)msg_data;

    buffer = mes_alloc_buf_item(msgdata->size);
    if (buffer == NULL) {
        return ERR_MES_MALLOC_FAIL;
    }

    ret = memcpy_s(buffer, msgdata->size, msg_data, msgdata->size);
    if (ret != EOK) {
        mes_free_buf_item(buffer);
        LOG_RUN_ERR("[mes] mes copy inter msg failed, msg_data size(%d).", msgdata->size);
        return ERR_MES_MEMORY_SET_FAIL;
    }

    MES_MESSAGE_ATTACH(&msg, buffer);
    ret = mes_put_inter_msg(&msg);
    if (ret != CM_SUCCESS) {
        mes_free_buf_item(buffer);
        LOG_RUN_ERR("[mes] mes_put_inter_msg failed.");
        return ret;
    }

    return CM_SUCCESS;
}

static int mes_set_buffer_pool(const mes_profile_t *profile)
{
    uint32 pool_count = profile->buffer_pool_attr.pool_count;
    uint32 queue_count = profile->buffer_pool_attr.queue_count;

    if ((pool_count == 0) || (pool_count > MES_MAX_BUFFPOOL_NUM)) {
        LOG_RUN_ERR("[mes] pool_count %u is invalid, legal scope is [1, %d].", pool_count, MES_MAX_BUFFPOOL_NUM);
        return CM_ERROR;
    }

    if ((queue_count == 0) || (queue_count > MES_MAX_BUFFER_QUEUE_NUM)) {
        LOG_RUN_ERR("[mes] pool_queue_count %u is invalid, legal scope is [1, %d].", queue_count,
            MES_MAX_BUFFER_QUEUE_NUM);
        return CM_ERROR;
    }

    MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.pool_count = pool_count;
    MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.queue_count = queue_count;

    for (uint32 i = 0; i < pool_count; i++) {
        MES_GLOBAL_INST_MSG.profile.buffer_pool_attr.buf_attr[i] = profile->buffer_pool_attr.buf_attr[i];
    }

    return CM_SUCCESS;
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

static void mes_set_work_thread_num(uint32 thread_num)
{
    if (thread_num < MES_MIN_TASK_NUM) {
        MES_GLOBAL_INST_MSG.profile.work_thread_cnt = MES_MIN_TASK_NUM;
        LOG_RUN_WAR("[mes] min work thread num is %d.", MES_MIN_TASK_NUM);
    } else if (thread_num > MES_MAX_TASK_NUM) {
        MES_GLOBAL_INST_MSG.profile.work_thread_cnt = MES_MAX_TASK_NUM;
        LOG_RUN_WAR("[mes] max work thread num is %d.", MES_MAX_TASK_NUM);
    } else {
        MES_GLOBAL_INST_MSG.profile.work_thread_cnt = thread_num;
    }

    LOG_RUN_INF("[mes] set work thread num %u.", MES_GLOBAL_INST_MSG.profile.work_thread_cnt);
    return;
}

static int mes_set_profile(mes_profile_t *profile)
{
    int ret;
    ret = mes_set_instance_info(profile->inst_id, profile->inst_cnt, profile->inst_net_addr);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: mes_set_instance_info failed.");
        return ret;
    }

    ret = mes_set_buffer_pool(profile);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]: set buffer pool failed.");
        return ret;
    }

    MES_GLOBAL_INST_MSG.profile.pipe_type = profile->pipe_type;
    MES_GLOBAL_INST_MSG.profile.conn_created_during_init = profile->conn_created_during_init;
    mes_set_channel_num(profile->channel_cnt);
    mes_set_work_thread_num(profile->work_thread_cnt);

    ret = memcpy_sp(MES_GLOBAL_INST_MSG.profile.task_group, sizeof(MES_GLOBAL_INST_MSG.profile.task_group),
        profile->task_group, sizeof(MES_GLOBAL_INST_MSG.profile.task_group));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes]: set buffer pool failed.");
        return ERR_MES_MEMORY_COPY_FAIL;
    }

    // mq
    MES_GLOBAL_INST_MSG.mq_ctx.task_num = MES_GLOBAL_INST_MSG.profile.work_thread_cnt;
    MES_GLOBAL_INST_MSG.mq_ctx.group.assign_task_idx = 0;

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

    LOG_RUN_INF("[mes]: set profile finish.");
    return CM_SUCCESS;
}

static int mes_init_session_room(void)
{
    uint32 i;
    mes_waiting_room_t *room = NULL;
    MES_GLOBAL_INST_MSG.mes_ctx.creatWaitRoom = CM_TRUE;

    for (i = 0; i < CM_MAX_MES_ROOMS; i++) {
        room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[i];

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

        room->rsn = 0;
        room->check_rsn = room->rsn;
    }
    return CM_SUCCESS;
}

static int mes_register_func(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        g_cbb_mes_callback.connect_func = mes_tcp_connect;
        g_cbb_mes_callback.disconnect_func = mes_tcp_disconnect;
        g_cbb_mes_callback.send_func = mes_tcp_send_data;
        g_cbb_mes_callback.send_bufflist_func = mes_tcp_send_bufflist;
        g_cbb_mes_callback.conn_ready_func = mes_tcp_connection_ready;
        g_cbb_mes_callback.alloc_msgitem_func = mes_alloc_msgitem_nolock;
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        g_cbb_mes_callback.connect_func = mes_rdma_rpc_connect_handle;
        g_cbb_mes_callback.disconnect_func = mes_rdma_rpc_disconnect_handle;
        g_cbb_mes_callback.send_func = mes_rdma_rpc_send_data;
        g_cbb_mes_callback.send_bufflist_func = mes_rdma_rpc_send_bufflist;
        g_cbb_mes_callback.conn_ready_func = mes_rdma_rpc_connection_ready;
        g_cbb_mes_callback.alloc_msgitem_func = mes_alloc_msgitem_nolock;
    }
    return CM_SUCCESS;
}

static int mes_init_conn(void)
{
    mes_conn_t *conn;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_TCP &&
        MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_RDMA) {
        return ERR_MES_CONNTYPE_ERR;
    }

    for (uint32 i = 0; i < CM_MAX_INSTANCES; i++) {
        conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[i];
        conn->is_connect = CM_FALSE;
        cm_init_thread_lock(&conn->lock);
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

static int mes_init_group_task(void)
{
    int ret;
    uint32 loop;
    uint32 task_num = 0;

    // check num
    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        task_num += MES_GLOBAL_INST_MSG.profile.task_group[loop];
    }

    if (task_num != MES_GLOBAL_INST_MSG.mq_ctx.task_num) {
        LOG_RUN_ERR("[mes] mes set group task num is not equal work thread num.");
        return ERR_MES_GROUPTASK_NUM_ERR;
    }

    for (loop = 0; loop < MES_TASK_GROUP_ALL; loop++) {
        ret = mes_set_group_task_num((mes_task_group_id_t)loop, MES_GLOBAL_INST_MSG.profile.task_group[loop]);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}


static int mes_init_resource(void)
{
    int ret;
    mes_init_msg_queue();
    (void)mes_register_func();

    ret = mes_init_group_task();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes set group task num failed.");
        return ret;
    }

    ret = mes_init_conn();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes init conn failed.");
        return ret;
    }

    ret = mes_init_session_room();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes_init_session_room failed.");
        return ret;
    }

    ret = mes_init_pipe_resource();
    if (ret != CM_SUCCESS) {
        mes_clean_session_mutex(CM_MAX_MES_ROOMS);
        LOG_RUN_ERR("mes_init_session_room failed.");
        return ret;
    }

    return CM_SUCCESS;
}

static void mes_destroy_msgitem_pool(void)
{
    mes_free_msgitem_pool(&MES_GLOBAL_INST_MSG.mq_ctx.pool);
    mes_init_msgitem_pool(&MES_GLOBAL_INST_MSG.mq_ctx.pool);
    mes_init_msgqueue(&MES_GLOBAL_INST_MSG.mq_ctx.local_queue);
}

static inline void mes_close_libdl(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        FinishOckRpcDl();
        FinishUlogDl();
    }
}

static void mes_destroy_resource(void)
{
    mes_destory_message_pool();
    mes_free_channels();
    mes_destroy_msgitem_pool();
    mes_clean_session_mutex(CM_MAX_MES_ROOMS);
    mes_close_libdl();
    return;
}

void mes_process_message(mes_msgqueue_t *my_queue, uint32 recv_idx, mes_message_t *msg)
{
    uint64 start_time = 0;
    mes_get_consume_time_start(&start_time);
    mes_msgitem_t *msgitem;

    mes_recv_message_stat(msg);
    if (MES_GLOBAL_INST_MSG.is_enqueue[msg->head->cmd]) {
        msgitem = MES_ALLOC_MSGITEM(my_queue);
        if (msgitem == NULL) {
            mes_release_message_buf(msg);
            LOG_RUN_ERR("[mes]: alloc msgitem failed.");
            return;
        }

        msgitem->msg.head = msg->head;
        msgitem->msg.buffer = msg->buffer;
        mes_put_msgitem_enqueue(msgitem);
        mes_consume_with_time(msg->head->cmd, MES_TIME_PUT_QUEUE, start_time);
        return;
    }
    MES_GLOBAL_INST_MSG.proc((MES_GLOBAL_INST_MSG.profile.work_thread_cnt + recv_idx), msg);
    mes_consume_with_time(msg->head->cmd, MES_TIME_PROC_FUN, start_time);
    return;
}

static int mes_start_work_thread(void)
{
    for (uint32 loop = 0; loop < MES_GLOBAL_INST_MSG.profile.work_thread_cnt; loop++) {
        MES_GLOBAL_INST_MSG.mes_ctx.work_thread_idx[loop] = loop;
        if (cm_create_thread(mes_task_proc, 0, &MES_GLOBAL_INST_MSG.mes_ctx.work_thread_idx[loop],
            &MES_GLOBAL_INST_MSG.mq_ctx.tasks[loop].thread) != CM_SUCCESS) {
            LOG_RUN_ERR("create work thread %u failed.", loop);
            return ERR_MES_WORK_THREAD_FAIL;
        }
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startWorkTh = CM_TRUE;
    return CM_SUCCESS;
}

static int mes_start_listen_thread(void)
{
    int ret;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        ret = mes_start_lsnr();
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("mes_init failed.");
            return ret;
        }
    } else if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        ret = mes_start_rdma_rpc_lsnr();
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("mes start rdma rpc lsnr failed, ret: %d", ret);
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

static void mes_close_work_thread(void)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.startWorkTh) {
        return;
    }

    for (uint32 loop = 0; loop < MES_GLOBAL_INST_MSG.profile.work_thread_cnt; loop++) {
        cm_close_thread(&MES_GLOBAL_INST_MSG.mq_ctx.tasks[loop].thread);
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startWorkTh = CM_FALSE;
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
        if (i == MES_GLOBAL_INST_MSG.profile.inst_id) {
            continue;
        }

        ret = mes_connect(i, MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].ip,
            MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].port);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] conncect to instance %u failed.", i);
            return ret;
        }
    }

    return CM_SUCCESS;
}

status_t mes_verify_ssl_key_pwd(ssl_config_t *ssl_cfg, char *plain, uint32 size)
{
    param_value_t keypwd;

    // check password which encrypted by CBB
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_PWD_PLAINTEXT, &keypwd));
    if (keypwd.inter_pwd.cipher_len > 0) {
        CM_RETURN_IFERR(cm_decrypt_pwd(&keypwd.inter_pwd, (uchar*)plain, &size));
        ssl_cfg->key_password = plain;
        return CM_SUCCESS;
    }

    // check password which encrypted by RSM
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_PWD_CIPHERTEXT, &keypwd));
    if (!CM_IS_EMPTY_STR(keypwd.ext_pwd)) {
        if (usr_cb_decrypt_pwd == NULL) {
            LOG_RUN_ERR("[MEC]user decrypt function has not registered");
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
    char plain[CM_PASSWD_MAX_LEN + 1] = { 0 };

    // verify ssl key password and KMC module
    if (mes_verify_ssl_key_pwd(ssl_cfg, plain, sizeof(plain) - 1) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        return CM_ERROR;
    }

    // create acceptor fd
    MES_GLOBAL_INST_MSG.ssl_acceptor_fd = cs_ssl_create_acceptor_fd(ssl_cfg);
    if (MES_GLOBAL_INST_MSG.ssl_acceptor_fd == NULL) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[MEC]create ssl acceptor context failed");
        return CM_ERROR;
    }

    // check cert expire
    if (mes_chk_ssl_cert_expire() != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[MEC]check ssl cert failed");
        return CM_ERROR;
    }

    // create connector fd
    MES_GLOBAL_INST_MSG.ssl_connector_fd = cs_ssl_create_connector_fd(ssl_cfg);
    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
    if (MES_GLOBAL_INST_MSG.ssl_connector_fd == NULL) {
        LOG_RUN_ERR("[MEC]create ssl connector context failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t mes_init_ssl(void)
{
    ssl_config_t ssl_cfg = { 0 };
    param_value_t ca, key, crl, cert, cipher;

    // Required parameters
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_CA, &ca));
    ssl_cfg.ca_file = ca.ssl_ca;
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_KEY, &key));
    ssl_cfg.key_file = key.ssl_key;
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_CERT, &cert));
    ssl_cfg.cert_file = cert.ssl_cert;

    if (CM_IS_EMPTY_STR(ssl_cfg.cert_file) ||
        CM_IS_EMPTY_STR(ssl_cfg.key_file) || CM_IS_EMPTY_STR(ssl_cfg.ca_file)) {
        LOG_RUN_WAR("SSL disabled: certificate file or private key file or CA certificate is not available.");
        LOG_ALARM(WARN_SSL_DIASBLED, "}");
        return CM_SUCCESS;
    }

    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_RDMA) {
        if (mes_ockrpc_init_ssl() != CM_SUCCESS) {
            LOG_RUN_ERR("[MEC]init ockrpc ssl failed");
            return CM_ERROR;
        }
    }

    // Optional parameters
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_CRL, &crl));
    ssl_cfg.crl_file = crl.ssl_crl;
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_CIPHER, &cipher));
    ssl_cfg.cipher = cipher.ssl_cipher;

    /* Require no public access to key file */
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.ca_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.key_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.cert_file));

    // create fd
    if (mes_create_ssl_fd(&ssl_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }

    g_ssl_enable = CM_TRUE;
    LOG_RUN_INF("[MEC]mes_init_ssl: ssl enable is %u.", (uint32)g_ssl_enable);
    return CM_SUCCESS;
}

void mes_uninit(void)
{
    mes_close_listen_thread();
    mes_close_work_thread();
    mes_stop_channels();
    mes_destroy_resource();
    mes_deinit_ssl();
    (void)memset_s(&MES_GLOBAL_INST_MSG, sizeof(mes_instance_t), 0, sizeof(mes_instance_t));
    return;
}

int mes_init(mes_profile_t *profile)
{
    int ret;

    if (profile == NULL) {
        LOG_RUN_ERR("[mes]: profile is NULL,init failed.");
        return ERR_MES_PARAM_NULL;
    }
    mes_init_stat(profile);

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

        ret = mes_start_work_thread();
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = mes_start_listen_thread();
        if (ret != CM_SUCCESS) {
            break;
        }
        ret = mes_connect_by_profile();
    } while (0);

    if (ret != CM_SUCCESS) {
        mes_uninit();
        return ret;
    }

    LOG_RUN_INF("[mes]: mes_init success.");
    return ret;
}

void mes_register_proc_func(mes_message_proc_t proc)
{
    MES_GLOBAL_INST_MSG.proc = proc;
    return;
}

void mes_set_msg_enqueue(unsigned int command, unsigned int is_enqueue)
{
    MES_GLOBAL_INST_MSG.is_enqueue[command] = is_enqueue;
    return;
}

void mes_notify_msg_recv(mes_message_t *msg)
{
    if (msg == NULL || msg->head->dst_sid >= CM_MAX_MES_ROOMS) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes]: mes notify msg recv failed");
        return;
    }

    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[msg->head->dst_sid];
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        room->msg_buf = msg->buffer;
        room->check_rsn = msg->head->rsn;
        mes_mutex_unlock(&room->mutex);
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
        mes_release_message_buf(msg);
    }
}

void mes_notify_broadcast_msg_recv_with_errcode(mes_message_t *msg)
{
    if (msg == NULL || msg->head->dst_sid >= CM_MAX_MES_ROOMS ||
        msg->head->size < MES_MSG_HEAD_SIZE + sizeof(int32)) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes]: mes notify broadcast-release msg failed");
        return;
    }

    int32 errcode = *(int32*)(msg->buffer + MES_MSG_HEAD_SIZE);
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[msg->head->dst_sid];

    while (room->broadcast_flag) {
        cm_usleep(1);
    }

    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        if (errcode == CM_SUCCESS) {
            MES_INST_SENT_SUCCESS(room->succ_insts, msg->head->src_inst);
        }
        (void)cm_atomic32_inc(&room->ack_count);
        if (room->ack_count >= room->req_count) {
            room->check_rsn = msg->head->rsn;
            mes_mutex_unlock(&room->broadcast_mutex);
        }
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
    }
    mes_release_message_buf(msg);
}

void mes_notify_broadcast_msg_recv_and_release(mes_message_t *msg)
{
    if (msg == NULL || msg->head->dst_sid >= CM_MAX_MES_ROOMS) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes]: mes notify broadcast-release msg failed");
        return;
    }

    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[msg->head->dst_sid];
    while (room->broadcast_flag) {
        cm_usleep(1);
    }

    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        (void)cm_atomic32_inc(&room->ack_count);
        if (room->ack_count >= room->req_count) {
            room->check_rsn = msg->head->rsn;
            mes_mutex_unlock(&room->broadcast_mutex);
        }
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
    }

    mes_release_message_buf(msg);

    return;
}

void mes_notify_broadcast_msg_recv_and_cahce(mes_message_t *msg)
{
    if (msg == NULL || msg->head->dst_sid >= CM_MAX_MES_ROOMS) {
        mes_release_message_buf(msg);
        LOG_RUN_ERR("[mes]: mes notify broadcast-cache msg failed");
        return;
    }

    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[msg->head->dst_sid];
    while (room->broadcast_flag) {
        cm_usleep(1);
    }

    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        room->broadcast_msg[msg->head->src_inst] = msg->buffer;
        (void)cm_atomic32_inc(&room->ack_count);
        if (room->ack_count >= room->req_count) {
            room->check_rsn = msg->head->rsn;
            mes_mutex_unlock(&room->broadcast_mutex);
        }
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
        mes_release_message_buf(msg);
    }
    return;
}

int mes_connect(unsigned int inst_id, const char *ip, unsigned short port)
{
    int ret;
    mes_conn_t *conn;

    if ((inst_id == MES_GLOBAL_INST_MSG.profile.inst_id) || (inst_id >= CM_MAX_INSTANCES)) {
        LOG_RUN_ERR("[mes]: connect inst_id %u failed, current inst_id %u.", inst_id,
            MES_GLOBAL_INST_MSG.profile.inst_id);
        return ERR_MES_PARAM_INVAIL;
    }

    conn = &MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id];

    cm_thread_lock(&conn->lock);
    if (MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect) {
        cm_thread_unlock(&conn->lock);
        LOG_RUN_INF("[mes]: dst instance %u has connected.", inst_id);
        return ERR_MES_IS_CONNECTED;
    }

    ret = MES_CONNECT(inst_id);
    if (ret != CM_SUCCESS) {
        cm_thread_unlock(&conn->lock);
        LOG_RUN_ERR("[mes]: MES_CONNECT failed.");
        return ret;
    }

    MES_GLOBAL_INST_MSG.mes_ctx.conn_arr[inst_id].is_connect = CM_TRUE;
    cm_thread_unlock(&conn->lock);

    LOG_RUN_INF("[mes]: connect to instance %u, %s:%hu.", inst_id, ip, port);

    return CM_SUCCESS;
}

void mes_disconnect_nowait(unsigned int inst_id)
{
    mes_conn_t *conn;

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

void mes_disconnect(unsigned int inst_id)
{
    mes_conn_t *conn;

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

unsigned int mes_connection_ready(unsigned int inst_id)
{
    return MES_CONNETION_READY(inst_id);
}

int mes_send_bufflist(mes_bufflist_t *buff_list)
{
    return MES_SEND_BUFFLIST(buff_list);
}

void mes_get_queue_count(int *queue_count)
{
    mes_task_group_t *task_group = NULL;
    uint8 temp_count;

    *queue_count = 0;
    for (uint8 i = 0; i < MES_TASK_GROUP_ALL; i++) {
        task_group = &MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[i];
        if (!task_group->is_set) {
            continue;
        }
        temp_count = (task_group->task_num < MES_GROUP_QUEUE_NUM ? task_group->task_num : MES_GROUP_QUEUE_NUM);
        (*queue_count) += temp_count;
    }
}

static int mes_send_inter_msg_in_queue(mes_message_head_t *msg_head, mes_msgqueue_t *queue)
{
    mes_message_t msg;
    char *buffer = NULL;
    int ret = CM_SUCCESS;

    buffer = mes_alloc_buf_item(msg_head->size);
    if (buffer == NULL) {
        return ERR_MES_MALLOC_FAIL;
    }

    ret = memcpy_s(buffer, msg_head->size, (char *)msg_head, msg_head->size);
    if (ret != EOK) {
        mes_free_buf_item(buffer);
        LOG_RUN_ERR("[mes] mes copy inter msg failed, msg_data size(%d).", msg_head->size);
        return ERR_MES_MEMORY_SET_FAIL;
    }

    MES_MESSAGE_ATTACH(&msg, buffer);
    ret = mes_put_inter_msg_in_queue(&msg, queue);
    if (ret != CM_SUCCESS) {
        mes_free_buf_item(buffer);
        LOG_RUN_ERR("[mes]mes_put_inter_msg_in_queue failed");
        return ret;
    }

    return CM_SUCCESS;
}

int mes_send_inter_msg_all_queue(mes_message_head_t *msg_head)
{
    mes_task_group_t *task_group = NULL;
    mes_msgqueue_t *queue = NULL;
    uint8 temp_count;
    int ret = CM_SUCCESS;

    for (uint8 i = 0; i < MES_TASK_GROUP_ALL; i++) {
        task_group = &MES_GLOBAL_INST_MSG.mq_ctx.group.task_group[i];
        if (!task_group->is_set) {
            continue;
        }
        temp_count = (task_group->task_num < MES_GROUP_QUEUE_NUM ? task_group->task_num : MES_GROUP_QUEUE_NUM);
        for (uint8 j = 0; j < temp_count; j++) {
            queue = &task_group->queue[j];
            ret = mes_send_inter_msg_in_queue(msg_head, queue);
            if (ret != CM_SUCCESS) {
                LOG_RUN_ERR("[mes]mes_send_inter_msg_all_queue failed, group: %d, queue: %d", i, j);
                return ret;
            }
        }
    }

    return CM_SUCCESS;
}

int mes_send_data(mes_message_head_t *msg)
{
    uint64 start_stat_time = 0;
    int ret;
    if (msg == NULL) {
        LOG_RUN_ERR("mes send data failed, msg data is NULL");
        return ERR_MES_PARAM_NULL;
    }

    mes_message_head_t *head = msg;
    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE)) {
        LOG_RUN_ERR("message length %hu excced max %u", head->size, MES_MESSAGE_BUFFER_SIZE);
        MES_LOG_ERR_HEAD_EX(head, "message length excced");
        return ERR_MES_MSG_TOO_LARGE;
    }

    if (head->dst_inst == MES_GLOBAL_INST_MSG.profile.inst_id && head->cmd != MES_HEARTBEAT_CMD) {
        return mes_send_inter_msg(msg);
    }
    mes_get_consume_time_start(&start_stat_time);

    ret = MES_SEND_DATA(msg);
    if (ret == CM_SUCCESS) {
        mes_send_stat(head->cmd);
        mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);
    }
    return ret;
}

int mes_send_data2(const mes_message_head_t *head, const void *body)
{
    uint64 start_stat_time = 0;
    int ret;
    mes_bufflist_t buff_list;

    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE)) {
        MES_LOG_ERR_HEAD_EX(head, "message length excced");
        return ERR_MES_MSG_TOO_LARGE;
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, sizeof(mes_message_head_t));
    mes_append_bufflist(&buff_list, body, head->size - sizeof(mes_message_head_t));

    if (head->dst_inst == MES_GLOBAL_INST_MSG.profile.inst_id) {
        return mes_send_inter_buffer_list(&buff_list);
    }

    mes_get_consume_time_start(&start_stat_time);
    ret = MES_SEND_BUFFLIST(&buff_list);
    if (ret == CM_SUCCESS) {
        mes_send_stat(head->cmd);
        mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);
    }
    return ret;
}

int mes_send_data3(const mes_message_head_t *head, unsigned int head_size, const void *body)
{
    uint64 start_stat_time = 0;
    int ret;
    mes_bufflist_t buff_list;

    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE)) {
        MES_LOG_ERR_HEAD_EX(head, "message length excced");
        return ERR_MES_MSG_TOO_LARGE;
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, head_size);
    mes_append_bufflist(&buff_list, body, head->size - head_size);

    if (head->dst_inst == MES_GLOBAL_INST_MSG.profile.inst_id) {
        return mes_send_inter_buffer_list(&buff_list);
    }

    mes_get_consume_time_start(&start_stat_time);
    ret = MES_SEND_BUFFLIST(&buff_list);
    if (ret == CM_SUCCESS) {
        mes_send_stat(head->cmd);
        mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);
    }
    return ret;
}

int mes_send_data4(const mes_message_head_t *head, unsigned int head_size, const void *body1, unsigned int len1,
    const void *body2, unsigned int len2)
{
    uint64 start_stat_time = 0;
    mes_bufflist_t buff_list;

    if (SECUREC_UNLIKELY(head->size > MES_MESSAGE_BUFFER_SIZE)) {
        MES_LOG_ERR_HEAD_EX(head, "message length excced");
        return ERR_MES_MSG_TOO_LARGE;
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, head_size);
    mes_append_bufflist(&buff_list, body1, len1);
    mes_append_bufflist(&buff_list, body2, len2);

    if (head->dst_inst == MES_GLOBAL_INST_MSG.profile.inst_id) {
        return mes_send_inter_buffer_list(&buff_list);
    }

    mes_get_consume_time_start(&start_stat_time);
    int ret = MES_SEND_BUFFLIST(&buff_list);
    if (ret == CM_SUCCESS) {
        mes_send_stat(head->cmd);
        mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);
    }
    return ret;
}

int mes_allocbuf_and_recv_data(unsigned short sid, mes_message_t *msg, unsigned int timeout)
{
    uint64 start_stat_time = cm_get_time_usec();
    uint32 wait_time = 0;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    for (;;) {
        if (!mes_mutex_timed_lock(&room->mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout) {
                mes_protect_when_timeout(
                    room); // when timeout the ack msg may reach, so need do some check and protect.
                LOG_DEBUG_WAR("recv data rsn %llu ", room->rsn);
                return ERR_MES_WAIT_OVERTIME;
            }
            continue;
        }

        MES_MESSAGE_ATTACH(msg, room->msg_buf);
        room->msg_buf = NULL;
        if (msg->buffer == NULL) {
            return ERR_MES_WAIT_OVERTIME;
        }

        if (SECUREC_UNLIKELY(room->rsn !=
            msg->head->rsn)) { // this situation should not happen, keep this code to observe some time.
            // rsn not match, ignore this message
            MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
            LOG_RUN_ERR("[mes]%s: receive unmatch msg, rsn=%llu, room rsn=%llu.", (char *)__func__,
                ((mes_message_head_t *)msg->buffer)->rsn, room->rsn);
            mes_release_message_buf(msg);
            MES_MESSAGE_DETACH(msg);
            continue;
        }

        break;
    }
    mes_consume_with_time(msg->head->cmd, MES_TIME_TEST_RECV, start_stat_time);

    return CM_SUCCESS;
}

void mes_broadcast3(unsigned int sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst,
    mes_send_data_func send_data)
{
    uint64 start_stat_time = 0;
    uint32 i;
    uint64 send_inst = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    room->req_count = 0;
    room->ack_count = 0;
    room->succ_insts = 0;
    room->broadcast_flag = CM_TRUE;
    mes_get_consume_time_start(&start_stat_time);
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (MES_IS_INST_SEND(inst_bits, i)) {
            head->dst_inst = (uint8)i;
            if (send_data((mes_message_head_t *)msg_data) != CM_SUCCESS) {
                continue;
            }
            (void)cm_atomic32_inc(&room->req_count);
            MES_INST_SENT_SUCCESS(send_inst, i);
            mes_send_stat(head->cmd);
        }
    }
    room->broadcast_flag = CM_FALSE;

    if (success_inst != NULL) {
        *success_inst = send_inst;
    }
    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return;
}

void mes_broadcast(unsigned int sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst)
{
    mes_broadcast3(sid, inst_bits, msg_data, success_inst, mes_send_data);
}

void mes_broadcast4(unsigned int sid, uint64 inst_bits, mes_message_head_t *head, const void *body,
    uint64 *success_inst, mes_send_data2_func send_data)
{
    uint64 start_stat_time = 0;
    uint32 i;
    uint64 send_inst = 0;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    room->req_count = 0;
    room->ack_count = 0;
    room->succ_insts = 0;
    room->broadcast_flag = CM_TRUE;
    mes_get_consume_time_start(&start_stat_time);
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (MES_IS_INST_SEND(inst_bits, i)) {
            head->dst_inst = (uint8)i;
            if (send_data(head, body) != CM_SUCCESS) {
                continue;
            }
            (void)cm_atomic32_inc(&room->req_count);
            MES_INST_SENT_SUCCESS(send_inst, i);
            mes_send_stat(head->cmd);
        }
    }
    room->broadcast_flag = CM_FALSE;

    if (success_inst != NULL) {
        *success_inst = send_inst;
    }
    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return;
}

void mes_broadcast5(unsigned int sid, uint64 inst_bits, mes_message_head_t *head, unsigned int head_size,
    const void *body, uint64 *success_inst, mes_send_data3_func send_data)
{
    uint64 start_stat_time = 0;
    uint32 i;
    uint64 send_inst = 0;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    room->req_count = 0;
    room->ack_count = 0;
    room->succ_insts = 0;
    room->broadcast_flag = CM_TRUE;
    mes_get_consume_time_start(&start_stat_time);
    for (i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        if (MES_IS_INST_SEND(inst_bits, i)) {
            head->dst_inst = (uint8)i;
            if (send_data(head, head_size, body) != CM_SUCCESS) {
                continue;
            }
            (void)cm_atomic32_inc(&room->req_count);
            MES_INST_SENT_SUCCESS(send_inst, i);
            mes_send_stat(head->cmd);
        }
    }
    room->broadcast_flag = CM_FALSE;

    if (success_inst != NULL) {
        *success_inst = send_inst;
    }
    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return;
}

static inline int mes_broadcast2_send_data(mes_message_head_t *head, const void *body)
{
    return mes_send_data2(head, body);
}

void mes_broadcast2(unsigned int sid, uint64 inst_bits, mes_message_head_t *head, const void *body,
    uint64 *success_inst)
{
    mes_broadcast4(sid, inst_bits, head, body, success_inst, mes_broadcast2_send_data);
}

int mes_wait_acks(unsigned int sid, unsigned int timeout)
{
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];
    uint32 wait_time = 0;

    for (;;) {
        if (room->req_count == 0) {
            break;
        }

        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout) {
                room->ack_count = 0; // invalid broadcast ack
                mes_protect_when_brcast_timeout(room, 0);
                LOG_RUN_WAR("[mes]timeout rsn=%llu, check rsn=%llu, sid=%u, ack_count=%d, req_count=%d", room->rsn,
                    room->check_rsn, sid, room->ack_count, room->req_count);
                return ERR_MES_WAIT_OVERTIME;
            }
            continue;
        }

        if (room->ack_count >= room->req_count) {
            break;
        }
    }

    return CM_SUCCESS;
}

int mes_wait_acks2(unsigned int sid, unsigned int timeout, uint64 *succ_insts)
{
    uint32 wait_time = 0;
    int32  ret = CM_SUCCESS;

    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    for (;;) {
        if (room->req_count == 0) {
            break;
        }

        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout) {
                room->ack_count = 0; // invalid broadcast ack
                mes_protect_when_brcast_timeout(room, 0);
                LOG_RUN_WAR("[mes]timeout rsn=%llu, check rsn=%llu, sid=%d, ack_count=%d, req_count=%d", room->rsn,
                    room->check_rsn, sid, room->ack_count, room->req_count);
                ret = ERR_MES_WAIT_OVERTIME;
                break;
            }
            continue;
        }

        if (room->ack_count >= room->req_count) {
            break;
        }
    }
    if (succ_insts != NULL) {
        *succ_insts = room->succ_insts;
    }
    return ret;
}

int mes_broadcast_and_wait(unsigned int sid, uint64 inst_bits, const void *msg_data, unsigned int timeout,
    uint64 *success_inst)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_broadcast3(sid, inst_bits, msg_data, success_inst, mes_send_data);
    int ret = mes_wait_acks(sid, timeout);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]mes_wait_acks failed.");
        return ret;
    }

    mes_consume_with_time(((mes_message_head_t *)msg_data)->cmd, MES_TIME_TEST_MULTICAST_AND_WAIT, start_stat_time);
    return CM_SUCCESS;
}

int mes_wait_acks_and_recv_msg2(unsigned int sid, unsigned int timeout, uint64 success_inst,
    char *recv_msg[MES_MAX_INSTANCES], mes_wait_acks_overtime_proc_func overtime_proc_func)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];
    uint32 wait_time = 0;

    (void)memset_sp(recv_msg, sizeof(char *) * MES_MAX_INSTANCES, 0, sizeof(char *) * MES_MAX_INSTANCES);

    for (;;) {
        if (room->req_count == 0) {
            break;
        }

        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            wait_time += MES_WAIT_TIMEOUT;
            if (wait_time >= timeout) {
                overtime_proc_func(success_inst, recv_msg);
                mes_protect_when_brcast_timeout(room, success_inst);
                LOG_RUN_WAR("[mes]timeout rsn=%llu, check rsn=%llu, sid=%u, ack_count=%d, req_count=%d", room->rsn,
                    room->check_rsn, sid, room->ack_count, room->req_count);
                room->ack_count = 0; // invalid broadcast ack
                return ERR_MES_WAIT_OVERTIME;
            }
            continue;
        }

        if (room->ack_count >= room->req_count) {
            break;
        }
    }

    mes_copy_recv_broadcast_msg(room, success_inst, recv_msg);
    mes_consume_with_time(((mes_message_head_t *)recv_msg)->cmd, MES_TIME_TEST_WAIT_AND_RECV, start_stat_time);
    return CM_SUCCESS;
}

static inline void mes_wait_acks_overtime_proc(uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    return;
}

int mes_wait_acks_and_recv_msg(unsigned int sid, unsigned int timeout, uint64 success_inst,
    char *recv_msg[MES_MAX_INSTANCES])
{
    return mes_wait_acks_and_recv_msg2(sid, timeout, success_inst, recv_msg, mes_wait_acks_overtime_proc);
}

unsigned long long mes_get_current_rsn(unsigned int sid)
{
    uint64 rsn;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    rsn = room->rsn;
    cm_spin_unlock(&room->lock);

    return rsn;
}

void mes_init_ack_head(const mes_message_head_t *req_head, mes_message_head_t *ack_head, unsigned int cmd,
    unsigned short size, unsigned int src_sid)
{
    ack_head->version = 0;
    ack_head->cmd = cmd;
    ack_head->src_inst = req_head->dst_inst;
    ack_head->dst_inst = req_head->src_inst;
    ack_head->src_sid = (uint16)src_sid;
    ack_head->dst_sid = req_head->src_sid;
    ack_head->rsn = req_head->rsn;
    ack_head->size = size;
    ack_head->flags = 0;
    ack_head->cluster_ver = req_head->cluster_ver;
    ack_head->unused1 = 0;
    ack_head->tickets = 0;
    ack_head->unused2 = 0;
}

unsigned long long mes_get_rsn(unsigned int sid)
{
    uint64 rsn;
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];
    cm_spin_lock(&room->lock, NULL);
    rsn = (uint64)cm_atomic_inc((atomic_t *)(&room->rsn));
    cm_spin_unlock(&room->lock);
    return rsn;
}

void mes_set_command_task_group(unsigned char command, mes_task_group_id_t group_id)
{
    MES_GLOBAL_INST_MSG.mq_ctx.command_attr[command].group_id = group_id;
}

void mes_release_message_buf(mes_message_t *msg_buf)
{
    if (msg_buf == NULL || msg_buf->buffer == NULL) {
        return;
    }

    mes_free_buf_item((char *)msg_buf->buffer);
    return;
}

static void cm_get_time_of_day(cm_timeval *tv)
{
    (void)cm_gettimeofday(tv);
}

uint64 cm_get_time_usec(void)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        cm_timeval now;
        uint64 now_usec;
        cm_get_time_of_day(&now);
        now_usec = (uint64)now.tv_sec * MICROSECS_PER_SECOND + (uint64)now.tv_usec;
        return now_usec;
    }
    return 0;
}

uint64 mes_get_stat_send_count(unsigned int cmd)
{
    return (uint64)g_mes_stat.mes_commond_stat[cmd].send_count;
}

uint64 mes_get_stat_recv_count(unsigned int cmd)
{
    return (uint64)g_mes_stat.mes_commond_stat[cmd].recv_count;
}

volatile long mes_get_stat_occupy_buf(unsigned int cmd)
{
    return g_mes_stat.mes_commond_stat[cmd].occupy_buf;
}

unsigned char mes_get_elapsed_switch(void)
{
    return (bool8)g_mes_elapsed_stat.mes_elapsed_switch;
}

void mes_set_elapsed_switch(unsigned char elapsed_switch)
{
    g_mes_elapsed_stat.mes_elapsed_switch = elapsed_switch;
    g_mes_stat.mes_elapsed_switch = elapsed_switch;
}

uint64 mes_get_elapsed_time(unsigned int cmd, mes_time_stat_t type)
{
    return g_mes_elapsed_stat.time_consume_stat[cmd].time[type];
}

uint64 mes_get_elapsed_count(unsigned int cmd, mes_time_stat_t type)
{
    return (uint64)g_mes_elapsed_stat.time_consume_stat[cmd].count[type];
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

int mes_set_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        LOG_RUN_ERR("[mes] param_name is null");
        return CM_ERROR;
    }

    if (cm_str_equal(param_name, "SSL_PWD_PLAINTEXT") || cm_str_equal(param_name, "SSL_PWD_CIPHERTEXT")) {
        LOG_RUN_INF("[mes] set ssl param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_RUN_INF("[mes] set ssl param, param_name=%s param_value=%s", param_name, param_value);
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
    CM_RETURN_IFERR(md_get_param(CBB_PARAM_SSL_CERT_NOTIFY_TIME, &cert_notify));
    ssl_ca_cert_expire(MES_GLOBAL_INST_MSG.ssl_acceptor_fd, (int32)cert_notify.ssl_cert_notify_time);
    return CM_SUCCESS;
}

void* mes_get_global_inst(void)
{
    return &g_mes_ptr;
}

void mes_msg_end_wait(unsigned long long rsn, unsigned int sid)
{
    mes_waiting_room_t *room = &MES_GLOBAL_INST_MSG.mes_ctx.waiting_rooms[sid];
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == rsn && room->check_rsn != rsn) {
        room->rsn = (uint64)cm_atomic_inc((atomic_t *)(&room->rsn));
        room->msg_buf = NULL;
        room->check_rsn = rsn;
        mes_mutex_unlock(&room->mutex);
    }
    cm_spin_unlock(&room->lock);
}

unsigned int mes_get_max_watting_rooms(void)
{
    return CM_MAX_MES_ROOMS;
}

void mes_get_wait_event(unsigned int cmd, unsigned long long *event_cnt, unsigned long long *event_time)
{
    unsigned long long cnt = 0;
    unsigned long long time = 0;
    for (int type = 0; type < MES_TIME_CEIL; ++type) {
        cnt += g_mes_elapsed_stat.time_consume_stat[cmd].count[type];
        time += g_mes_elapsed_stat.time_consume_stat[cmd].time[type];
    }
    if (event_cnt != NULL) {
        *event_cnt = cnt;
    }
    if (event_time != NULL) {
        *event_time = time;
    }
}
