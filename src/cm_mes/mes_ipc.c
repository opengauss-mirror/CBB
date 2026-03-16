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
 * mes_ipc.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_ipc.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <string.h>
#include <errno.h>
#include "mes_ipc.h"
#include "cm_log.h"
#include "cm_memory.h"
#include "mes_func.h"
#include "mes_msg_pool.h"
#include "mes_queue.h"
#include "cm_thread.h"
#include "cm_epoll.h"

#define MES_IPC_MAGIC 0x4D455349
#define MES_IPC_VERSION 1

static mes_ipc_conn_t g_ipc_conns[MES_IPC_MAX_INSTANCES] = {0};
static int g_shm_id = -1;
static mes_ipc_shm_t *g_shm_ptr = NULL;
static int g_sem_id = -1;

static bool8 g_ipc_recv_running = CM_FALSE;
static thread_t g_ipc_recv_thread;
static int g_ipc_recv_epfd = -1;
static int g_ipc_recv_pipe[2] = {-1, -1};

static bool8 mes_ipc_queue_is_full(mes_ipc_queue_t *queue)
{
    return __atomic_load_n(&queue->size, __ATOMIC_ACQUIRE) >= queue->capacity;
}

static bool8 mes_ipc_queue_is_empty(mes_ipc_queue_t *queue)
{
    return __atomic_load_n(&queue->size, __ATOMIC_ACQUIRE) == 0;
}

static inline void mes_ipc_cpu_pause(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#else
    __sync_synchronize();
#endif
}

static inline void mes_ipc_spin_lock(volatile uint32_t *lock)
{
    while (__atomic_test_and_set(lock, __ATOMIC_ACQUIRE)) {
        mes_ipc_cpu_pause();
    }
}

static inline void mes_ipc_spin_unlock(volatile uint32_t *lock)
{
    __atomic_clear(lock, __ATOMIC_RELEASE);
}

static int mes_ipc_queue_push(mes_ipc_queue_t *queue, mes_ipc_msg_t *msg)
{
    if (mes_ipc_queue_is_full(queue)) {
        return CM_ERROR;
    }

    uint32_t tail = __atomic_load_n(&queue->tail, __ATOMIC_RELAXED);
    mes_ipc_msg_t *slot = &queue->messages[tail];
    slot->head = msg->head;
    slot->data_size = msg->data_size;
    if (msg->data_size > 0) {
        memcpy(slot->buffer, msg->buffer, msg->data_size);
    }
    __atomic_store_n(&queue->tail, (tail + 1) % queue->capacity, __ATOMIC_RELEASE);
    __atomic_fetch_add(&queue->size, 1, __ATOMIC_RELEASE);
    return CM_SUCCESS;
}

static int mes_ipc_queue_pop(mes_ipc_queue_t *queue, mes_ipc_msg_t *msg)
{
    if (mes_ipc_queue_is_empty(queue)) {
        return CM_ERROR;
    }

    uint32_t head = __atomic_load_n(&queue->head, __ATOMIC_RELAXED);
    mes_ipc_msg_t *slot = &queue->messages[head];
    msg->head = slot->head;
    msg->data_size = slot->data_size;
    if (slot->data_size > 0) {
        memcpy(msg->buffer, slot->buffer, slot->data_size);
    }
    __atomic_store_n(&queue->head, (head + 1) % queue->capacity, __ATOMIC_RELEASE);
    __atomic_fetch_sub(&queue->size, 1, __ATOMIC_RELEASE);
    return CM_SUCCESS;
}

static int mes_ipc_create_sem(key_t key, int *sem_id)
{
    *sem_id = semget(key, 1, IPC_CREAT | IPC_EXCL | 0666);
    if (*sem_id < 0) {
        if (errno == EEXIST) {
            *sem_id = semget(key, 1, 0666);
            if (*sem_id < 0) {
                LOG_RUN_ERR("[mes] semget failed, key=0x%x, errno=%d", key, errno);
                return CM_ERROR;
            }
            if (semctl(*sem_id, 0, SETVAL, 1) < 0) {
                LOG_RUN_ERR("[mes] semctl SETVAL failed for existing sem, sem_id=%d, errno=%d", *sem_id, errno);
                return CM_ERROR;
            }
        } else {
            LOG_RUN_ERR("[mes] semget failed, key=0x%x, errno=%d", key, errno);
            return CM_ERROR;
        }
    } else {
        if (semctl(*sem_id, 0, SETVAL, 1) < 0) {
            LOG_RUN_ERR("[mes] semctl SETVAL failed, sem_id=%d, errno=%d", *sem_id, errno);
            semctl(*sem_id, 0, IPC_RMID);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int mes_ipc_init_shm(void)
{
    if (g_shm_ptr != NULL) {
        return CM_SUCCESS;
    }

    key_t shm_key = MES_IPC_SHM_KEY_BASE;
    key_t sem_key = MES_IPC_SHM_KEY_BASE + 1;

    g_shm_id = shmget(shm_key, MES_IPC_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0666);
    if (g_shm_id < 0) {
        if (errno == EEXIST) {
            g_shm_id = shmget(shm_key, MES_IPC_SHM_SIZE, 0666);
            if (g_shm_id < 0) {
                LOG_RUN_ERR("[mes] shmget failed, key=0x%x, errno=%d", shm_key, errno);
                return CM_ERROR;
            }
        } else {
            LOG_RUN_ERR("[mes] shmget failed, key=0x%x, errno=%d", shm_key, errno);
            return CM_ERROR;
        }
    }

    g_shm_ptr = (mes_ipc_shm_t *)shmat(g_shm_id, NULL, 0);
    if (g_shm_ptr == (void *)-1) {
        LOG_RUN_ERR("[mes] shmat failed, shm_id=%d, errno=%d", g_shm_id, errno);
        shmctl(g_shm_id, IPC_RMID, NULL);
        g_shm_ptr = NULL;
        return CM_ERROR;
    }

    if (g_shm_ptr->magic != MES_IPC_MAGIC) {
        memset(g_shm_ptr, 0, MES_IPC_SHM_SIZE);
        g_shm_ptr->magic = MES_IPC_MAGIC;
        g_shm_ptr->version = MES_IPC_VERSION;
        g_shm_ptr->inst_count = 0;
    }
    
    for (uint32 i = 0; i < MES_IPC_MAX_INSTANCES; i++) {
        if (g_shm_ptr->queues[i].recv_queue.capacity == 0) {
            g_shm_ptr->queues[i].recv_queue.capacity = MES_IPC_MSG_QUEUE_SIZE;
            g_shm_ptr->queues[i].recv_queue.lock = 0;
            g_shm_ptr->queues[i].recv_queue.head = 0;
            g_shm_ptr->queues[i].recv_queue.tail = 0;
            g_shm_ptr->queues[i].recv_queue.size = 0;
        }
    }

    if (mes_ipc_create_sem(sem_key, &g_sem_id) != CM_SUCCESS) {
        shmdt(g_shm_ptr);
        g_shm_ptr = NULL;
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes] IPC shared memory initialized successfully");
    return CM_SUCCESS;
}

void mes_ipc_init_channels_param(uintptr_t channelPtr)
{
    mes_channel_t *channel = (mes_channel_t *)channelPtr;
    for (uint32 i = 0; i < MES_PRIORITY_CEIL; i++) {
        mes_pipe_t *pipe = &channel->pipe[i];
        (void)cm_rwlock_init(&pipe->send_lock);
        (void)cm_rwlock_init(&pipe->recv_lock);
        pipe->priority = i;
        pipe->channel = channel;
        pipe->send_pipe_active = CM_FALSE;
        pipe->recv_pipe_active = CM_FALSE;
        pipe->msgbuf = NULL;
    }

    LOG_DEBUG_INF("[mes] mes_ipc_init_channels_param, channel_id:%u, instance_id:%u",
                  MES_CHANNEL_ID(channel->id), MES_INSTANCE_ID(channel->id));
}

void mes_ipc_try_connect(uintptr_t pipePtr)
{
    mes_pipe_t *pipe = (mes_pipe_t *)pipePtr;
    if (pipe == NULL) {
        LOG_RUN_ERR("[mes] mes_ipc_try_connect: pipe is NULL");
        return;
    }

    inst_type inst_id = MES_INSTANCE_ID(pipe->channel->id);
    if (inst_id >= MES_IPC_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] mes_ipc_try_connect: invalid inst_id %u", inst_id);
        return;
    }

    mes_ipc_conn_t *conn = &g_ipc_conns[inst_id];
    if (conn->is_connected) {
        return;
    }

    if (g_shm_ptr == NULL) {
        LOG_RUN_ERR("[mes] IPC shared memory not initialized");
        return;
    }

    conn->shm_id = g_shm_id;
    conn->shm_ptr = g_shm_ptr;
    conn->sem_send_id = g_sem_id;
    conn->sem_recv_id = g_sem_id;
    conn->inst_id = inst_id;
    conn->is_connected = CM_TRUE;

    g_shm_ptr->queues[inst_id].connected = 1;

    pipe->send_pipe_active = CM_TRUE;
    pipe->recv_pipe_active = CM_TRUE;

    LOG_RUN_INF("[mes] IPC connect to instance %u success", inst_id);
}

void mes_ipc_heartbeat_channel(uintptr_t channelPtr)
{
    mes_channel_t *channel = (mes_channel_t *)channelPtr;
    if (channel == NULL) {
        return;
    }

    inst_type inst_id = MES_INSTANCE_ID(channel->id);
    if (inst_id >= MES_IPC_MAX_INSTANCES) {
        return;
    }

    mes_ipc_conn_t *conn = &g_ipc_conns[inst_id];
    if (!conn->is_connected) {
        mes_ipc_try_connect((uintptr_t)&channel->pipe[0]);
        return;
    }

    if (conn->shm_ptr != NULL) {
        conn->shm_ptr->queues[inst_id].connected = 1;
    }

    for (unsigned int priority = 0; priority < MES_GLOBAL_INST_MSG.profile.priority_cnt; priority++) {
        mes_pipe_t *pipe = &channel->pipe[priority];
        if (!pipe->send_pipe_active) {
            mes_ipc_try_connect((uintptr_t)pipe);
        }
    }
}

void mes_ipc_disconnect(uint32 inst_id, bool32 wait)
{
    if (inst_id >= MES_IPC_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] invalid inst_id %u", inst_id);
        return;
    }

    mes_ipc_conn_t *conn = &g_ipc_conns[inst_id];
    if (!conn->is_connected) {
        return;
    }

    conn->is_connected = CM_FALSE;
    if (conn->shm_ptr != NULL) {
        conn->shm_ptr->queues[inst_id].connected = 0;
    }

    LOG_RUN_INF("[mes] IPC disconnect from instance %u success", inst_id);
}

int mes_ipc_send_data(const void *msg_data)
{
    if (msg_data == NULL) {
        LOG_RUN_ERR("[mes] mes_ipc_send_data: msg_data is NULL");
        return CM_ERROR;
    }

    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    inst_type dst_inst = head->dst_inst;

    if (dst_inst >= MES_IPC_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] mes_ipc_send_data: invalid dst_inst %u", dst_inst);
        return CM_ERROR;
    }

    mes_ipc_conn_t *conn = &g_ipc_conns[dst_inst];
    if (!conn->is_connected) {
        LOG_RUN_ERR("[mes] IPC not connected to instance %u", dst_inst);
        return CM_ERROR;
    }

    if (head->size > MES_IPC_MAX_MSG_SIZE) {
        LOG_RUN_ERR("[mes] message size %u exceeds max size %u", head->size, MES_IPC_MAX_MSG_SIZE);
        return CM_ERROR;
    }

    mes_ipc_msg_t msg;
    memcpy(&msg.head, head, sizeof(mes_message_head_t));
    if (head->size > sizeof(mes_message_head_t)) {
        uint32 data_size = head->size - sizeof(mes_message_head_t);
        memcpy(msg.buffer, (const char *)msg_data + sizeof(mes_message_head_t), data_size);
    }

    mes_ipc_queue_t *recv_queue = &conn->shm_ptr->queues[dst_inst].recv_queue;
    
    int ret = mes_ipc_queue_push(recv_queue, &msg);

    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] queue push failed, queue full");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int mes_ipc_send_bufflist(mes_bufflist_t *buff_list)
{
    if (buff_list == NULL || buff_list->cnt == 0) {
        LOG_RUN_ERR("[mes] mes_ipc_send_bufflist: invalid buff_list");
        return CM_ERROR;
    }

    mes_message_head_t *head = (mes_message_head_t *)buff_list->buffers[0].buf;
    inst_type dst_inst = head->dst_inst;

    if (dst_inst >= MES_IPC_MAX_INSTANCES) {
        LOG_RUN_ERR("[mes] mes_ipc_send_bufflist: invalid dst_inst %u", dst_inst);
        return CM_ERROR;
    }

    mes_ipc_conn_t *conn = &g_ipc_conns[dst_inst];
    if (!conn->is_connected) {
        LOG_RUN_ERR("[mes] IPC not connected to instance %u", dst_inst);
        return CM_ERROR;
    }

    uint32_t total_size = 0;
    for (int i = 0; i < buff_list->cnt; i++) {
        total_size += buff_list->buffers[i].len;
    }

    if (total_size > MES_IPC_MAX_MSG_SIZE) {
        LOG_RUN_ERR("[mes] total message size %u exceeds max size %u", total_size, MES_IPC_MAX_MSG_SIZE);
        return CM_ERROR;
    }

    mes_ipc_msg_t msg;
    msg.head.size = total_size;
    msg.head.cmd = head->cmd;
    msg.head.app_cmd = head->app_cmd;
    msg.head.flags = head->flags;
    msg.head.src_inst = head->src_inst;
    msg.head.dst_inst = head->dst_inst;
    msg.head.ruid = head->ruid;
    msg.head.version = head->version;
    msg.head.caller_tid = head->caller_tid;
    
    uint32_t offset = 0;
    for (int i = 0; i < buff_list->cnt; i++) {
        if (i == 0) {
            uint32_t data_size = buff_list->buffers[i].len - sizeof(mes_message_head_t);
            if (data_size > 0) {
                memcpy(msg.buffer, buff_list->buffers[i].buf + sizeof(mes_message_head_t), data_size);
                offset = data_size;
            }
        } else {
            memcpy(msg.buffer + offset, buff_list->buffers[i].buf, buff_list->buffers[i].len);
            offset += buff_list->buffers[i].len;
        }
    }
    msg.data_size = offset;

    mes_ipc_queue_t *recv_queue = &conn->shm_ptr->queues[dst_inst].recv_queue;
    
    mes_ipc_spin_lock(&recv_queue->lock);
    int ret = mes_ipc_queue_push(recv_queue, &msg);
    mes_ipc_spin_unlock(&recv_queue->lock);

    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] queue push failed, queue full");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

mes_msgitem_t *mes_ipc_alloc_msgitem(mes_msgqueue_t *queue, bool32 is_send)
{
    return mes_alloc_msgitem(queue, is_send);
}

void mes_ipc_cleanup(void)
{
    if (g_shm_ptr != NULL) {
        shmdt(g_shm_ptr);
        g_shm_ptr = NULL;
    }

    if (g_sem_id != -1) {
        semctl(g_sem_id, 0, IPC_RMID);
        g_sem_id = -1;
    }

    if (g_shm_id != -1) {
        shmctl(g_shm_id, IPC_RMID, NULL);
        g_shm_id = -1;
    }

    LOG_RUN_INF("[mes] IPC shared memory cleaned up successfully");
}

static void mes_ipc_recv_thread_entry(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    cm_block_sighup_signal();

    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_ipc_recv"));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
    }

    uint32 idle_count = 0;
    const uint32 spin_poll_threshold = 100;
    const uint32 yield_poll_threshold = 1000;
    mes_ipc_msg_t *batch_msgs = (mes_ipc_msg_t *)malloc(MES_IPC_BATCH_SIZE * sizeof(mes_ipc_msg_t));
    if (batch_msgs == NULL) {
        LOG_RUN_ERR("[mes] Failed to allocate batch_msgs buffer");
        return;
    }

    while (!thread->closed && g_ipc_recv_running) {
        uint32 total_processed = 0;
        uint64_t iter_start = cm_get_time_usec();

        for (uint32 inst_id = 0; inst_id < MES_IPC_MAX_INSTANCES; inst_id++) {
            mes_ipc_conn_t *conn = &g_ipc_conns[inst_id];
            if (!conn->is_connected || conn->shm_ptr == NULL) {
                continue;
            }

            mes_ipc_queue_t *recv_queue = &conn->shm_ptr->queues[inst_id].recv_queue;
            
            while (!mes_ipc_queue_is_empty(recv_queue)) {
                uint32 batch_count = 0;
                
                while (batch_count < MES_IPC_BATCH_SIZE && 
                       !mes_ipc_queue_is_empty(recv_queue)) {
                    if (mes_ipc_queue_pop(recv_queue, &batch_msgs[batch_count]) != CM_SUCCESS) {
                        break;
                    }
                    batch_count++;
                }

                for (uint32 i = 0; i < batch_count; i++) {
                    mes_ipc_msg_t *ipc_msg = &batch_msgs[i];
                    mes_message_head_t *head = &ipc_msg->head;

                    if (SECUREC_UNLIKELY(head->size < sizeof(mes_message_head_t) ||
                        head->size > MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile))) {
                        LOG_RUN_ERR("[mes] IPC received invalid message size %u", head->size);
                        continue;
                    }

                    if (SECUREC_UNLIKELY(MES_PRIORITY(head->flags) >= MES_PRIORITY_CEIL)) {
                        LOG_RUN_ERR("[mes] IPC received invalid priority %u", MES_PRIORITY(head->flags));
                        continue;
                    }

                    char *buffer = mes_alloc_buf_item(head->size, CM_FALSE, head->src_inst, MES_PRIORITY(head->flags));
                    if (buffer == NULL) {
                        LOG_RUN_ERR("[mes] IPC failed to allocate buffer for message size %u", head->size);
                        continue;
                    }

                    mes_message_t msg;
                    MES_MESSAGE_ATTACH(&msg, buffer);

                    errno_t err = memcpy_s(msg.buffer, head->size, head, sizeof(mes_message_head_t));
                    if (err != EOK) {
                        mes_free_buf_item(buffer);
                        LOG_RUN_ERR("[mes] memcpy_s failed for message head");
                        continue;
                    }

                    if (head->size > sizeof(mes_message_head_t)) {
                        uint32_t body_size = head->size - sizeof(mes_message_head_t);
                        if (ipc_msg->data_size < body_size) {
                            body_size = ipc_msg->data_size;
                        }
                        err = memcpy_s(msg.buffer + sizeof(mes_message_head_t),
                                       body_size,
                                       ipc_msg->buffer,
                                       body_size);
                        if (err != EOK) {
                            mes_free_buf_item(buffer);
                            LOG_RUN_ERR("[mes] memcpy_s failed for message body");
                            continue;
                        }
                    }

                    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
                    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
                    mes_msgqueue_t *my_queue = &mq_ctx->channel_private_queue[head->src_inst][channel_id];
                    mes_process_message(my_queue, &msg);
                }
                
                total_processed += batch_count;
            }
        }

        uint64_t iter_time = cm_get_time_usec() - iter_start;
        if (total_processed > 0 && iter_time > 100) {
            LOG_RUN_INF("[mes] IPC recv perf: processed=%u, total_time=%lu us", total_processed, iter_time);
        }
        if (total_processed > 0) {
            idle_count = 0;
        } else {
            idle_count++;
            if (idle_count < spin_poll_threshold) {
                mes_ipc_cpu_pause();
                continue;
            } else if (idle_count < yield_poll_threshold) {
                struct epoll_event events[1];
                epoll_wait(g_ipc_recv_epfd, events, 1, 0);
                sched_yield();
            } else {
                struct epoll_event events[1];
                epoll_wait(g_ipc_recv_epfd, events, 1, 1);
            }
        }
    }

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) {
        cb_thread_deinit();
    }
    free(batch_msgs);
}

int mes_ipc_start_receivers(void)
{
    if (g_ipc_recv_running) {
        LOG_RUN_INF("[mes] IPC receivers already running");
        return CM_SUCCESS;
    }

    g_ipc_recv_epfd = epoll_create(1);
    if (g_ipc_recv_epfd < 0) {
        LOG_RUN_ERR("[mes] epoll_create failed: errno=%d", errno);
        return CM_ERROR;
    }

    if (pipe(g_ipc_recv_pipe) < 0) {
        LOG_RUN_ERR("[mes] pipe failed: errno=%d", errno);
        epoll_close(g_ipc_recv_epfd);
        g_ipc_recv_epfd = -1;
        return CM_ERROR;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = g_ipc_recv_pipe[0];
    if (epoll_ctl(g_ipc_recv_epfd, EPOLL_CTL_ADD, g_ipc_recv_pipe[0], &ev) < 0) {
        LOG_RUN_ERR("[mes] epoll_ctl failed: errno=%d", errno);
        close(g_ipc_recv_pipe[0]);
        close(g_ipc_recv_pipe[1]);
        g_ipc_recv_pipe[0] = -1;
        g_ipc_recv_pipe[1] = -1;
        epoll_close(g_ipc_recv_epfd);
        g_ipc_recv_epfd = -1;
        return CM_ERROR;
    }

    g_ipc_recv_running = CM_TRUE;

    int ret = cm_create_thread(mes_ipc_recv_thread_entry, 0, NULL, &g_ipc_recv_thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] failed to create IPC receiver thread");
        g_ipc_recv_running = CM_FALSE;
        close(g_ipc_recv_pipe[0]);
        close(g_ipc_recv_pipe[1]);
        g_ipc_recv_pipe[0] = -1;
        g_ipc_recv_pipe[1] = -1;
        epoll_close(g_ipc_recv_epfd);
        g_ipc_recv_epfd = -1;
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes] IPC receivers started successfully");
    return CM_SUCCESS;
}

void mes_ipc_stop_receivers(void)
{
    if (!g_ipc_recv_running) {
        return;
    }

    g_ipc_recv_running = CM_FALSE;

    if (g_ipc_recv_pipe[1] >= 0) {
        write(g_ipc_recv_pipe[1], "x", 1);
    }

    cm_close_thread(&g_ipc_recv_thread);

    if (g_ipc_recv_pipe[0] >= 0) {
        close(g_ipc_recv_pipe[0]);
        g_ipc_recv_pipe[0] = -1;
    }
    if (g_ipc_recv_pipe[1] >= 0) {
        close(g_ipc_recv_pipe[1]);
        g_ipc_recv_pipe[1] = -1;
    }

    if (g_ipc_recv_epfd >= 0) {
        epoll_close(g_ipc_recv_epfd);
        g_ipc_recv_epfd = -1;
    }

    LOG_RUN_INF("[mes] IPC receivers stopped");
}

int mes_ipc_recv_message(mes_message_t *msg)
{
    if (msg == NULL) {
        return CM_ERROR;
    }

    for (uint32 inst_id = 0; inst_id < MES_IPC_MAX_INSTANCES; inst_id++) {
        mes_ipc_conn_t *conn = &g_ipc_conns[inst_id];
        if (!conn->is_connected || conn->shm_ptr == NULL) {
            continue;
        }

        mes_ipc_queue_t *recv_queue = &conn->shm_ptr->queues[inst_id].recv_queue;
        if (!mes_ipc_queue_is_empty(recv_queue)) {
            mes_ipc_msg_t ipc_msg;
            if (mes_ipc_queue_pop(recv_queue, &ipc_msg) == CM_SUCCESS) {
                mes_message_head_t *head = &ipc_msg.head;

                char *buffer = mes_alloc_buf_item(head->size, CM_FALSE, head->src_inst, MES_PRIORITY(head->flags));
                if (buffer == NULL) {
                    return CM_ERROR;
                }

                MES_MESSAGE_ATTACH(msg, buffer);
                memcpy(msg->buffer, head, sizeof(mes_message_head_t));
                if (head->size > sizeof(mes_message_head_t)) {
                    memcpy(msg->buffer + sizeof(mes_message_head_t), ipc_msg.buffer,
                           head->size - sizeof(mes_message_head_t));
                }
                return CM_SUCCESS;
            }
        }
    }

    return CM_ERROR;
}

int mes_ipc_add_recv_pipe_to_epoll(uint16 channel_id, mes_priority_t priority, uint32 version)
{
    (void)channel_id;
    (void)priority;
    (void)version;
    return CM_SUCCESS;
}

int mes_ipc_remove_recv_pipe_from_epoll(mes_priority_t priority, uint32 channel_id)
{
    (void)priority;
    (void)channel_id;
    return CM_SUCCESS;
}
int mes_init_ipc_resource(void)
{
    int ret;

    ret = mes_alloc_channels();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_alloc_channels failed.");
        return ret;
    }

    ret = mes_ipc_init_shm();
    if (ret != CM_SUCCESS) {
        mes_free_channels();
        LOG_RUN_ERR("[mes] IPC init shared memory failed, ret=%d", ret);
        return ret;
    }

    ret = mes_alloc_channel_msg_queue(CM_TRUE);
    if (ret != CM_SUCCESS) {
        mes_ipc_cleanup();
        mes_free_channels();
        LOG_RUN_ERR("[mes] IPC alloc send channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_alloc_channel_msg_queue(CM_FALSE);
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_ipc_cleanup();
        mes_free_channels();
        LOG_RUN_ERR("[mes] IPC alloc recv channel mesqueue failed.");
        return CM_ERROR;
    }

    LOG_RUN_INF("[mes] IPC resource initialized successfully");
    return CM_SUCCESS;
}
