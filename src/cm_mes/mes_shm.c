/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of the Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * mes_shm.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_shm_dl.h"
#include "mes_shm.h"
#include "mes_shm_dl.h"
#include "mes_shm_ring_buf.h"
#include "cm_thread.h"
#include "cm_memory.h"
#include "cm_sync.h"
#include "mes_recv.h"
#include "mes_func.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Shared memory receive thread polling thresholds */
static const uint32 SHM_RECV_SPIN_POLL_THRESHOLD = 10;     // Spin poll threshold for low idle
static const uint32 SHM_RECV_YIELD_POLL_THRESHOLD = 200;   // Yield CPU threshold for medium idle

/* Minimum shared memory size: 1MB */
#define MES_SHM_SIZE_B_MIN (1ULL * 1024 * 1024)

static char g_region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
static char g_shm_name[MAX_SHM_NAME_LENGTH] = {0};
static uint64_t g_shm_size = 0;

// Helper function to calculate shared memory parameters
static uint64_t mes_calculate_shm_params(uint32 priority_cnt, uint64_t *entry_size_out, uint64_t *entry_num_out)
{
    uint64_t entry_size = (uint64_t)MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
    uint64_t entry_num = 1024;
    
    // Calculate single ring buffer size with cacheline alignment
    uint64_t ring_hdr_sz = (sizeof(MPSCRingBuffer) + CACHELINE_SIZE - 1) & ~(CACHELINE_SIZE - 1);
    uint64_t entry_total_sz = sizeof(mpsc_entry_t) + entry_size;
    uint64_t single_ring_size = ring_hdr_sz + entry_num * entry_total_sz;
    
    // Output parameters
    if (entry_size_out) *entry_size_out = entry_size;
    if (entry_num_out) *entry_num_out = entry_num;
    
    return single_ring_size;
}

// Helper function to initialize all ring buffers in shared memory
static void mes_init_shm_ring_buffers(shm_rpc_lsnr_t *shm_lsnr, void *base_ptr, uint32 prio_cnt, 
                                     uint64_t ring_sz, uint64_t entry_size, uint64_t entry_num, int self_id)
{
    for (uint32 prio = 0; prio < prio_cnt; prio++) {
        MPSCRingBuffer *ring = (MPSCRingBuffer *)((char *)base_ptr + prio * ring_sz);
        shm_lsnr->peer_ring[prio][self_id] = ring;
        MPSCRingBuffer_init(ring, entry_size, entry_num);
        LOG_RUN_INF("[mes] initialized ring buffer for instance %u priority %u", self_id, prio);
    }
}

// Helper function to map a single peer's shared memory
static int mes_shm_map_single_peer(inst_type peer_id)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    
    // Skip self
    if (peer_id == self_id) {
        return CM_SUCCESS;
    }
    
    // Calculate shared memory parameters
    uint64_t entry_size, entry_num;
    uint64_t single_ring_size = mes_calculate_shm_params(MES_GLOBAL_INST_MSG.profile.priority_cnt, &entry_size, &entry_num);
    
    // Map the single shared memory block for this peer
    char peer_shm_name[MAX_SHM_NAME_LENGTH] = {0};
    int ret = sprintf_s(peer_shm_name, sizeof(peer_shm_name), "shm_mes_%llu", peer_id);
    if (ret <= EOK) {
        LOG_RUN_ERR("Failed to format peer shm name for instance %u.", peer_id);
        return CM_ERROR;
    }

    // Only map once per peer - check if priority 0 ring buffer is already mapped
    if (shm_lsnr->peer_ring[0][peer_id] == NULL) {
        void *base_ptr = NULL;
        
        // Retry mechanism for shared memory mapping - retry forever until found or error
        const int RETRY_DELAY_MS = 1000;  // 1 second retry interval
        
        while (true) {
            ret = ubsmem_shmem_map(NULL, g_shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, 
                peer_shm_name, 0, &base_ptr);
            
            if (ret == UBSM_OK) {
                break;  // Success, exit retry loop
            } else if (ret == UBSM_ERR_NOT_FOUND) {
                // Shared memory doesn't exist yet, retry indefinitely
                LOG_RUN_INF("[mes] peer %u shm not found, retrying...", peer_id);
                cm_usleep(RETRY_DELAY_MS * 1000);  // Convert to microseconds
            } else {
                // Other error, return immediately
                LOG_RUN_ERR("[mes] failed to map peer %u shm, err = %d.", peer_id, ret);
                return CM_ERROR;
            }
        }
        
        // Store the base address in priority 0 ring buffer pointer
        shm_lsnr->peer_ring[0][peer_id] = base_ptr;
        LOG_RUN_INF("[mes] mapped peer shared memory for instance %u", peer_id);
    } else {
        LOG_RUN_INF("[mes] peer %u shared memory already mapped", peer_id);
    }
    
    // Calculate and store pointers for all priorities in this peer's shared memory
    void *base_ptr = shm_lsnr->peer_ring[0][peer_id];
    for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
        // Calculate offset for this priority's ring buffer
        uint64_t offset = prio * single_ring_size;
        MPSCRingBuffer *ring = (MPSCRingBuffer *)((char *)base_ptr + offset);
        
        // Store the pointer to this priority's ring buffer
        shm_lsnr->peer_ring[prio][peer_id] = ring;
        
        LOG_RUN_INF("[mes] mapped peer ring buffer for instance %u priority %u at offset %lu",
                   peer_id, prio, (unsigned long)offset);
    }
    
    return CM_SUCCESS;
}

// Internal function to initialize shared memory
static int mes_init_shm(void)
{
    int ret = CM_ERROR;
    char *host_name = cm_sys_host_name();
    int self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    shm_rpc_lsnr_t* shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    ubsmem_regions_t regions;
    ubsmem_region_attributes_t region;
    ubsmem_options_t ubsm_shmem_opts;

    ret = ubsmem_init_attributes(&ubsm_shmem_opts);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("Failed to initialize ubsmem attributes, error: %d.", ret);
        return CM_ERROR;
    }

    ret =ubsmem_initialize(&ubsm_shmem_opts);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("Failed to initialize ubsmem, error: %d.", ret);
        return CM_ERROR;
    }

    ret = ubsmem_lookup_regions(&regions);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("Failed to lookup shm regions, error: %d.", ret);
        return CM_ERROR;
    }

    region = regions.region[0];
    for (int i = 1; i < region.host_num; i++) {
        region.hosts[i].affinity = (strcmp(region.hosts[i].host_name, host_name) == 0);
    }

    char region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    ret = sprintf_s(region_name, sizeof(region_name), "region_mes_%llu", self_id);
    if (ret <= EOK) {
        LOG_RUN_ERR("Failed to format shm region name.");
        return CM_ERROR;
    }

    ret = ubsmem_create_region(region_name, 0, &region);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("Failed to create shm region %s, error: %d.", region_name, ret);
        return CM_ERROR;
    }

    (void)strncpy_s(g_region_name, sizeof(g_region_name), region_name, sizeof(region_name) - 1);

    // Simplified calculations using helper function
    uint32 priority_cnt = MES_GLOBAL_INST_MSG.profile.priority_cnt;
    uint64_t entry_size, entry_num;
    uint64_t single_ring_size = mes_calculate_shm_params(priority_cnt, &entry_size, &entry_num);
    
    // Calculate total shared memory size with minimum size alignment
    uint64_t total_needed = priority_cnt * single_ring_size;
    uint64_t shm_size = (total_needed + MES_SHM_SIZE_B_MIN - 1) & ~((uint64_t)MES_SHM_SIZE_B_MIN - 1);
    shm_size = shm_size ? shm_size : MES_SHM_SIZE_B_MIN;
    g_shm_size = shm_size;

    char shm_name[MAX_SHM_NAME_LENGTH] = {0};
    ret = sprintf_s(shm_name, sizeof(shm_name), "shm_mes_%llu", self_id);
    if (ret <= EOK) {
        LOG_RUN_ERR("mes_init_shm: Failed to format shm name.");
        return CM_ERROR;
    }

    ret = ubsmem_shmem_allocate(region_name, shm_name, shm_size, 0600,
        UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("mes_init_shm: Failed to allocate shm %s, error: %d.", shm_name, ret);
        return CM_ERROR;
    }
    
    (void)strncpy_s(g_shm_name, sizeof(g_shm_name), shm_name, sizeof(shm_name) - 1);

    void *base_ptr = NULL;
    ret = ubsmem_shmem_map(NULL, g_shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_name, 0, &base_ptr);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("[mes] failed to map self shm, err = %d.", ret);
        return CM_ERROR;
    }

    // Initialize all ring buffers using helper function
    mes_init_shm_ring_buffers(shm_lsnr, base_ptr, priority_cnt, single_ring_size, entry_size, entry_num, self_id);
    
    return CM_SUCCESS;
}

// Public API: Map all peer shared memories
int mes_shm_map_peers(void)
{
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    bool all_mapped = false;
    int ret;
    
    while (!all_mapped) {
        all_mapped = true;
        for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
            inst_type peer_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
            
            // Skip self
            if (peer_id == self_id) {
                continue;
            }
            
            // Try to map this peer
            ret = mes_shm_map_single_peer(peer_id);
            if (ret != CM_SUCCESS) {
                LOG_RUN_INF("[mes] waiting for instance %u shm to be created...", peer_id);
                all_mapped = false;
                continue;
            }
            
            // Verify all priorities are mapped
            shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
            for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
                if (shm_lsnr->peer_ring[prio][peer_id] == NULL) {
                    LOG_RUN_INF("[mes] peer %u priority %u ring buffer not mapped yet", peer_id, prio);
                    all_mapped = false;
                    break;
                }
            }
        }
        
        if (!all_mapped) {
            cm_sleep(1000);
        }
    }
    
    return CM_SUCCESS;
}

// Public API: Try to establish shared memory connection
void mes_shm_try_connect(uintptr_t pipePtr)
{
    mes_pipe_t *pipe = (mes_pipe_t *)pipePtr;

    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    inst_type peer_id = MES_INSTANCE_ID(pipe->channel->id);
    
    if (peer_id >= MAX_HOST_NUM) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: invalid peer_id %u", peer_id);
        return;
    }

    // Check if self shared memory is initialized
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    uint32 prio_count = MES_GLOBAL_INST_MSG.profile.priority_cnt;
    bool has_valid_self_ring = true;
    
    for (uint32 prio = 0; prio < prio_count; prio++) {
        if (shm_lsnr->peer_ring[prio][self_id] == NULL) {
            has_valid_self_ring = false;
            break;
        }
    }
    
    if (!has_valid_self_ring) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: self shared memory not properly initialized");
        return;
    }

    // Check if peer shared memory is mapped for all priorities
    bool has_valid_peer_ring = true;
    for (uint32 prio = 0; prio < prio_count; prio++) {
        if (shm_lsnr->peer_ring[prio][peer_id] == NULL) {
            has_valid_peer_ring = false;
            break;
        }
    }
    
    if (!has_valid_peer_ring) {
        LOG_RUN_INF("[mes] mes_shm_try_connect: peer %u shared memory not fully mapped yet, attempting to remap", peer_id);
        
        // Try to remap the peer's shared memory
        int ret = mes_shm_map_single_peer(peer_id);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] mes_shm_try_connect: failed to remap peer %u shared memory", peer_id);
            // Still mark pipe as active - will retry in next heartbeat
        } else {
            LOG_RUN_INF("[mes] mes_shm_try_connect: successfully remapped peer %u shared memory", peer_id);
        }
    }

    // Always set pipe active flags for SHM mode
    pipe->send_pipe_active = CM_TRUE;
    pipe->recv_pipe_active = CM_TRUE;
    
    LOG_RUN_INF("[mes] SHM pipe to instance %u marked as active", peer_id);
}

// Public API: Send heartbeat for shared memory channel
void mes_shm_heartbeat_channel(uintptr_t channelPtr)
{
    mes_channel_t *channel = (mes_channel_t *)channelPtr;
    if (channel == NULL) {
        return;
    }

    inst_type peer_id = MES_INSTANCE_ID(channel->id);
    if (peer_id >= MAX_HOST_NUM) {
        return;
    }

    for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
        mes_pipe_t *pipe = &channel->pipe[prio];
        if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
            return;
        }
        if (!pipe->send_pipe_active) {
            mes_shm_try_connect((uintptr_t)pipe);
        } else {
            mes_heartbeat(pipe);
            if (!pipe->send_pipe_active) {
                mes_shm_try_connect((uintptr_t)pipe);
            }
        }
    }
    
    LOG_RUN_INF("[mes] SHM heartbeat completed for instance %u", peer_id);
}

// Public API: Send data via shared memory
int mes_shm_send_data(const void *msg_data)
{
    if (msg_data == NULL) {
        LOG_RUN_ERR("[mes_shm] send_data: msg_data is NULL");
        return CM_ERROR;
    }

    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    inst_type dst_inst = head->dst_inst;
    mes_priority_t prio = MES_PRIORITY(head->flags);
    
    if (dst_inst >= MAX_HOST_NUM) {
        LOG_RUN_ERR("[mes_shm] send_data: invalid dst_inst %u", dst_inst);
        return CM_ERROR;
    }

    if (prio >= MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[mes_shm] send_data: invalid priority %u", prio);
        return CM_ERROR;
    }

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    MPSCRingBuffer *peer_ring = (MPSCRingBuffer *)shm_lsnr->peer_ring[prio][dst_inst];
    
    if (peer_ring == NULL) {
        LOG_RUN_ERR("[mes_shm] send_data: peer_ring[%u][%u] not mapped", prio, dst_inst);
        return CM_ERROR;
    }

    uint64_t sent = MPSCRingBuffer_send(peer_ring, (const char *)msg_data, head->size, 1000);
    if (sent == 0) {
        LOG_RUN_ERR("[mes_shm] send_data: failed to send to inst %u prio %u, size %u", dst_inst, prio, head->size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// Public API: Send buffer list via shared memory
int mes_shm_send_bufflist(mes_bufflist_t *buff_list)
{
    if (buff_list == NULL || buff_list->cnt == 0) {
        LOG_RUN_ERR("[mes_shm] send_bufflist: invalid buff_list");
        return CM_ERROR;
    }

    mes_message_head_t *head = (mes_message_head_t *)buff_list->buffers[0].buf;
    uint32 total_size = 0;
    for (int i = 0; i < buff_list->cnt; i++) {
        total_size += buff_list->buffers[i].len;
    }

    head->size = total_size;
    char *buf = (char *)cm_malloc_prot(total_size);
    if (buf == NULL) {
        LOG_RUN_ERR("[mes_shm] send_bufflist: alloc failed");
        return CM_ERROR;
    }

    uint32 offset = 0;
    for (int i = 0; i < buff_list->cnt; i++) {
        if (memcpy_sp(buf + offset, buff_list->buffers[i].len, buff_list->buffers[i].buf, 
            buff_list->buffers[i].len) != EOK) {
            CM_FREE_PROT_PTR(buf);
            LOG_RUN_ERR("[mes_shm] send_bufflist: memcpy failed");
            return CM_ERROR;
        }
        offset += buff_list->buffers[i].len;
    }

    int ret = mes_shm_send_data(buf);
    CM_FREE_PROT_PTR(buf);
    return ret;
}

// Internal function: Shared memory receive thread entry
void mes_shm_recv_proc(thread_t *thread)
{
    receiver_t *receiver = (receiver_t *)thread->argument;
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    cm_block_sighup_signal();
    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_shm_recv_%u_%u", receiver->priority,
        receiver->id));
    cm_set_thread_name(thread_name);

    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (cb_thread_init != NULL) {
        cb_thread_init(CM_FALSE, (char **)&thread->reg_data);
        LOG_DEBUG_INF("[mes]: mes_shm_recv_proc thread init done");
    }

    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    mes_priority_t prio = receiver->priority;
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    MPSCRingBuffer *ring = (MPSCRingBuffer *)shm_lsnr->peer_ring[prio][self_id];

    uint64_t max_msg_size = MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
    char *local_buf = (char *)cm_malloc_prot((size_t)max_msg_size);
    if (local_buf == NULL) {
        LOG_RUN_ERR("[mes_shm] alloc local buf failed");
        return;
    }

    uint32 idle_count = 0;
    
    while (!thread->closed) {
        uint64_t got = MPSCRingBuffer_recv(ring, local_buf, max_msg_size);
        if (got > 0) {
            idle_count = 0; // 重置空闲计数
            
            mes_message_head_t *head = (mes_message_head_t *)local_buf;
            if (head->size < sizeof(mes_message_head_t) || head->size > max_msg_size) {
                LOG_RUN_ERR("[mes_shm recv] invalid head size %u", head->size);
                continue;
            }

            if (head->cmd == MES_CMD_HEARTBEAT) {
                continue;
            }

            char *data = mes_alloc_buf_item_fc(head->size, CM_FALSE, head->src_inst, prio);
            if (SECUREC_UNLIKELY(data == NULL)) {
                LOG_RUN_ERR("[mes_shm recv] alloc buf item failed size(%u)", head->size);
                continue;
            }
            if (memcpy_sp((void *)data, head->size, local_buf, head->size) != EOK) {
                LOG_RUN_ERR("[mes_shm recv] memcpy_sp failed");
                mes_free_buf_item(data);
                continue;
            }

            mes_message_t mes_msg;
            MES_MESSAGE_ATTACH((&mes_msg), (void *)data);
            uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
            mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
            mes_msgqueue_t *my_mq = &mq_ctx->channel_private_queue[head->src_inst][channel_id];
            mes_process_message(my_mq, &mes_msg);
        } else {
            idle_count++;
            if (idle_count < SHM_RECV_SPIN_POLL_THRESHOLD) {
                // 低空闲：短时间忙等待，保持低延迟
                fas_cpu_pause(); // 类似于CPU pause指令，减少CPU消耗
            } else if (idle_count < SHM_RECV_YIELD_POLL_THRESHOLD) {
                // 中空闲：让出CPU给其他线程
                sched_yield();
            }
        }
    }

    CM_FREE_PROT_PTR(local_buf);

    mes_thread_deinit_t cb_thread_deinit = mes_get_worker_deinit_cb();
    if (cb_thread_deinit != NULL) cb_thread_deinit();
}

// Disconnect handle for callback function
void mes_shm_disconnect_handle(uint32 inst_id, bool32 wait)
{
    LOG_RUN_INF("mes_shm_disconnect_handle start, inst_id(%u)", inst_id);
    
    if (inst_id >= MAX_HOST_NUM) {
        LOG_RUN_ERR("[mes_shm] invalid inst_id %u", inst_id);
        return;
    }

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    
    // Skip self disconnect
    if (inst_id == self_id) {
        LOG_RUN_ERR("[mes_shm] cannot disconnect from self instance %u", inst_id);
        return;
    }

    // Check if peer is actually mapped
    bool is_mapped = false;
    if (shm_lsnr->peer_ring[0][inst_id] != NULL) {
        is_mapped = true;
    }
    
    if (!is_mapped) {
        LOG_RUN_INF("[mes_shm] peer instance %u is not mapped, no need to disconnect", inst_id);
        return;
    }

    // Store base address for unmap
    void *base_ptr = shm_lsnr->peer_ring[0][inst_id];

    // Clear all priority ring buffer pointers for this peer
    for (uint32 prio = 0; prio < MES_PRIORITY_CEIL; prio++) {
        shm_lsnr->peer_ring[prio][inst_id] = NULL;
    }

    // Unmap the peer's shared memory
    int ret = ubsmem_shmem_unmap(base_ptr, g_shm_size);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("[mes_shm] failed to unmap peer %u shm, err = %d.", inst_id, ret);
    } else {
        LOG_RUN_INF("[mes_shm] unmapped peer shared memory for instance %u", inst_id);
    }

    // If wait is true, we could add additional synchronization here
    // For SHM, no special waiting is needed as memory operations are atomic

    LOG_RUN_INF("[mes_shm] disconnected from instance %u success", inst_id);
}

// Internal function: Shared memory monitor thread
void mes_shm_monitor_proc(thread_t *thread)
{
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    cm_block_sighup_signal();
    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "mes_shm_monitor_%u",
        MES_GLOBAL_INST_MSG.profile.inst_id));
    cm_set_thread_name(thread_name);

    LOG_RUN_INF("[mes_shm] monitor thread started for instance %u",
        MES_GLOBAL_INST_MSG.profile.inst_id);

    while (!thread->closed) {
        cm_sleep(10000);
    }

    LOG_RUN_INF("[mes_shm] monitor thread stopped for instance %u",
                MES_GLOBAL_INST_MSG.profile.inst_id);
}

// Public API: Cleanup shared memory resources
void mes_shm_cleanup(void)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    int ret = -1;
    
    // Unmap all mapped shared memory pointers
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        // Unmap once per instance (self or peer) when base pointer is valid
        if (shm_lsnr->peer_ring[0][id] != NULL) {
            ret = ubsmem_shmem_unmap(shm_lsnr->peer_ring[0][id], g_shm_size);
            if (ret != UBSM_OK) {
                LOG_RUN_ERR("[mes_shm_cleanup] failed to unmap shm for instance %u, err = %d.", id, ret);
            } 
            // Clear all priority pointers for this instance
            for (uint32 prio = 0; prio < MES_PRIORITY_CEIL; prio++) {
                shm_lsnr->peer_ring[prio][id] = NULL;
            }
        }
    }

    // Deallocate the single shared memory block
    if (strlen(g_shm_name) > 0) {
        do {
            ret = ubsmem_shmem_deallocate(g_shm_name);
            if (ret == UBSM_OK) {
                break;
            } else if (ret != UBSM_ERR_IN_USING) {
                LOG_RUN_ERR("[mes_shm_cleanup] failed to deallocate shm %s, err = %d.", g_shm_name, ret);
                break;
            }
             
            cm_sleep(1000);
        } while (true);
        g_shm_name[0] = '\0';
    }
    
    if (strlen(g_region_name) > 0) {
        (void)ubsmem_destroy_region(g_region_name);
        g_region_name[0] = '\0';
    }
    
    g_shm_size = 0;
}

// Public API: Initialize shared memory resources
int mes_init_shm_resource(void)
{
    int ret;

    ret = mes_alloc_channels();
    if (ret != CM_SUCCESS) {
        mes_free_channels();
        LOG_RUN_ERR("mes init channels failed.");
        return ret;
    }

    ret = mes_alloc_channel_msg_queue(CM_TRUE);
    if (ret != CM_SUCCESS) {
        mes_free_channels();
        LOG_RUN_ERR("[mes] alloc send channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_alloc_channel_msg_queue(CM_FALSE);
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channels();
        LOG_RUN_ERR("[mes] alloc recv channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_init_ubs_dlopen_so();
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channel_msg_queue(CM_FALSE);
        mes_free_channels();
        LOG_RUN_ERR("mes init ubs dlopen so failed.");
        return ret;
    }

    ret = mes_init_shm();
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channel_msg_queue(CM_FALSE);
        mes_free_channels();
        mes_shm_cleanup();
        FinishUbsMemDl();
        LOG_RUN_ERR("mes init ubs mem failed.");
        return ret;
    }

    return CM_SUCCESS;
}