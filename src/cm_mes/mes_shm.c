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
 * IDENTIFICATION
 *    src/cm_mes/mes_shm.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_interface.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mes_shm.h"
#include "mes_shm_dl.h"
#include "cm_system.h"
#include "cm_thread.h"
#include "cm_memory.h"
#include "cm_sync.h"
#include "mes_stat.h"
#include "mes_func.h"
#include "cm_atomic.h"

#define MES_SHM_SHMEM_MODE ((mode_t)0600)
#define MES_SHM_ALLOC_ALIGN ((uint64_t)(128ULL * 1024 * 1024))
#define MES_SHM_UB_RING_CAPACITY (4096U)
#define MES_SHM_UB_RING_CAPACITY_BIG (8192U)
#define MES_SHM_SLICE_BOOT_RAW ((uint64_t)((MES_MAX_INSTANCES + 1) * 128))
#define MES_SHM_SLICE_TAIL_PAD (1024ULL * 1024)
#define MES_SHM_UB_WIRE_MSG_PRIORITY (1U)
/* ub_dist_comm ring blob layout (must match lib sizing used by ub_comm_queue_init). */
#define MES_SHM_UB_COMM_SLOT_PREFIX_BYTES (8U)
#define MES_SHM_UB_COMM_RING_HEADER_BYTES (192U)

static char g_region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
static char g_shm_queue_names[MES_SHM_UB_QUEUE_NUM][MAX_SHM_NAME_LENGTH] = {{0}};
static uint32_t g_inst_id_map[MAX_HOST_NUM];
static inst_type g_mes_coordinator_inst_id = -1;
/* Per-queue ubsmem segment length (128MiB-aligned allocate/map/unmap); ring region uses size minus boot slice. */
static uint64_t g_mes_shm_size[MES_SHM_UB_QUEUE_NUM] = {0};
/* Round-robin among prio6 / prio7 / prio6-mirror UB queues for MES_PRIORITY_SIX sends. */
static atomic32_t g_mes_shm_prio6_ub_q_rr = 0;

static uint64_t mes_shm_align64_up_u64(uint64_t v)
{
    return (v + 63ULL) & ~63ULL;
}

void mes_shm_init_channels_param(uintptr_t channelPtr)
{
    mes_channel_t *channel = (mes_channel_t *)channelPtr;
    for (uint32 i = 0; i < MES_PRIORITY_CEIL; i++) {
        mes_pipe_t *pipe = &channel->pipe[i];
        (void)cm_rwlock_init(&pipe->send_lock);
        (void)cm_rwlock_init(&pipe->recv_lock);
        pipe->priority = i;
        pipe->channel = channel;
        pipe->send_pipe.connect_timeout = MES_GLOBAL_INST_MSG.profile.connect_timeout;
        pipe->send_pipe.socket_timeout = MES_GLOBAL_INST_MSG.profile.socket_timeout;
        pipe->send_pipe_active = CM_FALSE;
        pipe->recv_pipe_active = CM_FALSE;
        pipe->msgbuf = NULL;
    }

    LOG_DEBUG_INF("[mes_shm] init_channels_param, channel_id:%u, instance_id:%u",
        MES_CHANNEL_ID(channel->id), MES_INSTANCE_ID(channel->id));
}

static int mes_inst_id_qsort_cmp(const void *pa, const void *pb)
{
    if (pa == NULL || pb == NULL) {
        return 0;
    }
    inst_type a = *(const inst_type *)pa;
    inst_type b = *(const inst_type *)pb;
    if (a < b) {
        return -1;
    }
    return (a > b) ? 1 : 0;
}

static void mes_init_inst_id_map(void)
{
    int ret;
    if (MES_GLOBAL_INST_MSG.profile.inst_cnt == 0) {
        LOG_RUN_ERR("[mes] No instances available");
        return;
    }

    ret = memset_s(g_inst_id_map, sizeof(g_inst_id_map), 0xFF, sizeof(g_inst_id_map));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes] memset_s g_inst_id_map failed, ret=%d.", ret);
        return;
    }

    inst_type *temp_inst_ids = (inst_type *)cm_malloc_prot(MES_GLOBAL_INST_MSG.profile.inst_cnt * sizeof(inst_type));
    if (temp_inst_ids == NULL) {
        LOG_RUN_ERR("[mes] Failed to allocate memory for temp_inst_ids");
        return;
    }

    for (uint32_t i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        temp_inst_ids[i] = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
    }

    qsort(temp_inst_ids, (size_t)MES_GLOBAL_INST_MSG.profile.inst_cnt, sizeof(inst_type), mes_inst_id_qsort_cmp);

    for (uint32_t i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = temp_inst_ids[i];
        if (inst_id < MAX_HOST_NUM) {
            g_inst_id_map[inst_id] = i;
        }
    }
    g_mes_coordinator_inst_id = temp_inst_ids[0];
    CM_FREE_PTR(temp_inst_ids);
    LOG_RUN_INF("[mes] inst_id map ready, inst_cnt=%u", (unsigned int)MES_GLOBAL_INST_MSG.profile.inst_cnt);
}

static uint32_t mes_get_index_from_inst_id(inst_type inst_id)
{
    if (inst_id >= MAX_HOST_NUM || g_inst_id_map[inst_id] == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] Invalid inst_id %u in mapping table", inst_id);
        return 0xFFFFFFFF;
    }

    return g_inst_id_map[inst_id];
}

/* Max MES payload per ub queue for ring slot sizing; override per ub_queue_idx when priorities differ. */
static uint32_t mes_shm_max_msg_size(uint32_t ub_queue_idx)
{
    (void)ub_queue_idx;
    return (uint32_t)MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
}

/* Ring slot count for ub_comm on this ub queue; cluster must use same value per ub_queue_idx for shared segments. */
static uint32_t mes_shm_ring_capacity(uint32_t ub_queue_idx)
{
    if (ub_queue_idx == MES_PRIORITY_SIX || ub_queue_idx == MES_SHM_UB_QUEUE_PRIO6_MIRROR) {
        return (uint32_t)MES_SHM_UB_RING_CAPACITY_BIG;
    }

    if (ub_queue_idx == MES_PRIORITY_FIVE) {
        return (uint32_t)MES_SHM_UB_RING_CAPACITY_BIG;
    }

    return (uint32_t)MES_SHM_UB_RING_CAPACITY;
}

/* One ub_comm ring blob (metadata + slots), 64-byte aligned; used footprint excludes boot and slice tail pad. */
static uint64_t mes_shm_single_ring_bytes(uint32_t ub_queue_idx)
{
    uint64_t max_msg = (uint64_t)mes_shm_max_msg_size(ub_queue_idx);
    uint64_t slot = mes_shm_align64_up_u64((uint64_t)MES_SHM_UB_COMM_SLOT_PREFIX_BYTES + max_msg);
    uint32_t ring_cap = mes_shm_ring_capacity(ub_queue_idx);
    return mes_shm_align64_up_u64((uint64_t)MES_SHM_UB_COMM_RING_HEADER_BYTES + (uint64_t)ring_cap * slot);
}

/* Used footprint before 128MiB round-up: boot + ring + tail (64-byte aligned). */
static uint64_t mes_shm_calculate_shm_size(uint32_t ub_queue_idx)
{
    uint64_t ring_total = mes_shm_single_ring_bytes(ub_queue_idx);
    uint64_t raw = mes_shm_align64_up_u64(MES_SHM_SLICE_BOOT_RAW) + ring_total + MES_SHM_SLICE_TAIL_PAD;
    return mes_shm_align64_up_u64(raw);
}

/* Fills g_mes_shm_size (128MiB-aligned ubsmem length). mes_init_shm once per bring-up. */
static void mes_shm_refresh_per_queue_shm_size(void)
{
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        uint64_t used = mes_shm_calculate_shm_size(ub_queue_idx);
        g_mes_shm_size[ub_queue_idx] = (used + MES_SHM_ALLOC_ALIGN - 1ULL) & ~(MES_SHM_ALLOC_ALIGN - 1ULL);
    }
}

static void mes_shm_unmap_peer_queues(shm_rpc_lsnr_t *shm_lsnr, uint32_t index)
{
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (shm_lsnr->peer_ring[index][ub_queue_idx] != NULL) {
            uint64_t map_len = g_mes_shm_size[ub_queue_idx];
            (void)mes_ubsmem_shmem_unmap(shm_lsnr->peer_ring[index][ub_queue_idx], map_len);
            shm_lsnr->peer_ring[index][ub_queue_idx] = NULL;
        }
    }
}

static void mes_shm_deinit_ub_handles_upto(shm_rpc_lsnr_t *shm_lsnr, uint32_t bound)
{
    for (uint32_t rollback = 0; rollback < bound; rollback++) {
        (void)ub_comm_queue_deinit(&shm_lsnr->ub_handle[rollback]);
        shm_lsnr->ub_handle[rollback] = NULL;
    }
}

/*
 * Map one ub_queue slot for a peer; retries while shm not found. On hard map/sprintf failure, unmaps all
 * peer queues for index and returns CM_ERROR. On shutdown during retry, returns CM_ERROR without extra unmap.
 */
static int mes_shm_map_peer_queue(inst_type peer_id, uint32_t ub_queue_idx)
{
    const char *user_name = cm_sys_user_name();
    if (user_name == NULL || user_name[0] == '\0') {
        user_name = "unknown";
    }

    uint32_t index = mes_get_index_from_inst_id(peer_id);
    if (index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] peer %u not found in inst_net_addr", peer_id);
        return CM_ERROR;
    }
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;

    uint64_t map_len = g_mes_shm_size[ub_queue_idx];
    char peer_shm_name[MAX_SHM_NAME_LENGTH] = {0};
    int ret = sprintf_s(peer_shm_name, sizeof(peer_shm_name), "shm_mes_%s_%llu_%u", user_name,
        (unsigned long long)index, ub_queue_idx);
    if (ret <= EOK) {
        LOG_RUN_ERR("Failed to format peer shm name for instance %u ub_queue_idx=%u.", peer_id, ub_queue_idx);
        mes_shm_unmap_peer_queues(shm_lsnr, index);
        return CM_ERROR;
    }

    while (MES_GLOBAL_INST_MSG.mes_ctx.phase == SHUTDOWN_PHASE_NOT_BEGIN) {
        ret = mes_ubsmem_shmem_map(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, peer_shm_name, 0,
            &shm_lsnr->peer_ring[index][ub_queue_idx]);
        if (ret == UBSM_OK) {
            return CM_SUCCESS;
        }
        if (ret == UBSM_ERR_NOT_FOUND) {
            LOG_RUN_INF("[mes] peer %u shm ub_queue_idx=%u not found, retrying...", peer_id, ub_queue_idx);
            cm_sleep(CM_SLEEP_1000_FIXED);
            continue;
        }
        mes_shm_unmap_peer_queues(shm_lsnr, index);
        LOG_RUN_ERR("[mes] failed to map peer %u ub_queue_idx=%u shm, err = %d.", peer_id, ub_queue_idx, ret);
        return CM_ERROR;
    }

    return CM_ERROR;
}

static int mes_shm_map_single_peer(inst_type peer_id)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;

    if (peer_id == self_id) {
        return CM_SUCCESS;
    }

    uint32_t index = mes_get_index_from_inst_id(peer_id);
    if (index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] peer %u not found in inst_net_addr", peer_id);
        return CM_ERROR;
    }

    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (shm_lsnr->peer_ring[index][ub_queue_idx] != NULL) {
            continue;
        }
        int mret = mes_shm_map_peer_queue(peer_id, ub_queue_idx);
        if (mret != CM_SUCCESS) {
            if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
                LOG_RUN_INF("[mes] stop mapping peer shm inst=%u idx=%u due to shutdown phase=%d", peer_id, index,
                    (int)MES_GLOBAL_INST_MSG.mes_ctx.phase);
            }
            return CM_ERROR;
        }
    }

    LOG_RUN_INF("[mes] mapped peer shm inst=%u idx=%u (queues=%u)", peer_id, index,
        (unsigned int)MES_SHM_UB_QUEUE_NUM);
    return CM_SUCCESS;
}

static void mes_shm_rollback_self_queue_shm(shm_rpc_lsnr_t *shm_lsnr, uint32_t self_index)
{
    mes_shm_unmap_peer_queues(shm_lsnr, self_index);
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (g_shm_queue_names[ub_queue_idx][0] != '\0') {
            (void)mes_ubsmem_shmem_deallocate(g_shm_queue_names[ub_queue_idx]);
            g_shm_queue_names[ub_queue_idx][0] = '\0';
        }
    }
}

static int mes_init_shm(void)
{
    int ret;
    const char *user_name = cm_sys_user_name();
    if (user_name == NULL || user_name[0] == '\0') {
        user_name = "unknown";
    }
    char *host_name = cm_sys_host_name();
    int self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    uint32_t self_index = mes_get_index_from_inst_id(self_id);
    if (self_index == 0xFFFFFFFF) {
        LOG_RUN_ERR("mes_init_shm: self_id %u not in profile.", (unsigned int)self_id);
        return CM_ERROR;
    }

    /* Single refresh per bring-up: later mes_shm_map_peers / mes_init_shm_queue read g_mes_shm_size only. */
    mes_shm_refresh_per_queue_shm_size();

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    ubsmem_regions_t regions;
    ubsmem_region_attributes_t region;
    ubsmem_options_t ubsm_shmem_opts;

    ret = mes_ubsmem_init_and_set_inited(&ubsm_shmem_opts);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    ret = mes_ubsmem_lookup_regions(&regions);
    if (ret != UBSM_OK) {
        LOG_RUN_ERR("Failed to lookup shm regions, error: %d.", ret);
        return CM_ERROR;
    }

    region = regions.region[0];
    for (int i = 0; i < region.host_num; i++) {
        region.hosts[i].affinity = (strcmp(region.hosts[i].host_name, host_name) == 0);
    }

    char region_name[MAX_REGION_NAME_DESC_LENGTH] = {0};
    ret = sprintf_s(region_name, sizeof(region_name), "region_mes_%s_%llu", user_name, self_index);
    if (ret <= EOK) {
        LOG_RUN_ERR("Failed to format shm region name.");
        return CM_ERROR;
    }

    ret = mes_ubsmem_create_region(region_name, 0, &region);
    if (ret != UBSM_OK && ret != UBSM_ERR_ALREADY_EXIST) {
        LOG_RUN_ERR("Failed to create shm region %s, error: %d.", region_name, ret);
        return CM_ERROR;
    }
    if (ret == UBSM_ERR_ALREADY_EXIST) {
        LOG_RUN_INF("shm region %s already exists, continue.", region_name);
    }

    ret = strncpy_s(g_region_name, sizeof(g_region_name), region_name, sizeof(region_name) - 1);
    MEMS_RETURN_IFERR(ret);

    ret = memset_s(g_shm_queue_names, sizeof(g_shm_queue_names), 0, sizeof(g_shm_queue_names));
    MEMS_RETURN_IFERR(ret);

    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        uint64_t queue_shmem_sz = g_mes_shm_size[ub_queue_idx];
        if (queue_shmem_sz == 0) {
            LOG_RUN_ERR("mes_init_shm: invalid shm size for ub_queue_idx=%u self_index %u.", ub_queue_idx,
                (unsigned int)self_index);
            mes_shm_rollback_self_queue_shm(shm_lsnr, self_index);
            return CM_ERROR;
        }

        char shm_name[MAX_SHM_NAME_LENGTH] = {0};
        ret = sprintf_s(shm_name, sizeof(shm_name), "shm_mes_%s_%llu_%u", user_name, (unsigned long long)self_index,
            ub_queue_idx);
        if (ret <= EOK) {
            LOG_RUN_ERR("mes_init_shm: Failed to format shm name for ub_queue_idx=%u.", ub_queue_idx);
            mes_shm_rollback_self_queue_shm(shm_lsnr, self_index);
            return CM_ERROR;
        }

        ret = mes_ubsmem_shmem_allocate(region_name, shm_name, queue_shmem_sz, MES_SHM_SHMEM_MODE,
            UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE);
        if (ret != UBSM_OK && ret != UBSM_ERR_ALREADY_EXIST) {
            LOG_RUN_ERR("mes_init_shm: Failed to allocate shm %s, error: %d.", shm_name, ret);
            mes_shm_rollback_self_queue_shm(shm_lsnr, self_index);
            return CM_ERROR;
        }

        ret = strncpy_s(g_shm_queue_names[ub_queue_idx], sizeof(g_shm_queue_names[ub_queue_idx]), shm_name,
            sizeof(shm_name) - 1);
        MEMS_RETURN_IFERR(ret);

        ret = mes_ubsmem_shmem_map(NULL, queue_shmem_sz, PROT_READ | PROT_WRITE, MAP_SHARED, shm_name, 0,
            &shm_lsnr->peer_ring[self_index][ub_queue_idx]);
        if (ret != UBSM_OK) {
            LOG_RUN_ERR("[mes] failed to map self shm ub_queue_idx=%u, err = %d.", ub_queue_idx, ret);
            mes_shm_rollback_self_queue_shm(shm_lsnr, self_index);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static void mes_ub_comm_queue_call_back(const message_t *msg, void *ctx)
{
    uint32_t ub_queue_idx = (uint32_t)(uintptr_t)ctx;
    uint32 max_msg_size = MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
    uint64 stat_time = cm_get_time_usec();

    if (g_mes_stat.mes_elapsed_switch) {
        mes_shm_latency_note_shm_recv(ub_queue_idx);
    }

    if (msg->header.msg_type >= MES_CMD_MAX) {
        LOG_RUN_ERR("[mes_shm callback] Invalid cmd type: %u.", msg->header.msg_type);
        return;
    }

    if (msg->header.msg_type == MES_CMD_HEARTBEAT) {
        return;
    }

    if (msg->header.body_length < sizeof(mes_message_head_t) || msg->header.body_length > max_msg_size) {
        LOG_RUN_ERR("[mes_shm callback] Invalid message size: %u.", msg->header.body_length);
        return;
    }

    mes_message_head_t *mes_head = (mes_message_head_t *)msg->body;
    char *data = mes_alloc_buf_item_fc(msg->header.body_length, CM_FALSE, mes_head->src_inst,
        MES_PRIORITY(mes_head->flags));
    if (SECUREC_UNLIKELY(data == NULL)) {
        LOG_RUN_ERR("[mes_shm callback] Failed to allocate buffer item for message size: %u.", msg->header.body_length);
        return;
    }

    if (memcpy_sp((void *)data, msg->header.body_length, msg->body, msg->header.body_length) != EOK) {
        LOG_RUN_ERR("[mes_shm callback] Failed to copy message to buffer item.");
        mes_free_buf_item(data);
        return;
    }

    mes_message_t mes_msg;
    MES_MESSAGE_ATTACH((&mes_msg), (void *)data);
    mes_consume_with_time((uint16)mes_msg.head->app_cmd, MES_TIME_READ_SOCKET, stat_time);
    uint32 channel_id = MES_CALLER_TID_TO_CHANNEL_ID(mes_head->caller_tid);
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    mes_msgqueue_t *my_mq = &mq_ctx->channel_private_queue[mes_head->src_inst][channel_id];
    mes_process_message(my_mq, &mes_msg);
}

static void mes_shm_build_ub_comm_conf(uint32_t queue_idx, ub_comm_conf_t *conf, ub_ring_desc_t *ring_descs)
{
    mes_profile_t *profile = &MES_GLOBAL_INST_MSG.profile;

    conf->cpu_id = profile->mes_shm_ub_comm_cpu_ids[queue_idx];
    if (conf->cpu_id < 0) {
        conf->cpu_id = -1;
    }
    conf->max_nodes = profile->inst_cnt;
    conf->current_node_id = mes_get_index_from_inst_id(profile->inst_id);
    conf->num_rings = 1;
    conf->ring_descs = ring_descs;
    uint32_t max_msg = mes_shm_max_msg_size(queue_idx);
    ring_descs[0].ring_capacity = mes_shm_ring_capacity(queue_idx);
    ring_descs[0].max_msg_size = max_msg;
    ring_descs[0].priority = (uint8_t)MES_SHM_UB_WIRE_MSG_PRIORITY;
}

static int mes_shm_build_ring_region_entries(ub_ring_region_info_t *ring_info, uint32_t queue_idx)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    uint32_t inst_cnt = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    uint64_t boot_size = mes_shm_align64_up_u64(MES_SHM_SLICE_BOOT_RAW);
    uint64_t shm_segment_size = g_mes_shm_size[queue_idx];
    uint64_t ring_region_size = shm_segment_size - boot_size;

    for (uint32 i = 0; i < inst_cnt; i++) {
        inst_type index = mes_get_index_from_inst_id(MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id);
        if (index == 0xFFFFFFFF) {
            LOG_RUN_ERR("[mes] inst_id %u not found in inst_net_addr",
                MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id);
            return CM_ERROR;
        }
        void *base = shm_lsnr->peer_ring[index][queue_idx];
        ring_info[index].region.ptr = (void *)((uintptr_t)base + boot_size);
        ring_info[index].region.size = ring_region_size;
        ring_info[index].node_id = (uint8_t)index;
    }
    return CM_SUCCESS;
}

static int mes_shm_register_dist_comm_callbacks(ub_shm_comm_t *handle, uint32_t queue_idx)
{
    for (uint8_t msg_type = 0; msg_type < MES_CMD_MAX; msg_type++) {
        int err = ub_comm_queue_register_process_func(handle, msg_type, UB_FUNC_SYNC, mes_ub_comm_queue_call_back,
            (void *)(uintptr_t)queue_idx);
        if (err != 0) {
            LOG_RUN_ERR("Failed to register callback for msg_type %u, error: %d.", msg_type, err);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

int mes_init_shm_queue(void)
{
    int ret;
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    uint32_t coordinator_index = mes_get_index_from_inst_id(g_mes_coordinator_inst_id);
    if (coordinator_index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] coordinator inst_id %u not found in inst_net_addr", g_mes_coordinator_inst_id);
        return CM_ERROR;
    }

    ub_shm_area_t init_region;
    init_region.size = mes_shm_align64_up_u64(MES_SHM_SLICE_BOOT_RAW);

    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        void *coord_q = shm_lsnr->peer_ring[coordinator_index][ub_queue_idx];
        if (coord_q == NULL) {
            LOG_RUN_ERR("[mes] coordinator shm queue %u is NULL (idx %u)", (unsigned int)ub_queue_idx,
                coordinator_index);
            return CM_ERROR;
        }
        init_region.ptr = coord_q;

        ub_comm_conf_t conf;
        ub_ring_desc_t ring_descs[1];
        mes_shm_build_ub_comm_conf(ub_queue_idx, &conf, ring_descs);

        ub_ring_region_map_t ring_regions;
        ring_regions.count = MES_GLOBAL_INST_MSG.profile.inst_cnt;
        uint32_t inst_cnt = MES_GLOBAL_INST_MSG.profile.inst_cnt;
        ub_ring_region_info_t *ring_info = (ub_ring_region_info_t *)cm_malloc_prot(
            inst_cnt * sizeof(ub_ring_region_info_t));
        if (ring_info == NULL) {
            LOG_RUN_ERR("[mes_shm] failed to alloc ring_info for ub_queue_idx=%u.", (unsigned int)ub_queue_idx);
            return CM_ERROR;
        }
        ret = mes_shm_build_ring_region_entries(ring_info, ub_queue_idx);
        if (ret != CM_SUCCESS) {
            CM_FREE_PROT_PTR(ring_info);
            return CM_ERROR;
        }
        ring_regions.entries = ring_info;

        ret = ub_comm_queue_init(&shm_lsnr->ub_handle[ub_queue_idx], &init_region, &ring_regions, &conf);
        CM_FREE_PROT_PTR(ring_info);
        if (ret != 0) {
            LOG_RUN_ERR("Failed to initialize ub_dist_comm_queue ub_queue_idx=%u, error: %d.",
                (unsigned int)ub_queue_idx, ret);
            mes_shm_deinit_ub_handles_upto(shm_lsnr, ub_queue_idx);
            return CM_ERROR;
        }

        ret = mes_shm_register_dist_comm_callbacks(&shm_lsnr->ub_handle[ub_queue_idx], ub_queue_idx);
        if (ret != CM_SUCCESS) {
            (void)ub_comm_queue_deinit(&shm_lsnr->ub_handle[ub_queue_idx]);
            shm_lsnr->ub_handle[ub_queue_idx] = NULL;
            mes_shm_deinit_ub_handles_upto(shm_lsnr, ub_queue_idx);
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("[mes] ub_comm_queue init ok, queues=%u", (unsigned int)MES_SHM_UB_QUEUE_NUM);
    return CM_SUCCESS;
}

int mes_shm_map_peers(void)
{
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    LOG_RUN_INF("[mes] mes_shm_map_peers: self_id = %u", self_id);
    int ret;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type peer_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (peer_id == self_id) {
            continue;
        }

        ret = mes_shm_map_single_peer(peer_id);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[mes] mes_shm_map_single_peer failed, peer_id=%u", peer_id);
            continue;
        }
    }

    return CM_SUCCESS;
}

void mes_shm_try_connect(uintptr_t pipePtr)
{
    mes_pipe_t *pipe = (mes_pipe_t *)pipePtr;
    mes_priority_t mes_pri = pipe->priority;
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;
    inst_type peer_id = MES_INSTANCE_ID(pipe->channel->id);

    if (peer_id >= MAX_HOST_NUM) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: invalid peer_id %u", peer_id);
        return;
    }

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;

    uint32_t self_index = mes_get_index_from_inst_id(self_id);
    if (self_index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] self_id %u not found in inst_net_addr", self_id);
        return;
    }

    if (shm_lsnr->peer_ring[self_index][mes_pri] == NULL) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: self shared memory ub_queue_idx=%u not initialized", mes_pri);
        return;
    }

    uint32_t peer_index = mes_get_index_from_inst_id(peer_id);
    if (peer_index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] peer_id %u not found in inst_net_addr", peer_id);
        return;
    }

    if (shm_lsnr->peer_ring[peer_index][mes_pri] == NULL) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: peer_ring[%u][%u] is NULL", peer_index, mes_pri);
        return;
    }

    if (mes_pri >= MES_PRIORITY_CEIL) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: invalid mes_pri %u peer=%u", (unsigned int)mes_pri, peer_id);
        return;
    }

    if (shm_lsnr->ub_handle[(uint32_t)mes_pri] == NULL) {
        LOG_RUN_ERR("[mes] mes_shm_try_connect: ub_handle[%u] is NULL (mes_pri=%u)", (unsigned int)mes_pri,
            (unsigned int)mes_pri);
        return;
    }
    if (!ub_comm_queue_check_ready(&shm_lsnr->ub_handle[(uint32_t)mes_pri], (uint8_t)peer_id)) {
        pipe->send_pipe_active = CM_FALSE;
        pipe->recv_pipe_active = CM_FALSE;
        LOG_RUN_INF("[mes] SHM pipe mes_pri=%u ub_handle[%u] to instance %u not ready, keep mapped",
            (unsigned int)mes_pri, (unsigned int)mes_pri, peer_id);
        return;
    }

    pipe->send_pipe_active = CM_TRUE;
    pipe->recv_pipe_active = CM_TRUE;

    LOG_RUN_INF("[mes] SHM pipe mes_pri=%u to instance %u active (peer ready)", (unsigned int)mes_pri, peer_id);
}

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

    LOG_DEBUG_INF("[mes] SHM heartbeat completed for instance %u", peer_id);
}

static uint32_t mes_shm_send_pick_ub_q(mes_priority_t pri)
{
    uint32_t ub_q = (uint32_t)pri;
    if (pri == MES_PRIORITY_SIX) {
        uint32_t seq = (uint32_t)cm_atomic32_inc(&g_mes_shm_prio6_ub_q_rr);
        uint32_t selector = (seq - 1U) % 3U;
        ub_q = (selector == 0U) ? (uint32_t)MES_PRIORITY_SIX :
               ((selector == 1U) ? (uint32_t)MES_PRIORITY_SEVEN : (uint32_t)MES_SHM_UB_QUEUE_PRIO6_MIRROR);
    }
    return ub_q;
}

int mes_shm_send_data(const void *msg_data)
{
    int ret;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    CM_RETURN_IFERR(mes_check_send_head_info(head));

    if (MES_GLOBAL_INST_MSG.mes_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[mes_shm] send_data: reject during shutdown, phase=%d", (int)MES_GLOBAL_INST_MSG.mes_ctx.phase);
        return CM_ERROR;
    }

    mes_priority_t pri = MES_PRIORITY(head->flags);
    inst_type dst_inst = head->dst_inst;
    mes_channel_t *channel = mes_get_active_send_channel(head->dst_inst, head->caller_tid, head->flags);
    if (channel == NULL) {
        LOG_DEBUG_ERR("[mes_shm] send_data: dst_inst=%u channel is NULL.", dst_inst);
        return ERR_MES_SENDPIPE_NO_READY;
    }
    mes_pipe_t *pipe = &channel->pipe[pri];

    if (!pipe->send_pipe_active) {
        LOG_DEBUG_ERR("[mes_shm] send_data: dst_inst=%u pri=%u send pipe not ready.", dst_inst, (unsigned int)pri);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    uint32_t ub_q = mes_shm_send_pick_ub_q(pri);
    if (shm_lsnr->ub_handle[ub_q] == NULL) {
        LOG_DEBUG_ERR("[mes_shm] send_data: ub_handle[%u] is NULL, skip send dst_inst=%u", ub_q, head->dst_inst);
        return CM_ERROR;
    }

    message_t msg;
    msg.header.src_thread_id = 0;
    msg.header.body_length = head->size;
    msg.header.dest_node_id = mes_get_index_from_inst_id(dst_inst);
    msg.header.src_node_id = mes_get_index_from_inst_id(MES_GLOBAL_INST_MSG.profile.inst_id);
    msg.header.msg_type = head->cmd;
    msg.header.priority = (uint8_t)MES_SHM_UB_WIRE_MSG_PRIORITY;
    msg.body = (char *)msg_data;

    uint64 stat_time = cm_get_time_usec();
    ret = ub_comm_queue_send(&shm_lsnr->ub_handle[ub_q], &msg);
    if (ret != 0) {
        LOG_RUN_WAR("[mes_shm] send_data: failed to send to inst %u mes_pri=%u ub_handle_idx=%u size %u err %d",
            dst_inst, (unsigned int)pri, ub_q, head->size, ret);
        return CM_ERROR;
    }
    mes_consume_with_time_shm_send((uint16)head->app_cmd, stat_time, ub_q);
    return CM_SUCCESS;
}

int mes_shm_send_bufflist(mes_bufflist_t *buff_list)
{
    if (buff_list == NULL || buff_list->cnt == 0) {
        LOG_RUN_ERR("[mes_shm] send_bufflist: invalid buff_list");
        return CM_ERROR;
    }

    mes_message_head_t *head = (mes_message_head_t *)buff_list->buffers[0].buf;
    uint32 total_size = 0;
    for (uint32_t i = 0; i < buff_list->cnt; i++) {
        uint32 prev = total_size;
        total_size += buff_list->buffers[i].len;
        if (total_size < prev) {
            LOG_RUN_ERR("[mes_shm] send_bufflist: total_size overflow");
            return CM_ERROR;
        }
    }

    head->size = total_size;
    char *buf = (char *)cm_malloc_prot(total_size);
    if (buf == NULL) {
        LOG_RUN_ERR("[mes_shm] send_bufflist: alloc failed");
        return CM_ERROR;
    }

    uint32 offset = 0;
    for (uint32_t i = 0; i < buff_list->cnt; i++) {
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

static void mes_shm_mark_peer_channels_down(inst_type peer_inst)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    if (ctx->channels == NULL || peer_inst >= MES_MAX_INSTANCES || ctx->channels[peer_inst] == NULL) {
        return;
    }
    for (uint32 ch = 0; ch < MES_GLOBAL_INST_MSG.profile.channel_cnt; ch++) {
        mes_channel_t *channel = &ctx->channels[peer_inst][ch];
        for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
            mes_pipe_t *pipe = &channel->pipe[prio];
            pipe->send_pipe_active = CM_FALSE;
            pipe->recv_pipe_active = CM_FALSE;
        }
    }
}

static void mes_shm_deinit_all_ub_handles(shm_rpc_lsnr_t *shm_lsnr)
{
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (shm_lsnr->ub_handle[ub_queue_idx] == NULL) {
            continue;
        }
        int ret = ub_comm_queue_deinit(&shm_lsnr->ub_handle[ub_queue_idx]);
        if (ret != 0) {
            LOG_RUN_ERR("[mes_shm] failed to deinit ub_dist_comm_queue ub_queue_idx=%u, error: %d.",
                (unsigned int)ub_queue_idx, ret);
        }
        shm_lsnr->ub_handle[ub_queue_idx] = NULL;
    }
}

static void mes_shm_unmap_peer(shm_rpc_lsnr_t *shm_lsnr, uint32_t idx, inst_type inst_id)
{
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (shm_lsnr->peer_ring[idx][ub_queue_idx] == NULL) {
            continue;
        }
        uint64_t unmap_len = g_mes_shm_size[ub_queue_idx];
        int ret = mes_ubsmem_shmem_unmap(shm_lsnr->peer_ring[idx][ub_queue_idx], unmap_len);
        if (ret != UBSM_OK) {
            LOG_RUN_ERR("[mes_shm] failed to unmap shm for instance %u (idx %u ub_queue_idx=%u), err = %d.",
                inst_id, idx, ub_queue_idx, ret);
        }
        shm_lsnr->peer_ring[idx][ub_queue_idx] = NULL;
    }
}

static void mes_shm_stop_cluster_queue(void)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;

    mes_shm_deinit_all_ub_handles(shm_lsnr);

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        uint32_t idx = mes_get_index_from_inst_id(inst_id);
        if (idx == 0xFFFFFFFF) {
            continue;
        }
        mes_shm_unmap_peer(shm_lsnr, idx, inst_id);
    }

    int ret = memset_s(shm_lsnr, sizeof(shm_rpc_lsnr_t), 0, sizeof(shm_rpc_lsnr_t));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes_shm] memset_s shm_lsnr failed, ret=%d.", ret);
    }
}

void mes_shm_disconnect_handle(uint32 inst_id, bool32 wait)
{
    (void)wait;
    if (inst_id >= MAX_HOST_NUM) {
        LOG_RUN_ERR("[mes_shm] invalid inst_id %u", inst_id);
        return;
    }

    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    inst_type self_id = MES_GLOBAL_INST_MSG.profile.inst_id;

    if (inst_id == self_id) {
        LOG_RUN_ERR("[mes_shm] cannot disconnect from self instance %u", inst_id);
        return;
    }

    uint32_t index = mes_get_index_from_inst_id(inst_id);
    if (index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes_shm] inst %u not found in inst_net_addr", inst_id);
        return;
    }

    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (shm_lsnr->peer_ring[index][ub_queue_idx] == NULL) {
            continue;
        }
        void *base_ptr = shm_lsnr->peer_ring[index][ub_queue_idx];
        shm_lsnr->peer_ring[index][ub_queue_idx] = NULL;
        uint64_t unmap_len = g_mes_shm_size[ub_queue_idx];
        int ret = mes_ubsmem_shmem_unmap(base_ptr, unmap_len);
        if (ret != UBSM_OK) {
            LOG_RUN_ERR("[mes_shm] failed to unmap peer %u shm ub_queue_idx=%u, err = %d.", inst_id, ub_queue_idx, ret);
        }
    }
    LOG_RUN_INF("[mes_shm] unmapped peer %u shared memory (idx %u, queues=%u), cluster handle kept", inst_id, index,
        (unsigned int)MES_SHM_UB_QUEUE_NUM);

    mes_shm_mark_peer_channels_down((inst_type)inst_id);

    LOG_RUN_INF("[mes_shm] disconnected from instance %u (single-node eviction)", inst_id);
}

void mes_shm_cleanup(void)
{
    int ret;
    mes_shm_stop_cluster_queue();

    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        if (g_shm_queue_names[ub_queue_idx][0] == '\0') {
            continue;
        }
        do {
            ret = mes_ubsmem_shmem_deallocate(g_shm_queue_names[ub_queue_idx]);
            if (ret == UBSM_OK) {
                break;
            } else if (ret != UBSM_ERR_IN_USING) {
                LOG_RUN_ERR("[mes_shm_cleanup] failed to deallocate shm %s, err = %d.", g_shm_queue_names[ub_queue_idx],
                    ret);
                break;
            }
            cm_sleep(CM_SLEEP_1000_FIXED);
        } while (true);
        g_shm_queue_names[ub_queue_idx][0] = '\0';
    }

    if (strlen(g_region_name) > 0) {
        (void)mes_ubsmem_destroy_region(g_region_name);
        g_region_name[0] = '\0';
    }

    ret = memset_s(g_mes_shm_size, sizeof(g_mes_shm_size), 0, sizeof(g_mes_shm_size));
    if (ret != EOK) {
        LOG_RUN_ERR("[mes_shm_cleanup] memset_s g_mes_shm_size failed, ret=%d.", ret);
    }
}

int mes_init_shm_resource(void)
{
    int ret;

    mes_init_inst_id_map();

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
