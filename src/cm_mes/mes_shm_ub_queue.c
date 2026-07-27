/*
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * mes_shm_ub_queue.c
 *
 * UB dist-comm queue init, callback registration, and handle deinit.
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_ub_queue.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_shm_ub_queue.h"

#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include "mes_shm.h"
#include "mes_shm_fallback_internal.h"
#include "mes_shm_sigbus.h"
#include "cm_memory.h"
#include "mes_stat.h"
#include "mes_func.h"
#include "mes_msg_pool.h"
#include "ub_dist_comm_queue.h"

#define MES_SHM_SLICE_BOOT_RAW ((uint64_t)((MES_MAX_INSTANCES + 1) * 128))

static uint64_t mes_shm_align64_up_u64(uint64_t v)
{
    return (v + 63ULL) & ~63ULL;
}

/* Copy UB message body into MES buffer; CM_ERROR on copy fail or handled UB fault. */
static int mes_ub_callback_copy_body(char *data, const message_t *msg)
{
#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    int ub_fault_rc = sigsetjmp(g_mes_shm_sigbus_jump_env, 1);
    if (ub_fault_rc == 0) {
        g_mes_shm_sigbus_jump_active = CM_TRUE;
        if (memcpy_sp((void *)data, msg->header.body_length, msg->body, msg->header.body_length) != EOK) {
            g_mes_shm_sigbus_jump_active = CM_FALSE;
            LOG_RUN_ERR("[mes_shm callback] Failed to copy message to buffer item.");
            return CM_ERROR;
        }
        MES_SHM_ESB_BARRIER();
        g_mes_shm_sigbus_jump_active = CM_FALSE;
        return CM_SUCCESS;
    }
    g_mes_shm_sigbus_jump_active = CM_FALSE;
    mes_shm_handle_ub_fault("mes_ub_comm_queue_call_back");
    return CM_ERROR;
#else
    if (memcpy_sp((void *)data, msg->header.body_length, msg->body, msg->header.body_length) != EOK) {
        LOG_RUN_ERR("[mes_shm callback] Failed to copy message to buffer item.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
#endif
}

static void mes_ub_comm_queue_call_back(const message_t *msg, void *ctx)
{
    uint32_t ub_queue_idx = (uint32_t)(uintptr_t)ctx;
    uint32 max_msg_size = MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile);
    uint64 stat_time = cm_get_time_usec();
    mes_message_head_t *mes_head;
    char *data;
    mes_message_t mes_msg;
    uint32 channel_id;
    mq_context_t *mq_ctx;
    mes_msgqueue_t *my_mq;

    if (g_mes_stat.mes_elapsed_switch) {
        mes_shm_latency_note_shm_recv(ub_queue_idx);
    }
    if (msg->header.msg_type >= MES_CMD_MAX) {
        LOG_RUN_ERR("[mes_shm callback] Invalid cmd type: %u.", msg->header.msg_type);
        return;
    }
    if (msg->header.body_length < sizeof(mes_message_head_t) || msg->header.body_length > max_msg_size) {
        LOG_RUN_ERR("[mes_shm callback] Invalid message size: %u.", msg->header.body_length);
        return;
    }

    mes_head = (mes_message_head_t *)msg->body;
    data = mes_alloc_buf_item_fc(msg->header.body_length, CM_FALSE, mes_head->src_inst,
        MES_PRIORITY(mes_head->flags));
    if (SECUREC_UNLIKELY(data == NULL)) {
        LOG_RUN_ERR("[mes_shm callback] Failed to allocate buffer item for message size: %u.", msg->header.body_length);
        return;
    }
    if (mes_ub_callback_copy_body(data, msg) != CM_SUCCESS) {
        mes_free_buf_item(data);
        return;
    }

    MES_MESSAGE_ATTACH((&mes_msg), (void *)data);
    mes_consume_with_time((uint16)mes_msg.head->app_cmd, MES_TIME_READ_SOCKET, stat_time);
    channel_id = MES_CALLER_TID_TO_CHANNEL_ID(mes_head->caller_tid);
    mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    my_mq = &mq_ctx->channel_private_queue[mes_head->src_inst][channel_id];
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
    ring_descs[0].ring_capacity = mes_shm_ring_capacity(queue_idx);
    ring_descs[0].max_msg_size = (uint32_t)MES_MESSAGE_BUFFER_SIZE(profile);
    ring_descs[0].priority = (uint8_t)MES_SHM_UB_WIRE_MSG_PRIORITY;
}

static int mes_shm_build_ring_region_entries(ub_ring_region_info_t *ring_info, uint32_t queue_idx)
{
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    uint32_t inst_cnt = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    uint64_t boot_size = mes_shm_align64_up_u64(MES_SHM_SLICE_BOOT_RAW);
    uint64_t shm_segment_size = mes_shm_get_queue_shm_size(queue_idx);
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

static void mes_ub_heartbeat_recv_callback(const message_t *msg, void *ctx)
{
    (void)msg;
    (void)ctx;
}

static int mes_shm_register_dist_comm_callbacks(ub_shm_comm_t *handle, uint32_t queue_idx)
{
    for (uint8_t msg_type = 0; msg_type < MES_CMD_MAX; msg_type++) {
        ub_func_type_t func_type;
        ub_callback_t func;

        if (msg_type == MES_CMD_HEARTBEAT) {
            func_type = UB_FUNC_ASYNC;
            func = mes_ub_heartbeat_recv_callback;
        } else {
            func_type = UB_FUNC_SYNC;
            func = mes_ub_comm_queue_call_back;
        }

        int err = ub_comm_queue_register_process_func(handle, msg_type, func_type, func,
            (void *)(uintptr_t)queue_idx);
        if (err != 0) {
            LOG_RUN_ERR("Failed to register callback for msg_type %u, error: %d.", msg_type, err);
            return CM_ERROR;
        }
    }

    int err = ub_comm_queue_register_process_func(handle, (uint8_t)MES_SHM_UB_MSG_TYPE_FALLBACK, UB_FUNC_SYNC,
        mes_ub_fallback_recv_callback, (void *)(uintptr_t)queue_idx);
    if (err != 0) {
        LOG_RUN_ERR("Failed to register SHM fallback msg_type %u, error: %d.", (unsigned)MES_SHM_UB_MSG_TYPE_FALLBACK,
            err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void mes_shm_deinit_all_ub_handles(shm_rpc_lsnr_t *shm_lsnr)
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

static int mes_shm_init_one_ub_queue(shm_rpc_lsnr_t *shm_lsnr, uint32_t ub_queue_idx, uint32_t coordinator_index,
    ub_shm_area_t *init_region)
{
    int ret;
    ub_comm_conf_t conf;
    ub_ring_desc_t ring_descs[1];
    ub_ring_region_map_t ring_regions;
    uint32_t inst_cnt;
    ub_ring_region_info_t *ring_info;
    void *coord_q = shm_lsnr->peer_ring[coordinator_index][ub_queue_idx];

    if (coord_q == NULL) {
        LOG_RUN_ERR("[mes] coordinator shm queue %u is NULL (idx %u)", (unsigned int)ub_queue_idx, coordinator_index);
        return CM_ERROR;
    }
    init_region->ptr = coord_q;
    mes_shm_build_ub_comm_conf(ub_queue_idx, &conf, ring_descs);

    ring_regions.count = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    inst_cnt = MES_GLOBAL_INST_MSG.profile.inst_cnt;
    ring_info = (ub_ring_region_info_t *)cm_malloc_prot(inst_cnt * sizeof(ub_ring_region_info_t));
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

    ret = ub_comm_queue_init(&shm_lsnr->ub_handle[ub_queue_idx], init_region, &ring_regions, &conf);
    CM_FREE_PROT_PTR(ring_info);
    if (ret != 0) {
        LOG_RUN_ERR("Failed to initialize ub_dist_comm_queue ub_queue_idx=%u, error: %d.",
            (unsigned int)ub_queue_idx, ret);
        return CM_ERROR;
    }
    return mes_shm_register_dist_comm_callbacks(&shm_lsnr->ub_handle[ub_queue_idx], ub_queue_idx);
}

int mes_init_shm_queue(void)
{
    int ret;
    shm_rpc_lsnr_t *shm_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.shm;
    inst_type coordinator_id = mes_shm_get_coordinator_inst_id();
    uint32_t coordinator_index = mes_get_index_from_inst_id(coordinator_id);
    ub_shm_area_t init_region;

    if (coordinator_index == 0xFFFFFFFF) {
        LOG_RUN_ERR("[mes] coordinator inst_id %u not found in inst_net_addr", (unsigned)coordinator_id);
        return CM_ERROR;
    }

    init_region.size = mes_shm_align64_up_u64(MES_SHM_SLICE_BOOT_RAW);
    for (uint32_t ub_queue_idx = 0; ub_queue_idx < MES_SHM_UB_QUEUE_NUM; ub_queue_idx++) {
        ret = mes_shm_init_one_ub_queue(shm_lsnr, ub_queue_idx, coordinator_index, &init_region);
        if (ret != CM_SUCCESS) {
            mes_shm_deinit_all_ub_handles(shm_lsnr);
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("[mes] ub_comm_queue init ok, queues=%u", (unsigned int)MES_SHM_UB_QUEUE_NUM);
    mes_shm_start_map_touch_thread();
    return CM_SUCCESS;
}
