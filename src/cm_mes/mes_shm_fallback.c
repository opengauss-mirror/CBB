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
 * mes_shm_fallback.c
 *
 * MES SHM UB memory fault autonomous fallback to TCP.
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_fallback.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_shm_fallback_internal.h"

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef WIN32
#include <pthread.h>
#endif

#include "mes_interface.h"
#include "mes_shm.h"
#include "mes_shm_sigbus.h"
#include "cm_thread.h"
#include "mes_func.h"
#include "mes_tcp.h"
#include "mes_recv.h"
#include "ub_dist_comm_queue.h"

typedef enum en_mes_shm_fallback_trigger {
    MES_SHM_FALLBACK_FROM_FAULT = 0,
    MES_SHM_FALLBACK_FROM_PEER = 1,
} mes_shm_fallback_trigger_t;

/* Detached worker: ub_comm_queue_deinit must not run on SYNC callback thread. */
static thread_t g_shm_fallback_thread;
static volatile bool8 g_shm_fallback_thread_started = CM_FALSE;
static mes_shm_fallback_trigger_t g_shm_fallback_trigger = MES_SHM_FALLBACK_FROM_FAULT;
static inst_type g_shm_fallback_peer_src = 0;

static void mes_shm_clear_fallback_in_progress(void)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_SHM) {
        __atomic_store_n(&MES_GLOBAL_INST_MSG.mes_ctx.shm_degraded_to_tcp, CM_FALSE, __ATOMIC_RELEASE);
    }
}

bool mes_shm_fallback_in_progress(void)
{
    return MES_GLOBAL_INST_MSG.mes_ctx.shm_degraded_to_tcp;
}

/* Stop SHM send/connect reuse of pipes while fallback worker runs. */
static void mes_shm_fence_channels_on_degrade(void)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || ctx->channels[inst_id] == NULL) {
            continue;
        }
        for (uint32 ch = 0; ch < MES_GLOBAL_INST_MSG.profile.channel_cnt; ch++) {
            mes_channel_t *channel = &ctx->channels[inst_id][ch];
            for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
                channel->pipe[prio].send_pipe_active = CM_FALSE;
                channel->pipe[prio].recv_pipe_active = CM_FALSE;
            }
        }
    }
}

static void mes_shm_send_fallback_notify(inst_type dst_inst)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    shm_rpc_lsnr_t *shm_lsnr = &ctx->lsnr.shm;
    mes_priority_t pri;
    uint32_t ub_q;
    uint32_t total_size = (uint32_t)sizeof(mes_message_head_t);
    char wire_buf[MES_MESSAGE_BUFFER_SIZE(&MES_GLOBAL_INST_MSG.profile)];
    mes_message_head_t *mes_head = (mes_message_head_t *)wire_buf;
    message_t msg;

    if (dst_inst >= MES_MAX_INSTANCES || ctx->channels[dst_inst] == NULL ||
        shm_lsnr->ub_handle[0] == NULL) {
        return;
    }

    pri = (mes_priority_t)(((uint32_t)cm_get_time_usec() ^ (uint32_t)dst_inst) % MES_PRIORITY_CEIL);
    ub_q = mes_shm_send_pick_ub_q(pri);
    if (shm_lsnr->ub_handle[ub_q] == NULL) {
        return;
    }

    if (memset_s(wire_buf, sizeof(wire_buf), 0, total_size) != EOK) {
        return;
    }
    mes_head->src_inst = MES_MY_ID;
    mes_head->dst_inst = dst_inst;
    mes_head->size = total_size;

    msg.header.src_thread_id = 0;
    msg.header.body_length = total_size;
    msg.header.dest_node_id = mes_get_index_from_inst_id(dst_inst);
    msg.header.src_node_id = mes_get_index_from_inst_id(MES_GLOBAL_INST_MSG.profile.inst_id);
    msg.header.msg_type = (uint8_t)MES_SHM_UB_MSG_TYPE_FALLBACK;
    msg.header.priority = (uint8_t)MES_SHM_UB_WIRE_MSG_PRIORITY;
    msg.body = wire_buf;

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    {
        int ub_fault_rc = sigsetjmp(g_mes_shm_sigbus_jump_env, 1);
        if (ub_fault_rc == 0) {
            g_mes_shm_sigbus_jump_active = CM_TRUE;
            (void)ub_comm_queue_send(&shm_lsnr->ub_handle[ub_q], &msg);
            MES_SHM_ESB_BARRIER();
            g_mes_shm_sigbus_jump_active = CM_FALSE;
        } else {
            g_mes_shm_sigbus_jump_active = CM_FALSE;
            mes_shm_handle_ub_fault("mes_shm_send_fallback_notify");
        }
    }
#else
    (void)ub_comm_queue_send(&shm_lsnr->ub_handle[ub_q], &msg);
#endif
}

static void mes_shm_notify_all_peers_fallback(void)
{
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || !MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].need_connect) {
            continue;
        }
        mes_shm_send_fallback_notify(inst_id);
    }
}

int mes_switch_shm_to_tcp(void)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    int ret;

    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        return CM_SUCCESS;
    }

    LOG_RUN_WAR("[mes] UB fault detected, switching SHM to TCP");

    mes_shm_cleanup();

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || ctx->channels[inst_id] == NULL) {
            continue;
        }
        for (uint32 ch = 0; ch < MES_GLOBAL_INST_MSG.profile.channel_cnt; ch++) {
            mes_tcp_init_channels_param((uintptr_t)&ctx->channels[inst_id][ch]);
        }
    }

    ret = mes_start_lsnr();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] TCP fallback lsnr start failed, ret=%d", ret);
        return ret;
    }

    ret = mes_start_receivers(
        MES_GLOBAL_INST_MSG.profile.priority_cnt,
        MES_GLOBAL_INST_MSG.profile.recv_task_count,
        mes_recv_pipe_event_proc);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] TCP fallback receivers start failed, ret=%d", ret);
        return ret;
    }

    g_cbb_mes_callback.connect_func = mes_tcp_try_connect;
    g_cbb_mes_callback.heartbeat_func = mes_tcp_heartbeat_channel;
    g_cbb_mes_callback.disconnect_func = mes_tcp_disconnect;
    g_cbb_mes_callback.send_func = mes_tcp_send_data;
    g_cbb_mes_callback.send_bufflist_func = mes_tcp_send_bufflist;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || ctx->channels[inst_id] == NULL) {
            continue;
        }
        for (uint32 ch = 0; ch < MES_GLOBAL_INST_MSG.profile.channel_cnt; ch++) {
            mes_channel_t *channel = &ctx->channels[inst_id][ch];
            for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
                channel->pipe[prio].send_pipe_active = CM_FALSE;
                channel->pipe[prio].recv_pipe_active = CM_FALSE;
            }
        }
    }

    MES_GLOBAL_INST_MSG.profile.pipe_type = MES_TYPE_TCP;
    __atomic_store_n(&ctx->shm_degraded_to_tcp, CM_TRUE, __ATOMIC_RELEASE);
    mes_shm_sigbus_unregister_handler();

    LOG_RUN_INF("[mes] switched from SHM to TCP successfully");
    return CM_SUCCESS;
}

void mes_shm_tcp_bringup_peers(void)
{
    unsigned char inst_list[MES_MAX_INSTANCES];
    unsigned char inst_cnt = 0;

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || !MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].need_connect) {
            continue;
        }
        if (mes_connect(inst_id) != CM_SUCCESS) {
            LOG_RUN_WAR("[mes_shm] mes_connect inst %u failed during TCP bringup", inst_id);
        }
        if (inst_cnt < MES_MAX_INSTANCES) {
            inst_list[inst_cnt++] = (unsigned char)inst_id;
        }
    }

    if (inst_cnt > 0) {
        (void)mes_wait_connect_batch(inst_list, inst_cnt);
    }

    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        inst_type inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        if (inst_id == MES_GLOBAL_INST_MSG.profile.inst_id || MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] == NULL) {
            continue;
        }
        for (uint32 ch = 0; ch < MES_GLOBAL_INST_MSG.profile.channel_cnt; ch++) {
            mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][ch];
            for (uint32 prio = 0; prio < MES_GLOBAL_INST_MSG.profile.priority_cnt; prio++) {
                mes_tcp_try_connect((uintptr_t)&channel->pipe[prio]);
            }
        }
    }
}

static void mes_shm_run_fallback_sequence(bool32 notify_peers, inst_type peer_src)
{
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        LOG_RUN_INF("[mes_shm] SHM to TCP fallback sequence skipped, already on TCP");
        return;
    }

    if (notify_peers) {
        LOG_RUN_WAR("[mes_shm] starting SHM to TCP fallback sequence");
        mes_shm_notify_all_peers_fallback();
        if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
            LOG_RUN_INF("[mes_shm] SHM to TCP fallback sequence skipped, switched during notify");
            return;
        }
    } else {
        LOG_RUN_WAR("[mes_shm] peer fallback: notify from inst %u, switching SHM to TCP",
            (unsigned)peer_src);
    }

    if (mes_switch_shm_to_tcp() != CM_SUCCESS) {
        LOG_RUN_ERR("[mes_shm] mes_switch_shm_to_tcp failed");
        mes_shm_clear_fallback_in_progress();
        return;
    }

    if (MES_GLOBAL_INST_MSG.profile.pipe_type != MES_TYPE_TCP) {
        mes_shm_clear_fallback_in_progress();
        return;
    }

    mes_shm_tcp_bringup_peers();
    LOG_RUN_INF("[mes_shm] SHM to TCP fallback sequence completed");
}

static void mes_shm_fallback_worker_entry(thread_t *thread)
{
    mes_shm_fallback_trigger_t trigger = g_shm_fallback_trigger;
    inst_type peer_src = g_shm_fallback_peer_src;

    (void)thread;
    cm_set_thread_name("mes_shm_fb");
    LOG_RUN_INF("[mes_shm] fallback worker started (trigger=%s)",
        (trigger == MES_SHM_FALLBACK_FROM_PEER) ? "peer_notify" : "local_fault");

    if (trigger == MES_SHM_FALLBACK_FROM_PEER) {
        mes_shm_run_fallback_sequence(CM_FALSE, peer_src);
    } else {
        mes_shm_run_fallback_sequence(CM_TRUE, 0);
    }

    LOG_RUN_INF("[mes_shm] fallback worker finished");
}

static status_t mes_shm_schedule_fallback_worker(mes_shm_fallback_trigger_t trigger, inst_type peer_src)
{
    bool8 expected = CM_FALSE;

    if (!__atomic_compare_exchange_n(&g_shm_fallback_thread_started, &expected, CM_TRUE, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        LOG_RUN_INF("[mes_shm] fallback worker already scheduled");
        return CM_SUCCESS;
    }

    g_shm_fallback_trigger = trigger;
    g_shm_fallback_peer_src = peer_src;

    if (cm_create_thread(mes_shm_fallback_worker_entry, 0, NULL, &g_shm_fallback_thread) != CM_SUCCESS) {
        g_shm_fallback_thread_started = CM_FALSE;
        mes_shm_clear_fallback_in_progress();
        LOG_RUN_ERR("[mes_shm] failed to create fallback worker thread");
        return CM_ERROR;
    }

#ifndef WIN32
    /* Detach so no one joins this worker (especially not from ub_comm). */
    (void)pthread_detach(g_shm_fallback_thread.id);
#endif
    LOG_RUN_INF("[mes_shm] scheduled fallback worker (trigger=%s peer=%u)",
        (trigger == MES_SHM_FALLBACK_FROM_PEER) ? "peer_notify" : "local_fault", (unsigned)peer_src);
    return CM_SUCCESS;
}

static void mes_shm_handle_peer_fallback_notify(inst_type src_inst)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    bool8 was_degraded;

    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        return;
    }

    was_degraded = (bool8)__atomic_exchange_n(&ctx->shm_degraded_to_tcp, CM_TRUE, __ATOMIC_ACQ_REL);
    if (was_degraded == CM_TRUE) {
        return;
    }

    mes_shm_fence_channels_on_degrade();

    LOG_RUN_WAR("[mes_shm] peer inst %u notified SHM to TCP fallback, scheduling worker",
        (unsigned)src_inst);

    if (mes_shm_schedule_fallback_worker(MES_SHM_FALLBACK_FROM_PEER, src_inst) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes_shm] schedule fallback worker failed on peer notify from inst %u",
            (unsigned)src_inst);
    }
}

void mes_shm_handle_ub_fault(const char *site)
{
    mes_context_t *ctx = &MES_GLOBAL_INST_MSG.mes_ctx;
    bool8 was_degraded;

    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        return;
    }

    LOG_RUN_WAR("[mes_shm] SIGBUS fault captured at %s", (site != NULL) ? site : "unknown");

    was_degraded = (bool8)__atomic_exchange_n(&ctx->shm_degraded_to_tcp, CM_TRUE, __ATOMIC_ACQ_REL);
    if (was_degraded == CM_TRUE) {
        return;
    }

    mes_shm_fence_channels_on_degrade();

    /* Offload cleanup/deinit off the faulting thread. */
    if (mes_shm_schedule_fallback_worker(MES_SHM_FALLBACK_FROM_FAULT, 0) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes_shm] schedule fallback worker failed after fault at %s",
            (site != NULL) ? site : "unknown");
    }
}

void mes_ub_fallback_recv_callback(const message_t *msg, void *ctx)
{
    (void)ctx;

    if (msg->header.body_length < sizeof(mes_message_head_t)) {
        LOG_RUN_ERR("[mes_shm fallback callback] Invalid fallback notify size: %u.", msg->header.body_length);
        return;
    }
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        return;
    }
    mes_message_head_t *notify_head = (mes_message_head_t *)msg->body;
    mes_shm_handle_peer_fallback_notify((inst_type)notify_head->src_inst);
}

