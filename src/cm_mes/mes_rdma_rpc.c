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
 * mes_rdma_rpc.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rdma_rpc.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "securec.h"
#include "mes_rpc.h"
#include "mes_func.h"
#include "cm_error.h"
#include "cm_log.h"
#include "cm_file.h"
#include "mes_msg_pool.h"
#include "mes_interface.h"
#include "mes_metadata.h"
#include "mes_rpc_ulog4c.h"
#include "mes_rpc_openssl_dl.h"
#include "mes_rpc_dl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pem.h"
#include "cm_file.h"

#define RECONNECT_SLEEP_TIME 1000

typedef enum {
    OCK_CONFIG_ZERO = 0,
    OCK_CONFIG_ONE,
    OCK_CONFIG_TWO,
    OCK_CONFIG_ALL,
} OCK_CONFIG_NUM;

#define OCK_CONFIG_BIND_CPU_STR_LEN 16
#define OCK_WORKER_NUM_STR_LEN      16
#define WRK_THR_GRP_NAME    "worker.thread.groups"
#define USE_EXCLUSIVE_NET   "netstack.exclusive.enable"
#define USE_POLL_SERVER     "worker.poll.enable"
#define OCK_RPC_YES         "yes"
#define OCK_RPC_NO          "no"
#define OCK_WRK_CPU_SET     "worker.thread.cpuset"
#define OCK_SEP_CPU_SET     "-"

#define PATH_LENGTH PATH_MAX
#define OCK_RPC_ENV_PATH   "OCK_RPC_LIB_PATH"
#define ULOG_SO_NAME    "libulog.so"
#define OCK_RPC_SO_NAME "librpc_ucx.so"

// Ulog input param
#define ULOG_FILE_OUTPUT    1
#define ULOG_ERR_LOG_LEVEL  4
#define ULOG_DEFAULT_FILE_NAME  "ockrpc.log"
#define ULOG_FILE_SIZE      (1024 * 1024 * 10ULL)
#define ULOG_FILE_CNT       10

#define ERASE_FULL_1_NUM    (0xff)
#define ERASE_KEY_PASS_COUNT 30
#define CERT_FILE_OK (1)
#define CERT_VERIFY_SUCCESS 1
#define CERT_VERIFY_FAILED (-1)

typedef struct ockrpc_ssl_cfg {
    char ca_file[PATH_MAX];
    char cert_file[PATH_MAX];
    char key_file[PATH_MAX];
    char crl_file[PATH_MAX];
    char cipher[PATH_MAX];
} ockrpc_ssl_cfg;

ockrpc_ssl_cfg g_ockrpc_ssl_cfg;

void mes_ockrpc_tls_get_cert(const char **certPath);
void mes_ockrpc_tls_get_CA_verify(const char **caPath, const char **crlPath, OckRpcTlsCertVerify *verify);

static inline char* ConstructBindCpuStr(uint8_t cpu_start, uint8_t cpu_end)
{
    static char bind_cpu_str[OCK_CONFIG_BIND_CPU_STR_LEN] = {0};
    int ret = snprintf_s(bind_cpu_str, OCK_CONFIG_BIND_CPU_STR_LEN, OCK_CONFIG_BIND_CPU_STR_LEN - 1,
        "%u%s%u", cpu_start, OCK_SEP_CPU_SET, cpu_end);
    if (ret > OCK_CONFIG_BIND_CPU_STR_LEN) {
        LOG_RUN_ERR("bind cpu str err, len(%d)", ret);
    }
    return bind_cpu_str;
}

enum MesRpcServiceId {
    DEFAULT_RPC_SERVICE_ID = 0,
    RPC_CONNECTION_REQ,
    RPC_CONNECTION_CMD,
    RPC_CONNECTION_HEARTBEAT,
};

static inline void mes_clear_rdma_rpc_server(void)
{
    cm_rwlock_wlock(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_lock);
    if (MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_handle != 0) {
        OckRpcServerDestroy(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_handle);
    }
    cm_rwlock_unlock(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_lock);
}

static int mes_get_lib_path(char* rpcPath)
{
    char* tmp = getenv(OCK_RPC_ENV_PATH);
    if (tmp == NULL) {
        LOG_RUN_ERR("mes getenv %s failed.", OCK_RPC_ENV_PATH);
        return CM_ERROR;
    }
#ifdef WIN32
    if (!_fullpath(rpcPath, tmp, PATH_MAX - 1)) {
        LOG_RUN_ERR("_fullpath ock_log_path failed");
        return CM_ERROR;
    }
#else
    if (realpath(tmp, rpcPath) == NULL) {
        LOG_RUN_ERR("realpath ock_log_path failed");
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

static int mes_init_ulog(void)
{
    char logPath[PATH_MAX] = {0};
    char *logPathPtr = logPath;
    char path[PATH_MAX] = {0};
#ifdef WIN32
    if (!_fullpath(path, MES_GLOBAL_INST_MSG.profile.ock_log_path, MES_MAX_LOG_PATH - 1)) {
        LOG_RUN_ERR("_fullpath ock_log_path failed");
        return CM_ERROR;
    }
#else
    if (realpath(MES_GLOBAL_INST_MSG.profile.ock_log_path, path) == NULL) {
        LOG_RUN_ERR("realpath ock_log_path failed");
        return CM_ERROR;
    }
#endif
    if (cm_access_file(path, F_OK | R_OK | W_OK) != CM_SUCCESS) {
        LOG_RUN_ERR("access log path(%s) failed.", path);
        return CM_ERROR;
    }
    int ret = snprintf_s(logPath, PATH_MAX, PATH_MAX - 1, "%s/%s", path, ULOG_DEFAULT_FILE_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("snprintf path(%s) + filename(%s) failed", path, ULOG_DEFAULT_FILE_NAME);
        return CM_ERROR;
    }
    
    return ULOG_Init(ULOG_FILE_OUTPUT, ULOG_ERR_LOG_LEVEL, logPathPtr, ULOG_FILE_SIZE, ULOG_FILE_CNT);
}

static int mes_init_rdma_dlopen_so(void)
{
    char rpcPath[PATH_LENGTH] = {0};
    int ret = mes_get_lib_path(rpcPath);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    // init ulog dlopen
    char ockUlogDlPath[PATH_LENGTH] = {0};
    ret = snprintf_s(ockUlogDlPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", rpcPath, ULOG_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct ulog dl path failed, ret %d.", ret);
        return CM_ERROR;
    }
    ret = InitUlogDl(ockUlogDlPath, PATH_LENGTH);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes init UlogDl failed.");
        return CM_ERROR;
    }

    // init ockrpc dlopen
    char ockRpcDlPath[PATH_LENGTH] = {0};
    ret = snprintf_s(ockRpcDlPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", rpcPath, OCK_RPC_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct rpc dl failed, ret %d.", ret);
        return CM_ERROR;
    }
    ret = InitOckRpcDl(ockRpcDlPath, PATH_LENGTH);
    if (ret != CM_SUCCESS) {
        FinishUlogDl();
        LOG_RUN_ERR("mes init OckRpcDl failed.");
        return CM_ERROR;
    }

    static bool32 ulog_init = CM_FALSE;
    if (!ulog_init) {
        ret = mes_init_ulog();
        if (ret != 0) {
            LOG_RUN_ERR("ULog_Init failed, ret %d", ret);
            FinishOckRpcDl();
            FinishUlogDl();
            return CM_ERROR;
        }
        ulog_init = CM_TRUE;
    }

    if (OpensslDlopenAndSet((const char*)rpcPath) != DL_OPENSSL_OK) {
        LOG_RUN_ERR("mes set ock openssl libpath failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int mes_init_ock_server_configs(RpcConfigPair* pairs, OckRpcCreateConfig* configs,
    char ock_worker_num[OCK_WORKER_NUM_STR_LEN])
{
    int ret;
    uint8_t start_cpu = MES_GLOBAL_INST_MSG.profile.rdma_rpc_bind_core_start;
    uint8_t end_cpu = MES_GLOBAL_INST_MSG.profile.rdma_rpc_bind_core_end;
    configs->configs.size = OCK_CONFIG_ALL;
    configs->mask = (uint64_t)OCK_RPC_CONFIG_USE_SERVER_CTX_BUILD | (uint64_t)OCK_RPC_CONFIG_USE_RPC_CONFIGS;
    configs->serverCtxbuilder = OckRpcServerCtxBuilderThreadLocal;
    configs->serverCtxCleanup = OckRpcServerCtxCleanupThreadLocal;
    configs->configs.pairs = pairs;
    pairs[OCK_CONFIG_ZERO].key = WRK_THR_GRP_NAME;
    pairs[OCK_CONFIG_ZERO].value = ock_worker_num;
    pairs[OCK_CONFIG_ONE].key = USE_POLL_SERVER;
    if (MES_GLOBAL_INST_MSG.profile.rdma_rpc_use_busypoll) {
        pairs[OCK_CONFIG_ONE].value = OCK_RPC_YES;
    } else {
        pairs[OCK_CONFIG_ONE].value = OCK_RPC_NO;
    }
    
    if (MES_GLOBAL_INST_MSG.profile.rdma_rpc_is_bind_core) {
        pairs[OCK_CONFIG_TWO].key = OCK_WRK_CPU_SET;
        pairs[OCK_CONFIG_TWO].value = ConstructBindCpuStr(start_cpu, end_cpu);
        ret = snprintf_s(ock_worker_num, OCK_WORKER_NUM_STR_LEN, OCK_WORKER_NUM_STR_LEN - 1, "%d",
            ((end_cpu - start_cpu) + 1));
    } else {
        configs->configs.size--;
        ret = snprintf_s(ock_worker_num, OCK_WORKER_NUM_STR_LEN, OCK_WORKER_NUM_STR_LEN - 1,
            "%u", MES_GLOBAL_INST_MSG.profile.channel_cnt);
    }
    if (ret < 0) {
        LOG_RUN_ERR("construct ock work num failed, ret %d.", ret);
        return CM_ERROR;
    }

    if (g_ssl_enable) {
        configs->mask |= OCK_RPC_CONFIG_USE_SSL_CALLBACK;
        configs->getCaAndVerify = mes_ockrpc_tls_get_CA_verify;
        configs->getCert = mes_ockrpc_tls_get_cert;
        configs->getPriKey = mes_ockrpc_tls_get_private_key;
        OckRpcDisableSecureHmac();
    }

    return CM_SUCCESS;
}

static int mes_init_rdma_rpc_server(void)
{
    rdma_rpc_lsnr_t* rdma_lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma;
    mes_addr_t *addr = NULL;
    uint32 index;
    if (mes_get_inst_net_add_index(MES_GLOBAL_INST_MSG.profile.inst_id, &index) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_init_rdma_rpc_server, find addr failed");
        return CM_ERROR;
    }
    addr = &MES_GLOBAL_INST_MSG.profile.inst_net_addr[index];

    (void)cm_rwlock_init(&rdma_lsnr->server_lock);
    cm_rwlock_wlock(&rdma_lsnr->server_lock);
    if (rdma_lsnr->server_handle != 0) {
        OckRpcServerDestroy(rdma_lsnr->server_handle);
    }

    RpcConfigPair pairs[OCK_CONFIG_ALL];
    OckRpcCreateConfig configs;
    char ock_worker_num[OCK_WORKER_NUM_STR_LEN] = {0};
    
    int ret = mes_init_ock_server_configs(pairs, &configs, ock_worker_num);
    if (ret != OCK_RPC_OK) {
        cm_rwlock_unlock(&rdma_lsnr->server_lock);
        return ret;
    }
    
    ret = OckRpcServerCreateWithCfg(addr->ip, addr->port, &rdma_lsnr->server_handle, &configs);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("OckRpcServerCreate failed, inst_id(%u), ip(%s), port(%hu)", MES_GLOBAL_INST_MSG.profile.inst_id,
            addr->ip, addr->port);
        cm_rwlock_unlock(&rdma_lsnr->server_lock);
        return CM_ERROR;
    }
    cm_rwlock_unlock(&rdma_lsnr->server_lock);
    return CM_SUCCESS;
}

int mes_init_rdma_rpc_resource(void)
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
        LOG_RUN_ERR("[MES] alloc send channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_alloc_channel_msg_queue(CM_FALSE);
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channels();
        LOG_RUN_ERR("[MES] alloc recv channel mesqueue failed.");
        return CM_ERROR;
    }

    ret = mes_init_rdma_dlopen_so();
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channel_msg_queue(CM_FALSE);
        mes_free_channels();
        LOG_RUN_ERR("mes init rdma dlopen so failed.");
        return ret;
    }

    ret = mes_init_rdma_rpc_server();
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channel_msg_queue(CM_FALSE);
        mes_free_channels();
        FinishOckRpcDl();
        FinishUlogDl();
        LOG_RUN_ERR("mes init rdma rpc server failed.");
        return ret;
    }
    
    ret = mes_register_rdma_rpc_proc_func();
    if (ret != CM_SUCCESS) {
        mes_free_channel_msg_queue(CM_TRUE);
        mes_free_channel_msg_queue(CM_FALSE);
        mes_clear_rdma_rpc_server();
        mes_free_channels();
        FinishOckRpcDl();
        FinishUlogDl();
        LOG_RUN_ERR("[mes]: reg rdma rpc proc func failed.");
        return ret;
    }

    return CM_SUCCESS;
}

int mes_start_rdma_rpc_lsnr(void)
{
    int ret = OckRpcServerStart(MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_handle);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("OckRpcServerStart failed, inst_id(%u)", MES_GLOBAL_INST_MSG.profile.inst_id);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void mes_rdma_rpc_default_proc_func(OckRpcServerContext handle, OckRpcMessage msg)
{
    mes_msgqueue_t *my_queue = NULL;
    mq_context_t *mq_ctx = &MES_GLOBAL_INST_MSG.recv_mq;
    mes_message_head_t* head = (mes_message_head_t*)msg.data;
    uint32_t channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->src_inst][channel_id];
    mes_pipe_t *pipe = &channel->pipe[MES_PRIORITY(head->flags)];
    my_queue = &mq_ctx->channel_private_queue[head->src_inst][channel_id];

    (void)cm_atomic_inc(&(pipe->recv_count));
    char *data = mes_alloc_buf_item_fc(head->size, CM_FALSE, head->src_inst, MES_PRIORITY(head->flags));
    if (SECUREC_UNLIKELY(data == NULL)) {
        LOG_RUN_ERR("[mes proc]: get buf item failed, size(%u).", (uint32)head->size);
        OckRpcServerCleanupCtx(handle);
        return;
    }

    if (memcpy_sp((void*)data, head->size, msg.data, head->size) != EOK) {
        LOG_RUN_ERR("[mes proc] malloc data failed, size(%lu).", msg.len);
        OckRpcServerCleanupCtx(handle);
        return;
    }

    mes_message_t mes_msg;
    MES_MESSAGE_ATTACH((&mes_msg), (void*)data);

    mes_process_message(my_queue, &mes_msg);
    OckRpcServerCleanupCtx(handle);
}

static inline void get_cpu_affinity(cpu_set_t* get)
{
#ifndef WIN32
    if (sched_getaffinity(0, sizeof(*get), get) == -1) {
        return;
    }
#endif
}

static inline void set_cpu_affinity(cpu_set_t *set)
{
#ifndef WIN32
    if (sched_setaffinity(0, sizeof(*set), set) == -1) {
        return;
    }
#endif
}

static void mes_rdma_rpc_connection_proc_func(OckRpcServerContext handle, OckRpcMessage msg)
{
    static thread_local_var bool32 init_flag = CM_FALSE;
    char *reg_data = NULL;
    mes_thread_init_t cb_thread_init = mes_get_worker_init_cb();
    if (!init_flag && cb_thread_init != NULL) {
#ifdef WIN32
        cb_thread_init(CM_FALSE, &reg_data);
#else
        cpu_set_t set;
        CPU_ZERO(&set);
        get_cpu_affinity(&set);
        cb_thread_init(CM_FALSE, &reg_data);
        set_cpu_affinity(&set);
#endif
        init_flag = CM_TRUE;
        LOG_DEBUG_INF("[mes]: status_notify thread init callback: rpc channel entry cb_thread_init done");
    }
    if (msg.len != sizeof(mes_message_head_t) + sizeof(version_proto_code_t)) {
        LOG_RUN_ERR("recv VERSION_PROTO_CODE message error, size(%lu), expect(%lu).", msg.len, sizeof(uint32_t));
        OckRpcServerCleanupCtx(handle);
        return;
    }

    mes_message_head_t *head = (mes_message_head_t *)msg.data;
    mes_channel_t *channel =
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->src_inst][MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid)];
    mes_pipe_t *pipe = &channel->pipe[MES_PRIORITY(head->flags)];

    version_proto_code_t *version_proto_code = (version_proto_code_t *)((char *)msg.data + sizeof(mes_message_head_t));
    if (!IS_BIG_ENDIAN) {
        // Unified big-endian mode for VERSION
        version_proto_code->version = cs_reverse_uint32(version_proto_code->version);
    }
    pipe->recv_pipe.version = version_proto_code->version;
    if (version_proto_code->proto_code != CM_PROTO_CODE) {
        LOG_RUN_ERR("recv PROTO_CODE message error, CODE(%u), expect(%u).", version_proto_code->proto_code,
            CM_PROTO_CODE);
        OckRpcServerCleanupCtx(handle);
        return;
    }

    link_ready_ack_t ack;
    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    ack.flags = 0;

    OckRpcMessage reply = {.data = &ack, .len = sizeof(ack)};
    int ret = OckRpcServerReply(handle, RPC_CONNECTION_REQ, &reply, NULL);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("send reply failed.");
        OckRpcServerCleanupCtx(handle);
        return;
    }

    OckRpcServerCleanupCtx(handle);
}

static void mes_rdma_rpc_connection_cmd_func(OckRpcServerContext handle, OckRpcMessage msg)
{
    if (msg.len != sizeof(mes_message_head_t)) {
        LOG_RUN_ERR("recv connection cmd message error, size(%lu), expect(%lu).", msg.len, sizeof(uint32_t));
        OckRpcServerCleanupCtx(handle);
        return;
    }

    mes_message_head_t* head = (mes_message_head_t*)msg.data;
    if (head->cmd != MES_CMD_CONNECT || head->src_inst >= MES_MAX_INSTANCES) {
        LOG_RUN_ERR("CONNECT_CMD message error, cmd(%d), inst_id(%d), channel_id(%d).", head->cmd,
            head->src_inst, head->caller_tid);
        OckRpcServerCleanupCtx(handle);
        return;
    }

    LOG_RUN_INF("recv CONNECT_CMD message, inst_id(%d), channel_id(%d), priority(%d)", head->src_inst, head->caller_tid,
        MES_PRIORITY(head->flags));

    mes_channel_t *channel =
        &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->src_inst][MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid)];
    mes_pipe_t *pipe = &channel->pipe[MES_PRIORITY(head->flags)];
    cm_rwlock_wlock(&pipe->recv_lock);
    pipe->recv_pipe_active = CM_TRUE;
    cm_rwlock_unlock(&pipe->recv_lock);
}

static void mes_rdma_rpc_connection_heartbeat_func(OckRpcServerContext handle, OckRpcMessage msg)
{
    /* pass */
}

int mes_register_rdma_rpc_proc_func(void)
{
    OckRpcServer server = MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_handle;
    if ((void*)server == NULL) {
        LOG_RUN_ERR("register rdma rpc proc func failed, server handler(%p).", (void*)server);
        return CM_ERROR;
    }
    
    OckRpcService service = {.id = DEFAULT_RPC_SERVICE_ID, .handler = mes_rdma_rpc_default_proc_func};
    int ret = OckRpcServerAddService(server, &service);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_WAR("add service DEFAULT_RPC_SERVICE_ID failed, server handle(%p), ret(%d)", (void*)server, ret);
        return CM_ERROR;
    }

    OckRpcService ackservice = {.id = RPC_CONNECTION_REQ, .handler = mes_rdma_rpc_connection_proc_func};
    ret = OckRpcServerAddService(server, &ackservice);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_WAR("add service RPC_CONNECTION_REQ failed, server handle(%p), ret(%d)", (void*)server, ret);
        return CM_ERROR;
    }

    OckRpcService conncmdService = {.id = RPC_CONNECTION_CMD, .handler = mes_rdma_rpc_connection_cmd_func};
    ret = OckRpcServerAddService(server, &conncmdService);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_WAR("add service RPC_CONNECTION_CMD failed, server handle(%p), ret(%d)", (void*)server, ret);
        return CM_ERROR;
    }

    OckRpcService conn_heartbeat_service = {.id = RPC_CONNECTION_HEARTBEAT,
        .handler = mes_rdma_rpc_connection_heartbeat_func};
    ret = OckRpcServerAddService(server, &conn_heartbeat_service);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_WAR("add service conn_heartbeat_service failed, server handle(%p), ret(%d)",
            (void *)server, ret);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void mes_set_pipe_ack(link_ready_ack_t* ack, cs_pipe_t *pipe)
{
    uint8 local_endian;
    local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    if (local_endian != ack->endian) {
        ack->flags = cs_reverse_int16(ack->flags);
        ack->version = cs_reverse_int32(ack->version);
        pipe->options |= CSO_DIFFERENT_ENDIAN;
    }

    if ((ack->flags & CSO_SUPPORT_SSL) != 0) {
        pipe->options |= (uint32)CSO_SUPPORT_SSL;
    } else {
        pipe->options &= (uint32)~CSO_SUPPORT_SSL;
    }

    pipe->version = ack->version;
}

static int mes_rdma_client_connect(uint32 inst_id, uint32_t channel_id, mes_priority_t priority)
{
    mes_addr_t *addr = NULL;
    uint32 index;
    if (mes_get_inst_net_add_index(inst_id, &index) != CM_SUCCESS) {
        LOG_RUN_ERR("[mes] mes_rdma_client_connect, find addr failed");
        return CM_ERROR;
    }
    addr = &MES_GLOBAL_INST_MSG.profile.inst_net_addr[index];
    
    OckRpcCreateConfig cfgs;
    cfgs.mask = OCK_RPC_CONFIG_USE_RPC_CONFIGS;
    RpcConfigPair pairs;
    RpcConfigs configs;
    configs.size = 1;
    configs.pairs = &pairs;
    pairs.key = USE_EXCLUSIVE_NET;
    pairs.value = OCK_RPC_YES;
    cfgs.configs = configs;

    if (g_ssl_enable) {
        cfgs.mask |= OCK_RPC_CONFIG_USE_SSL_CALLBACK;
        cfgs.getCaAndVerify = mes_ockrpc_tls_get_CA_verify;
        cfgs.getCert = mes_ockrpc_tls_get_cert;
        cfgs.getPriKey = mes_ockrpc_tls_get_private_key;
    }

    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];
    int ret = OckRpcClientConnectWithCfg(addr->ip, addr->port, &pipe->rdma_client.client_handle, &cfgs);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("OckRpcClientConnectWithCfg failed, ret %d", ret);
        return CM_ERROR;
    }

    OckRpcClientSetTimeout(pipe->rdma_client.client_handle, pipe->send_pipe.socket_timeout);

    return CM_SUCCESS;
}

static int mes_rdma_send_connect_protocode(uint32 inst_id, uint32_t channel_id, mes_priority_t priority)
{
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];
    mes_message_head_t head = { 0 };
    head.cmd = RPC_CONNECTION_REQ;
    head.dst_inst = MES_INSTANCE_ID(pipe->channel->id);
    head.src_inst = MES_GLOBAL_INST_MSG.profile.inst_id;
    head.caller_tid = MES_CHANNEL_ID(pipe->channel->id); // use caller_tid to represent channel id
    head.size = (uint16)sizeof(mes_message_head_t);
    head.ruid = 0;
    head.flags = pipe->priority;
    head.version = 0;

    version_proto_code_t version_proto_code = {.version = CS_LOCAL_VERSION, .proto_code = CM_PROTO_CODE};
    if (!IS_BIG_ENDIAN) {
        // Unified big-endian mode for VERSION
        version_proto_code.version = cs_reverse_uint32(version_proto_code.version);
    }
    uint32 data_len = (uint32)(sizeof(mes_message_head_t) + sizeof(version_proto_code_t));
    char *data = (char *)malloc(data_len);
    if (data == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)data_len, "malloc memory");
        return CM_ERROR;
    }
    (void)memcpy_s(data, data_len, &head, sizeof(mes_message_head_t));
    (void)memcpy_s(data + sizeof(mes_message_head_t), data_len, &version_proto_code, sizeof(version_proto_code_t));
    OckRpcMessage request = {.data = (void*)data, .len = data_len};
    OckRpcMessage response = {0};

    int ret = OckRpcClientCall(pipe->rdma_client.client_handle, RPC_CONNECTION_REQ, &request, &response, NULL);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("RpcClientCall failed, RPC_CONNECTION_REQ message, inst_id(%u), channel_id(%u), priority(%u)",
                    inst_id, channel_id, priority);
        return CM_ERROR;
    }

    // reverse if endian is different
    if (response.len != sizeof(link_ready_ack_t)) {
        if (response.data != NULL) {
            free(response.data);
        }
        LOG_RUN_ERR("send connect protocode failed, recv ack size(%lu) != expect(%lu), inst_id(%u), channel_id(%u)",
                    response.len, sizeof(link_ready_ack_t), inst_id, channel_id);
        return CM_ERROR;
    }
    link_ready_ack_t* ack = response.data;
    mes_set_pipe_ack(ack, &pipe->send_pipe);

    if (response.data != NULL) {
        free(response.data);
    }

    return CM_SUCCESS;
}

static int mes_rdma_send_connect_cmd(uint32 inst_id, uint32_t channel_id, mes_priority_t priority)
{
    // send ack message to server, set recv_pipe_acitive = true
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];
    mes_message_head_t head = { 0 };
    head.cmd = MES_CMD_CONNECT;
    head.dst_inst = MES_INSTANCE_ID(pipe->channel->id);
    head.src_inst = MES_GLOBAL_INST_MSG.profile.inst_id;
    head.caller_tid = MES_CHANNEL_ID(pipe->channel->id); // use caller_tid to represent channel id
    head.size = (uint16)sizeof(mes_message_head_t);
    head.ruid = 0;
    head.flags = pipe->priority;
    head.version = 0;
    OckRpcMessage request = {.data = (void*)&head, .len = sizeof(mes_message_head_t)};
    int ret = OckRpcClientCall(pipe->rdma_client.client_handle, RPC_CONNECTION_CMD, &request, NULL, NULL);
    if (ret != OCK_RPC_OK) {
        LOG_RUN_ERR("RpcClientCall failed, RPC_CONNECTION_CMD message, inst_id(%u), channel_id(%u), priority(%u)",
                    inst_id, channel_id, priority);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void mes_rdma_rpc_try_connect(uintptr_t pipePtr)
{
    mes_pipe_t *pipe = (mes_pipe_t *)pipePtr;
    inst_type inst_id = MES_INSTANCE_ID(pipe->channel->id);
    uint32_t channel_id = MES_CHANNEL_ID(pipe->channel->id);
    mes_priority_t priority = pipe->priority;
    rwlock_t *send_lock = &pipe->send_lock;
    cm_rwlock_wlock(send_lock);
    if (pipe->rdma_client.client_handle != 0) {
        LOG_RUN_ERR("mes_rdma_rpc_connect failed, rpc instance is not nullptr, \
            inst_id(%u), channel_id(%u), priority(%u)", inst_id, channel_id, priority);
        cm_rwlock_unlock(send_lock);
        return;
    }

    int ret = mes_rdma_client_connect(inst_id, channel_id, priority);
    if (ret != CM_SUCCESS) {
        cm_rwlock_unlock(send_lock);
        return;
    }

    ret = mes_rdma_send_connect_protocode(inst_id, channel_id, priority);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes_rdma_rpc_connect send proto code failed, inst_id(%u), channel_id(%u), priority(%u)",
                    inst_id, channel_id, priority);
        cm_rwlock_unlock(send_lock);
        mes_rdma_rpc_disconnect(inst_id, channel_id, priority);
        return;
    }

    ret = mes_rdma_send_connect_cmd(inst_id, channel_id, priority);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes_rdma_rpc_connect send connect cmd failed, inst_id(%u), channel_id(%u), priority(%u)",
                    inst_id, channel_id, priority);
        cm_rwlock_unlock(send_lock);
        mes_rdma_rpc_disconnect(inst_id, channel_id, priority);
        return;
    }
    cm_rwlock_unlock(send_lock);

    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    pipe = &channel->pipe[priority];
    cm_rwlock_wlock(&pipe->send_lock);
    pipe->send_pipe_active = CM_TRUE;
    cm_rwlock_unlock(&pipe->send_lock);

    LOG_RUN_INF(
        "mes_rdma_rpc_connect success, inst_id(%u), channel_id(%u), priority(%u)", inst_id, channel_id, priority);
}

static inline void mes_rdma_rpc_close_recv_pipe(uint32 inst_id, uint32_t channel_id, mes_priority_t priority)
{
    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];
    cm_rwlock_wlock(&pipe->recv_lock);
    pipe->recv_pipe_active = CM_FALSE;
    cm_rwlock_unlock(&pipe->recv_lock);
}

void mes_rdma_rpc_disconnect(uint32 inst_id, uint32_t channel_id, mes_priority_t priority)
{
    LOG_RUN_INF(
        "mes_rdma_rpc_disconnect start, inst_id(%u), channel_id(%u), priority(%u)", inst_id, channel_id, priority);

    mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][channel_id];
    mes_pipe_t *pipe = &channel->pipe[priority];
    cm_rwlock_wlock(&pipe->send_lock);
    pipe->send_pipe_active = CM_FALSE;

    if (pipe->rdma_client.client_handle == 0) {
        cm_rwlock_unlock(&pipe->send_lock);
        LOG_RUN_ERR("mes_rdma_rpc_disconnect failed, rpc instance is nullptr, \
            inst_id(%u), channel_id(%u), priority(%u)", inst_id, channel_id, priority);
        return ;
    }

    OckRpcClientDisconnect(pipe->rdma_client.client_handle);
    pipe->rdma_client.client_handle = 0;
    cm_rwlock_unlock(&pipe->send_lock);
    LOG_RUN_INF(
        "mes_rdma_rpc_disconnect complete, inst_id(%u), channel_id(%u), priority(%u)", inst_id, channel_id, priority);
    return;
}

void mes_rdma_rpc_disconnect_handle(uint32 inst_id, bool32 wait)
{
    LOG_RUN_INF("mes_rdma_rpc_disconnect_handle start, inst_id(%u)", inst_id);
    for (uint32_t i = 0; i < MES_GLOBAL_INST_MSG.profile.channel_cnt; ++i) {
        if (MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id] == NULL) {
            return;
        }
        mes_channel_t *channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[inst_id][i];
        for (uint32 j = 0; j < MES_GLOBAL_INST_MSG.profile.priority_cnt; j++) {
            mes_pipe_t *pipe = &channel->pipe[j];
            cm_close_thread(&pipe->thread);
            mes_rdma_rpc_close_recv_pipe(inst_id, i, j);
            mes_rdma_rpc_disconnect(inst_id, i, j);
        }
    }
}

int mes_rdma_rpc_send_data(const void* msg_data)
{
    int ret;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    CM_RETURN_IFERR(mes_check_send_head_info(head));

    uint32_t channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
    mes_channel_t* channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][channel_id];
    uint32 priority = MES_PRIORITY(head->flags);
    mes_pipe_t *pipe = &channel->pipe[priority];

    cm_rwlock_wlock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_rwlock_unlock(&pipe->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "send pipe to instance %d is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    OckRpcClient client = pipe->rdma_client.client_handle;
    OckRpcMessage request = {.data = (void*)msg_data, .len = head->size};

    ret = OckRpcClientCall(client, DEFAULT_RPC_SERVICE_ID, &request, NULL, NULL);
    if (ret != OCK_RPC_OK) {
        cm_rwlock_unlock(&pipe->send_lock);
        uint32 i = 0;
        (void)mes_get_inst_net_add_index(head->dst_inst, &i);
        LOG_RUN_ERR("OckRpcClientCall failed, cmd(%d), inst_id(%d), dst_id(%d), size(%d),\
            headsize(%lu), ip(%s), port(%d), ruid->rid(%llu), ruid->rsn(%llu)",
                    head->cmd, head->src_inst, head->dst_inst, head->size, sizeof(mes_message_head_t),
                    MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].ip,
                    MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].port,
                    (uint64)MES_RUID_GET_RID((head)->ruid), (uint64)MES_RUID_GET_RSN((head)->ruid));
        mes_rdma_rpc_disconnect(head->dst_inst, channel_id, priority);

        return CM_ERROR;
    }
    cm_rwlock_unlock(&pipe->send_lock);
    (void)cm_atomic_inc(&(pipe->send_count));

    return CM_SUCCESS;
}

void init_ockrpc_client_iov_param(OckRpcClientCallParams* params, mes_bufflist_t *buff_list, OckRpcMessage* msgs,
    OckRpcClient client)
{
    params->mask = OCK_RPC_CLIENT_CALL_DEFAULT;
    params->client = client;
    params->context = 0;
    params->msgId = DEFAULT_RPC_SERVICE_ID;
    params->reqIov.count = buff_list->cnt;
    params->reqIov.msgs = msgs;
    for (uint32 i = 0; i < buff_list->cnt; ++i) {
        params->reqIov.msgs[i].data = buff_list->buffers[i].buf;
        params->reqIov.msgs[i].len = buff_list->buffers[i].len;
    }
    
    params->rspIov.count = 0;
    params->rspIov.msgs = NULL;
    params->done = NULL;
}

int mes_rdma_rpc_send_bufflist(mes_bufflist_t *buff_list)
{
    int ret;
    mes_message_head_t *head = (mes_message_head_t *)((void*)buff_list->buffers[0].buf);
    CM_RETURN_IFERR(mes_check_send_head_info(head));

    uint32_t channel_id = MES_CALLER_TID_TO_CHANNEL_ID(head->caller_tid);
    mes_channel_t* channel = &MES_GLOBAL_INST_MSG.mes_ctx.channels[head->dst_inst][channel_id];
    uint32 priority = MES_PRIORITY(head->flags);
    mes_pipe_t *pipe = &channel->pipe[priority];

    cm_rwlock_wlock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_rwlock_unlock(&pipe->send_lock);
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "send pipe to instance %d is not ready", head->dst_inst);
        return ERR_MES_SENDPIPE_NO_READY;
    }

    OckRpcClientCallParams param;
    OckRpcMessage msgs[MES_MAX_BUFFERLIST];
    init_ockrpc_client_iov_param(&param, buff_list, msgs, pipe->rdma_client.client_handle);

    ret = OckRpcClientCallWithParam(&param);
    if (ret != OCK_RPC_OK) {
        cm_rwlock_unlock(&pipe->send_lock);
        uint32 i = 0;
        (void)mes_get_inst_net_add_index(head->dst_inst, &i);
        LOG_RUN_ERR("OckRpcClientBuffListCall failed, cmd(%d), inst_id(%d), dst_id(%d), size(%d), headsize(%lu),\
            ip(%s), port(%d), ruid->rid(%llu), ruid->rsn(%llu)",
                    head->cmd, head->src_inst, head->dst_inst, head->size, sizeof(mes_message_head_t),
                    MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].ip,
                    MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].port,
                    (uint64)MES_RUID_GET_RID((head)->ruid), (uint64)MES_RUID_GET_RSN((head)->ruid));
        mes_rdma_rpc_disconnect(head->dst_inst, channel_id, priority);

        return CM_ERROR;
    }
    cm_rwlock_unlock(&pipe->send_lock);
    (void)cm_atomic_inc(&(pipe->send_count));

    return CM_SUCCESS;
}

void stop_rdma_rpc_lsnr(void)
{
    mes_clear_rdma_rpc_server();
    cm_rwlock_deinit(&MES_GLOBAL_INST_MSG.mes_ctx.lsnr.rdma.server_lock);
}

int mes_ockrpc_init_ssl(void)
{
    param_value_t param_value;

    // Required parameters
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CA, &param_value));
    if (memcpy_sp(g_ockrpc_ssl_cfg.ca_file, PATH_MAX, param_value.ssl_ca, CM_FULL_PATH_BUFFER_SIZE) != EOK) {
        LOG_RUN_INF("[MEC] cpy ca_file path failed.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_KEY, &param_value));
    if (memcpy_sp(g_ockrpc_ssl_cfg.key_file, PATH_MAX, param_value.ssl_key, CM_FULL_PATH_BUFFER_SIZE) != EOK) {
        LOG_RUN_INF("[MEC] copy key_file path failed.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CERT, &param_value));
    if (memcpy_sp(g_ockrpc_ssl_cfg.cert_file, PATH_MAX, param_value.ssl_cert, CM_FULL_PATH_BUFFER_SIZE)
        != EOK) {
        LOG_RUN_INF("[MEC] copy cert_file path failed.");
        return CM_ERROR;
    }

    if (CM_IS_EMPTY_STR(g_ockrpc_ssl_cfg.cert_file) ||
        CM_IS_EMPTY_STR(g_ockrpc_ssl_cfg.key_file) || CM_IS_EMPTY_STR(g_ockrpc_ssl_cfg.ca_file)) {
        LOG_RUN_INF("[MEC]mes_ockrpc_init_ssl: ssl is disabled.");
        return CM_ERROR;
    }

    // Optional parameters
    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CRL, &param_value));
    if (memcpy_sp(g_ockrpc_ssl_cfg.crl_file, PATH_MAX, param_value.ssl_crl, CM_FULL_PATH_BUFFER_SIZE) != EOK) {
        LOG_RUN_INF("[MEC] copy key_file path failed.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(mes_md_get_param(CBB_PARAM_SSL_CIPHER, &param_value));
    if (memcpy_sp(g_ockrpc_ssl_cfg.cipher, PATH_MAX, param_value.ssl_cipher, CM_MAX_SSL_CIPHER_LEN) != EOK) {
        LOG_RUN_INF("[MEC] copy key_file path failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void mes_ockrpc_tls_keypass_erase(char* keypass)
{
    uint32 len = CM_PASSWD_MAX_LEN + 1;
    for (uint32 i = 0; i < ERASE_KEY_PASS_COUNT; ++i) {
        int32 ret = memset_sp(keypass, len, 0, len);
        if (ret != EOK) {
            LOG_RUN_ERR("memset_sp keypass 0 failed, ret(%d)", ret);
        }

        ret = memset_sp(keypass, len, ERASE_FULL_1_NUM, len);
        if (ret != EOK) {
            LOG_RUN_ERR("memset_sp keypass full 1 failed, ret(%d)", ret);
        }
    }

    free(keypass);
}

void mes_ockrpc_tls_get_private_key(const char** privateKeyPath, char** keypass, OckRpcTlsKeypassErase *erase)
{
    ssl_config_t ssl_cfg = { 0 };
    uint32 max_passwd_size = CM_PASSWD_MAX_LEN + 1;
    char* passwd_plain = calloc(max_passwd_size, sizeof(char));
    if (passwd_plain == NULL) {
        LOG_RUN_ERR("malloc passwd_plain failed, size(%u)", max_passwd_size);
        return;
    }

    // verify ssl key password and KMC module
    if (mes_verify_ssl_key_pwd(&ssl_cfg, passwd_plain, CM_PASSWD_MAX_LEN) != CM_SUCCESS) {
        LOG_RUN_ERR("CBB verify ssl key password failed");
        (void)memset_s(passwd_plain, sizeof(passwd_plain), 0, sizeof(passwd_plain));
        free(passwd_plain);
        *privateKeyPath = NULL;
        *keypass = NULL;
        *erase = NULL;
        return;
    }

    *privateKeyPath = g_ockrpc_ssl_cfg.key_file;
    *keypass = passwd_plain;
    *erase = mes_ockrpc_tls_keypass_erase;
}

void mes_ockrpc_tls_get_cert(const char** certPath)
{
    *certPath = g_ockrpc_ssl_cfg.cert_file;
}

static X509_CRL *ockrpc_load_crl_file(const char* file)
{
    BIO *in = NULL;
    X509_CRL *crl = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        return NULL;
    }

    if (BIO_read_filename(in, file) <= 0) {
        (void)BIO_free(in);
        return NULL;
    }

    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    if (crl == NULL) {
        (void)BIO_free(in);
        return NULL;
    }

    (void)BIO_free(in);

    return crl;
}

static X509_CRL *LoadCertRevokListFile(const char *crlFile)
{
    X509_CRL *crl = NULL;

    // check whether file is exist
    if (access(crlFile, R_OK) != CM_SUCCESS) {
        LOG_RUN_ERR("crl file(%s) is not access.", crlFile);
        return NULL;
    }

    // load crl file
    crl = ockrpc_load_crl_file(crlFile);
    if (crl == NULL) {
        LOG_RUN_ERR("failed to load cert revocation list(%s).", crlFile);
        return NULL;
    }

    return crl;
}

static int32_t GetExpireAndEarlyDayFromCert(X509 *cert)
{
    ASN1_TIME *asnExpireTime = NULL;
    ASN1_TIME *asnEarlyTime = NULL;

    // get Expire time of cert
    asnExpireTime = X509_get_notAfter(cert);
    if (asnExpireTime == NULL) {
        LOG_RUN_ERR("Failed to get expire time.");
        return CERT_VERIFY_FAILED;
    }

    if (X509_cmp_time(asnExpireTime, NULL) == CERT_VERIFY_FAILED) {
        return CERT_VERIFY_FAILED;
    }

    asnEarlyTime = X509_get_notBefore(cert);
    if (asnEarlyTime == NULL) {
        LOG_RUN_ERR("Failed to get early time.");
        return CERT_VERIFY_FAILED;
    }

    if (X509_cmp_time(asnEarlyTime, NULL) != CERT_VERIFY_FAILED) {
        return CERT_VERIFY_FAILED;
    }

    return CERT_VERIFY_SUCCESS;
}

int mes_ockrpc_verify_cert(void* x509)
{
    int32_t result;

    X509_STORE_CTX *x509ctx = (X509_STORE_CTX *)x509;

    // verify cert
    result = X509_verify_cert(x509ctx);
    if (result != CERT_FILE_OK) {
        result = X509_STORE_CTX_get_error(x509ctx);
        LOG_RUN_ERR("verify cert file failed, ret(%d).", result);
        return CERT_VERIFY_FAILED;
    }

    X509 *cert = X509_STORE_CTX_get_current_cert(x509ctx);
    if (cert == NULL) {
        LOG_RUN_ERR("get cert failed.");
        return CERT_VERIFY_FAILED;
    } else {
        result = GetExpireAndEarlyDayFromCert(cert);
        if (result != CERT_VERIFY_SUCCESS) {
            LOG_RUN_ERR("certficate has been expired.");
            return CERT_VERIFY_FAILED;
        }
    }

    return CERT_VERIFY_SUCCESS;
}

int mes_ockrpc_tls_cert_verify(void* x509, const char* crlPath)
{
    int32 result;
    X509_STORE_CTX *x509ctx = (X509_STORE_CTX *)x509;

    if (crlPath == NULL || crlPath[0] == '\0') {
        return mes_ockrpc_verify_cert(x509);
    }

    // get X509_CRL structure from revok list file
    X509_CRL *crl = LoadCertRevokListFile(crlPath);
    if (crl == NULL) {
        LOG_RUN_ERR("load crl file failed, file(%s).", crlPath);
        return mes_ockrpc_verify_cert(x509);
    }
    
    X509_STORE *x509Store = X509_STORE_CTX_get0_store(x509ctx);
    X509_STORE_CTX_set_flags(x509ctx, (unsigned long)X509_V_FLAG_CRL_CHECK);
    result = X509_STORE_add_crl(x509Store, crl);
    if (result != CERT_FILE_OK) {
        LOG_RUN_ERR("store add crl failed, file(%s) ret(%d).", crlPath, result);
        X509_CRL_free(crl);
        return CERT_VERIFY_FAILED;
    }

    // verify X509 cert
    result = X509_verify_cert(x509ctx);
    if (result != CERT_FILE_OK) {
        result = X509_STORE_CTX_get_error(x509ctx);
        LOG_RUN_ERR("verify cert file failed, ret(%d).", result);
        X509_CRL_free(crl);
        return CERT_VERIFY_FAILED;
    }

    X509_CRL_free(crl);

    X509 *cert = X509_STORE_CTX_get_current_cert(x509ctx);
    if (cert == NULL) {
        LOG_RUN_ERR("get cert failed.");
        return CERT_VERIFY_FAILED;
    } else {
        // get expire time of cert
        result = GetExpireAndEarlyDayFromCert(cert);
        if (result != CERT_VERIFY_SUCCESS) {
            LOG_RUN_ERR("certficate has been expired.");
            return CERT_VERIFY_FAILED;
        }
    }

    return CERT_VERIFY_SUCCESS;
}

void mes_ockrpc_tls_get_CA_verify(const char **caPath, const char **crlPath,
    OckRpcTlsCertVerify *verify)
{
    *caPath = g_ockrpc_ssl_cfg.ca_file;
    *crlPath = g_ockrpc_ssl_cfg.crl_file;
    *verify = mes_ockrpc_tls_cert_verify;
}

void mes_rdma_stop_channels(void)
{
    if (!MES_GLOBAL_INST_MSG.mes_ctx.startChannelsTh) {
        return;
    }

    if (MES_GLOBAL_INST_MSG.profile.channel_cnt == 0) {
        LOG_RUN_ERR("channel_cnt %u is invalid", MES_GLOBAL_INST_MSG.profile.channel_cnt);
        return;
    }
    for (uint32 i = 0; i < MES_GLOBAL_INST_MSG.profile.inst_cnt; i++) {
        uint32 inst_id = MES_GLOBAL_INST_MSG.profile.inst_net_addr[i].inst_id;
        mes_disconnect(inst_id);
    }

    MES_GLOBAL_INST_MSG.mes_ctx.startChannelsTh = CM_FALSE;
    return;
}