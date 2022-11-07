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
 * mes_rpc_dl.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_dl.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include "securec.h"
#include "mes_rpc.h"
#include "cm_log.h"
#include "cm_utils.h"

typedef OckRpcStatus (*ServerCreateWithCfg)(const char* ip, uint16_t port, OckRpcServer* server,
    OckRpcCreateConfig* configs);
typedef OckRpcStatus (*ServerAddService)(OckRpcServer server, OckRpcService* service);
typedef OckRpcStatus (*ServerStart)(OckRpcServer server);
typedef void (*ServerDestroy)(OckRpcServer server);
typedef OckRpcStatus (*ServerReply)(OckRpcServerContext ctx, uint16_t msgId,
    OckRpcMessage* reply, OckRpcCallDone* done);
typedef void (*ServerCleanupCtx)(OckRpcServerContext ctx);
typedef OckRpcStatus (*ClientConnectWithCfg)(const char* ip, uint16_t port, OckRpcClient* client,
    OckRpcCreateConfig* cfg);
typedef void (*ClientDisconnect)(OckRpcClient client);
typedef OckRpcStatus (*ClientCall)(OckRpcClient client, uint16_t msgId,
    OckRpcMessage* request, OckRpcMessage* response, OckRpcCallDone* done);
typedef OckRpcStatus (*ClientCallWithParam)(OckRpcClientCallParams *params);
typedef void (*ClientSetTimeout)(OckRpcClient client, int64_t timeout);
typedef void (*DisableSecureHmac)(void);

typedef struct RpcUcxFunc {
    OckRpcServerCtxBuilderHandler serverCtxBuildThrdLocal;
    OckRpcServerCtxCleanupHandler serverCtxCleanupThrdLocal;
    ServerCreateWithCfg serverCreateWithCfg;
    ServerAddService    serverAddService;
    ServerStart serverStart;
    ServerDestroy serverDestroy;
    ServerReply serverReply;
    ServerCleanupCtx serverCleanCtx;
    ClientConnectWithCfg clientConnectWithCfg;
    ClientDisconnect clientDisconnect;
    ClientCall clientCall;
    ClientCallWithParam clientCallWithParam;
    ClientSetTimeout clientSetTimeout;
    DisableSecureHmac disableSecureHmac;
} RpcUcxFunc;

void* g_rpcUcxDl = NULL;
RpcUcxFunc g_rpcUcxFunc;

static int OckRpcServerDlsym(void)
{
    int32 ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerCtxBuilderThreadLocal",
        (void**)&g_rpcUcxFunc.serverCtxBuildThrdLocal);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerCtxCleanupThreadLocal",
        (void**)&g_rpcUcxFunc.serverCtxCleanupThrdLocal);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerCreateWithCfg", (void**)&g_rpcUcxFunc.serverCreateWithCfg);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerAddService", (void**)&g_rpcUcxFunc.serverAddService);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerStart", (void**)&g_rpcUcxFunc.serverStart);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerDestroy", (void**)&g_rpcUcxFunc.serverDestroy);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerReply", (void**)&g_rpcUcxFunc.serverReply);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcServerCleanupCtx", (void**)&g_rpcUcxFunc.serverCleanCtx);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    return CM_SUCCESS;
}

static int OckRpcClientDlsym(void)
{
    int ret = cm_load_symbol(g_rpcUcxDl, "OckRpcClientConnectWithCfg",
        (void**)&g_rpcUcxFunc.clientConnectWithCfg);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }
    
    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcClientDisconnect", (void**)&g_rpcUcxFunc.clientDisconnect);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcClientCall", (void**)&g_rpcUcxFunc.clientCall);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcClientCallWithParam", (void**)&g_rpcUcxFunc.clientCallWithParam);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcClientSetTimeout", (void**)&g_rpcUcxFunc.clientSetTimeout);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    ret = cm_load_symbol(g_rpcUcxDl, "OckRpcDisableSecureHmac", (void**)&g_rpcUcxFunc.disableSecureHmac);
    if (ret != CM_SUCCESS) {
        return OCK_RPC_ERR;
    }

    return CM_SUCCESS;
}

void FinishOckRpcDl(void)
{
    if (g_rpcUcxDl != NULL) {
        cm_close_dl(g_rpcUcxDl);
        g_rpcUcxDl = NULL;
    }

    if (memset_sp(&g_rpcUcxFunc, sizeof(g_rpcUcxFunc), 0, sizeof(g_rpcUcxFunc)) != EOK) {
        LOG_RUN_ERR("memset_sp failed");
    }
}

int InitOckRpcDl(char* path, uint32_t pathLen)
{
    if (path == NULL || pathLen == 0) {
        LOG_RUN_ERR("dlopen rpc_ucx path is nullptr");
        return OCK_RPC_ERR;
    }

    int32 ret = OCK_RPC_OK;
    if (g_rpcUcxDl != NULL) {
        return OCK_RPC_OK;
    }

    ret = cm_open_dl(&g_rpcUcxDl, path);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlopen rpc_ucx path %s", path);
        return OCK_RPC_ERR;
    }

    ret = OckRpcServerDlsym();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlsym ock rpc server func, path %s", path);
        FinishOckRpcDl();
        return OCK_RPC_ERR;
    }

    ret = OckRpcClientDlsym();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlsym ock rpc client func, path %s", path);
        FinishOckRpcDl();
        return OCK_RPC_ERR;
    }
    
    return OCK_RPC_OK;
}

OckRpcServerContext OckRpcServerCtxBuilderThreadLocal(OckRpcServer server)
{
    OckRpcServerContext ret;
    if (g_rpcUcxFunc.serverCtxBuildThrdLocal != NULL) {
        ret = g_rpcUcxFunc.serverCtxBuildThrdLocal(server);
    } else {
        ret = 0;
    }
    return ret;
}
void OckRpcServerCtxCleanupThreadLocal(OckRpcServer server, OckRpcServerContext ctx)
{
    if (g_rpcUcxFunc.serverCtxCleanupThrdLocal != NULL) {
        g_rpcUcxFunc.serverCtxCleanupThrdLocal(server, ctx);
    }
}

/**
 * @brief Create a rpc server with ucx config.
 *
 * Only create a server object, does not start listening.
 *
 * @param ip Server IP.
 * @param port Server port.
 * @param server Created server.
 * @param configMap Ucx configs.
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerCreateWithCfg(const char* ip, uint16_t port, OckRpcServer* server, OckRpcCreateConfig* configs)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.serverCreateWithCfg != NULL) {
        ret = g_rpcUcxFunc.serverCreateWithCfg(ip, port, server, configs);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Add sercice.
 *
 * Register the message handling method to the server. When a message with this
 * ID is received, the registered message handler is called.
 *
 * @param server Server handle.
 * @param service Message processing object.
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerAddService(OckRpcServer server, OckRpcService* service)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.serverAddService != NULL) {
        ret = g_rpcUcxFunc.serverAddService(server, service);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Start the server.
 *
 * This is not a blocking routine, it will return after listening the binded address.
 *
 * @param server Server handle returned by @ref OckRpcServerCreate .
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerStart(OckRpcServer server)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.serverStart != NULL) {
        ret = g_rpcUcxFunc.serverStart(server);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Stop and destroy the server.
 *
 * After this routine, the server handle can not be used again.
 *
 * @param server Server handle returned by @ref OckRpcServerCreate
 */
void OckRpcServerDestroy(OckRpcServer server)
{
    if (g_rpcUcxFunc.serverDestroy != NULL) {
        g_rpcUcxFunc.serverDestroy(server);
    }
}

/**
 * @brief Send a reply.
 *
 * The @b ctx is passed to the user along with the request message through
 * @ref OckRpcMsgHandler .
 *
 * The message id of this reply must be the same as the request message ID.
 *
 * If @b done is not nullptr, this routine behaves as an asynchronous routine. When
 * this routine return OCK_RPC_OK, it only means that the operation is triggered,
 * and the real result will be reported to the user through @b done. The @b done
 * may be executed in the routine, please pay attention to this. Before the done
 * execution, the memory in the @b reply cannot be released.
 *
 * If @b done is nullptr, the return value means the the real result.
 *
 * @param ctx Context passed to the user through @ref OckRpcMsgHandler .
 * @param msgId Message ID.
 * @param reply Reply message.
 * @param done Notify the result to user.
 * @return OCK_RPC_OK for success and others for failure. If @b done is not nullptr,
 *         OCK_RPC_OK means it's still inprogress.
 */
OckRpcStatus OckRpcServerReply(OckRpcServerContext ctx, uint16_t msgId,
                               OckRpcMessage* reply, OckRpcCallDone* done)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.serverReply != NULL) {
        ret = g_rpcUcxFunc.serverReply(ctx, msgId, reply, done);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Cleanup the server context.
 *
 * Once cleaned up, the context can no longer be used, and the message data pointer
 * passed to the user together with it can no longer be used too.
 *
 * @param ctx Context passed to user through @ref OckRpcMsgHandler.
 */
void OckRpcServerCleanupCtx(OckRpcServerContext ctx)
{
    if (g_rpcUcxFunc.serverCleanCtx != NULL) {
        g_rpcUcxFunc.serverCleanCtx(ctx);
    }
}

/**
 * @brief Connect to server with ucx config.
 *
 * Connect to a specified address and return a handler that can be used to rpc call.
 *
 * @param ip Server IP.
 * @param port Server port.
 * @param client Client handle that connected to the server.
 * @param configMap Ucx configs.
 * @return OCK_RPC_OK for success and others for failure.
 */
 
OckRpcStatus OckRpcClientConnectWithCfg(const char* ip, uint16_t port, OckRpcClient* client,
    OckRpcCreateConfig* cfg)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.clientConnectWithCfg != NULL) {
        ret = g_rpcUcxFunc.clientConnectWithCfg(ip, port, client, cfg);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Disconnect.
 *
 * After this routine, the client handle can not be used again.
 *
 * @param client Client handle returned by @ref OckRpcClientConnect
 */
void OckRpcClientDisconnect(OckRpcClient client)
{
    if (g_rpcUcxFunc.clientDisconnect != NULL) {
        g_rpcUcxFunc.clientDisconnect(client);
    }
}

/**
 * @brief Send request and receive response(optional).
 *
 * If @b response is nullptr, it just sends the request and returns.
 *
 * If @b response is not nullptr, it will receives a response. If user does not
 * know the real length of the response, user can set @b response->data to nullptr,
 * so RPC will allocate enough memroy to hold the response, and store the memory
 * address to @b response->data. User are required to use free() to release this
 * memory. There will be additional overhead.
 *
 * If @b done is not nullptr, this routine behaves as an asynchronous routine,
 * and all memory like @b response can not be released unitl the @b done is invoked.
 * @b done will be called to notify the real result. The @b done may be executed
 * in the routine, please pay attention to this
 *
 * If @b done is nullptr, the return value means the the real result.
 *
 * @param client Client handle.
 * @param msgId Message ID.
 * @param request Request.
 * @param response Response, can be nullptr.
 * @param done Notify the result to user.
 * @return OckRpcStatus OCK_RPC_OK for success and others for failure. If @b done is not nullptr,
 *         OCK_RPC_OK means it's still inprogress.
 */
OckRpcStatus OckRpcClientCall(OckRpcClient client, uint16_t msgId,
                              OckRpcMessage* request, OckRpcMessage* response,
                              OckRpcCallDone* done)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.clientCall != NULL) {
        ret = g_rpcUcxFunc.clientCall(client, msgId, request, response, done);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

/**
 * @brief Same with OckRpcClientCall()
 */
OckRpcStatus OckRpcClientCallWithParam(OckRpcClientCallParams *params)
{
    OckRpcStatus ret;
    if (g_rpcUcxFunc.clientCallWithParam != NULL) {
        ret = g_rpcUcxFunc.clientCallWithParam(params);
    } else {
        ret = OCK_RPC_ERR;
    }
    return ret;
}

void OckRpcClientSetTimeout(OckRpcClient client, int64_t timeout)
{
    if (g_rpcUcxFunc.clientSetTimeout != NULL) {
        g_rpcUcxFunc.clientSetTimeout(client, timeout);
    }
}

/**
 * @brief Disable the HMAC check when use SSL transfer data.
 * @note This is global configure, it will affect all servers and clients
 */
void OckRpcDisableSecureHmac(void)
{
    if (g_rpcUcxFunc.disableSecureHmac != NULL) {
        g_rpcUcxFunc.disableSecureHmac();
    }
}
