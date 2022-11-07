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
 * mes_rpc.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_RPC_H__
#define __MES_RPC_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OCK_RPC_OK = 0,
    OCK_RPC_ERR = -1,
    OCK_RPC_ERR_INVALID_PARAM = -2,
    OCK_RPC_ERR_MISMATCH_MSG_ID = -3,
    OCK_RPC_ERR_CONN_UNCONNECTED = -4,
    OCK_RPC_ERR_SERIALIZE = -5,
    OCK_RPC_ERR_DESERIALIZE = -6,
    OCK_RPC_ERR_NO_MEMORY = -7,
    OCK_RPC_ERR_RDMA_NOT_ENABLE = -8,
    OCK_RPC_ERR_UNPACK_RKEY = -9,
    OCK_RPC_ERR_UCP_TAG_SEND = -10,
    OCK_RPC_ERR_UCP_TAG_RECV = -11,
    OCK_RPC_ERR_UCP_PUT = -12,
    OCK_RPC_ERR_UCP_GET = -13,
    OCK_RPC_ERR_UNSUPPORT = -14,
    OCK_RPC_ERR_SERVICE_EXIST = -15,
    OCK_RPC_ERR_ENCRYPT = -16,
    OCK_RPC_ERR_DECRYPT = -17,
    OCK_RPC_ERR_SINATURE = -18,
    OCK_RPC_ERR_UCP_TIMEOUT = -19,
    OCK_RPC_ERR_UCP_CLOSE = -20,
    OCK_RPC_ERR_CONN_BROKEN = -21,
    OCK_RPC_ERR_INVALID_RKEY = -22,
} OckRpcStatus;

#define OCK_RPC_BIT(i) (1ul << (i))

typedef uintptr_t OckRpcServer;

typedef uintptr_t OckRpcClient;
typedef uintptr_t OckRpcClientContext;

typedef uintptr_t OckRpcServerContext;

/** @brief TLS callbacks */
/**
 * @brief Keypass erase function
 * @param keypass       the memory address of keypass
 */
typedef void (*OckRpcTlsKeypassErase)(char *keypass);

/**
 * @brief Get private key file's path and length, and get the keypass
 * @param priKeyPath    the path of private key
 * @param keypass       the keypass
 * @param erase         the erase function
 */
typedef void (*OckRpcTlsGetPrivateKey)(const char **priKeyPath,
                                       char **keypass,
                                       OckRpcTlsKeypassErase *erase);
/**
 * @brief Get the certificate file of public key
 * @param certPath      the path of certificate
 */
typedef void (*OckRpcTlsGetCert)(const char **certPath);

/**
 * @brief The cert verify function
 * @param x509          the x509 object of CA
 * @param crlPath       the crl file path
 *
 * @return -1 for failed, and 1 for success
 */
typedef int (*OckRpcTlsCertVerify)(void *x509, const char *crlPath);

/**
 * @brief Get the CA and verify
 * @param caPath        the path of CA file
 * @param crlPath       the crl file path
 * @param verify        the verify function
 */
typedef void (*OckRpcTlsGetCAAndVerify)(const char **caPath, const char **crlPath,
                                        OckRpcTlsCertVerify *verify);

/**
 * @brief Message struct.
 */
typedef struct {
    void* data;
    size_t len;
} OckRpcMessage;

typedef struct {
    size_t count;
    OckRpcMessage *msgs;
} OckRpcMessageIov;

/**
 * @brief Message handler.
 *
 * User can pass the @b ctx and @b msg to other thread, it will remain valid until
 * @ref OckRpcServerCleanupCtx is called. After calling the @ref OckRpcServerReply,
 * user need to call @ref OckRpcServerCleanupCtx to release @b ctx. The lifetime
 * of the memory that @b msg points to is same as @b ctx. So after invoking
 * @ref OckRpcServerCleanupCtx, the @b msg is freed and can not be used anymore.
 */
typedef void(*OckRpcMsgHandler)(OckRpcServerContext ctx, OckRpcMessage msg);

/**
 * @brief RPC call completion callback.
 *
 * @b status is the result of the communication call and @b arg is specified by user.
 */
typedef void(*OckRpcDoneCallback)(OckRpcStatus status, void* arg);

/**
 * @brief User-defined server context creation and clearance functions.
 *
 *  The server default context builder and cleanup functions use the glibc new/delete,
 *  Sometimes its performance cannot meet the requirements of the current scenario, users
 *  can use customized functions to accelerate the performance.
 */
typedef OckRpcServerContext (*OckRpcServerCtxBuilderHandler)(OckRpcServer server);
typedef void (*OckRpcServerCtxCleanupHandler)(OckRpcServer server, OckRpcServerContext ctx);

/**
 * @brief Default server-context builder by static thread local variable
 *
 * @note If user use those server context handlers, please make sure that every context
 *       must be cleanup before @ref OckRpcMsgHandler return, you can not use server context
 *       in other thread.
 */

OckRpcServerContext OckRpcServerCtxBuilderThreadLocal(OckRpcServer server);
void OckRpcServerCtxCleanupThreadLocal(OckRpcServer server, OckRpcServerContext ctx);
/**
 * @brief RPC Service.
 *
 * Each service is a kind of message processing object.
 */
typedef struct {
    uint16_t id; /**  Message ID handled by this service. The range is [0,1024). */
    OckRpcMsgHandler handler; /**  Message handler. */
} OckRpcService;

/**
 * @brief RPC call completion handle.
 *
 * This structure should be allocated by the user and can be passed to communication
 * primitives, such as @ref OckRpcClientCall. When the structure object is passed
 * in, the communication routine changes to asynchronous mode. And if the routine
 * returns success, the actual completion result will be notified through this callback.
 */
typedef struct {
    OckRpcDoneCallback cb; /**  User callback function. */
    void* arg; /**  Argument of callback. */
} OckRpcCallDone;

typedef struct {
    const char* key;
    const char* value;
} RpcConfigPair;

typedef struct {
    int size;
    RpcConfigPair *pairs;
} RpcConfigs;

typedef enum {
    OCK_RPC_CONFIG_USE_RPC_CONFIGS       = OCK_RPC_BIT(0),
    OCK_RPC_CONFIG_USE_SERVER_CTX_BUILD  = OCK_RPC_BIT(1),
    OCK_RPC_CONFIG_USE_SSL_CALLBACK      = OCK_RPC_BIT(2),
} OckRpcCreateConfigMask;

typedef struct {
    /* Must enable special bit before you set config value OckRpcCreateConfigMask */
    uint64_t mask;

    /* Set Key-Value mode to config, must enable OCK_RPC_CONFIG_USE_RPC_CONFIGS */
    RpcConfigs configs;

    /* Set user define Server Ctx build and cleanup handler, must enable OCK_RPC_CONFIG_USE_SERVER_CTX_BUILD */
    OckRpcServerCtxBuilderHandler serverCtxbuilder;
    OckRpcServerCtxCleanupHandler serverCtxCleanup;

    /**
     * Set SSL handler, must enable OCK_RPC_CONFIG_USE_SSL_CALLBACK
     *
     * In Server side getCert and getPriKey can't be nullptr
     * In Client side getCaAndVerify can't be nullptr
     */
    OckRpcTlsGetCAAndVerify getCaAndVerify; /* get the CA path and verify callback. */
    OckRpcTlsGetCert getCert;               /* get the certificate file of public key */
    OckRpcTlsGetPrivateKey getPriKey;       /* get the private key and keypass */
} OckRpcCreateConfig;

typedef struct {
    uint64_t mask;      /* reserved mask for code compatible, please set to OCK_RPC_CLIENT_CALL_DEFAULT */

    OckRpcClient client;
    /**
     * It is recommended that the client context be reused for the high performance, so users can call
     * @ref OckRpcClientCreateCtx() for alloc context.
     *
     * @note But for convenience that user can set it to NULL.
     */
    OckRpcClientContext context;
    uint16_t msgId;
    OckRpcMessageIov reqIov;    /* at least has one valid msg */

    /**
     * There are 3 methods to use rspIov
     * 1. Don't recv response, so set the rspIov.count to 0;
     * 2. Recv the response but don't know the length of response, so set the rspIov.count to 1 and
     *    set the first msg in rspIov.msgs to {.data = NULL, .len = 0}, finally RPC will put response
     *    to rspIov.msgs[0], and user need to free this memory in rspIov.msgs[0].data.
     * 3. Know the length of response
     */
    OckRpcMessageIov rspIov;
    OckRpcCallDone *done;
} OckRpcClientCallParams;

typedef enum {
    OCK_RPC_CLIENT_CALL_DEFAULT          = 0,        /* default mask */
} OckRpcClientCallParamMask;

/**
 * @brief Create a rpc server with rpc create config
 *
 * Only create a server object, does not start listening.
 *
 * @param ip        Server IP.
 * @param port      Server port.
 * @param server    Created server.
 * @param config    Server create configurations, please configure the corresponding mask.
 *
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerCreateWithCfg(const char* ip, uint16_t port, OckRpcServer* server,
                                       OckRpcCreateConfig *configs);


/**
 * @brief Add service.
 *
 * Register the message handling method to the server. When a message with this
 * ID is received, the registered message handler is called.
 *
 * @param server Server handle.
 * @param service Message processing object.
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerAddService(OckRpcServer server, OckRpcService* service);

/**
 * @brief Start the server.
 *
 * This is not a blocking routine, it will return after listening the binded address.
 *
 * @param server Server handle returned by @ref OckRpcServerCreate .
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcServerStart(OckRpcServer server);

/**
 * @brief Stop and destroy the server.
 *
 * After this routine, the server handle can not be used again.
 *
 * @param server Server handle returned by @ref OckRpcServerCreate
 */
void OckRpcServerDestroy(OckRpcServer server);

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
                               OckRpcMessage* reply, OckRpcCallDone* done);

/**
 * @brief Cleanup the server context.
 *
 * Once cleaned up, the context can no longer be used, and the message data pointer
 * passed to the user together with it can no longer be used too.
 *
 * @param ctx Context passed to user through @ref OckRpcMsgHandler.
 */
void OckRpcServerCleanupCtx(OckRpcServerContext ctx);

/**
 * @brief Connect to server with config.
 *
 * Connect to a specified address and return a handler that can be used to rpc call.
 *
 * @param ip        Server IP.
 * @param port      Server port.
 * @param client    Client handle that connected to the server.
 * @param cfg       The create configs.
 * @return OCK_RPC_OK for success and others for failure.
 */
OckRpcStatus OckRpcClientConnectWithCfg(const char* ip, uint16_t port, OckRpcClient* client,
    OckRpcCreateConfig* cfg);

/**
 * @brief Disconnect.
 *
 * After this routine, the client handle can not be used again.
 *
 * @param client Client handle returned by @ref OckRpcClientConnect
 */
void OckRpcClientDisconnect(OckRpcClient client);

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
 * and all memory like @b response can not be released until the @b done is invoked.
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
                              OckRpcCallDone* done);
/**
 * @brief Same with OckRpcClientCall()
 */
OckRpcStatus OckRpcClientCallWithParam(OckRpcClientCallParams *params);

/**
 * @brief Set timeout
 *
 * After setting timeout by this routine, if the @ref OckRpcClientCall is not
 * completed within the specified time, a failure is returned.
 *
 * 1. timeout = 0: return immediately
 * 2. timeout < 0: never timeout, usually set to -1
 * 3. timeout > 0: Millisecond precision timeout.
 * Default timeout is -1.
 *
 * @param client Client.
 * @param timeout Milliseconds.
 */
void OckRpcClientSetTimeout(OckRpcClient client, int64_t timeout);

/**
 * @brief Disable the HMAC check when use SSL transfer data.
 * @note This is global configure, it will affect all servers and clients
 */
void OckRpcDisableSecureHmac(void);
#ifdef __cplusplus
}
#endif

#endif
