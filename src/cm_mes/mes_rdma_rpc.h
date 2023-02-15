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
 * mes_rdma_rpc.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rdma_rpc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef MES_RDMA_RPC_H
#define MES_RDMA_RPC_H

#include "cm_types.h"
#include "cm_rwlock.h"
#include "mes_rpc.h"
#include "mes_type.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct rdma_rpc_client_t {
    OckRpcClient client_handle;
} rdma_rpc_client_t;


int mes_init_rdma_rpc_resource(void);

int mes_start_rdma_rpc_lsnr(void);

int mes_rdma_rpc_connect_handle(uint32 inst_id);

void mes_rdma_rpc_disconnect(uint32 inst_id, uint32_t channel_id);

void mes_rdma_rpc_disconnect_handle(uint32 inst_id, bool32 wait);

int mes_rdma_rpc_send_data(const void* msg_data);

int mes_rdma_rpc_send_bufflist(mes_bufflist_t *buff_list);

bool32 mes_rdma_rpc_connection_ready(uint32 inst_id);

int mes_register_rdma_rpc_proc_func(void);

void stop_rdma_rpc_lsnr(void);

int mes_ockrpc_init_ssl(void);

int mes_ockrpc_tls_cert_verify(void* x509, const char* crlPath);

void mes_ockrpc_tls_get_private_key(const char** privateKeyPath, char** keypass, OckRpcTlsKeypassErase *erase);

#ifdef __cplusplus
}
#endif
#endif  // MES_RDMA_RPC_H