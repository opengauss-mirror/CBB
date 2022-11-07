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
 * mes_rpc_dl.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_dl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_OCK_RPC_DL_H
#define MES_OCK_RPC_DL_H

#include "mes_type.h"

#ifdef __cplusplus
extern "C" {
#endif
/*******************************************************************************
  Function Name:  InitOckRpcDl
  Function Usage:  dlopen librpc_ucx.so, reg function of mes_rpc.h
  Input Parameter:  the path of librpc_ucx.so
  Output Parameter:  None
  Return:  0 for success and -1 for failed
*******************************************************************************/
int InitOckRpcDl(char* path, uint32 pathLen);

/*******************************************************************************
  Function Name:  FinishOckRpcDl
  Function Usage:  doesnot use librpc_ucx.so again. dlclose it
  Input Parameter:  None
  Output Parameter:  None
  Return:  None
*******************************************************************************/
void FinishOckRpcDl(void);

#ifdef __cplusplus
}
#endif
#endif  // MES_OCK_RPC_DL_H
