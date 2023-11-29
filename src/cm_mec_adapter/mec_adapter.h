/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * mec_adapter.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mec_adapter/mec_adapter.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_ADAPTER_H__
#define __MEC_ADAPTER_H__

#include "mec_type.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MEC_PROC_DIFF_ENDIAN_ADAPTER(head)                        \
do {                                                              \
    (head)->batch_size = cs_reverse_int16((head)->batch_size);    \
    (head)->src_inst = cs_reverse_uint32((head)->src_inst);       \
    (head)->dst_inst = cs_reverse_uint32((head)->dst_inst);       \
    (head)->stream_id = cs_reverse_uint32((head)->stream_id);     \
    (head)->size = cs_reverse_uint32((head)->size);               \
    (head)->serial_no = cs_reverse_uint32((head)->serial_no);     \
    (head)->frag_no = cs_reverse_uint32((head)->frag_no);         \
    (head)->version = cs_reverse_uint32((head)->version);         \
} while (0)

#define MEC_STREAM_TO_CHANNEL_ID_ADAPTER(stream_id, channel_num) (uint8)((stream_id) % (channel_num))

bool32 is_old_mec_version(uint32 version);
void mec_tcp_try_connect(mes_pipe_t *mes_pipe, cs_pipe_t *send_pipe);
int mec_accept(cs_pipe_t *pipe);
int mec_process_event(mes_pipe_t *pipe);

#ifdef __cplusplus
}
#endif

#endif
