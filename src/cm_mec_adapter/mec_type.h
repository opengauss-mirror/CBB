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
 * mec_type.h
 *  
 *
 * IDENTIFICATION
 *    src/cm_mec_adapter/mec_type.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <sys/syscall.h>
#endif
#include "cm_defs.h"
#include "mes_type.h"

#ifndef __MEC_TYPE_H__
#define __MEC_TYPE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* only for old mec (pipe->version < CS_VERSION_5) head flag */
#define MEC_FLAG_NONE_ADAPTER            0x0000
#define MEC_FLAG_MORE_DATA_ADAPTER       0x0001   // continue to recv more data
#define MEC_FLAG_END_DATA_ADAPTER        0x0002   // end to last packet
#define MEC_FLAG_PEER_CLOSED_ADAPTER     0x0004
#define MEC_FLAG_COMPRESS_ADAPTER        0x0008
#define MEC_FLAG_PRIV_LOW_ADAPTER        0x0010
#define MEC_FLAG_BATCH_ADAPTER           0x0020
#define MEC_FLAG_ALGORITHM_ADAPTER       0x0040

#define MEC_FLAG_ALGORITHM_LZ4_ADAPTER   0x0040

#define MEC_MORE_DATA_ADAPTER(flag)      ((flag)&MEC_FLAG_MORE_DATA_ADAPTER)
#define MEC_END_DATA_ADAPTER(flag)       ((flag)&MEC_FLAG_END_DATA_ADAPTER)
#define MEC_COMPRESS_ADAPTER(flag)       ((flag)&MEC_FLAG_COMPRESS_ADAPTER)
#define MEC_PRIV_LOW_ADAPTER(flag)       ((flag)&MEC_FLAG_PRIV_LOW_ADAPTER)
#define MEC_BATCH_ADAPTER(flag)          ((flag)&MEC_FLAG_BATCH_ADAPTER)
#define MEC_ALGORITHM_ADAPTER(flag)      ((flag)&MEC_FLAG_ALGORITHM_ADAPTER)

#define MEC_DEFAULT_STREAM_ID_ADAPTER    1

typedef enum en_mec_msg_priv_adapter {
    MEC_PRIV_HIGH_ADAPTER = 0,  // high priority message = MES_PRIORITY_ZERO
    MEC_PRIV_LOW_ADAPTER = 1,   // low priority message  = MES_PRIORITY_ONE
    MEC_PRIV_CEIL_ADAPTER,
} mec_msg_priv_adapter_t;

typedef struct st_mec_message_head_adapter {
    unsigned char cmd;  // command
    unsigned char flags;
    unsigned short batch_size;  // batch size
    unsigned int src_inst;      // from instance
    unsigned int dst_inst;      // to instance
    unsigned int stream_id;     // stream id
    unsigned int size;
    unsigned int serial_no;
    unsigned int frag_no;
    unsigned int version;
    unsigned long long time1;
    unsigned long long time2;
    unsigned long long time3;
} mec_message_head_adapter_t;

#define MEC_MSG_HEAD_SIZE_ADAPTER sizeof(mec_message_head_adapter_t)

typedef struct st_mec_message_adapter {
    mec_message_head_adapter_t *head;
    char *buffer;
} mec_message_adapter_t;

typedef enum en_mec_command_adapter {
    // normal cmd:
    MEC_CMD_CONNECT_ADAPTER = 0,
    MEC_CMD_HEALTH_CHECK_HIGH_ADAPTER = 1,
    MEC_CMD_HEALTH_CHECK_LOW_ADAPTER = 2,
    MEC_CMD_APPEND_LOG_RPC_REQ_ADAPTER = 3,
    MEC_CMD_APPEND_LOG_RPC_ACK_ADAPTER = 4,
    MEC_CMD_VOTE_REQUEST_RPC_REQ_ADAPTER = 5,
    MEC_CMD_VOTE_REQUEST_RPC_ACK_ADAPTER = 6,
    MEC_CMD_GET_COMMIT_INDEX_REQ_ADAPTER = 7,
    MEC_CMD_GET_COMMIT_INDEX_ACK_ADAPTER = 8,
    MEC_CMD_PROMOTE_LEADER_RPC_REQ_ADAPTER = 9,
    MEC_CMD_BLOCK_NODE_RPC_REQ_ADAPTER = 10,
    MEC_CMD_BLOCK_NODE_RPC_ACK_ADAPTER = 11,
    MEC_CMD_SEND_COMMON_MSG_ADAPTER = 12,
    MEC_CMD_CHANGE_MEMBER_RPC_REQ_ADAPTER = 13,
    MEC_CMD_UNIVERSAL_WRITE_REQ_ADAPTER = 14,
    MEC_CMD_UNIVERSAL_WRITE_ACK_ADAPTER = 15,
    MEC_CMD_STATUS_CHECK_RPC_REQ_ADAPTER = 16,
    MEC_CMD_STATUS_CHECK_RPC_ACK_ADAPTER = 17,
    MEC_CMD_CASCADE_CONNECT_RPC_REQ_ADAPTER = 18,
    MEC_CMD_CASCADE_CONNECT_RPC_ACK_ADAPTER = 19,
    MEC_CMD_CASCADE_PROMOTE_RPC_REQ_ADAPTER = 20,
    MEC_CMD_CASCADE_PROMOTE_RPC_ACK_ADAPTER = 21,
    MEC_CMD_SEND_CROSS_CLUSTER_MSG_ADAPTER = 22,
    MEC_CMD_QUERY_LOGGER_LOG_REQ_ADAPTER = 23,
    MEC_CMD_QUERY_LOGGER_LOG_ACK_ADAPTER = 24,
    MEC_CMD_CATCHUP_LOGGER_REQ_ADAPTER = 25,
    MEC_CMD_CATCHUP_LOGGER_ACK_ADAPTER = 26,
    MEC_CMD_CASCADE_VOTE_REQUEST_RPC_REQ_ADAPTER = 27,
    MEC_CMD_CASCADE_VOTE_REQUEST_RPC_ACK_ADAPTER = 28,
    MEC_CMD_NORMAL_CEIL_ADAPTER,  // please add normal cmd before this

    // test cmd:
    MEC_CMD_TEST_REQ_ADAPTER = MEC_CMD_NORMAL_CEIL_ADAPTER + 1,
    MEC_CMD_TEST_ACK_ADAPTER = MEC_CMD_NORMAL_CEIL_ADAPTER + 2,
    MEC_CMD_TEST1_REQ_ADAPTER = MEC_CMD_NORMAL_CEIL_ADAPTER + 3,
    MEC_CMD_TEST1_ACK_ADAPTER = MEC_CMD_NORMAL_CEIL_ADAPTER + 4,
    MEC_CMD_BRD_TEST_ADAPTER = MEC_CMD_NORMAL_CEIL_ADAPTER + 5,

    MEC_CMD_CEIL_ADAPTER,
} mec_command_adapter_t;

#define MEC_MESSAGE_BODY_ADAPTER(msg) ((msg)->buffer + sizeof(mec_message_head_adapter_t))

#define MEC_INVALID_NODE_ID_ADAPTER   0
#define MEC_MAX_NODE_COUNT_ADAPTER    256

// node id switch, transform node id in cross cluster to local cluster or vice versa.
#define NODE_ID_SWITCH_ADAPTER(node_id) \
    (((node_id) == MEC_INVALID_NODE_ID_ADAPTER) ? MEC_INVALID_NODE_ID_ADAPTER : \
    (MEC_MAX_NODE_COUNT_ADAPTER - (node_id)))
#define IS_LOCAL_CLUSTER_NODE_ADAPTER(node_id) \
    (((node_id) > MEC_INVALID_NODE_ID_ADAPTER) && ((node_id) < MEC_MAX_NODE_COUNT_ADAPTER / CM_2X_FIXED))
#define IS_CROSS_CLUSTER_NODE_ADAPTER(node_id) \
    (((node_id) > MEC_MAX_NODE_COUNT_ADAPTER / CM_2X_FIXED) && ((node_id) < MEC_MAX_NODE_COUNT_ADAPTER))

#ifdef __cplusplus
}
#endif

#endif
