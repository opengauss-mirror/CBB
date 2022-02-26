/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
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
 * mes.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_H__
#define __MES_H__

#include "cm_defs.h"
#include "mes_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief mes init
 * @param profile -  config value
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_init(mes_profile_t *profile);

/*
 * @brief mes uninit
 * @param
 * @return
 */
void mes_uninit(void);

/*
 * @brief Setting the CMD Enqueue.
          The queued tasks are assigned to the working thread for processing.
          Tasks that do not enqueue are processed by the channel thread.
 * @param command -  cmd
 * @param is_enqueue - is enqueue.
 * @return
 */
void mes_set_msg_enqueue(uint32 command, bool32 is_enqueue);

/*
 * @brief Register the callback function of the service.
 * @param proc -  callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
void mes_register_proc_func(mes_message_proc_t proc);

/*
 * @brief Registering the cmd callback function.
          Notify the process to receive messages from the peer end.
 * @param msg - Messages sent by the peer end.
 * @return
 */
void mes_notify_msg_recv(mes_message_t *msg);

/*
 * @brief Registering the cmd callback function.
          The notification process accepts the broadcast message from the peer end and release the message.
 * @param msg - Messages sent by the peer end.
 * @return
 */
void mes_notify_broadcast_msg_recv_and_release(mes_message_t *msg);

/*
 * @brief Registering the cmd callback function.
          The notification process accepts the broadcast message from the peer end and caches the message.
 * @param msg - Messages sent by the peer end.
 * @return
 */
void mes_notify_broadcast_msg_recv_and_cahce(mes_message_t *msg);

/*
 * @brief Set the group corresponding to each cmd.
 * @param group_id -  group id.
 * @param command - command
 * @return
 */
void mes_set_command_task_group(uint8 command, mes_task_group_id_t group_id);

/*
 * @brief Connecting to the instance
 * @param inst_id -  the instance id.
 * @param ip -  listening ip address of the instance
 * @param port -  listening port address of the instance
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect(uint32 inst_id, char *ip, uint16 port);

/*
 * @brief DisConnecting to the instance
 * @param inst_id -  the instance id.
 * @return
 */
void mes_disconnect(uint32 inst_id);

/*
 * @brief Connecting to the instances
 * @param inst_id_list -  the instance id.
 * @param inst_id_cnt -  the instance count
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect_batch(const uint8 *inst_id_list, uint8 inst_id_cnt);

/*
 * @brief DisConnecting to the instances
 * @param inst_id_list -  the instance id.
 * @param inst_id_cnt -  the instance count
 * @return
 */
void mes_disconnect_batch(const uint8 *inst_id_list, uint8 inst_id_cnt);

/*
 * @brief Check the connection status.
 * @param inst_id -  the instance id.
 * @return true - the connection to the instance is normal.
           false - the connection to the instance is abnormal.
 */
bool32 mes_connection_ready(uint32 inst_id);

/*
 * @brief send data
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data(mes_message_head_t *msg);

/*
 * @brief send data2
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data2(const mes_message_head_t *head, const void *body);

/*
 * @brief send data3
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data3(const mes_message_head_t *head, uint32 head_size, const void *body);

/*
 * @brief send data4
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data4(const mes_message_head_t *head, const void *body1, uint32 len1, const void *body2, uint32 len2);

/*
 * @brief recv msg
 * @param sid -  Session ID
 * @param msg -  Receive messages. The memory is applied by the MES.
                 Use the mes_release_message_buf api to release memory.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_allocbuf_and_recv_data(uint16 sid, mes_message_t *msg, uint32 timeout);

/*
 * @brief release message buf
 * @param msg -  The msg is applied by the mes_allocbuf_and_recv_data api.
 * @return
 */
void mes_release_message_buf(mes_message_t *msg_buf);

/*
 * @brief Broadcast Message
 * @param sid -  Session ID.
 * @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
 * @param msg_data - send msg.
 * @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
 * @return
 */
void mes_broadcast(uint32 sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst);

/*
 * @brief Broadcast Message
 * @param sid -  Session ID.
 * @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
 * @param head - msg head info.
 * @param body - msg body info.
 * @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
 * @return
 */
void mes_broadcast2(uint32 sid, uint64 inst_bits, mes_message_head_t *head, const void *body, uint64 *success_inst);

/*
 * @brief Broadcast Message and wait for the replay
 * @param sid -  Session ID.
 * @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
 * @param msg_data - send msg.
 * @param timeout - wait time.
 * @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
 * @return
 */
int mes_broadcast_and_wait(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout, uint64 *success_inst);

/*
 * @brief Get current rsn
 * @param sid -  Session ID.
 * @return rsn
 */
uint32 mes_get_current_rsn(uint32 sid);

/*
 * @brief Init ack message head
 * @param req_head -  req message head.
 * @param ack_head -  ack message head.
 * @param cmd - message command.
 * @param size - head size.
 * @param src_sid - source session id.
 * @return
 */
void mes_init_ack_head(const mes_message_head_t *req_head, mes_message_head_t *ack_head, uint8 cmd, uint16 size,
    uint32 src_sid);

/*
 * @brief Waiting for a message from the peer end,
          It is usually used after the mes_broadcast interface.
 * @param group_id -  group id.
 * @param command - command
 * @return
 */
int mes_wait_acks(uint32 sid, uint32 timeout);

/*
 * @brief Waits for messages from the peer end and caches the messages,
          It is usually used after the mes_broadcast interface.
 * @param group_id -  group id.
 * @param command - command
 * @param success_inst - success_inst
 * @param recv_msg - recv_msg
 * @return
 */
int mes_wait_acks_and_recv_msg(uint32 sid, uint32 timeout, uint64 success_inst, char *recv_msg[CM_MAX_INSTANCES]);

/*
 * @brief Obtain the request sequence number.
 * @param sid -  Session ID.
 * @return rsn -  The request sequence number
 */
uint32 mes_get_rsn(uint32 sid);

/*
 * @brief Obtain the number of times the commond was sent.
 * @param cmd - command.
 * @return count -  The number of times the commond was sent.
 */
uint64 mes_get_stat_send_count(uint32 cmd);

/*
 * @brief Obtain the number of times the commond was received.
 * @param cmd - command.
 * @return count - The number of times the commond was received
 */
uint64 mes_get_stat_recv_count(uint32 cmd);

/*
 * @brief Obtain the number of buffer the commond occupy.
 * @param cmd - command.
 * @return count -  The number of buffer the commond occupy.
 */
atomic32_t mes_get_stat_occupy_buf(uint32 cmd);

/*
 * @brief Obtain the state of mes elapsed switch.
 * @return state -  The state of mes elapsed switch.
 */
bool8 mes_get_elapsed_switch(void);

/*
 * @brief set elapsed switch.
 * @param elapsed_switch - The state of mes elapsed switch
 * @return
 */
void mes_set_elapsed_switch(bool8 elapsed_switch);

/*
 * @brief Obtain elapsed time command is used.
 * @param cmd - command.
 * @param type - time type.
 * @return count - The time command is used.
 */
uint64 mes_get_elapsed_time(uint32 cmd, mes_time_stat_t type);

/*
 * @brief Obtain the number of times command occurs.
 * @param cmd - command.
 * @param type - time type.
 * @return count - The number of times command occurs.
 */
uint64 mes_get_elapsed_count(uint32 cmd, mes_time_stat_t type);

#ifdef __cplusplus
}
#endif

#endif /* __MES_H__ */
