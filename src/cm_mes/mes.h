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

#include "mes_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mes_thread_init_t)(unsigned char need_startup, char **reg_data);
typedef int (*mes_send_data_func)(mes_message_head_t *msg);
typedef int (*mes_send_data2_func)(mes_message_head_t *head, const void *body);
typedef void (*mes_wait_acks_overtime_proc_func)(uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES]);

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
void mes_set_msg_enqueue(unsigned int command, unsigned int is_enqueue);

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
* @brief Registering the cmd callback function.
The notification process accepts the broadcast message from the peer end , parse errcode and set succ_insts.
* @param msg - Messages sent by the peer end.
* @return
*/
void mes_notify_broadcast_msg_recv_with_errcode(mes_message_t *msg);

/*
 * @brief Set the group corresponding to each cmd.
 * @param group_id -  group id.
 * @param command - command
 * @return
 */
void mes_set_command_task_group(unsigned char command, mes_task_group_id_t group_id);

/*
 * @brief Connecting to the instance
 * @param inst_id -  the instance id.
 * @param ip -  listening ip address of the instance
 * @param port -  listening port address of the instance
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect(unsigned int inst_id, const char *ip, unsigned short port);

/*
 * @brief DisConnecting to the instance
 * @param inst_id -  the instance id.
 * @return
 */
void mes_disconnect(unsigned int inst_id);

/*
 * @brief DisConnecting to the instance
 * @param inst_id -  the instance id.
 * @return
 */
void mes_disconnect_nowait(unsigned int inst_id);

/*
 * @brief Connecting to the instances
 * @param inst_id_list -  the instance id.
 * @param inst_id_cnt -  the instance count
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/*
 * @brief Connecting to the instances and do not wait connection ready
 * @param inst_id_list -  the instance id.
 * @param inst_id_cnt -  the instance count
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect_batch_no_wait(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/*
 * @brief DisConnecting to the instances
 * @param inst_id_list -  the instance id.
 * @param inst_id_cnt -  the instance count
 * @return
 */
void mes_disconnect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/*
 *  @brief wait connenect to the instance
 *  @param inst_id_list -  the instance id.
 *  @param inst_id_cnt -  the instance count
 *  @return CM_SUCCESS - success;otherwise: failed
 */
int mes_wait_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/*
 *  @brief close connenect to the instance without destory channel thread
 *  @param inst_id_list -  the instance id.
 *  @param inst_id_cnt -  the instance count
 *  @return CM_SUCCESS - success;otherwise: failed
 */

int mes_close_connect_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/*
 * @brief Check the connection status.
 * @param inst_id -  the instance id.
 * @return true - the connection to the instance is normal.
           false - the connection to the instance is abnormal.
 */
unsigned int mes_connection_ready(unsigned int inst_id);

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
int mes_send_data3(const mes_message_head_t *head, unsigned int head_size, const void *body);

/*
 * @brief send data4
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data4(const mes_message_head_t *head, unsigned int head_size, const void *body1, unsigned int len1,
    const void *body2, unsigned int len2);

/*
 * @brief recv msg
 * @param sid -  Session ID
 * @param msg -  Receive messages. The memory is applied by the MES.
                 Use the mes_release_message_buf api to release memory.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_allocbuf_and_recv_data(unsigned short sid, mes_message_t *msg, unsigned int timeout);

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
void mes_broadcast(unsigned int sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst);

/*
 * @brief Broadcast Message
 * @param sid -  Session ID.
 * @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
 * @param head - msg head info.
 * @param body - msg body info.
 * @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
 * @return
 */
void mes_broadcast2(unsigned int sid, uint64 inst_bits, mes_message_head_t *head, const void *body,
    uint64 *success_inst);

/*
* @brief Broadcast Message
* @param sid -  Session ID.
* @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
* @param head - msg head info.
* @param body - msg body info.
* @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
* @param send_data - send message data function
* @return
*/
void mes_broadcast3(unsigned int sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst,
    mes_send_data_func send_data);

/*
* @brief Broadcast Message
* @param sid -  Session ID.
* @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
* @param head - msg head info.
* @param body - msg body info.
* @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
* @param send_data - send message data function
* @return
*/
void mes_broadcast4(unsigned int sid, uint64 inst_bits, mes_message_head_t *head, const void *body,
    uint64 *success_inst, mes_send_data2_func send_data);

/*
 * @brief Broadcast Message and wait for the replay
 * @param sid -  Session ID.
 * @param inst_bits -  inst_bits are used to control which instances need to be broadcast.
 * @param msg_data - send msg.
 * @param timeout - wait time.
 * @param success_inst - success_inst is used to indicate which instances have been successfully broadcast
 * @return
 */
int mes_broadcast_and_wait(unsigned int sid, uint64 inst_bits, const void *msg_data, unsigned int timeout,
    uint64 *success_inst);

/*
 * @brief Get current rsn
 * @param sid -  Session ID.
 * @return rsn
 */
unsigned long long mes_get_current_rsn(unsigned int sid);

/*
 * @brief Init ack message head
 * @param req_head -  req message head.
 * @param ack_head -  ack message head.
 * @param cmd - message command.
 * @param size - head size.
 * @param src_sid - source session id.
 * @return
 */
void mes_init_ack_head(const mes_message_head_t *req_head, mes_message_head_t *ack_head, unsigned char cmd,
    unsigned short size, unsigned int src_sid);

/*
 * @brief Waiting for a message from the peer end,
          It is usually used after the mes_broadcast interface.
 * @param sid -  session id.
 * @param timeout - wait timeout
 * @return
 */
int mes_wait_acks(unsigned int sid, unsigned int timeout);

/*
* @brief Waiting for a message from the peer end,
It is usually used after the mes_broadcast interface.
* @param sid -  session id.
* @param timeout - wait timeout
* @param succ_insts - instances which the request message was successfully executed
* @return
*/
int mes_wait_acks2(unsigned int sid, unsigned int timeout, uint64 *succ_insts);

/*
 * @brief Waits for messages from the peer end and caches the messages,
          It is usually used after the mes_broadcast interface.
 * @param group_id -  group id.
 * @param command - command
 * @param success_inst - success_inst
 * @param recv_msg - recv_msg
 * @return
 */
int mes_wait_acks_and_recv_msg(unsigned int sid, unsigned int timeout, uint64 success_inst,
    char *recv_msg[MES_MAX_INSTANCES]);

/*
* @brief Waits for messages from the peer end and caches the messages,
It is usually used after the mes_broadcast interface.
* @param group_id -  group id.
* @param command - command
* @param success_inst - success_inst
* @param recv_msg - recv_msg
* @param overtime_proc_func - the processing function when the broadcast response timeout
* @return
*/
int mes_wait_acks_and_recv_msg2(unsigned int sid, unsigned int timeout, uint64 success_inst,
    char *recv_msg[MES_MAX_INSTANCES], mes_wait_acks_overtime_proc_func overtime_proc_func);

/*
 * @brief Obtain the request sequence number.
 * @param sid -  Session ID.
 * @return rsn -  The request sequence number
 */
unsigned long long mes_get_rsn(unsigned int sid);

/*
 * @brief Obtain the number of times the commond was sent.
 * @param cmd - command.
 * @return count -  The number of times the commond was sent.
 */
uint64 mes_get_stat_send_count(unsigned int cmd);

/*
 * @brief Obtain the number of times the commond was received.
 * @param cmd - command.
 * @return count - The number of times the commond was received
 */
uint64 mes_get_stat_recv_count(unsigned int cmd);

/*
 * @brief Obtain the number of buffer the commond occupy.
 * @param cmd - command.
 * @return count -  The number of buffer the commond occupy.
 */
volatile long mes_get_stat_occupy_buf(unsigned int cmd);

/*
 * @brief Obtain the state of mes elapsed switch.
 * @return state -  The state of mes elapsed switch.
 */
unsigned char mes_get_elapsed_switch(void);

/*
 * @brief set elapsed switch.
 * @param elapsed_switch - The state of mes elapsed switch
 * @return
 */
void mes_set_elapsed_switch(unsigned char elapsed_switch);

/*
 * @brief Obtain elapsed time command is used.
 * @param cmd - command.
 * @param type - time type.
 * @return count - The time command is used.
 */
uint64 mes_get_elapsed_time(unsigned int cmd, mes_time_stat_t type);

/*
 * @brief Obtain the number of times command occurs.
 * @param cmd - command.
 * @param type - time type.
 * @return count - The number of times command occurs.
 */
uint64 mes_get_elapsed_count(unsigned int cmd, mes_time_stat_t type);

/*
 * @brief Register the callback function of the decrypt password.
 * @param proc -  callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_register_decrypt_pwd(usr_cb_decrypt_pwd_t proc);

/*
 * @brief Obtain the number of queue in used
 * @param queue_count - number of queue in used
 * @return CM_SUCCESS - success;otherwise: failed
 */
void mes_get_queue_count(int *queue_count);

/*
 * @brief send data to all queue
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_inter_msg_all_queue(mes_message_head_t *msg_head);

/*
 * @brief init mes log and set loglevel to MAX
 * @return
 */
void mes_init_log(void);

#ifdef WIN32
typedef void (*mes_usr_cb_log_output_t)(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...);
#else
typedef void (*mes_usr_cb_log_output_t)(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...) __attribute__((format(printf, 6, 7)));
#endif

/*
 * @brief regist user's log func
 * @param cb_func - user's log func.
 * @return
 */
void mes_register_log_output(mes_usr_cb_log_output_t cb_func);

/*
 * @brief set param for mes, param like:
 *        "SSL_CA"
 *        "SSL_KEY"
 *        "SSL_CRL"
 *        "SSL_CERT"
 *        "SSL_CIPHER"
 *        "SSL_PWD_PLAINTEXT"
 *        "SSL_PWD_CIPHERTEXT"
 *        "SSL_CERT_NOTIFY_TIME"

 * @param param_name - parameter name.
 * @param param_value - parameter value.
 * @return 0 - success;otherwise: failed
*/
int mes_set_param(const char *param_name, const char *param_value);

/*
 * @brief check ssl cert expire
 *
 * @return 0 - success;otherwise: failed
*/
int mes_chk_ssl_cert_expire(void);

/*
 * @brief get g_cbb_mes address
 *
 * @return g_cbb_mes address
*/
void* mes_get_global_inst();

#ifdef __cplusplus
}
#endif

#endif /* __MES_H__ */
