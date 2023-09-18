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
 * mes_interface.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MES_INTERFACE_H__
#define __MES_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MES_MAX_BUFFPOOL_NUM ((int)8)
#define MES_MAX_IP_LEN 64
#define MES_MAX_LOG_PATH 4096
#define MES_MAX_INSTANCES (unsigned int)64

#define MES_FLAG_PRIO_0 0x00
#define MES_FLAG_PRIO_1 0x01
#define MES_FLAG_PRIO_2 0x02
#define MES_FLAG_PRIO_3 0x03
#define MES_FLAG_PRIO_4 0x04
#define MES_FLAG_PRIO_5 0x05
#define MES_FLAG_PRIO_6 0x06
#define MES_FLAG_PRIO_7 0x07
#define MES_FLAG_SERIAL (0x1<<3)

typedef unsigned long long ruid_type;
typedef unsigned int inst_type;
typedef unsigned int flag_type;

typedef enum en_mes_pipe_type {
    MES_TYPE_TCP = 1,
    MES_TYPE_IPC = 2,
    MES_TYPE_DOMAIN_SCOKET = 3,
    MES_TYPE_SSL = 4,
    MES_TYPE_EMBEDDED = 5, // embedded mode, reserved
    MES_TYPE_DIRECT = 6,   // direct mode, reserveds
    MES_TYPE_RDMA = 7,     // direct mode, reserved
    MES_TYPE_CEIL
} mes_pipe_type_t;

typedef enum en_mes_task_group_id_t {
    MES_TASK_GROUP_ZERO = 0,
    MES_TASK_GROUP_ONE,
    MES_TASK_GROUP_TWO,
    MES_TASK_GROUP_THREE,
    MES_TASK_GROUP_ALL
} mes_task_group_id_t;

typedef enum en_mes_time_stat {
    MES_TIME_TEST_SEND = 0,
    MES_TIME_SEND_IO,
    MES_TIME_TEST_RECV,
    MES_TIME_TEST_MULTICAST,
    MES_TIME_TEST_MULTICAST_AND_WAIT,
    MES_TIME_TEST_WAIT_AND_RECV,
    MES_TIME_GET_BUF,
    MES_TIME_READ_MES,
    MES_TIME_PROC_FUN,
    MES_TIME_PUT_QUEUE,
    MES_TIME_GET_QUEUE,
    MES_TIME_QUEUE_PROC,
    MES_TIME_PUT_BUF,
    MES_TIME_CEIL
} mes_time_stat_t;

typedef struct st_mes_buffer_attr {
    unsigned int size;
    unsigned int count;
} mes_buffer_attr_t;

typedef struct st_mes_buffer_pool_attr {
    unsigned int pool_count;
    unsigned int queue_count;
    mes_buffer_attr_t buf_attr[MES_MAX_BUFFPOOL_NUM];
} mes_buffer_pool_attr_t;

typedef struct st_mes_addr {
    inst_type inst_id;
    char ip[MES_MAX_IP_LEN];
    unsigned short port;
    unsigned char reserved[2];
} mes_addr_t;

typedef struct st_mes_profile {
    inst_type inst_id;
    unsigned int inst_cnt;
    mes_pipe_type_t pipe_type;
    mes_buffer_pool_attr_t buffer_pool_attr;
    unsigned int channel_cnt;
    unsigned int work_thread_cnt;
    unsigned int mes_elapsed_switch;
    unsigned char rdma_rpc_use_busypoll;    // busy poll need to occupy the cpu core
    unsigned char rdma_rpc_is_bind_core;
    unsigned char rdma_rpc_bind_core_start;
    unsigned char rdma_rpc_bind_core_end;
    char ock_log_path[MES_MAX_LOG_PATH];
    mes_addr_t inst_net_addr[MES_MAX_INSTANCES];
    unsigned int task_group[MES_TASK_GROUP_ALL];
    // Indicates whether to connected to other instances during MES initialization
    unsigned int conn_created_during_init : 1;
    unsigned int reserved : 31;
} mes_profile_t;

typedef struct st_mes_msg {
    char *buffer;
    unsigned int size;
    inst_type src_inst;
} mes_msg_t;

typedef struct st_mes_msg_list {
    mes_msg_t messages[MES_MAX_INSTANCES];
    unsigned int count;
} mes_msg_list_t;

typedef void (*mes_thread_init_t)(unsigned char need_startup, char **reg_data);

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
 * @brief mes add and connect instance
 * @param
 * @return
 */
int mes_add_instance(inst_type inst_id, char* ip, unsigned short port);

/*
 * @brief mes disconnect and remove instance
 * @param
 * @return
 */
int mes_del_instance(inst_type inst_id);

/*
 * @brief Check the connection status.
 * @param inst_id -  the instance id.
 * @return true - the connection to the instance is normal.
           false - the connection to the instance is abnormal.
 */
unsigned int mes_connection_ready(unsigned int inst_id);

/*
 * @brief Register the callback function of the service.
 * @param proc -  callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
typedef void (*mes_message_proc_t)(unsigned int work_idx, ruid_type ruid, mes_msg_t* msg);
void mes_register_proc_func(mes_message_proc_t proc);

/*
 * @brief send data
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data(inst_type dest_inst, flag_type flag, char* data, unsigned int size);

/*
 * @brief send data with multiple body
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_data_x(inst_type dest_inst, flag_type flag, unsigned int count, ...);

/*
 * @brief send request
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_request(inst_type dest_inst, flag_type flag, ruid_type* ruid, char* data, unsigned int size);

/*
 * @brief send request with multiple body
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_request_x(inst_type dest_inst, flag_type flag, ruid_type* ruid, unsigned int count, ...);

/*
 * @brief prepare request sending, reserving necessary resources.
 * note: use in pair with *mes_forward_request_x* to bind with specific ruid.
 * if resources need to be freed, use *mes_get_response* with timeout_ms = 0.
 * @return ruid: 0 if failed, success otherwise
 */
void mes_prepare_request(ruid_type* ruid);

/*
 * @brief forward request with multiple body
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_forward_request_x(inst_type dest_inst, flag_type flag, ruid_type ruid, unsigned int count, ...);

/*
 * @brief send response
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_response(inst_type dest_inst, flag_type flag, ruid_type ruid, char* data, unsigned int size);

/*
 * @brief send response with multiple body
 * @param msg - send msg.
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_send_response_x(inst_type dest_inst, flag_type flag, ruid_type ruid, unsigned int count, ...);

/*
 * @brief get response, when return from mes_get_response, the room will be recycled, the response
 * that arrive late will be discarded
 * @param timeout_ms - if timeout_ms < 0 waiting forever, if timeout_ms = 0 nowait, if timeout_ms > 0
 * waiting specify time(ms).
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_get_response(ruid_type ruid, mes_msg_t* response, int timeout_ms);

void mes_release_msg(mes_msg_t* msg);

/*
 * @brief Broadcast Message
 * @return
 */
int mes_broadcast(flag_type flag, char* msg_data, unsigned int size);
int mes_broadcast_x(flag_type flag, unsigned int count, ...);
int mes_broadcast_sp(inst_type* inst_list, unsigned int inst_count, flag_type flag, char* msg_data, unsigned int size);
int mes_broadcast_spx(inst_type* inst_list, unsigned int inst_count, flag_type flag, unsigned int count, ...);

/*
 * @brief Broadcast Message
 * @return
 */
int mes_broadcast_request(flag_type flag, ruid_type* ruid, char* msg_data, unsigned int size);
int mes_broadcast_request_x(flag_type flag, ruid_type* ruid, unsigned int count, ...);
int mes_broadcast_request_sp(inst_type* inst_list, unsigned int inst_count,
    flag_type flag, ruid_type* ruid, char* msg_data, unsigned int size);
int mes_broadcast_request_spx(inst_type* inst_list, unsigned int inst_count,
    flag_type flag, ruid_type* ruid, unsigned int count, ...);
int mes_broadcast_get_response(ruid_type ruid, mes_msg_list_t* responses, int timeout_ms);
void mes_release_msg_list(mes_msg_list_t* message_list);

/*
 * @brief Register the callback function of the decrypt password.
 * @param proc -  callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
typedef int(*usr_cb_decrypt_pwd_t)(const char *cipher, unsigned int len, char *plain, unsigned int size);
int mes_register_decrypt_pwd(usr_cb_decrypt_pwd_t proc);

/*
 * @brief Obtain the number of queue in used
 * @param queue_count - number of queue in used
 * @return CM_SUCCESS - success;otherwise: failed
 */
void mes_get_queue_count(int *queue_count);

/*
 * @brief init mes log and set loglevel to MAX
 * @return
 */
void mes_init_log(void);

#if defined(WIN32) || defined(_WIN32)
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
 * @brief get global variable address
 * @return global variable address
*/
void* mes_get_global_inst(void);

/*
 * @brief end wait mes_allocbuf_and_recv_data
 * @return
*/
void mes_discard_response(ruid_type ruid);

#ifdef __cplusplus
}
#endif

#endif /* __MES_INTERFACE_H__ */
