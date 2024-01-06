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
#define MES_MAX_INSTANCES (unsigned int)256
#define MES_MIN_PRIORITY_NUM 1
#define MES_MAX_PRIORITY_NUM 8
#define MES_MIN_TASK_NUM (1)
#define MES_MAX_TASK_NUM (128)

/* only for mes head flags */
// Bits 1-2 and 3 indicate the priority and supports eight types of priority.
// (0b111 == 0x07)
#define MES_SET_PRIORITY_FLAG(flags, priority)            ((flags) |= ((priority) & (0x07)))
#define MES_RESET_PRIORITY_FLAG(flags)                    ((flags) &= (~(0x07)))

// Bit 4 indicates whether to maintain the message execution sequence at the thread level between nodes.
// (0b1000 == 0x08)
#define MES_FLAG_SERIAL                                   (0x1<<3)

// Bits 5-6 and 7 indicate compression and supports eight types of compression algorithm.
// (0b1110000 == 0x70)
#define MES_SET_COMPRESS_ALGORITHM_FLAG(flags, algorithm) ((flags) |= (((algorithm) & (0x07)) << 4))
#define MES_RESET_COMPRESS_ALGORITHM_FLAG(flags)          ((flags) &= (~(0x70)))

// Bits 8-12 indicate compress level and range 0 to 32.
// (0b111110000000 == 0xF80)
#define MES_SET_COMPRESS_LEVEL_FLAG(flags, level)         ((flags) |= (((level) & (0x1F)) << 7))
#define MES_RESET_COMPRESS_LEVEL_FLAG(flags)              ((flags) &= (~(0xF80)))

#define MES_PRIORITY(flags)                               (mes_priority_t)((flags) & (0x07))
#define MES_SERIAL(flags)                                 ((flags) & MES_FLAG_SERIAL)
#define MES_COMPRESS_ALGORITHM(flags)                     (compress_algorithm_t)((flags >> 4) & (0x07))
#define MES_COMPRESS_LEVEL(flags)                         ((flags >> 7) & (0x1F))

typedef unsigned long long ruid_type;
typedef unsigned int inst_type;
typedef unsigned int flag_type;

typedef enum en_mes_pipe_type {
    MES_TYPE_TCP = 1,
    MES_TYPE_IPC = 2,
    MES_TYPE_DOMAIN_SCOKET = 3,
    MES_TYPE_SSL = 4,
    MES_TYPE_EMBEDDED = 5, // embedded mode, reserved
    MES_TYPE_DIRECT = 6,   // direct mode, reserved
    MES_TYPE_RDMA = 7,     // direct mode, reserved
    MES_TYPE_CEIL
} mes_pipe_type_t;

typedef enum en_mes_priority_t {
    MES_PRIORITY_ZERO = 0,      // max priority
    MES_PRIORITY_ONE = 1,
    MES_PRIORITY_TWO = 2,
    MES_PRIORITY_THREE = 3,
    MES_PRIORITY_FOUR = 4,
    MES_PRIORITY_FIVE = 5,
    MES_PRIORITY_SIX = 6,
    MES_PRIORITY_SEVEN = 7,     // min priority
    MES_PRIORITY_CEIL
} mes_priority_t;

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

typedef enum en_compress_algorithm {
    COMPRESS_NONE = 0,
    COMPRESS_LZ4 = 1,
    COMPRESS_CEIL = 2,
} compress_algorithm_t;

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
    char secondary_ip[MES_MAX_IP_LEN];
    unsigned short port;
    unsigned char need_connect;
    unsigned char reserved[1];
} mes_addr_t;

typedef struct st_mes_task_threadpool_group_attr {
    unsigned int group_id;
    unsigned int enabled;
    unsigned char num_fixed;
    unsigned char unused[2];
    unsigned int min_cnt;
    unsigned int max_cnt;
    unsigned int task_num_ceiling;
    unsigned int task_num_floor;
} mes_task_threadpool_group_attr_t;

typedef struct st_mes_task_threadpool_attr {
    unsigned char enable_threadpool;
    unsigned char unused[3];
    unsigned int group_num;
    mes_task_threadpool_group_attr_t group_attr[MES_PRIORITY_CEIL];
    unsigned int min_cnt;
    unsigned int max_cnt;
} mes_task_threadpool_attr_t;

typedef struct st_mes_profile {
    inst_type inst_id;
    unsigned int inst_cnt;
    mes_pipe_type_t pipe_type;
    mes_buffer_pool_attr_t buffer_pool_attr[MES_PRIORITY_CEIL];
    unsigned int channel_cnt;
    unsigned int priority_cnt;
    unsigned int mes_elapsed_switch;
    unsigned char rdma_rpc_use_busypoll;    // busy poll need to occupy the cpu core
    unsigned char rdma_rpc_is_bind_core;
    unsigned char rdma_rpc_bind_core_start;
    unsigned char rdma_rpc_bind_core_end;
    char ock_log_path[MES_MAX_LOG_PATH];
    mes_addr_t inst_net_addr[MES_MAX_INSTANCES];
    unsigned int send_task_count[MES_PRIORITY_CEIL];
    unsigned int recv_task_count[MES_PRIORITY_CEIL];
    unsigned int work_task_count[MES_PRIORITY_CEIL];
    // Each bit indicates a priority.
    // For example, 0b00000010 indicates that compression is enabled for priority 1.
    unsigned char enable_compress_priority;
    compress_algorithm_t algorithm;
    unsigned int compress_level;
    // max message buffer size supported
    unsigned int frag_size;
    int connect_timeout;  // ms
    int socket_timeout;   // ms
    struct {
        // Indicates whether to connected to other instances during MES initialization
        unsigned int conn_created_during_init : 1;
        // 0:support send request and get response 1:no support send request and get response
        unsigned int disable_request : 1;
        // Indicates whether to maintain the message execution sequence at the thread level between instances.
        unsigned int need_serial : 1;
        // Indicates whether a message needs to be added to the sending queue or directly sent.
        // 1: send directly; 0: added to the sending queue
        unsigned int send_directly : 1;
        unsigned int reserved : 28;
    };
    mes_task_threadpool_attr_t tpool_attr;
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
typedef void (*mes_thread_deinit_t)();

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
 * @brief 1) add or update one instance profile;
 *        2) connect instance;
 * @param inst_net_addr - instance net address
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_add_instance(const mes_addr_t *inst_net_addr);

/*
 * @brief only connect instance;
 * @param inst_id - dst instance
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_connect_instance(inst_type inst_id);

/*
 * @brief 1) add, remove or update instance profile(multiple instances can be operated);
 *        2) connect that need to be connected;
 *        3) disconnect that need to be disconnected.
 * @param inst_cnt - instance count
 * @param inst_net_addrs - instance net addresses
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_update_instance(unsigned int inst_cnt, const mes_addr_t *inst_net_addrs);

/*
 * @brief 1) remove one instance profile;
 *        2) disconnect instance;
 * @param inst_id - dst instance
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_del_instance(inst_type inst_id);

/*
 * @brief only disconnect instance
 * @param inst_id - dst instance
 * @return CM_SUCCESS - success;otherwise: failed
 */
int mes_disconnect_instance(inst_type inst_id);

/*
 * @brief Check the connection status.
 * @param inst_id -  the instance id.
 * @return true - the connection to the instance is normal.
           false - the connection to the instance is abnormal.
 */
unsigned int mes_connection_ready(inst_type inst_id);

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
 * @brief mes_interrupt_get_response cancels all response waits,
 * until mes_resume_get_response restores them
 */
void mes_interrupt_get_response(void);
void mes_resume_get_response(void);

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
 * @brief get the number of messages to be processed of a specified priority.
 * @param is_send - 1:send; 0:receive
 * @param priority - priority
 * @return the number of messages to be processed of a specified priority
 */
int mes_get_queue_count(unsigned char is_send, mes_priority_t priority);

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

/*
 * @brief register the callback function for convert instance id.
 * @param proc - callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
typedef void(*usr_cb_convert_inst_id_t)(inst_type *src_inst, inst_type *dst_inst);
int mes_register_convert_inst_id_proc_func(usr_cb_convert_inst_id_t proc);

/*
 * @brief register the callback function for connect state change.
 * @param proc - callback function
 * @return CM_SUCCESS - success;otherwise: failed
 */
typedef int (*usr_cb_conn_state_change_t)(inst_type dst_inst, unsigned char is_connected);
int mes_register_conn_state_proc_func(usr_cb_conn_state_change_t proc);

/*
 * @brief Sets whether compression is allowed for a specified priority.
 * @param priority - priority
 * @param enable_compress - CM_TRUE:enable; CM_FALSE:disable
 * @return
 */
void mes_set_specified_priority_enable_compress(mes_priority_t priority, unsigned char enable_compress);

/*
 * @brief set compress algorithm.
 * @param algorithm - compress algorithm
 * @return
 */
void mes_set_compress_algorithm(compress_algorithm_t algorithm);

/*
 * @brief set compress level.
 * @param level - compress level
 * @return
 */
void mes_set_compress_level(unsigned int level);

/*
 * @brief Check whether the current instance and the dst instance are in different endian.
 * @param dst_inst - dst instance
 * @return CM_TRUE: different endian;
 */
int mes_is_different_endian(inst_type dst_inst);

/*
 * @brief get memory capacity of a specified priority.
 *        every instance is the same
 * @param is_send - 1:send; 0:receive
 * @param priority - priority
 * @return memory capacity of a specified priority
 */
long long mes_get_mem_capacity(unsigned char is_send, mes_priority_t priority);

/*
 * @brief get the count of started work thread task.
 * @param is_send - 1:send; 0:receive
 * @return the count of started work thread task
 */
int mes_get_started_task_count(unsigned char is_send);

/*
* @brief get mes worker init variable.
* @return mes worker init variable
*/
mes_thread_init_t mes_get_worker_init_cb(void);

/*
* @brief get mes worker deinit variable.
* @return mes worker deinit variable
*/
mes_thread_deinit_t mes_get_worker_deinit_cb(void);

/*
* @brief set mes worker init variable.
* @param callback - mes worker init variable
* @return
*/
void mes_set_worker_init_cb(mes_thread_init_t callback);

/*
* @brief set mes worker deinit variable.
* @param callback - mes worker deinit variable
* @return
*/
void mes_set_worker_deinit_cb(mes_thread_deinit_t callback);

#ifdef __cplusplus
}
#endif

#endif /* __MES_INTERFACE_H__ */
