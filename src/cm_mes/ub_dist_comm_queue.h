/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */

#ifndef UB_DIST_COMM_QUEUE_H
#define UB_DIST_COMM_QUEUE_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOG_LEVEL_DEBUG
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_CRITICAL 4
#endif

typedef struct {
    size_t size; /*memory size (Bytes) */
    void *ptr;   /*ub share memory address*/
} ub_shm_area_t; /* shared memory area descriptor */

typedef struct {
    ub_shm_area_t region; /* ring region information of this node */
    uint8_t node_id;      /* node ID */
} ub_ring_region_info_t;  /* node memory information descriptor */

typedef struct {
    ub_ring_region_info_t *entries; /* array of ring regions of all nodes */
    uint8_t count;                  /* number of elements in the array */
} ub_ring_region_map_t;             /* node ring region map descriptor */

typedef struct {
    uint32_t ring_capacity; /* ring capacity (must be a power of 2) */
    uint32_t max_msg_size;  /* max message size (Bytes) */
    uint8_t priority;       /* ring priority (0, 1, 2...) */
} ub_ring_desc_t;           /* single ring configuration descriptor */

typedef struct {
    int32_t cpu_id;             /* dispatch CPU ID */
    uint8_t max_nodes;          /* maximum number of nodes in the cluster */
    uint8_t current_node_id;    /* current node ID */
    uint8_t num_rings;          /* number of rings created by this node */
    ub_ring_desc_t *ring_descs; /* pointer to ring configuration array */
} ub_comm_conf_t;               /* global ub share memory communication configuration */

typedef struct {
    uint64_t src_thread_id; /* source thread ID */
    uint32_t body_length;   /* message body length */
    uint8_t dest_node_id;   /* destination node ID */
    uint8_t src_node_id;    /* source node ID */
    uint8_t msg_type;       /* business message type ID */
    uint8_t priority;       /* message priority */
} message_header_t;

typedef struct {
    message_header_t header; /* message header */
    char *body;              /* message body */
} message_t;

/* ub share memory communication instance type */
typedef void *ub_shm_comm_t;

/* message processing function type */
typedef void (*ub_callback_t)(const message_t *msg, void *ctx);

typedef enum {
    UB_FUNC_SYNC = 0, /* synchronous callback */
    UB_FUNC_ASYNC     /* asynchronous callback */
} ub_func_type_t;     /* callback type*/

/*
 * @brief Initialize ub share memory communication instance
 * @param handle [out]            : pointer to ub share memory communication instance handle
 * @param init_region [in]        : global initialization region
 * @param ring_regions [in]       : ring regions of all nodes
 * @param conf [in]               : pointer to global communication configuration
 * @return 0 on success, negative error code on failure
 */
int ub_comm_queue_init(ub_shm_comm_t *handle, ub_shm_area_t *init_region, ub_ring_region_map_t *ring_regions,
                       ub_comm_conf_t *conf);

/*
 * @brief Deinitialize ub share memory communication instance
 * @param handle [in]   : pointer to ub share memory communication instance handle
 * @return 0 on success, negative error code on failure
 */
int ub_comm_queue_deinit(ub_shm_comm_t *handle);

/*
 * @brief Send message
 * @param handle [in]   : pointer to ub share memory communication instance handle
 * @param msg [in]      : pointer to message to be sent
 * @return 0 on success, negative error code on failure
 */
int ub_comm_queue_send(ub_shm_comm_t *handle, const message_t *msg);

/*
 * @brief Check node status
 * @param handle [in]   : pointer to ub share memory communication instance handle
 * @param node_id [in]  : node ID to check status
 * @return true if the node is ready, false otherwise
 */
bool ub_comm_queue_check_ready(ub_shm_comm_t *handle, const uint8_t node_id);

/*
 * @brief Receive message
 * @param handle [in]   : pointer to ub share memory communication instance handle
 * @param buffer [out]  : pointer to buffer to receive message
 * @param length [in]   : length of the buffer
 * @return 0 on success, negative error code on failure
 */
int ub_comm_queue_recv(ub_shm_comm_t *handle, void *buffer, uint32_t length);

/*
 * @brief Register message process callback function of specific msg_type
 * @param handle [in]       : pointer to ub share memory communication instance handle
 * @param msg_type [in]     : message type
 * @param func_type [in]    : callback function type
 * @param func [in]         : callback function pointer
 * @param ctx [in]          : callback function context
 * @return 0 on success, negative error code on failure
 */
int ub_comm_queue_register_process_func(ub_shm_comm_t *handle, uint8_t msg_type, ub_func_type_t func_type,
                                        ub_callback_t func, void *ctx);

#ifndef UB_ATOMIC_LOG_FUNC_TYPEDEF
#define UB_ATOMIC_LOG_FUNC_TYPEDEF
/*
* @brief log func
* @param level [in] : LogLevel
* @param file [in] : source file name
* @param func [in] : function name
* @param line [in] : line number
* @param message [in] : formatted message
*/
typedef int (*ub_atomic_log_func)(int level, const char *file, const char *func, uint32_t line, const char *message);

/*
* @brief register log function
* @param func [in] : user-defined log function pointer
*/
void ub_atomic_register_log_func(ub_atomic_log_func func);

/*
* @brief set log level threshold
* @param level [in] : log level threshold (LOG_LEVEL_DEBUG ~ LOG_LEVEL_CRITICAL)
* @return 0 on success, -1 on invalid level
*/
int ub_atomic_set_log_level(int level);
#endif
#ifdef __cplusplus
}
#endif

#endif // UB_DIST_COMM_QUEUE_H
