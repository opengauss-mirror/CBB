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
 * cm_error.h
 *
 *
 * IDENTIFICATION
 *    src/cm_defines/cm_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ERROR_H_
#define __CM_ERROR_H_

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_status {
    CM_ERROR = -1,
    CM_SUCCESS = 0,
    CM_TIMEDOUT = 1,
    CM_PIPECLOSED = 2,
} status_t;

/*
 * @Note
 * Attention1: add error code to the corresponding range
 *
 * ERROR                                  |   RANGE
 * OS errors                              |   1 - 99
 * internal errors or common errors       |   100 - 199
 * configuration errors                   |   200 - 299
 * network errors                         |   300 - 399
 * replication errors                     |   400 - 499
 * storage errors                         |   500 - 599
 */
typedef enum en_cm_errno {
    ERR_ERRNO_BASE = 0,
    /* OS errors: 1 - 99 */
    ERR_SYSTEM_CALL = 1,
    ERR_RESET_MEMORY = 2,
    ERR_ALLOC_MEMORY_REACH_LIMIT = 3,
    ERR_ALLOC_MEMORY = 4,
    ERR_LOAD_LIBRARY = 5,
    ERR_LOAD_SYMBOL = 6,
    ERR_DATAFILE_FSYNC = 7,
    ERR_DATAFILE_FDATASYNC = 8,
    ERR_INVALID_FILE_NAME = 9,
    ERR_CREATE_FILE = 10,
    ERR_OPEN_FILE = 11,
    ERR_READ_FILE = 12,
    ERR_WRITE_FILE = 13,
    ERR_WRITE_FILE_PART_FINISH = 14,
    ERR_SEEK_FILE = 15,
    ERR_CREATE_DIR = 16,
    ERR_RENAME_FILE = 17,
    ERR_FILE_SIZE_MISMATCH = 18,
    ERR_REMOVE_FILE = 19,
    ERR_TRUNCATE_FILE = 20,
    ERR_LOCK_FILE = 21,
    ERR_CREATE_THREAD = 22,
    ERR_INIT_THREAD = 23,
    ERR_SET_THREAD_STACKSIZE = 24,
    ERR_INVALID_DIR = 25,
    ERR_COMPRESS_INIT_ERROR = 26,
    ERR_COMPRESS_ERROR = 27,
    ERR_DECOMPRESS_ERROR = 28,
    ERR_COMPRESS_FREE_ERROR = 29,
    ERR_NULL_PTR = 30,
    ERR_UNLOCK_FILE = 31,
    ERR_NOT_EXIST_FILE = 32,
    // 60 - 70 buddy memory error
    ERR_MEM_ZONE_INIT_FAIL = 60,
    ERR_MEM_OUT_OF_MEMORY = 61,
    ERR_CREATE_EVENT = 62,
    /* internal errors or common errors: 100 - 199 */
    ERR_TEXT_FORMAT_ERROR = 100,
    ERR_BUFFER_OVERFLOW = 101,
    ERR_COVNERT_FORMAT_ERROR = 102,
    ERR_ZERO_DIVIDE = 103,
    ERR_RBT_INSERT_ERROR = 104,
    ERR_TYPE_OVERFLOW = 105,
    ERR_ASSERT_ERROR = 106,
    ERR_VALUE_ERROR = 107,
    ERR_INVALID_VALUE = 108,
    ERR_MALLOC_BYTES_MEMORY = 109,
    ERR_PASSWORD_IS_TOO_SIMPLE = 110,
    ERR_PASSWORD_FORMAT_ERROR = 111,
    ERR_INVALID_PARAM = 112,
    /* Error code for access interface of SCSI */
    ERR_SCSI_LOCK_OCCUPIED = 136,
    ERR_SCSI_REG_CONFLICT = 137,

    /* invalid configuration errors: 200 - 299 */
    ERR_PARSE_CFG_STR = 200,

    /* network errors: 300 - 399 */
    ERR_INIT_NETWORK_ENV = 301,

    ERR_ESTABLISH_TCP_CONNECTION = 303,
    ERR_PEER_CLOSED = 304,
    ERR_TCP_TIMEOUT = 305,
    ERR_CREATE_SOCKET = 306,
    ERR_SET_SOCKET_OPTION = 307,
    ERR_TCP_PORT_CONFLICTED = 308,
    ERR_SOCKET_BIND = 309,
    ERR_SOCKET_LISTEN = 310,
    ERR_INVALID_PROTOCOL = 311,
    ERR_SOCKET_TIMEOUT = 312,
    ERR_TCP_RECV = 313,

    ERR_PACKET_READ = 315,
    ERR_TCP_INVALID_IPADDRESS = 316,
    ERR_IPADDRESS_NUM_EXCEED = 317,

    ERR_PEER_CLOSED_REASON = 318,
    ERR_PACKET_SEND = 319,
    ERR_PROTOCOL_NOT_SUPPORT = 320,
    ERR_MEC_INIT_FAIL = 321,
    ERR_MEC_CREATE_AREA = 322,
    ERR_MEC_CREATE_SOCKET = 323,
    ERR_MEC_INVALID_CMD = 324,
    ERR_MEC_RECV_FAILED = 325,
    ERR_MEC_CREATE_MUTEX = 326,
    ERR_MEC_ILEGAL_MESSAGE = 327,
    ERR_MEC_PARAMETER = 328,
    ERR_MEC_ALREADY_CONNECT = 329,
    ERR_MEC_SEND_FAILED = 330,
    ERR_MEC_FRAGMENT_THRESHOLD = 331,
    ERR_MEC_INCONSISTENT_FRAG_NO = 332,
    ERR_SSL_INIT_FAILED = 333,
    ERR_SSL_RECV_FAILED = 334,
    ERR_SSL_VERIFY_CERT = 335,
    ERR_SSL_CONNECT_FAILED = 336,
    ERR_SSL_FILE_PERMISSION = 337,
    ERR_FULL_PACKET = 338,
    /* replication errors: 400 - 499 */
    ERR_TERM_IS_NOT_MATCH = 400,
    ERR_TERM_IS_EXPIRED = 401,
    ERR_APPEN_LOG_REQ_LOST = 402,

    /* storage errors: 500 - 599 */
    ERR_APPEND_ENTRY_FAILED = 500,
    ERR_INDEX_NOT_CONTIGUOUS = 501,
    ERR_INDEX_BEFORE_APPLIED = 502,
    ERR_ADD_CACHE_FAILED = 503,
    ERR_ADD_QUEUE_FAILED = 504,
    ERR_STG_INTERNAL_ERROR = 505,
    ERR_STG_MEM_POOL_FULL = 506,

    /* mes errno 600 ~ 1000 */
    ERR_MES_MEMORY_COPY_FAIL = 600,
    ERR_MES_MEMORY_SET_FAIL = 601,
    ERR_MES_STR_COPY_FAIL = 602,
    ERR_MES_PARAM_NULL = 603,
    ERR_MES_PARAM_INVAIL = 604,
    ERR_MES_CREAT_MUTEX_FAIL = 605,
    ERR_MES_MALLOC_FAIL = 606,
    ERR_MES_WORK_THREAD_FAIL = 607,
    ERR_MES_START_LSRN_FAIL = 608,
    ERR_MES_IS_CONNECTED = 609,
    ERR_MES_CONNTYPE_ERR = 610,
    ERR_MES_THE_GROUP_SETED = 611,
    ERR_MES_CHANNEL_THREAD_FAIL = 612,
    ERR_MES_ALLOC_MSGITEM_FAIL = 613,
    ERR_MES_SENDPIPE_NO_REDAY = 614,
    ERR_MES_SEND_MSG_FAIL = 615,
    ERR_MES_MSG_TOO_LARGE = 616,
    ERR_MES_WAIT_OVERTIME = 617,
    ERR_MES_BUF_ID_EXCEED = 618,
    ERR_MES_FREELIST_CNT_ERR = 619,
    ERR_MES_READ_MSG_FAIL = 620,
    ERR_MES_PROTOCOL_INVALID = 621,
    ERR_MES_WAIT_FAIL = 622,
    ERR_MES_CMD_TYPE_ERR = 623,
    ERR_MES_GROUPTASK_NUM_ERR = 624,
    ERR_MES_EPOLL_INIT_FAIL = 625,
    ERR_MES_SOCKET_FAIL = 626,
    ERR_MES_CONNECT_TIMEOUT = 627,
    ERR_MES_RECV_PIPE_INACTIVE = 628,
    ERR_MES_INVALID_MSG_HEAD = 629,
    // The max error number
    ERR_CODE_CEIL = 2000,
} cm_errno_t;

// buf in thread local storage, which used for converting text to string
#define CM_T2S_BUFFER_SIZE (uint32)256
#define CM_T2S_LARGER_BUFFER_SIZE SIZE_K(16)

/* using for client communication with server, such as error buffer */
#define CM_MESSAGE_BUFFER_SIZE (uint32)2048

typedef struct st_error_info_t {
    int32 code;
    char t2s_buf1[CM_T2S_LARGER_BUFFER_SIZE];
    char t2s_buf2[CM_T2S_BUFFER_SIZE];
    char message[CM_MESSAGE_BUFFER_SIZE];
} error_info_t;

#ifndef EOK
#define EOK (0)
#endif
#ifndef errno_t
typedef int errno_t;
#endif

int cm_get_os_error(void);
int cm_get_sock_error(void);
void cm_set_sock_error(int32 e);
void cm_reset_error(void);

int32 cm_get_error_code(void);
const char *cm_get_errormsg(int32 code);
void cm_get_error(int32 *code, const char **message);

static inline void cm_panic(bool32 condition)
{
    if (SECUREC_UNLIKELY(!condition)) {
        *((uint32 *)NULL) = 1;
    }
}

#define securec_check_ret(err)                        \
    do {                                              \
        if ((err) != EOK) {                           \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode); \
            return CM_ERROR;                          \
        }                                             \
    } while (0)

#define securec_check_panic(err)                        \
        do {                                              \
            if ((err) != EOK) {                           \
                cm_panic(0);                              \
            }                                             \
        } while (0)

#define CM_THROW_ERROR(error_no, ...)                                                                                  \
    do {                                                                                                               \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no,    \
            g_error_desc[error_no], ##__VA_ARGS__); \
    } while (0)

#define CM_THROW_ERROR_EX(error_no, format, ...)                                                          \
    do {                                                                                                  \
        cm_set_error_ex((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

void cm_set_error(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);
void cm_set_error_ex(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);

extern const char *g_error_desc[];

/* convert text to string, using local thread buffer */
char *cm_get_t2s_addr(void);
char *cm_t2s(const char *buf, uint32 len);
char *cm_concat_t2s(const char *buf1, uint32 len1, const char *buf2, uint32 len2, char c_mid);
char *cm_t2s_ex(const char *buf, uint32 len);
char *cm_t2s_case(const char *buf, uint32 len, bool32 case_sensitive);
void cm_register_error(uint16 errnum, const char *errmsg);
typedef status_t (*cm_error_handler)(const char *file, uint32 line, cm_errno_t code, const char *format,
    va_list args);
status_t cm_set_log_error(const char *file, uint32 line, cm_errno_t code, const char *format, va_list args);
void cm_init_error_handler(cm_error_handler handler);
#define T2S(text) cm_t2s((text)->str, (text)->len)
#define T2S_EX(text) cm_t2s_ex((text)->str, (text)->len)
#define T2S_CASE(text, flag) cm_t2s_case((text)->str, (text)->len, (flag))
#define CC_T2S(text1, text2, c_mid) cm_concat_t2s((text1)->str, (text1)->len, (text2)->str, (text2)->len, (c_mid))

#ifdef __cplusplus
}
#endif
#endif
