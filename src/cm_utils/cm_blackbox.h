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
 * cm_blackbox.h
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_blackbox.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BLACKBOX_H__
#define __CM_BLACKBOX_H__

#include "signal.h"
#include "pthread.h"
#include "cm_log.h"
#include "cm_defs.h"
#include "cm_thread_pool.h"
#include "cm_spinlock.h"
#include "cm_system.h"

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_MAX_NAME_LEN  32
#define BOX_INS_CONT_LEN  32
#define BOX_VERSION_LEN 128
#define BOX_SPACE_SIZE 2
#define BOX_EXCP_MAGIC  (0xECECECEC)
#define BOX_EXCP_TO_LOG (0X12345678)
#define BOX_TAIL_MAGIC (0xFFFFFFFF)
#define SIG_STACK_MAX_BUFFER   SIZE_K(8)
#define BOX_PROC_MEMINFO_PATH "/proc/meminfo"

typedef enum en_default_action {
    TERMINATE_SIG = 0,
    IGNORE_SIG,
    CONTINUE_SIG,
    STOP_SIG,
    DUMP_SIG,
} default_action_t;

typedef struct st_sig_info {
    const char* comment;
    default_action_t action;
} sig_info_t;

typedef struct st_box_reg_info {
#if (defined __X86_64__)
    int64 r8;
    int64 r9;
    int64 r10;
    int64 r11;
    int64 r12;
    int64 r13;
    int64 r14;
    int64 r15;
    int64 rdi;
    int64 rsi;
    int64 rbp;
    int64 rbx;
    int64 rdx; 
    int64 rax;    
    int64 rcx;
    int64 rsp;
    int64 rip;
    int64 eflags;
    int64 cs;
    int64 err;
    int64 trapno;
    int64 oldmask;
    int64 cr2;
#elif (defined __aarch64__)
    uint64 reg[31]; /* arm register */
    uint64 sp;
    uint64 pc;
#endif
} box_reg_info_t;
 
 typedef struct st_box_excp_item {
    uint32 magic;
    uint64 loc_id;
    pthread_t thread_id;
    uint32 sig_index;
    int32 sig_code;
    box_reg_info_t reg_info;
    uintptr_t stack_addr;
    char sig_name[CM_NAME_BUFFER_SIZE];
    char loc_name[CM_FILE_NAME_BUFFER_SIZE + 1];
    char platform[CM_NAME_BUFFER_SIZE];
    uchar ins_content[BOX_INS_CONT_LEN];
    char version[BOX_VERSION_LEN];
    char date[CM_MAX_TIME_STRLEN];
    uint32 trace_tail[BOX_SPACE_SIZE];
    union {
        struct {
            uid_t sig_uid;
            pid_t sig_pid;
        };
        struct {
            void* sig_addr;
        };        
    };
} box_excp_item_t;

typedef enum {
    SIG_BUFFER_IDLE = 0,
    SIG_BUFFER_COLLECTING,
    SIG_BUFFER_COLLECTED,
    SIG_BUFFER_ERROR,
} sig_buf_status_t;

typedef struct st_sig_buf_node_t {
    char buf[SIG_STACK_MAX_BUFFER];
    uint32 offset;
    spinlock_t lock;
    spinlock_t thread_lock;
    sig_buf_status_t status;
} sig_buf_node_t;

status_t cm_proc_sign_init(box_excp_item_t *excep_info);
void cm_proc_sig_get_header(box_excp_item_t *excep_info, int32 sig_num, siginfo_t *siginfo, void *context);
void cm_proc_get_register_info(box_reg_info_t *cpu_info, ucontext_t *uc);
void cm_print_sig_info(box_excp_item_t *excep_info, void *cpu_info);
void cm_print_reg(box_reg_info_t *reg_info);
void cm_print_assembly(box_reg_info_t *reg_info);
void cm_print_call_link(box_reg_info_t *reg_info);
void cm_save_proc_maps_file(box_excp_item_t *excep_info);
void cm_save_proc_meminfo_file(void);
void cm_sig_collect_backtrace(uint32 log_id, thread_t* thread, const char *format, ...);
void cm_sig_backtrace_func(int32 sig_num, siginfo_t *sig_info, void *context);

#ifdef __cplusplus
}
#endif
#endif
