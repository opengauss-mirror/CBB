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
 * cm_backtrace.h
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_backtrace.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BACKTRACE_H__
#define __CM_BACKTRACE_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_memory.h"
#include "cm_stack.h"

#ifndef WIN32

#include <dlfcn.h>
#include <execinfo.h>
#include <unwind.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYMHDR_NUM  2
#define BACKTRACE_NAME_MAX_LEN 256
#define BACKTRACE_MAX_ESHAR_NUM 1000

typedef struct st_trace_arg {
    void **pc_addr;
    void **cfa_addr;
    _Unwind_Word cfa;
    int32 cnt;
    int32 size;
} trace_arg_t;

typedef struct st_stack_name_array {
    char data[BACKTRACE_NAME_MAX_LEN];
    uint32 len;
} stack_name_array;

typedef struct st_elf_entry {
    const char *fname;
    int32 fd;
    Elf64_Ehdr ehdr;
    Elf64_Shdr symhdr[SYMHDR_NUM];
    int32 sym_count;
    bool32 dyn;
} elf_entry_t;

typedef _Unwind_Reason_Code (*unwind_backtrace_t)(_Unwind_Trace_Fn, void *);
typedef _Unwind_Ptr (*unwind_getip_t)(struct _Unwind_Context *);
typedef _Unwind_Word (*unwind_getcfa_t)(struct _Unwind_Context *);
typedef struct st_unwind_bt_handle {
    bool32 inited;
    void *backtrace_handle;
    unwind_backtrace_t unwind_backtrace;
    unwind_getip_t unwind_getip;
    unwind_getcfa_t unwind_getcfa;
} unwind_bt_handle_t;

void cm_init_backtrace_handle(void);
int32 cm_backtrace(void **array, void **cfa_addr, uint32 size, bool32 *dump_cfa);
void cm_backtrace_symbols(void **array, size_t size, stack_name_array *call_stack);

#ifdef __cplusplus
}

#endif
#endif
#endif
