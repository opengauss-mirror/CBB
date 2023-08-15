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
 * cm_blackbox.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_blackbox.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef _WIN32
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ucontext.h>
#include <cm_signal.h>
#include <sys/prctl.h>
#include "cm_timer.h"
#include "cm_file.h"
#include "cm_blackbox.h"
#include "cm_backtrace.h"

__thread bool32 g_in_backtrace = CM_FALSE;

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined(__cplusplus)) && (!defined(NO_CPP_DEMANGLE))
#define NO_CPP_DEMANGLE
#endif

#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#ifdef __cplusplus
using __cxxabiv1::__cxa_demangle;
#endif
#endif

#if (defined __x86_64__)
#define REGFORMAT "%s0x%016llx\n"
#elif (defined __aarch64__)
#define REGFORMAT "x[%02d]    0x%016llx\n"
#endif

static bool32 need_print_sig_addr(uint32 sig_num)
{
    const uint32 sig_list[] = {SIGILL, SIGBUS, SIGFPE, SIGSEGV};
    for (uint32 i = 0; i < ARRAY_NUM(sig_list); i++) {
        if (sig_num == sig_list[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static void print_sig_extend_info(box_excp_item_t *excep_info)
{
    if (excep_info->sig_code <= 0) {
        LOG_BLACKBOX_INF("Sending User = %u\n", excep_info->sig_uid);
        LOG_BLACKBOX_INF("Sending Process = %d\n", excep_info->sig_pid);
        return;
    }
    if (need_print_sig_addr(excep_info->sig_index)) {
        LOG_BLACKBOX_INF("Exception Addr = 0x%016llx\n", (uint64)excep_info->sig_addr);
    }
}

void cm_print_sig_info(box_excp_item_t *excep_info, void *cpu_info)
{
    LOG_BLACKBOX_INF("\n==================exception info==================\n");
    LOG_BLACKBOX_INF("Exception Date = %s\n", excep_info->date);
    LOG_BLACKBOX_INF("Exception Number = %u\n", excep_info->sig_index);
    LOG_BLACKBOX_INF("Exception Code = %d\n", excep_info->sig_code);
    LOG_BLACKBOX_INF("Exception Name = %s\n", excep_info->sig_name);
    LOG_BLACKBOX_INF("Exception Process = 0x%016llx\n", excep_info->loc_id);
    LOG_BLACKBOX_INF("Exception Thread = 0x%016llx\n", (uint64)excep_info->thread_id);
    LOG_BLACKBOX_INF("Exception Process name = %s\n", excep_info->loc_name);
    print_sig_extend_info(excep_info);
    LOG_BLACKBOX_INF("Version = %s\n", excep_info->version);
    LOG_BLACKBOX_INF("Platform = %s\n", excep_info->platform);
}

void cm_print_reg(box_reg_info_t *reg_info)
{
    LOG_BLACKBOX_INF("Register Contents:\n");
#if (defined __x86_64__)
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RAX    ", reg_info->rax);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RBX    ", reg_info->rbx);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RCX    ", reg_info->rcx);   
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RDX    ", reg_info->rdx);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RSI    ", reg_info->rsi);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RDI    ", reg_info->rdi);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RBP    ", reg_info->rbp);  
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RSP    ", reg_info->rsp);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R8     ", reg_info->r8);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R9     ", reg_info->r9);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R10    ", reg_info->r10);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R11    ", reg_info->r11);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R12    ", reg_info->r12);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R13    ", reg_info->r13);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R14    ", reg_info->r14);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  R15    ", reg_info->r15);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  RIP    ", reg_info->rip);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  EFLAGS ", reg_info->eflags);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  CS     ", reg_info->cs);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  ERR    ", reg_info->err); 
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  TRAPNO ", reg_info->trapno);  
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  OM     ", reg_info->oldmask);
    LOG_BLACKBOX_INF(REGFORMAT, "reg:  CR2    ", reg_info->cr2);            
#elif (defined __aarch64__)
    for (uint32 i = 0; i < 31; i++) {
        LOG_BLACKBOX_INF(REGFORMAT, i, reg_info->reg[i]); 
    }
    LOG_BLACKBOX_INF("sp      0x%016llx\n", reg_info->sp);
    LOG_BLACKBOX_INF("pc      0x%016llx\n", reg_info->pc);
#endif
}

void cm_print_assembly(box_reg_info_t *reg_info)
{
    unsigned char *pc = NULL;
    LOG_BLACKBOX_INF("\nAssembly instruction:");
#if (defined __x86_64__)
    pc = (unsigned char*)reg_info->rip;
#elif (defined __aarch64__)
    pc = (unsigned char*)reg_info->sp;
#endif
    for (int32 i = -8; i < 16; i++) {
        if (i % 8 == 0) {
            if (i == 0) {
                LOG_BLACKBOX_INF("\n%s ", ">");
            } else {
                LOG_BLACKBOX_INF("\n  ");
            }
        }
        LOG_BLACKBOX_INF("%02x ", *(pc + i));
    }
    LOG_BLACKBOX_INF("\n");
}

status_t cm_proc_sign_init(box_excp_item_t *excep_info)
{
    errno_t ret = memset_s(excep_info, sizeof(box_excp_item_t), 0, sizeof(box_excp_item_t));
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void cm_proc_get_register_info(box_reg_info_t *cpu_info, ucontext_t *uc)
{
    if (cpu_info == NULL || uc == NULL) {
        return;
    }
#if (defined __x86_64__)
    cpu_info->rax = uc->uc_mcontext.gregs[REG_RAX];
    cpu_info->rbx = uc->uc_mcontext.gregs[REG_RBX];
    cpu_info->rcx = uc->uc_mcontext.gregs[REG_RCX];
    cpu_info->rdx = uc->uc_mcontext.gregs[REG_RDX];
    cpu_info->rsi = uc->uc_mcontext.gregs[REG_RSI];    
    cpu_info->rdi = uc->uc_mcontext.gregs[REG_RDI];
    cpu_info->rbp = uc->uc_mcontext.gregs[REG_RBP];
    cpu_info->rsp = uc->uc_mcontext.gregs[REG_RSP];
    cpu_info->r8 = uc->uc_mcontext.gregs[REG_R8];
    cpu_info->r9 = uc->uc_mcontext.gregs[REG_R9];
    cpu_info->r10 = uc->uc_mcontext.gregs[REG_R10];
    cpu_info->r11 = uc->uc_mcontext.gregs[REG_R11];
    cpu_info->r12 = uc->uc_mcontext.gregs[REG_R12];
    cpu_info->r13 = uc->uc_mcontext.gregs[REG_R13];
    cpu_info->r14 = uc->uc_mcontext.gregs[REG_R14];
    cpu_info->r15 = uc->uc_mcontext.gregs[REG_R15];
    cpu_info->rip = uc->uc_mcontext.gregs[REG_RIP];
    cpu_info->eflags = uc->uc_mcontext.gregs[REG_EFL];
    cpu_info->cs = uc->uc_mcontext.gregs[REG_CSGSFS];
    cpu_info->err = uc->uc_mcontext.gregs[REG_ERR];
    cpu_info->trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
    cpu_info->oldmask = uc->uc_mcontext.gregs[REG_OLDMASK];
    cpu_info->cr2 = uc->uc_mcontext.gregs[REG_CR2];
#elif (defined __aarch64__)
for (uint32 i = 0; i < 31; i++) {
        cpu_info->reg[i] = uc->uc_mcontext.regs[i]; 
    }
    cpu_info->sp = uc->uc_mcontext.sp;
    cpu_info->pc = uc->uc_mcontext.pc;
#endif
}

void cm_proc_sig_get_header(box_excp_item_t *excep_info, int32 sig_num, siginfo_t *siginfo, void *context)
{
    uint32 loop = 0;
    char *platform_name = NULL;
    char *loc_name = NULL;
    excep_info->magic = (uint32)BOX_EXCP_MAGIC;
    excep_info->trace_tail[loop] = (uint32)BOX_TAIL_MAGIC;
    for (loop = 1; loop < BOX_SPACE_SIZE; loop++) {
        excep_info->trace_tail[loop] = (uint32)BOX_TAIL_MAGIC;
    }
    excep_info->sig_index = (uint32)sig_num;
    excep_info->thread_id = pthread_self();
    excep_info->loc_id = cm_sys_pid();
    platform_name = cm_sys_platform_name();
    int32 ret = strncpy_s(excep_info->platform, CM_NAME_BUFFER_SIZE, platform_name, strlen(platform_name));
    securec_check_panic(ret);
    loc_name = cm_sys_program_name();
    ret = strncpy_s(excep_info->loc_name, CM_NAME_BUFFER_SIZE, loc_name, strlen(loc_name));
    securec_check_panic(ret);
   if (siginfo != NULL) {
        excep_info->sig_code = siginfo->si_code;
        if (excep_info->sig_code <= 0) {
            excep_info->sig_uid = siginfo->si_uid;
            excep_info->sig_pid = siginfo->si_pid;
        } else if (need_print_sig_addr(excep_info->sig_index)) {
            excep_info->sig_addr = siginfo->si_addr;
        }
   }
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", excep_info->date, CM_MAX_TIME_STRLEN);
}

#define CM_MAP_BUFFER_LEN 512
void cm_save_proc_maps_file(box_excp_item_t *excep_info)
{
    int32 fd;
    ssize_t cnt;
    char buffer[CM_MAP_BUFFER_LEN] = {0};
    (void)sprintf_s(buffer, sizeof(buffer), "/proc/%u/maps", (uint32)excep_info->loc_id);
    LOG_BLACKBOX_INF("Proc maps information:\n");
    if (cm_open_file_ex(buffer, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &fd) != CM_SUCCESS) {
        return;
    }
    cnt = read(fd, buffer, sizeof(buffer) - 1);
    while (cnt > 0) {
        ((char *)buffer)[cnt] = '\0';
        LOG_BLACKBOX_INF("%s", buffer);
        cnt = read(fd, buffer, sizeof(buffer) - 1);
    }
    LOG_BLACKBOX_INF("\n");
    cm_close_file(fd);
}

#define CM_PROC_MEM_BUFFER_LEN 512

void cm_save_proc_meminfo_file(void)
{
    int32 fd;
    ssize_t cnt;
    char buffer[CM_PROC_MEM_BUFFER_LEN] = {0};
    LOG_BLACKBOX_INF("Proc memory information:\n");
    if (cm_open_file_ex(BOX_PROC_MEMINFO_PATH, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &fd) != CM_SUCCESS) {
        return;
    }
    cnt = read(fd, buffer, sizeof(buffer) - 1);
    while (cnt > 0) {
        ((char *)buffer)[cnt] = '\0';
        LOG_BLACKBOX_INF("%s", buffer);
        cnt = read(fd, buffer, sizeof(buffer) - 1);
    }
    LOG_BLACKBOX_INF("\n");
    cm_close_file(fd);
}

sig_buf_node_t g_sig_bt_buffer = {0};

void cm_sig_collect_backtrace(uint32 log_id, thread_t* thread, const char *format, ...)
{
    int32 cnt;
    int32 len;
    errno_t ret;
    char log_head[CM_MAX_LOG_HEAD_LENGTH] = {0};
    if (thread == NULL || thread->closed || thread->id == 0) {
        return;
    }
    cm_spin_lock(&g_sig_bt_buffer.lock, NULL);
    g_sig_bt_buffer.status = SIG_BUFFER_COLLECTING;
    len = snprintf_s(log_head, CM_MAX_LOG_HEAD_LENGTH, CM_MAX_LOG_HEAD_LENGTH - 1, "\n");
    if (len < 0) {
        cm_spin_unlock(&g_sig_bt_buffer.lock);
        return;
    }
    va_list args;
    va_start(args, format);
    ret = vsnprintf_s(log_head + len, CM_MAX_LOG_HEAD_LENGTH - len, CM_MAX_LOG_HEAD_LENGTH - len - 1, format, args);
    va_end(args);
    if (ret < 0) {
        cm_spin_unlock(&g_sig_bt_buffer.lock);
        return;
    }
    len += ret;
    ret = snprintf_s(log_head + len, CM_MAX_LOG_HEAD_LENGTH - len, CM_MAX_LOG_HEAD_LENGTH - len - 1, " stack info\n");
    if (ret < 0) {
        cm_spin_unlock(&g_sig_bt_buffer.lock);
        return;
    }
    cnt = 0;
    pthread_kill(thread->id, SIG_BACKTRACE);
    while (g_sig_bt_buffer.status == SIG_BUFFER_COLLECTING && cnt < 100) {
        cm_sleep(1);
        cnt++;
    }
    if (g_sig_bt_buffer.status == SIG_BUFFER_COLLECTED) {
        LOG_BLACKBOX_INF("%s", log_head);
        LOG_BLACKBOX_INF("%s", g_sig_bt_buffer.buf);
    }
    g_sig_bt_buffer.status = SIG_BUFFER_IDLE;
    cm_spin_unlock(&g_sig_bt_buffer.lock);
}

void cm_print_call_link(box_reg_info_t *reg_info)
{
    void *array[CM_MAX_BLACK_BOX_DEPTH] = {0};
    void *cfa_addr[CM_MAX_BLACK_BOX_DEPTH] = {0};
    stack_name_array call_stack[CM_MAX_BLACK_BOX_DEPTH] = {0};
    bool32 dump_cfa = CM_TRUE;
    void *pc = NULL;
    uint32 start_size;
    if (g_in_backtrace) {
        LOG_BLACKBOX_INF("\nIn backtrace, can not collect backtrace\n");
        return;
    }
    size_t size = (size_t)cm_backtrace(array, cfa_addr, CM_MAX_BLACK_BOX_DEPTH, &dump_cfa);
    cm_backtrace_symbols(array, size, call_stack);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    start_size = CM_MIN_BLACK_BOX_DEPTH;
#else
    start_size = CM_INIT_BLACK_BOX_DEPTH + 1;
#endif
    if (size <= start_size) {
        LOG_BLACKBOX_INF("print stack failed, backtrace stack size %u is not correct\n", (uint32)size);
        return;
    }
    LOG_BLACKBOX_INF("\nStack information when exception\n");
    for (uint32 i = start_size; i < (uint32)size; i++) {
        LOG_BLACKBOX_INF("  %s\n", call_stack[i].data);
    }
    if (!dump_cfa) {
        return;
    }
    LOG_BLACKBOX_INF("\nDump each stack frame memory:\n");
    for (uint32 i = start_size; i < (uint32)size - 1; i++) {
        LOG_BLACKBOX_INF("Frame %u %s\n", i - CM_INIT_BLACK_BOX_DEPTH, call_stack[i].data);
#if (defined __x86_64__)
        pc = (i == start_size) ? (void *)reg_info->rsp : cfa_addr[i];
#elif (defined __aarch64__)
        pc = (i == start_size) ? (void *)reg_info->reg[29] : cfa_addr[i];
#endif
        LOG_BLACKBOX_INF("Stack area: %p - %p", i < size - 1 ? cfa_addr[i + 1] : 0x0, pc);
        cm_dump_mem_in_blackbox(pc, (uint32)(cfa_addr[i + 1] - pc));
        LOG_BLACKBOX_INF("\n\n");
    }
}

void cm_sig_backtrace_func_call(void)
{
    void *array[CM_MAX_BLACK_BOX_DEPTH] = {0};
    stack_name_array call_stack[CM_MAX_BLACK_BOX_DEPTH] = {0};
    uint32 offset = 0;
    int32 lens;
    bool32 dump_cfa = CM_FALSE;
    if (g_in_backtrace) {
        lens = snprintf_s(g_sig_bt_buffer.buf, SIG_STACK_MAX_BUFFER, SIG_STACK_MAX_BUFFER - 1, "%s\n",
            "In backtrace, do not trigger collection backtrace.");
        if (lens > 0) {
            g_sig_bt_buffer.offset = lens;
        }
        g_sig_bt_buffer.status = SIG_BUFFER_COLLECTED;
        return;
    }
    size_t size = (size_t)cm_backtrace(array, NULL, CM_MAX_BLACK_BOX_DEPTH, &dump_cfa);
    cm_backtrace_symbols(array, size, call_stack);
    if (size <= CM_MIN_BLACK_BOX_DEPTH) {
        g_sig_bt_buffer.status = SIG_BUFFER_ERROR;
        return;
    }
    for (uint32 i = CM_MIN_BLACK_BOX_DEPTH; i < (uint32)size; i++) {
        lens = snprintf_s(g_sig_bt_buffer.buf + offset, SIG_STACK_MAX_BUFFER - offset,
            SIG_STACK_MAX_BUFFER - offset - 1, "%s\n", call_stack[i].data);
        if (lens <= 0) {
            break;
        }
        offset += lens;
    }
    g_sig_bt_buffer.offset = offset;
    CM_MFENCE;
    g_sig_bt_buffer.status = SIG_BUFFER_COLLECTED;
    return;
}

void cm_sig_backtrace_func(int32 sig_num, siginfo_t *sig_info, void *context)
{
    if (g_sig_bt_buffer.status != SIG_BUFFER_COLLECTING) {
        return;
    }
    if (!cm_spin_try_lock(&g_sig_bt_buffer.thread_lock)) {
        return;
    }
    sigset_t obj_sign_mask;
    sigset_t save_mask;
    (void)sigfillset(&obj_sign_mask);
    pthread_sigmask(SIG_SETMASK, &obj_sign_mask, &save_mask);
    cm_sig_backtrace_func_call();
    pthread_sigmask(SIG_SETMASK, &save_mask, NULL);
    cm_spin_unlock(&g_sig_bt_buffer.thread_lock);
}

#ifdef __cplusplus
}
#endif
#endif