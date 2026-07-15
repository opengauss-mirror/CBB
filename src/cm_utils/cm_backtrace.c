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
 * cm_backtrace.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_backtrace.c
 *
 * -------------------------------------------------------------------------
 */


#include <cm_backtrace.h>
#ifndef _WIN32

#ifdef __cplusplus
extern "C" {
#endif

static unwind_bt_handle_t g_unwind_bt_handle = {.inited = CM_FALSE, .backtrace_handle = NULL};
static inline unwind_bt_handle_t *cm_unwind_bt_handle(void)
{
    return &g_unwind_bt_handle;
}

static _Unwind_Word cm_dummy_getcfa(struct _Unwind_Context *ctx __attribute__((unused)))
{
    return 0;
}

void cm_init_backtrace_handle(void)
{
    unwind_bt_handle_t *handle = cm_unwind_bt_handle();
    handle->backtrace_handle = dlopen("libgcc_s.so.1", RTLD_LAZY);
    if (handle->backtrace_handle == NULL) {
        LOG_RUN_INF("Load backtrace handle failed.");
        return;
    }
    handle->unwind_backtrace = dlsym(handle->backtrace_handle, "_Unwind_Backtrace");
    handle->unwind_getip = dlsym(handle->backtrace_handle, "_Unwind_GetIP");
    if (handle->unwind_getip == NULL) {
        handle->unwind_backtrace = NULL;
    }
    handle->unwind_getcfa = dlsym(handle->backtrace_handle, "_Unwind_GetCFA");
    if (handle->unwind_getcfa == NULL) {
        handle->unwind_getcfa = cm_dummy_getcfa;
    }
    handle->inited = (handle->unwind_backtrace == NULL) ? CM_FALSE : CM_TRUE;
    if (handle->inited) {
        LOG_RUN_INF("Load backtrace handle succeed.");
    } else {
        LOG_RUN_INF("Load backtrace handle failed.");
    }
}

static _Unwind_Reason_Code cm_backtrace_helper(struct _Unwind_Context *ctx, void *input)
{
    trace_arg_t *arg = input;
    if (arg->cnt != -1) {
        arg->pc_addr[arg->cnt] = (void *)cm_unwind_bt_handle()->unwind_getip(ctx);
        _Unwind_Word cfa = cm_unwind_bt_handle()->unwind_getcfa(ctx);
        if (arg->cfa_addr != NULL) {
            arg->cfa_addr[arg->cnt] = (void *)cfa;
        }
        if (arg->cnt > 0 && arg->pc_addr[arg->cnt -1] == arg->pc_addr[arg->cnt] && cfa == arg->cfa) {
            return _URC_END_OF_STACK;
        }
        arg->cfa = cfa;
    }
    arg->cnt++;
    if (arg->cnt == arg->size) {
        return _URC_END_OF_STACK;
    }
    return _URC_NO_REASON;
}

int32 cm_backtrace(void **array, void **cfa_addr, uint32 size, bool32 *dump_cfa)
{
    unwind_bt_handle_t *handle = cm_unwind_bt_handle();
    trace_arg_t arg = {.pc_addr = array, .cfa_addr = cfa_addr, .cfa = 0, .size = size, .cnt = -1};
    if (!handle->inited || (*dump_cfa) == CM_FALSE) {
        *dump_cfa = CM_FALSE;
        return (int32)backtrace(array, size);
    }
    if (size >= 1) {
        handle->unwind_backtrace(cm_backtrace_helper, &arg);
    }
    if (arg.cnt > 1 && arg.pc_addr[arg.cnt - 1] == NULL) {
        arg.cnt--;
    }
    return (arg.cnt != -1 ? arg.cnt : 0);
}

bool32 cm_stack_load_section_table(const char *file_name, elf_entry_t *elf_entry)
{
    Elf64_Shdr shdr;
    elf_entry->fd = open(file_name, O_RDONLY);
    if (elf_entry->fd == -1) {
        return CM_FALSE;
    }
    elf_entry->fname = file_name;
    if (read(elf_entry->fd, &elf_entry->ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        return CM_FALSE;
    }
    elf_entry->dyn = (elf_entry->ehdr.e_type = ET_DYN) ? CM_TRUE : CM_FALSE;
    if (elf_entry->ehdr.e_shnum > BACKTRACE_MAX_ESHAR_NUM) {
        return CM_FALSE;
    }
    for (int32 i = 0; i < elf_entry->ehdr.e_shnum; i++) {
        off_t off = (off_t)(elf_entry->ehdr.e_shoff + i * elf_entry->ehdr.e_shentsize);
        if (pread(elf_entry->fd, &shdr, sizeof(Elf64_Shdr), off) != sizeof(Elf64_Shdr)) {
            return CM_FALSE;
        }
        if ((shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) && elf_entry->sym_count < SYMHDR_NUM) {
            if (memcpy_s(elf_entry->symhdr + elf_entry->sym_count, sizeof(Elf64_Shdr), &shdr, sizeof(Elf64_Shdr))) {
                return CM_FALSE;
            }
            elf_entry->sym_count++;
        }
    }
    return CM_TRUE;
}

bool32 cm_match_addr_symbol(uintptr_t addr, uint32 *strtab_idx, uint32 *pos, uint32 *offset, elf_entry_t *elf_entry)
{
    for (int32 i = 0; i < elf_entry->sym_count; i++) {
        off_t off = (off_t)(elf_entry->symhdr[i].sh_offset);
        if (lseek(elf_entry->fd, off, SEEK_SET) != off) {
            return CM_FALSE;
        }

        Elf64_Sym sym;
        int32 count = (int)(elf_entry->symhdr[i].sh_size / elf_entry->symhdr[i].sh_entsize);
        for (int32 j = 0; j < count; j++) {
            if (read(elf_entry->fd, &sym, sizeof(Elf64_Sym)) != sizeof(Elf64_Sym)) {
                return CM_FALSE;
            }
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC || addr < sym.st_value || addr > (sym.st_value + sym.st_size)) {
                continue;
            }
            *strtab_idx = elf_entry->symhdr[i].sh_link;
            *pos = sym.st_name;
            *offset = (uint32)(addr - sym.st_value);
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static bool32 cm_stack_copy_symbol_name(uint32 strtab_idx, uint32 pos, char *buf, elf_entry_t *elf_entry)
{
    off_t off = (off_t)(elf_entry->ehdr.e_shoff + strtab_idx * elf_entry->ehdr.e_shentsize);
    if (lseek(elf_entry->fd, off, SEEK_SET) != off) {
        return CM_FALSE;
    }
    Elf64_Shdr shdr;
    if (read(elf_entry->fd, &shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
        return CM_FALSE;
    }
    off = (off_t)(shdr.sh_offset + pos);
    if (lseek(elf_entry->fd, off, SEEK_SET) != off) {
        return CM_FALSE;
    }
    if (read(elf_entry->fd, buf, BACKTRACE_NAME_MAX_LEN) == -1) {
        return CM_FALSE;
    }
    buf[BACKTRACE_NAME_MAX_LEN - 1] = '\0';
    return CM_TRUE;
}

static bool32 cm_stack_find_symbol(uintptr_t addr, char *buf, uint32 *sym_off, elf_entry_t *elf_entry)
{
    uint32 strtab_idx;
    uint32 pos;
    if (cm_match_addr_symbol(addr, &strtab_idx, &pos, sym_off, elf_entry)) {
        return cm_stack_copy_symbol_name(strtab_idx, pos, buf, elf_entry);
    }
    return CM_FALSE;
}

static inline void cm_init_elf_entry(elf_entry_t *elf_entry)
{
    elf_entry->fd = -1;
    elf_entry->fname = NULL;
    elf_entry->sym_count = 0;
    elf_entry->dyn = CM_TRUE;
    (void)memset_s(&elf_entry->ehdr, sizeof(Elf64_Ehdr), 0, sizeof(Elf64_Ehdr));
    (void)memset_s(elf_entry->symhdr, sizeof(Elf64_Shdr), 0, sizeof(Elf64_Shdr));
}

static inline void cm_close_elf_entry(elf_entry_t *elf_entry)
{
    if (elf_entry->fd != -1) {
        (void)close(elf_entry->fd);
    }
}

void cm_stack_find_addr_name(void *pc, Dl_info *dl_info, stack_name_array *call_stack, elf_entry_t *elf_entry)
{
    uintptr_t dl_off = (uintptr_t)pc - (uintptr_t)dl_info->dli_fbase;
    if (elf_entry->fname == NULL || strcmp(elf_entry->fname, dl_info->dli_fname) != 0) {
        if (elf_entry->fd != -1) {
            (void)close(elf_entry->fd);
        }
        cm_init_elf_entry(elf_entry);
        if (!cm_stack_load_section_table(dl_info->dli_fname, elf_entry)) {
            if (elf_entry->fd != -1) {
                (void)close(elf_entry->fd);
                cm_init_elf_entry(elf_entry);
            }
            (void)sprintf_s(call_stack->data, BACKTRACE_NAME_MAX_LEN, "[%s + 0x%x] %p", dl_info->dli_fname, dl_off, pc);
            return;
        }
    }
    char buf[BACKTRACE_NAME_MAX_LEN] = {0};
    uint32 sym_off;
    uintptr_t addr = elf_entry->dyn ? ((uintptr_t)pc - (uintptr_t)dl_info->dli_fbase) : (uintptr_t)pc;
    if (cm_stack_find_symbol(addr, buf, &sym_off, elf_entry)) {
        (void)sprintf_s(
            call_stack->data, BACKTRACE_NAME_MAX_LEN, "[%s + 0x%x] %s + 0x%x", dl_info->dli_fname,
            dl_off, buf, sym_off);
    } else {
        (void)sprintf_s(call_stack->data, BACKTRACE_NAME_MAX_LEN, "[%s + 0x%x] %p", dl_info->dli_fname, dl_off, addr);
    }
}

void cm_find_each_stack_symbol(void *pc, stack_name_array *call_stack, elf_entry_t *elf_entry)
{
    Dl_info dl_info;
    if (dladdr(pc, &dl_info) != 0 && dl_info.dli_fbase != NULL && dl_info.dli_fname != NULL) {
        if (dl_info.dli_saddr != NULL && dl_info.dli_sname != NULL) {
            (void)sprintf_s(call_stack->data, BACKTRACE_NAME_MAX_LEN, "[%s + 0x%x] %s + 0x%x", dl_info.dli_fname,
                (uintptr_t)pc - (uintptr_t)dl_info.dli_fbase, dl_info.dli_sname, (uintptr_t)pc - (uintptr_t)dl_info.dli_saddr);
        } else {
            cm_stack_find_addr_name(pc, &dl_info, call_stack, elf_entry);
        }
    } else {
        (void)sprintf_s(call_stack->data, BACKTRACE_NAME_MAX_LEN, "%p\n", pc);
    }
}

void cm_backtrace_symbols(void **array, size_t size, stack_name_array *call_stack)
{
    elf_entry_t elf_entry = {0};
    cm_init_elf_entry(&elf_entry);
    for (size_t i = CM_INIT_BLACK_BOX_DEPTH; i < size; i++) {
        cm_find_each_stack_symbol(array[i], &call_stack[i], &elf_entry);
    }
    cm_close_elf_entry(&elf_entry);
}

#ifdef __cplusplus
}
#endif
#endif