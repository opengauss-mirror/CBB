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
 * cm_defs.c
 *
 *
 * IDENTIFICATION
 *    src/cm_defines/cm_defs.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

static cm_malloc_proc_t cm_malloc_proc = NULL;
static cm_free_proc_t cm_free_proc = NULL;
void regist_cm_malloc_proc(cm_malloc_proc_t malloc_proc, cm_free_proc_t free_proc)
{
    cm_malloc_proc = malloc_proc;
    cm_free_proc = free_proc;
}

void *cm_malloc_prot(size_t size)
{
    if (cm_malloc_proc == NULL) {
        return malloc(size);
    } else {
        return cm_malloc_proc(size);
    }
}

void cm_free_prot(void *pointer)
{
    if (cm_free_proc == NULL) {
        free(pointer);
    } else {
        cm_free_proc(pointer);
    }
}

#ifdef __cplusplus
}
#endif
