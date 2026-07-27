/*
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
 * mes_shm_dl.h
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_dl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_DL_H
#define MES_SHM_DL_H

#include <limits.h>

#include "mes_interface.h"
#include "ub_dist_comm_queue.h"
#include "ubs_mem_def.h"

/* Max path buffer for dlopen path resolution (env dir + '/' + so name); realpath second arg needs >= PATH_MAX. */
#ifndef PATH_MAX
#define PATH_LENGTH 4096
#else
#define PATH_LENGTH PATH_MAX
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define UBS_MEM_ENV_PATH   "UBS_MEM_LIB_PATH"
#define UBS_MEM_SO_NAME    "libubsm_sdk.so"
#define UBS_MEM_DEFAULT_SO_PATH "/usr/local/ubs_mem/lib/libubsm_sdk.so"

#define UB_DIST_COMM_ENV_PATH        "UB_DIST_COMM_LIB_PATH"
#define UB_DIST_COMM_SO_NAME         "libubs-atomic.so"
#define UB_DIST_COMM_DEFAULT_SO_PATH "/usr/lib64/libubs-atomic.so"

int mes_init_ubs_dlopen_so(void);
void FinishUbsMemDl(void);

int mes_ubsmem_init_attributes(ubsmem_options_t *ubsm_shmem_opts);
int mes_ubsmem_initialize(const ubsmem_options_t *ubsm_shmem_opts);
int mes_ubsmem_finalize(void);
int mes_ubsmem_lookup_regions(ubsmem_regions_t *regions);
int mes_ubsmem_create_region(const char *region_name, size_t size,
    const ubsmem_region_attributes_t *reg_attr);
int mes_ubsmem_destroy_region(const char *region_name);
int mes_ubsmem_shmem_allocate(const char *region_name, const char *name,
    size_t size, mode_t mode, uint64_t flags);
int mes_ubsmem_shmem_allocate_with_provider(const ubs_mem_provider_t *src_loc, const char *name,
    size_t size, mode_t mode, uint64_t flags);
int mes_ubsmem_shmem_deallocate(const char *name);
int mes_ubsmem_shmem_map(void *addr, size_t length, int port, int flags,
    const char *name, off_t offset, void **local_ptr);
int mes_ubsmem_shmem_unmap(void *local_ptr, size_t length);

int mes_ubsmem_init_and_set_inited(ubsmem_options_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* MES_SHM_DL_H */