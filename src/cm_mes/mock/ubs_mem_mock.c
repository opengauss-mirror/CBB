/*
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * ubs_mem_mock.c
 * Mock implementation of UBS Memory SDK for testing
 *
 * IDENTIFICATION
 *    src/cm_mes/mock/ubs_mem_mock.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "ubs_mem_def.h"
#include "ubs_mem.h"

#define MOCK_LOG(fmt, ...) fprintf(stderr, "[UBS_MOCK] " fmt "\n", ##__VA_ARGS__)

#define MAX_MOCK_REGIONS 16
#define MAX_MOCK_SHMS 64

typedef struct {
    char name[MAX_REGION_NAME_DESC_LENGTH];
    size_t size;
    void *ptr;
    int in_use;
} mock_region_t;

typedef struct {
    char name[MAX_SHM_NAME_LENGTH + 1];
    size_t size;
    void *ptr;
    int fd;
    int in_use;
    int ref_count;
} mock_shm_t;

static mock_region_t g_regions[MAX_MOCK_REGIONS];
static mock_shm_t g_shms[MAX_MOCK_SHMS];
static int g_initialized = 0;
static int g_log_level = 1;

static void mock_log(int level, const char *msg)
{
    if (level <= g_log_level) {
        MOCK_LOG("%s", msg);
    }
}

SHMEM_API int ubsmem_init_attributes(ubsmem_options_t *ubsm_shmem_opts)
{
    (void)ubsm_shmem_opts;
    MOCK_LOG("ubsmem_init_attributes called");
    return UBSM_OK;
}

SHMEM_API int ubsmem_initialize(const ubsmem_options_t *ubsm_shmem_opts)
{
    (void)ubsm_shmem_opts;
    MOCK_LOG("ubsmem_initialize called");
    
    if (g_initialized) {
        return UBSM_OK;
    }
    
    memset(g_regions, 0, sizeof(g_regions));
    memset(g_shms, 0, sizeof(g_shms));
    g_initialized = 1;
    
    return UBSM_OK;
}

SHMEM_API int ubsmem_finalize(void)
{
    MOCK_LOG("ubsmem_finalize called");
    
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (g_shms[i].in_use && g_shms[i].ptr != NULL) {
            munmap(g_shms[i].ptr, g_shms[i].size);
            if (g_shms[i].fd >= 0) {
                close(g_shms[i].fd);
                shm_unlink(g_shms[i].name);
            }
            g_shms[i].in_use = 0;
        }
    }
    
    for (int i = 0; i < MAX_MOCK_REGIONS; i++) {
        if (g_regions[i].in_use && g_regions[i].ptr != NULL) {
            free(g_regions[i].ptr);
            g_regions[i].in_use = 0;
        }
    }
    
    g_initialized = 0;
    return UBSM_OK;
}

SHMEM_API int ubsmem_set_logger_level(int level)
{
    g_log_level = level;
    return UBSM_OK;
}

SHMEM_API int ubsmem_set_extern_logger(void (*func)(int level, const char *msg))
{
    (void)func;
    return UBSM_OK;
}

SHMEM_API int ubsmem_lookup_regions(ubsmem_regions_t* regions)
{
    (void)regions;
    MOCK_LOG("ubsmem_lookup_regions called");
    return UBSM_OK;
}

SHMEM_API int ubsmem_create_region(const char *region_name, size_t size, const ubsmem_region_attributes_t *reg_attr)
{
    (void)reg_attr;
    
    if (!g_initialized) {
        return UBSM_ERR_PARAM_INVALID;
    }
    
    for (int i = 0; i < MAX_MOCK_REGIONS; i++) {
        if (!g_regions[i].in_use) {
            strncpy(g_regions[i].name, region_name, MAX_REGION_NAME_DESC_LENGTH - 1);
            g_regions[i].size = size;
            g_regions[i].ptr = malloc(size);
            if (g_regions[i].ptr == NULL) {
                return UBSM_ERR_MALLOC_FAIL;
            }
            memset(g_regions[i].ptr, 0, size);
            g_regions[i].in_use = 1;
            MOCK_LOG("Created region '%s' size=%zu", region_name, size);
            return UBSM_OK;
        }
    }
    
    return UBSM_ERR_MALLOC_FAIL;
}

SHMEM_API int ubsmem_lookup_region(const char *region_name, ubsmem_region_desc_t *region_desc)
{
    (void)region_name;
    (void)region_desc;
    MOCK_LOG("ubsmem_lookup_region called for '%s'", region_name);
    return UBSM_OK;
}

SHMEM_API int ubsmem_destroy_region(const char *region_name)
{
    for (int i = 0; i < MAX_MOCK_REGIONS; i++) {
        if (g_regions[i].in_use && strcmp(g_regions[i].name, region_name) == 0) {
            if (g_regions[i].ptr != NULL) {
                free(g_regions[i].ptr);
            }
            memset(&g_regions[i], 0, sizeof(mock_region_t));
            MOCK_LOG("Destroyed region '%s'", region_name);
            return UBSM_OK;
        }
    }
    return UBSM_ERR_NOT_FOUND;
}

SHMEM_API int ubsmem_shmem_allocate(
    const char *region_name, const char *name, size_t size, mode_t mode, uint64_t flags)
{
    (void)region_name;
    (void)mode;
    (void)flags;
    
    if (!g_initialized) {
        return UBSM_ERR_PARAM_INVALID;
    }
    
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (!g_shms[i].in_use) {
            strncpy(g_shms[i].name, name, MAX_SHM_NAME_LENGTH);
            g_shms[i].size = size;
            g_shms[i].ptr = NULL;
            g_shms[i].fd = -1;
            g_shms[i].in_use = 1;
            g_shms[i].ref_count = 0;
            
            // Pre-create the shared memory so other processes can find it
            char shm_path[256];
            snprintf(shm_path, sizeof(shm_path), "/%s", name);
            
            int fd = shm_open(shm_path, O_RDWR | O_CREAT, 0666);
            if (fd < 0) {
                MOCK_LOG("Failed to create shm '%s': %s", shm_path, strerror(errno));
                memset(&g_shms[i], 0, sizeof(mock_shm_t));
                return UBSM_ERR_MEMORY;
            }
            
            if (ftruncate(fd, size) != 0) {
                MOCK_LOG("Failed to set shm size: %s", strerror(errno));
                close(fd);
                shm_unlink(shm_path);
                memset(&g_shms[i], 0, sizeof(mock_shm_t));
                return UBSM_ERR_MEMORY;
            }
            
            g_shms[i].fd = fd;
            MOCK_LOG("Allocated shm '%s' size=%zu fd=%d", name, size, fd);
            return UBSM_OK;
        }
    }
    
    return UBSM_ERR_MALLOC_FAIL;
}

SHMEM_API int ubsmem_shmem_deallocate(const char *name)
{
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (g_shms[i].in_use && strcmp(g_shms[i].name, name) == 0) {
            if (g_shms[i].ref_count > 0) {
                return UBSM_ERR_IN_USING;
            }
            if (g_shms[i].ptr != NULL) {
                munmap(g_shms[i].ptr, g_shms[i].size);
            }
            if (g_shms[i].fd >= 0) {
                close(g_shms[i].fd);
                shm_unlink(g_shms[i].name);
            }
            memset(&g_shms[i], 0, sizeof(mock_shm_t));
            MOCK_LOG("Deallocated shm '%s'", name);
            return UBSM_OK;
        }
    }
    return UBSM_ERR_NOT_FOUND;
}

SHMEM_API int ubsmem_shmem_map(void *addr, size_t length, int prot, int flags, const char *name, off_t offset,
                               void **local_ptr)
{
    (void)addr;
    (void)prot;
    (void)flags;
    (void)offset;
    
    // First check if we already have this shm in our local table
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (g_shms[i].in_use && strcmp(g_shms[i].name, name) == 0) {
            if (g_shms[i].ptr == NULL) {
                // Need to map it
                char shm_path[256];
                snprintf(shm_path, sizeof(shm_path), "/%s", name);
                
                // Try to open existing shm first (created by peer process)
                int fd = shm_open(shm_path, O_RDWR, 0666);
                if (fd < 0) {
                    // Doesn't exist, create it
                    fd = shm_open(shm_path, O_RDWR | O_CREAT, 0666);
                    if (fd < 0) {
                        MOCK_LOG("Failed to create shm '%s': %s", shm_path, strerror(errno));
                        return UBSM_ERR_MEMORY;
                    }
                    if (ftruncate(fd, length) != 0) {
                        close(fd);
                        shm_unlink(shm_path);
                        return UBSM_ERR_MEMORY;
                    }
                }
                
                g_shms[i].fd = fd;
                g_shms[i].ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                g_shms[i].size = length;
                
                if (g_shms[i].ptr == MAP_FAILED) {
                    g_shms[i].ptr = NULL;
                    close(fd);
                    return UBSM_ERR_MEMORY;
                }
            }
            
            *local_ptr = g_shms[i].ptr;
            g_shms[i].ref_count++;
            MOCK_LOG("Mapped shm '%s' at %p size=%zu", name, *local_ptr, length);
            return UBSM_OK;
        }
    }
    
    // Not found in local table, try to open an existing shm from peer process
    char shm_path[256];
    snprintf(shm_path, sizeof(shm_path), "/%s", name);
    
    int fd = shm_open(shm_path, O_RDWR, 0666);
    if (fd < 0) {
        MOCK_LOG("shm '%s' not found: %s", name, strerror(errno));
        return UBSM_ERR_NOT_FOUND;
    }
    
    // Find a free slot in our local table
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (!g_shms[i].in_use) {
            strncpy(g_shms[i].name, name, MAX_SHM_NAME_LENGTH);
            g_shms[i].size = length;
            g_shms[i].fd = fd;
            g_shms[i].ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            g_shms[i].in_use = 1;
            g_shms[i].ref_count = 1;
            
            if (g_shms[i].ptr == MAP_FAILED) {
                g_shms[i].ptr = NULL;
                close(fd);
                memset(&g_shms[i], 0, sizeof(mock_shm_t));
                return UBSM_ERR_MEMORY;
            }
            
            *local_ptr = g_shms[i].ptr;
            MOCK_LOG("Mapped peer shm '%s' at %p size=%zu", name, *local_ptr, length);
            return UBSM_OK;
        }
    }
    
    close(fd);
    return UBSM_ERR_MALLOC_FAIL;
}

SHMEM_API int ubsmem_shmem_unmap(void *local_ptr, size_t length)
{
    (void)length;
    
    for (int i = 0; i < MAX_MOCK_SHMS; i++) {
        if (g_shms[i].in_use && g_shms[i].ptr == local_ptr) {
            g_shms[i].ref_count--;
            MOCK_LOG("Unmapped shm '%s' ref_count=%d", g_shms[i].name, g_shms[i].ref_count);
            return UBSM_OK;
        }
    }
    
    return UBSM_ERR_NOT_FOUND;
}

SHMEM_API int ubsmem_shmem_set_ownership(const char *name, void *start, size_t length, int prot)
{
    (void)name;
    (void)start;
    (void)length;
    (void)prot;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_write_lock(const char *name)
{
    (void)name;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_read_lock(const char *name)
{
    (void)name;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_unlock(const char *name)
{
    (void)name;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_list_lookup(const char *prefix, ubsmem_shmem_desc_t *shm_list, uint32_t *shm_cnt)
{
    (void)prefix;
    (void)shm_list;
    (void)shm_cnt;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_lookup(const char *name, ubsmem_shmem_info_t *shm_info)
{
    (void)name;
    (void)shm_info;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_attach(const char *name)
{
    (void)name;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_detach(const char *name)
{
    (void)name;
    return UBSM_OK;
}

SHMEM_API int ubsmem_lease_malloc(const char *region_name, size_t size, ubsmem_distance_t mem_distance, uint64_t flags,
                                  void **local_ptr)
{
    (void)region_name;
    (void)mem_distance;
    (void)flags;
    
    *local_ptr = malloc(size);
    if (*local_ptr == NULL) {
        return UBSM_ERR_MALLOC_FAIL;
    }
    memset(*local_ptr, 0, size);
    MOCK_LOG("lease_malloc size=%zu at %p", size, *local_ptr);
    return UBSM_OK;
}

SHMEM_API int ubsmem_lease_free(void *local_ptr)
{
    free(local_ptr);
    MOCK_LOG("lease_free %p", local_ptr);
    return UBSM_OK;
}

SHMEM_API int ubsmem_lookup_cluster_statistic(ubsmem_cluster_info_t* info)
{
    (void)info;
    return UBSM_OK;
}

SHMEM_API int ubsmem_shmem_faults_register(shmem_faults_func registerFunc)
{
    (void)registerFunc;
    return UBSM_OK;
}

SHMEM_API int ubsmem_local_nid_query(uint32_t* nid)
{
    if (nid) {
        *nid = 0;
    }
    return UBSM_OK;
}
