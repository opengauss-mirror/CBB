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
 * mes_shm_dl.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_dl.c
 *
 * -------------------------------------------------------------------------
 */
#include <string.h>
#include "mes_interface.h"
#include "cm_utils/cm_utils.h"
#include "ubs_mem_def.h"
#include "mes_shm_dl.h"

typedef struct UbsMemFunc {
    bool matrix_mem_inited;
    int (*ubsmem_init_attributes)(ubsmem_options_t *ubsm_shmem_opts);
    int (*ubsmem_initialize)(const ubsmem_options_t *ubsm_shmem_opts);
    int (*ubsmem_finalize)(void);
    int (*ubsmem_create_region)(const char *region_name, size_t size, const ubsmem_region_attributes_t *reg_attr);
    int (*ubsmem_lookup_regions)(ubsmem_regions_t *regions);
    int (*ubsmem_destroy_region)(const char *region_name);
    int (*ubsmem_shmem_allocate)(const char *region_name, const char *name, size_t size, mode_t mode, uint64_t flags);
    int (*ubsmem_shmem_deallocate)(const char *name);
    int (*ubsmem_shmem_map)(void *addr, size_t length, int port, int flags, const char *name, off_t offset,
                            void **local_ptr);
    int (*ubsmem_shmem_unmap)(void *local_ptr, size_t length);
} UbsMemFunc;

typedef struct UbDistCommFunc {
    int (*ub_comm_queue_init)(ub_shm_comm_t *handle, ub_shm_area_t *init_region, ub_ring_region_map_t *ring_regions,
                              ub_comm_conf_t *conf);
    int (*ub_comm_queue_deinit)(ub_shm_comm_t *handle);
    int (*ub_comm_queue_send)(ub_shm_comm_t *handle, const message_t *msg);
    int (*ub_comm_queue_recv)(ub_shm_comm_t *handle, void *buffer, uint32_t length);
    bool (*ub_comm_queue_check_ready)(ub_shm_comm_t *handle, const uint8_t node_id);
    int (*ub_comm_queue_register_process_func)(ub_shm_comm_t *handle, uint8_t msg_type, ub_func_type_t func_type,
                                              ub_callback_t func, void *ctx);
    void (*ub_atomic_register_log_func)(ub_atomic_log_func func);
    int (*ub_atomic_set_log_level)(int level);
} UbDistCommFunc;

void* g_ubsMemDl = NULL;
void* g_ubDistCommDl = NULL;
UbsMemFunc g_ubsMemFunc;
UbDistCommFunc g_ubDistCommFunc;

/* so_basename: UBS_MEM_SO_NAME or UB_DIST_COMM_SO_NAME — selects env key and default full path in header. */
static int mes_fill_so_path_from_dir(char *path_buf, const char *so_basename)
{
    const char *env_key = NULL;
    const char *default_full_path = NULL;

    if (strcmp(so_basename, UBS_MEM_SO_NAME) == 0) {
        env_key = UBS_MEM_ENV_PATH;
        default_full_path = UBS_MEM_DEFAULT_SO_PATH;
    } else if (strcmp(so_basename, UB_DIST_COMM_SO_NAME) == 0) {
        env_key = UB_DIST_COMM_ENV_PATH;
        default_full_path = UB_DIST_COMM_DEFAULT_SO_PATH;
    } else {
        return CM_ERROR;
    }

    if (path_buf == NULL) {
        return CM_ERROR;
    }

    const uint32_t path_buf_len = PATH_LENGTH;
    const char *dir = getenv(env_key);

    if (dir != NULL && dir[0] != '\0') {
        char resolved_dir[PATH_LENGTH] = {0};
        bool resolved = (realpath_file(dir, resolved_dir, PATH_LENGTH) == CM_SUCCESS && resolved_dir[0] != '\0');
        if (!resolved) {
            LOG_RUN_ERR("realpath_file failed for %s (%s)", dir, so_basename);
        } else {
            int n = snprintf_s(path_buf, path_buf_len, path_buf_len - 1, "%s/%s", resolved_dir, so_basename);
            if (n >= 0) {
                return CM_SUCCESS;
            }
            LOG_RUN_ERR("construct %s/%s failed, ret %d.", resolved_dir, so_basename, n);
        }
        LOG_RUN_WAR("[mes] %s: resolve failed, fallback %s", so_basename, default_full_path);
    }

    errno_t rc = strncpy_s(path_buf, path_buf_len, default_full_path, path_buf_len - 1);
    if (rc != EOK) {
        LOG_RUN_ERR("[mes] %s: strncpy_s default path failed, rc=%d.", so_basename, rc);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int UbsMemDlsym(void)
{
    if (cm_load_symbol(g_ubsMemDl, "ubsmem_init_attributes",
                       (void **)&g_ubsMemFunc.ubsmem_init_attributes) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_initialize",
                       (void **)&g_ubsMemFunc.ubsmem_initialize) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_finalize",
                       (void **)&g_ubsMemFunc.ubsmem_finalize) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_lookup_regions",
                       (void **)&g_ubsMemFunc.ubsmem_lookup_regions) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_create_region",
                       (void **)&g_ubsMemFunc.ubsmem_create_region) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_destroy_region",
                       (void **)&g_ubsMemFunc.ubsmem_destroy_region) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_allocate",
                       (void **)&g_ubsMemFunc.ubsmem_shmem_allocate) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_deallocate",
                       (void **)&g_ubsMemFunc.ubsmem_shmem_deallocate) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_map",
                       (void **)&g_ubsMemFunc.ubsmem_shmem_map) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_unmap",
                       (void **)&g_ubsMemFunc.ubsmem_shmem_unmap) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void FinishUbsMemDl(void)
{
    errno_t rc;
    if (g_ubsMemFunc.matrix_mem_inited) {
        int ret = mes_ubsmem_finalize();
        if (ret != UBSM_OK) {
            LOG_RUN_ERR("Failed to finalize ubs_mem, error: %d.", ret);
        }
        LOG_RUN_INF("finalized ubs_mem.");
    }

    if (g_ubsMemDl != NULL) {
        dlclose(g_ubsMemDl);
        g_ubsMemDl = NULL;
        rc = memset_s(&g_ubsMemFunc, sizeof(UbsMemFunc), 0, sizeof(UbsMemFunc));
        if (rc != EOK) {
            LOG_RUN_ERR("memset_s g_ubsMemFunc failed, rc=%d.", rc);
        }
        LOG_RUN_INF("Successfully closed ubs_mem dynamic library.");
    }

    if (g_ubDistCommDl != NULL) {
        dlclose(g_ubDistCommDl);
        g_ubDistCommDl = NULL;
        rc = memset_s(&g_ubDistCommFunc, sizeof(UbDistCommFunc), 0, sizeof(UbDistCommFunc));
        if (rc != EOK) {
            LOG_RUN_ERR("memset_s g_ubDistCommFunc failed, rc=%d.", rc);
        }
        LOG_RUN_INF("Successfully closed ub_dist_comm dynamic library.");
    }
}

int InitUbsMemDl(char* path, uint32_t pathLen)
{
    if (path == NULL || pathLen == 0) {
        LOG_RUN_ERR("InitUbsMemDl path is nullptr");
        return CM_ERROR;
    }

    int ret = CM_ERROR;
    if (g_ubsMemDl != NULL) {
        return CM_SUCCESS;
    }

    ret = cm_open_dl(&g_ubsMemDl, path);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlopen ubsMem path %s", path);
        return CM_ERROR;
    }

    ret = UbsMemDlsym();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlsym Ubs Mem func, path %s", path);
        FinishUbsMemDl();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int UbDistCommDlsym(void)
{
    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_init",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_init) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_deinit",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_deinit) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_send",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_send) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_recv",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_recv) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_check_ready",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_check_ready) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_comm_queue_register_process_func",
                       (void **)&g_ubDistCommFunc.ub_comm_queue_register_process_func) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_atomic_register_log_func",
                       (void **)&g_ubDistCommFunc.ub_atomic_register_log_func) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_load_symbol(g_ubDistCommDl, "ub_atomic_set_log_level",
                       (void **)&g_ubDistCommFunc.ub_atomic_set_log_level) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int InitUbDistCommDl(char *path, uint32_t pathLen)
{
    int ret;

    if (path == NULL || pathLen == 0) {
        LOG_RUN_ERR("InitUbDistCommDl path is nullptr");
        return CM_ERROR;
    }
    if (g_ubDistCommDl != NULL) {
        return CM_SUCCESS;
    }

    ret = cm_open_dl(&g_ubDistCommDl, path);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlopen ub_dist_comm path %s", path);
        return CM_ERROR;
    }

    ret = UbDistCommDlsym();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlsym ub_dist_comm func, path %s", path);
        if (g_ubDistCommDl != NULL) {
            (void)dlclose(g_ubDistCommDl);
            g_ubDistCommDl = NULL;
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int ub_dist_comm_log_callback(int level, const char *file, const char *func, uint32_t line, const char *message)
{
    switch (level) {
        case LOG_LEVEL_DEBUG:
            LOG_DEBUG_INF("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
        case LOG_LEVEL_INFO:
            LOG_RUN_INF("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
        case LOG_LEVEL_WARN:
            LOG_RUN_WAR("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
        case LOG_LEVEL_ERROR:
            LOG_RUN_ERR("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
        case LOG_LEVEL_CRITICAL:
            LOG_RUN_ERR("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
        default:
            LOG_RUN_INF("[UB_DIST_COMM] %s:%d %s: %s", file, line, func, message);
            break;
    }
    return 0;
}

static int mes_get_ub_dist_comm_log_level(void)
{
    /*
     * CBB/MES uses bitmask-based log switches, while ub_dist_comm expects a
     * threshold level. Map the currently enabled highest-detail level to the
     * nearest ub_dist_comm threshold.
     */
    if (LOG_DEBUG_INF_ON || LOG_DEBUG_WAR_ON || LOG_DEBUG_ERR_ON ||
        LOG_MEC_ON || LOG_TRACE_ON || LOG_PROFILE_ON) {
        return LOG_LEVEL_DEBUG;
    }
    if (LOG_RUN_INF_ON || LOG_OPER_ON) {
        return LOG_LEVEL_INFO;
    }
    if (LOG_RUN_WAR_ON) {
        return LOG_LEVEL_ERROR;
    }
    return LOG_LEVEL_CRITICAL;
}

static void register_ub_dist_comm_log(void)
{
    ub_atomic_register_log_func(ub_dist_comm_log_callback);
    LOG_RUN_INF("Successfully registered ub_dist_comm log callback.");

    int log_level = mes_get_ub_dist_comm_log_level();
    int ret = ub_atomic_set_log_level(log_level);
    if (ret != 0) {
        LOG_RUN_WAR("Failed to set ub_dist_comm log level, error: %d.", ret);
    }
}

int mes_init_ubs_dlopen_so(void)
{
    char ubs_path[PATH_LENGTH] = {0};
    char queue_path[PATH_LENGTH] = {0};

    if (mes_fill_so_path_from_dir(ubs_path, UBS_MEM_SO_NAME) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (mes_fill_so_path_from_dir(queue_path, UB_DIST_COMM_SO_NAME) != CM_SUCCESS) {
        return CM_ERROR;
    }
    LOG_RUN_INF("[mes] mes_init_ubs_dlopen_so ubs_mem soPath=%s, ub_dist_comm soPath=%s", ubs_path, queue_path);

    if (InitUbsMemDl(ubs_path, PATH_LENGTH) != CM_SUCCESS) {
        LOG_RUN_ERR("mes init UbsMemDl failed.");
        return CM_ERROR;
    }
    if (InitUbDistCommDl(queue_path, PATH_LENGTH) != CM_SUCCESS) {
        LOG_RUN_ERR("mes init ub_dist_comm dl failed.");
        FinishUbsMemDl();
        return CM_ERROR;
    }
    register_ub_dist_comm_log();
    return CM_SUCCESS;
}

int mes_ubsmem_init_attributes(ubsmem_options_t *ubsm_shmem_opts)
{
    if (g_ubsMemFunc.ubsmem_init_attributes != NULL) {
        return g_ubsMemFunc.ubsmem_init_attributes(ubsm_shmem_opts);
    }

    return CM_ERROR;
}

int mes_ubsmem_initialize(const ubsmem_options_t *ubsm_shmem_opts)
{
    if (g_ubsMemFunc.ubsmem_initialize != NULL) {
        return g_ubsMemFunc.ubsmem_initialize(ubsm_shmem_opts);
    }

    return CM_ERROR;
}

int mes_ubsmem_finalize(void)
{
    if (g_ubsMemFunc.ubsmem_finalize != NULL) {
        return g_ubsMemFunc.ubsmem_finalize();
    }

    return CM_ERROR;
}

int mes_ubsmem_lookup_regions(ubsmem_regions_t *regions)
{
    if (g_ubsMemFunc.ubsmem_lookup_regions != NULL) {
        return g_ubsMemFunc.ubsmem_lookup_regions(regions);
    }

    return CM_ERROR;
}

int mes_ubsmem_create_region(const char *region_name, size_t size,
    const ubsmem_region_attributes_t *reg_attr)
{
    if (g_ubsMemFunc.ubsmem_create_region != NULL) {
        return g_ubsMemFunc.ubsmem_create_region(region_name, size, reg_attr);
    }

    return CM_ERROR;
}

int mes_ubsmem_destroy_region(const char *region_name)
{
    if (g_ubsMemFunc.ubsmem_destroy_region != NULL) {
        return g_ubsMemFunc.ubsmem_destroy_region(region_name);
    }

    return CM_ERROR;
}

int mes_ubsmem_shmem_allocate(const char *region_name, const char *name,
    size_t size, mode_t mode, uint64_t flags)
{
    if (g_ubsMemFunc.ubsmem_shmem_allocate != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_allocate(region_name, name, size, mode, flags);
    }

    return CM_ERROR;
}

int mes_ubsmem_shmem_deallocate(const char *name)
{
    if (g_ubsMemFunc.ubsmem_shmem_deallocate != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_deallocate(name);
    }

    return CM_ERROR;
}

int mes_ubsmem_shmem_map(void *addr, size_t length, int port, int flags,
    const char *name, off_t offset, void **local_ptr)
{
    if (g_ubsMemFunc.ubsmem_shmem_map != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_map(addr, length, port, flags, name, offset, local_ptr);
    }

    return CM_ERROR;
}

int mes_ubsmem_shmem_unmap(void *local_ptr, size_t length)
{
    if (g_ubsMemFunc.ubsmem_shmem_unmap != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_unmap(local_ptr, length);
    }

    return CM_ERROR;
}

int ub_comm_queue_init(ub_shm_comm_t *handle, ub_shm_area_t *init_region, ub_ring_region_map_t *ring_regions,
                       ub_comm_conf_t *conf)
{
    if (g_ubDistCommFunc.ub_comm_queue_init != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_init(handle, init_region, ring_regions, conf);
    }

    LOG_RUN_ERR("ub_comm_queue_init function not loaded.");
    return CM_ERROR;
}

int ub_comm_queue_deinit(ub_shm_comm_t *handle)
{
    if (g_ubDistCommFunc.ub_comm_queue_deinit != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_deinit(handle);
    }

    LOG_RUN_ERR("ub_comm_queue_deinit function not loaded.");
    return CM_ERROR;
}

int ub_comm_queue_send(ub_shm_comm_t *handle, const message_t *msg)
{
    if (g_ubDistCommFunc.ub_comm_queue_send != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_send(handle, msg);
    }

    LOG_RUN_ERR("ub_comm_queue_send function not loaded.");
    return CM_ERROR;
}

int ub_comm_queue_recv(ub_shm_comm_t *handle, void *buffer, uint32_t length)
{
    if (g_ubDistCommFunc.ub_comm_queue_recv != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_recv(handle, buffer, length);
    }

    LOG_RUN_ERR("ub_comm_queue_recv function not loaded.");
    return CM_ERROR;
}

bool ub_comm_queue_check_ready(ub_shm_comm_t *handle, const uint8_t node_id)
{
    if (g_ubDistCommFunc.ub_comm_queue_check_ready != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_check_ready(handle, node_id);
    }

    LOG_RUN_ERR("ub_comm_queue_check_ready function not loaded.");
    return false;
}

int ub_comm_queue_register_process_func(ub_shm_comm_t *handle, uint8_t msg_type, ub_func_type_t func_type,
                                        ub_callback_t func, void *ctx)
{
    if (g_ubDistCommFunc.ub_comm_queue_register_process_func != NULL) {
        return g_ubDistCommFunc.ub_comm_queue_register_process_func(handle, msg_type, func_type, func, ctx);
    }

    LOG_RUN_ERR("ub_comm_queue_register_process_func function not loaded.");
    return CM_ERROR;
}

void ub_atomic_register_log_func(ub_atomic_log_func func)
{
    if (g_ubDistCommFunc.ub_atomic_register_log_func != NULL) {
        g_ubDistCommFunc.ub_atomic_register_log_func(func);
        return;
    }

    LOG_RUN_ERR("ub_atomic_register_log_func function not loaded.");
}

int ub_atomic_set_log_level(int level)
{
    if (g_ubDistCommFunc.ub_atomic_set_log_level != NULL) {
        return g_ubDistCommFunc.ub_atomic_set_log_level(level);
    }

    LOG_RUN_ERR("ub_atomic_set_log_level function not loaded.");
    return CM_ERROR;
}
