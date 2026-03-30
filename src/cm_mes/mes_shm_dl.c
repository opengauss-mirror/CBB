#include "ubs_mem.h"
#include "cm_utils/cm_utils.h"
#include "ubs_mem_def.h"
#include "mes_shm_dl.h"

typedef struct UbsMemFunc {
    bool matrix_mem_inited;
    void *handle;
    int (*ubsmem_init_attributes)(ubsmem_options_t *ubsm_shmem_opts);
    int (*ubsmem_initialize)(const ubsmem_options_t *ubsm_shmem_opts);
    int (*ubsmem_finalize)(void);
    int (*ubsmem_set_logger_level)(int level);
    int (*ubsmem_set_extern_logger)(void (*func)(int level, const char *msg));
    int (*ubsmem_create_region)(const char *region_name, size_t size, const ubsmem_region_attributes_t *reg_attr);
    int (*ubsmem_lookup_regions)(ubsmem_regions_t *regions);
    int (*ubsmem_destroy_region)(const char *region_name);
    int (*ubsmem_shmem_allocate)(const char *region_name, const char *name, size_t size, mode_t mode, uint64_t flags);
    int (*ubsmem_shmem_deallocate)(const char *name);
    int (*ubsmem_shmem_map)(void *addr, size_t length, int port, int flags, const char *name, off_t offset,
                            void **local_ptr);
    int (*ubsmem_shmem_unmap)(void *local_ptr, size_t length);
} UbsMemFunc;

void* g_ubsMemDl = NULL;
UbsMemFunc g_ubsMemFunc;

static int mes_get_lib_path(char* ubsPath)
{
    char* tmp = getenv(UBS_MEM_ENV_PATH);
    if (tmp == NULL) {
        LOG_RUN_ERR("mes getenv %s failed.", UBS_MEM_ENV_PATH);
        return CM_ERROR;
    }
#ifdef WIN32
    if (!_fullpath(ubsPath, tmp, PATH_MAX - 1)) {
        LOG_RUN_ERR("_fullpath ock_log_path failed");
        return CM_ERROR;
    }
#else
    if (realpath(tmp, ubsPath) == NULL) {
        LOG_RUN_ERR("realpath ock_log_path failed");
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

static int UbsMemDlsym(void)
{
    int ret = cm_load_symbol(g_ubsMemDl, "ubsmem_init_attributes", (void**)&g_ubsMemFunc.ubsmem_init_attributes);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_initialize", (void**)&g_ubsMemFunc.ubsmem_initialize);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_finalize", (void**)&g_ubsMemFunc.ubsmem_finalize);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_set_logger_level", (void**)&g_ubsMemFunc.ubsmem_set_logger_level);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_set_extern_logger", (void**)&g_ubsMemFunc.ubsmem_set_extern_logger);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_lookup_regions", (void**)&g_ubsMemFunc.ubsmem_lookup_regions);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_create_region", (void**)&g_ubsMemFunc.ubsmem_create_region);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_destroy_region", (void**)&g_ubsMemFunc.ubsmem_destroy_region);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_allocate", (void**)&g_ubsMemFunc.ubsmem_shmem_allocate);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_deallocate", (void**)&g_ubsMemFunc.ubsmem_shmem_deallocate);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_map", (void**)&g_ubsMemFunc.ubsmem_shmem_map);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    ret = cm_load_symbol(g_ubsMemDl, "ubsmem_shmem_unmap", (void**)&g_ubsMemFunc.ubsmem_shmem_unmap);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void FinishUbsMemDl(void)
{
    if (g_ubsMemFunc.matrix_mem_inited) {
        ubsmem_finalize();
        (void)dlclose(g_ubsMemFunc.handle);
        g_ubsMemFunc.handle = NULL;
        g_ubsMemFunc.matrix_mem_inited = false;
    }

    if (g_ubsMemDl != NULL) {
        dlclose(g_ubsMemDl);
        g_ubsMemDl = NULL;
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
int mes_init_ubs_dlopen_so(void)
{
    char ubsPath[PATH_LENGTH] = {0};
    int ret = mes_get_lib_path(ubsPath);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    char ubsMemDlPath[PATH_LENGTH] = {0};
    ret = snprintf_s(ubsMemDlPath, PATH_LENGTH, PATH_LENGTH - 1, "%s/%s", ubsPath, UBS_MEM_SO_NAME);
    if (ret < 0) {
        LOG_RUN_ERR("construct UbsMemdl failed, ret %d.", ret);
        return CM_ERROR;
    }
    ret = InitUbsMemDl(ubsMemDlPath, PATH_LENGTH);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("mes init UbsMemDl failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int ubsmem_init_attributes(ubsmem_options_t *ubsm_shmem_opts)
{
    if (g_ubsMemFunc.ubsmem_init_attributes != NULL) {
        return g_ubsMemFunc.ubsmem_init_attributes(ubsm_shmem_opts);
    }

    return CM_ERROR;
}

int ubsmem_initialize(const ubsmem_options_t *ubsm_shmem_opts)
{
    if (g_ubsMemFunc.ubsmem_initialize != NULL) {
        return g_ubsMemFunc.ubsmem_initialize(ubsm_shmem_opts);
    }

    return CM_ERROR;
}

int ubsmem_finalize(void)
{
    if (g_ubsMemFunc.ubsmem_finalize != NULL) {
        return g_ubsMemFunc.ubsmem_finalize();
    }

    return CM_ERROR;
}

int ubsmem_set_logger_level(int level)
{
    if (g_ubsMemFunc.ubsmem_set_logger_level != NULL) {
        return g_ubsMemFunc.ubsmem_set_logger_level(level);
    }

    return CM_ERROR;
}

int ubsmem_set_extern_logger(void (*func)(int level, const char *msg))
{
    if (g_ubsMemFunc.ubsmem_set_extern_logger != NULL) {
        return g_ubsMemFunc.ubsmem_set_extern_logger(func);
    }

    return CM_ERROR;
}

int ubsmem_lookup_regions(ubsmem_regions_t *regions)
{
    if (g_ubsMemFunc.ubsmem_lookup_regions != NULL) {
        return g_ubsMemFunc.ubsmem_lookup_regions(regions);
    }

    return CM_ERROR;
}

int ubsmem_create_region(const char *region_name, size_t size,
    const ubsmem_region_attributes_t *reg_attr)
{
    if (g_ubsMemFunc.ubsmem_create_region != NULL) {
        return g_ubsMemFunc.ubsmem_create_region(region_name, size, reg_attr);
    }

    return CM_ERROR;
}

int ubsmem_destroy_region(const char *region_name)
{
    if (g_ubsMemFunc.ubsmem_destroy_region != NULL) {
        return g_ubsMemFunc.ubsmem_destroy_region(region_name);
    }

    return CM_ERROR;
}

int ubsmem_shmem_allocate(const char *region_name, const char *name,
    size_t size, mode_t mode, uint64_t flags)
{
    if (g_ubsMemFunc.ubsmem_shmem_allocate != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_allocate(region_name, name, size, mode, flags);
    }

    return CM_ERROR;
}

int ubsmem_shmem_deallocate(const char *name)
{
    if (g_ubsMemFunc.ubsmem_shmem_deallocate != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_deallocate(name);
    }

    return CM_ERROR;
}

int ubsmem_shmem_map(void *addr, size_t length, int port, int flags,
    const char *name, off_t offset, void **local_ptr)
{
    if (g_ubsMemFunc.ubsmem_shmem_map != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_map(addr, length, port, flags, name, offset, local_ptr);
    }

    return CM_ERROR;
}

int ubsmem_shmem_unmap(void *local_ptr, size_t length)
{
    if (g_ubsMemFunc.ubsmem_shmem_unmap != NULL) {
        return g_ubsMemFunc.ubsmem_shmem_unmap(local_ptr, length);
    }

    return CM_ERROR;
}
    