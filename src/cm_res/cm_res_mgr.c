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
 * cm_res_mgr.c
 *
 *
 * IDENTIFICATION
 *    src/cm_res/cm_res_mgr.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_res_mgr.h"
#include "cm_utils.h"
#include "ddes_json.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t cm_res_json_malloc(mem_pool_t *ctx, uint32 size, void **buf)
{
    *buf = galloc(size, ctx);
    if (*buf == NULL) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void cm_res_json_free(mem_pool_t *ctx, void *buf)
{
    gfree(buf);
}

status_t cm_res_init_memctx(cm_res_mem_ctx_t *res_mem_ctx)
{
    status_t ret = buddy_pool_init("test_ddes_json_mem_pool", COMM_MEM_POOL_MIN_SIZE, COMM_MEM_POOL_MAX_SIZE,
        &res_mem_ctx->mem_pool);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    res_mem_ctx->alloc.mem_ctx = &res_mem_ctx->mem_pool;
    res_mem_ctx->alloc.f_alloc = (f_malloc_t)cm_res_json_malloc;
    res_mem_ctx->alloc.f_free = (f_free_t)cm_res_json_free;
    return CM_SUCCESS;
}

void cm_res_uninit_memctx(cm_res_mem_ctx_t *res_mem_ctx)
{
    buddy_pool_deinit(&res_mem_ctx->mem_pool);
    res_mem_ctx->alloc.mem_ctx = NULL;
    res_mem_ctx->alloc.f_alloc = NULL;
    res_mem_ctx->alloc.f_free = NULL;
}

static status_t cm_res_init_stat_func(cm_res_mgr_t *cm_res_mgr)
{
    status_t ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmGetResStats",
        (void **)&cm_res_mgr->cm_get_res_stat);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmFreeResStats", (void **)&cm_res_mgr->cm_free_res_stat);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return CM_SUCCESS;
}

static status_t cm_res_init_lock_func(cm_res_mgr_t *cm_res_mgr)
{
    status_t ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmResLock", (void **)&cm_res_mgr->cm_res_lock);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmResUnlock", (void **)&cm_res_mgr->cm_res_unlock);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmResGetLockOwner", (void **)&cm_res_mgr->cm_res_get_lock_owner);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmResTransLock", (void **)&cm_res_mgr->cm_res_trans_lock);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return ret;
}

status_t cm_res_mgr_init(const char *so_lib_path, cm_res_mgr_t *cm_res_mgr, cm_allocator_t *alloc)
{
    if (so_lib_path == NULL || strlen(so_lib_path) == 0) {
        cm_res_mgr->so_hanle = NULL;
        return CM_SUCCESS;
    }
    status_t ret = cm_open_dl(&cm_res_mgr->so_hanle, (char *)so_lib_path);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_load_symbol(cm_res_mgr->so_hanle, "CmInit", (void **)&cm_res_mgr->cm_init);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_res_init_stat_func(cm_res_mgr);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = cm_res_init_lock_func(cm_res_mgr);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return CM_SUCCESS;
}

void cm_res_mgr_uninit(cm_res_mgr_t *cm_res_mgr)
{
    if (cm_res_mgr->so_hanle != NULL) {
        cm_close_dl(cm_res_mgr->so_hanle);
        cm_res_mgr->so_hanle = NULL;
    }
}

// register info by interface
int cm_res_init(cm_res_mgr_t *cm_res_mgr, unsigned int instance_id, const char *res_name, cm_notify_func_t func)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_ERROR;
    }
    return cm_res_mgr->cm_init(instance_id, res_name, func);
}

// get or set  by so interface directly
int cm_res_lock(cm_res_mgr_t *cm_res_mgr, const char *lock_name)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_ERROR;
    }
    return cm_res_mgr->cm_res_lock(lock_name);
}

int cm_res_unlock(cm_res_mgr_t *cm_res_mgr, const char *lock_name)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_ERROR;
    }
    return cm_res_mgr->cm_res_unlock(lock_name);
}

int cm_res_get_lock_owner(cm_res_mgr_t *cm_res_mgr, const char *lock_name, unsigned int *inst_id)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_ERROR;
    }
    return cm_res_mgr->cm_res_get_lock_owner(lock_name, inst_id);
}

int cm_res_trans_lock(cm_res_mgr_t *cm_res_mgr, const char *lock_name, unsigned int inst_id)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_ERROR;
    }
    return cm_res_mgr->cm_res_trans_lock(lock_name, inst_id);
}

// get origin stats info by interface
cm_res_stat_ptr_t cm_res_get_stat(cm_res_mgr_t *cm_res_mgr, cm_res_mem_ctx_t *res_mem_ctx)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return NULL;
    }
    char *json = cm_res_mgr->cm_get_res_stat();
    if (json == NULL) {
        return NULL;
    }
    text_t txt = {json, (uint32)strlen(json)};
    json_t *statJson;
    status_t ret = json_create(&statJson, &txt, &res_mem_ctx->alloc);
    cm_res_mgr->cm_free_res_stat(json);
    if (ret != CM_SUCCESS) {
        return NULL;
    }
    return (cm_res_stat_ptr_t)statJson;
}

void cm_res_free_stat(cm_res_mgr_t *cm_res_mgr, cm_res_stat_ptr_t res_stat)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return;
    }
    json_t *statJson = (json_t *)res_stat;
    json_destroy(statJson, NULL, &(statJson->allocator));
}

int cm_res_get_cm_version(unsigned long long *version, cm_res_mgr_t *cm_res_mgr, const cm_res_stat_ptr_t res_stat)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_SUCCESS;
    }
    json_t *statJson = (json_t *)res_stat;

    text_t key;
    key.str = (char *)"version";
    key.len = (uint32)strlen(key.str);
    return json_get_uint64(statJson, &key, version);
}

// get detail stats info
int cm_res_get_instance_count(unsigned int *inst_count, cm_res_mgr_t *cm_res_mgr, const cm_res_stat_ptr_t res_stat)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return CM_SUCCESS;
    }
    json_t *statJson = (json_t *)res_stat;

    text_t key;
    key.str = (char *)"inst_count";
    key.len = (uint32)strlen(key.str);
    uint64 inst_count_tmp = 0ULL;
    status_t ret = json_get_uint64(statJson, &key, &inst_count_tmp);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    *inst_count = (uint32)inst_count_tmp;
    return CM_SUCCESS;
}

const cm_res_inst_info_ptr_t cm_res_get_instance_info(cm_res_mgr_t *cm_res_mgr,
    const cm_res_stat_ptr_t res_stat, unsigned int instance_idx)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return NULL;
    }
    json_t *statJson = (json_t *)res_stat;

    text_t key;
    key.str = (char *)"inst_status";
    key.len = (uint32)strlen(key.str);
    json_arr_t *arr = NULL;
    (void) json_get_arr(statJson, &arr, &key);
    if (arr == NULL) {
        return NULL;
    }
    json_t *json_sub = NULL;
    (void) jarr_get_obj(arr, &json_sub, instance_idx);
    if (json_sub == NULL) {
        return NULL;
    }
    return (char *)json_sub;
}

int cm_res_get_inst_node_id(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return -1;
    }
    json_t *inst_stat = (json_t *)instance_info;
    text_t key;
    key.str = (char *)"node_id";
    key.len = (uint32)strlen(key.str);
    uint64 node_id = 0;
    status_t ret = json_get_uint64(inst_stat, &key, &node_id);
    if (ret != CM_SUCCESS) {
        return -1;
    }
    return (int)node_id;
}

int cm_res_get_inst_instance_id(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return -1;
    }
    json_t *inst_stat = (json_t *)instance_info;

    text_t key;
    key.str = (char *)"res_instance_id";
    key.len = (uint32)strlen(key.str);
    uint64 res_instance_id = 0;
    status_t ret = json_get_uint64(inst_stat, &key, &res_instance_id);
    if (ret != CM_SUCCESS) {
        return -1;
    }
    return (int)res_instance_id;
}

int cm_res_get_inst_is_work_member(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return -1;
    }
    json_t *inst_stat = (json_t *)instance_info;

    text_t key;
    key.str = (char *)"is_work_member";
    key.len = (uint32)strlen(key.str);
    uint64 is_work_member = 0;
    status_t ret = json_get_uint64(inst_stat, &key, &is_work_member);
    if (ret != CM_SUCCESS) {
        return -1;
    }
    return (int)is_work_member;
}

int cm_res_get_inst_stat(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info)
{
    if (cm_res_mgr->so_hanle == NULL) {
        return -1;
    }
    json_t *inst_stat = (json_t *)instance_info;

    text_t key;
    key.str = (char *)"status";
    key.len = (uint32)strlen(key.str);
    uint64 status = 0;
    status_t ret = json_get_uint64(inst_stat, &key, &status);
    if (ret != CM_SUCCESS) {
        return -1;
    }
    return (int)status;
}

#ifdef __cplusplus
}
#endif
