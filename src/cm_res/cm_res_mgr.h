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
 * cm_res_mgr.h
 *
 *
 * IDENTIFICATION
 *    src/cm_res/cm_res_mgr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_RES_MGR_H
#define CM_RES_MGR_H

#include <stdlib.h>
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_text.h"
#include "cm_memory.h"
#include "cm_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*cm_notify_func_t)(void);

#define CM_RES_STATUS_UNKOWN 0
#define CM_RES_STATUS_ONLINE 1
#define CM_RES_STATUS_OFFLINE 2

typedef struct st_cm_res_mem_ctx {
    mem_pool_t mem_pool;
    cm_allocator_t alloc;
} cm_res_mem_ctx_t;

typedef struct st_cm_res_mgr_func {
    void *so_hanle;
    /*
    * cm client init function for resource
    * @param [in] instance_id: resource instance id, not same with cm instance id
    * @param [in] res_name: resource name
    * @param [in] func: callback function
    * @return 0: success; -1 failed
    */
    int (*cm_init)(unsigned int instance_id, const char *res_name, cm_notify_func_t func);

    /*
    * cm client init function, before init success, other interfaces fail to be executed.
    * @param [in] instId: resource instance id, set in cm_resource.json
    * @param [in] resName: resource name, len need to be shorter than 32
    * @param [in] func: callback function, can be NULL
    * @return the json info like this:
        {
        // the same as CmInit input para:resName
        "res_name": "example",
        "version": 0,           // is_work_member or status changed increse with step 1
        "inst_count": 2, // max 64
        "inst_status": [{
                "node_id": 1,
                "res_instance_id": 0,
                "is_work_member": 1,   // 1 in cluster,0 not in cluster
                "status": 0            // 0:unknown, 1:online, 2:offline
            },
            {
                "node_id": 2,
                "res_instance_id": 1,
                "is_work_member": 1,
                "status": 0
            }
            ]
        }
    */
    char *(*cm_get_res_stat)(void);
    void (*cm_free_res_stat)(char *res_stat);

    /*
    * resource get lock from cm
    * @return: cm_res_err_code
     */
    int (*cm_res_lock)(const char *lock_name);
    /*
    * lock owner unlock from cm
    * @return: cm_res_err_code
     */
    int (*cm_res_unlock)(const char *lock_name);
    /*
    * get lock owner's res_instance_id from cm
    * @param [in&out] inst_id: lock owner's instance id
    * @return: cm_res_err_code
     */
    int (*cm_res_get_lock_owner)(const char *lock_name, unsigned int *inst_id);
    /*
    * lock owner transfer lock to other instance
    * @param [in] inst_id: new lock owner's instance id
    * @return: cm_res_err_code
     */
    int (*cm_res_trans_lock)(const char *lock_name, unsigned int inst_id);
} cm_res_mgr_t;

// init interface from so
status_t cm_res_mgr_init(const char *so_lib_path, cm_res_mgr_t *cm_res_mgr, cm_allocator_t *alloc);
void cm_res_mgr_uninit(cm_res_mgr_t *cm_res_mgr);

// register info by interface
int cm_res_init(cm_res_mgr_t *cm_res_mgr, unsigned int instance_id, const char *res_name, cm_notify_func_t func);

// get or set  by so interface directly
int cm_res_lock(cm_res_mgr_t *cm_res_mgr, const char *lock_name);
int cm_res_unlock(cm_res_mgr_t *cm_res_mgr, const char *lock_name);
int cm_res_get_lock_owner(cm_res_mgr_t *cm_res_mgr, const char *lock_name, unsigned int *inst_id);
int cm_res_trans_lock(cm_res_mgr_t *cm_res_mgr, const char *lock_name, unsigned int inst_id);

// get stats info by interface, return res_stat or NULL
typedef void *cm_res_stat_ptr_t;
cm_res_stat_ptr_t cm_res_get_stat(cm_res_mgr_t *cm_res_mgr, cm_res_mem_ctx_t *res_mem_ctx);
void cm_res_free_stat(cm_res_mgr_t *cm_res_mgr, cm_res_stat_ptr_t res_stat);
status_t cm_res_init_memctx(cm_res_mem_ctx_t *res_mem_ctx);
void cm_res_uninit_memctx(cm_res_mem_ctx_t *res_mem_ctx);

int cm_res_get_cm_version(unsigned long long *version, cm_res_mgr_t *cm_res_mgr, const cm_res_stat_ptr_t res_stat);
// get detail stats info
int cm_res_get_instance_count(unsigned int *inst_count, cm_res_mgr_t *cm_res_mgr, const cm_res_stat_ptr_t res_stat);
typedef void *cm_res_inst_info_ptr_t;
const cm_res_inst_info_ptr_t cm_res_get_instance_info(cm_res_mgr_t *cm_res_mgr,
    const cm_res_stat_ptr_t res_stat, unsigned int instance_idx);
int cm_res_get_inst_node_id(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info);
int cm_res_get_inst_instance_id(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info);
int cm_res_get_inst_is_work_member(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info);
int cm_res_get_inst_stat(cm_res_mgr_t *cm_res_mgr, const cm_res_inst_info_ptr_t instance_info);

#ifdef __cplusplus
}
#endif

#endif
