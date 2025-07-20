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
 * ddes_perctrl_server.h
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/service/ddes_perctrl_server.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_PERCTRL_SERVER_H__
#define __DDES_PERCTRL_SERVER_H__

#include "ddes_perctrl_api.h"

typedef int32 (*cmd_executor_t)(perctrl_packet_t *req, perctrl_packet_t *ack);
typedef struct st_perctrl_cmd_hdl {
    perctrl_cmd_e cmd;
    cmd_executor_t exec[2];
} perctrl_cmd_hdl_t;

typedef enum en_perctrl_log_param_id {
    PERCTRL_PARAM_LOG_HOME = 0,
    PERCTRL_PARAM_LOG_LEVEL,
    PERCTRL_PARAM_LOG_BACK_FILE_COUNT,
    PERCTRL_PARAM_MAX_LOG_FILE_SIZE,
    PERCTRL_PARAM_LOG_FILE_PERMISS,
    PERCTRL_PARAM_LOG_PATH_PERMISS,
    PERCTRL_PARAM_LOG_BAK_FILE_PERMISS,
    PERCTRL_PARAM_LOG_COMPRESSED,
    PERCTRL_PARAM_LOG_TOTAL_CNT, 
} perctrl_log_param_id_t;

typedef struct st_perctrl_log_param_set_t {
    perctrl_log_param_id_t id;
    char name[CM_MAX_NAME_LEN];
}perctrl_log_param_set_t;

perctrl_log_param_set_t g_perctrl_log_param[] = {
    {PERCTRL_PARAM_LOG_HOME, "log_home"},
    {PERCTRL_PARAM_LOG_LEVEL, "log_level"},
    {PERCTRL_PARAM_LOG_BACK_FILE_COUNT, "log_backup_file_count"},
    {PERCTRL_PARAM_MAX_LOG_FILE_SIZE, "max_log_file_size"},
    {PERCTRL_PARAM_LOG_FILE_PERMISS, "log_file_permissions"},
    {PERCTRL_PARAM_LOG_PATH_PERMISS, "log_path_permissions"},
    {PERCTRL_PARAM_LOG_BAK_FILE_PERMISS, "log_bak_file_permissions"},
    {PERCTRL_PARAM_LOG_COMPRESSED, "log_compressed"},
};

typedef struct st_cm_log_def_t {
    log_type_t log_id;
    char log_filename[CM_MAX_NAME_LEN];
} cm_log_def_t;

cm_log_def_t g_perctrl_log[] = {
    {LOG_DEBUG, "debug/perctrl.dlog"},
    {LOG_RUN, "run/perctrl.rlog"},
};

#endif
