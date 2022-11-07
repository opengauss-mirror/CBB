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
 * mes_rpc_ulog4c_dl.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_ulog4c_dl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_utils.h"

typedef int (*ULOGDL_Init)(int logType, int minLogLevel, const char *path, int rotationFileSize, int rotationFileCount);

typedef struct UlogFunc {
    ULOGDL_Init init;
} UlogFuncPtr;

void* g_ulogDl = NULL;
UlogFuncPtr g_ulogFunc;

#define RETURN_OK 0
#define RETURN_ERR (-1)

int InitUlogDl(char* path, unsigned int len)
{
    if (path == NULL || len == 0) {
        LOG_RUN_ERR("ulog path is nullptr");
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    if (g_ulogDl != NULL) {
        return RETURN_OK;
    }

    ret = cm_open_dl(&g_ulogDl, path);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dlopen ulog error");
        return RETURN_ERR;
    }

    ret = cm_load_symbol(g_ulogDl, "ULOG_Init", (void**)&g_ulogFunc.init);
    if (ret != CM_SUCCESS) {
        return RETURN_ERR;
    }

    return ret;
}

void FinishUlogDl(void)
{
    if (g_ulogDl != NULL) {
        cm_close_dl(g_ulogDl);
        g_ulogDl = NULL;
    }

    if (memset_sp(&g_ulogFunc, sizeof(g_ulogFunc), 0, sizeof(g_ulogFunc)) != EOK) {
        LOG_RUN_ERR("memset_sp failed");
    }
}

int ULOG_Init(int logType, int minLogLevel, const char *path, int rotationFileSize, int rotationFileCount)
{
    int ret;
    if (g_ulogFunc.init != NULL) {
        ret = g_ulogFunc.init(logType, minLogLevel, path, rotationFileSize, rotationFileCount);
    } else {
        ret = RETURN_ERR;
    }
    return ret;
}