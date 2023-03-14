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
 * cm_sec_file.c
 *
 *
 * IDENTIFICATION
 *    src/cm_security/cm_sec_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_encrypt.h"
#include "cm_file.h"
#include "cm_log.h"
#include "cm_num.h"
#include "cm_sec_file.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t cm_cyclewrite_file(int32 file, int32 file_size, char *buf, int32 buf_len, int32 value)
{
    if (cm_seek_file(file, 0, SEEK_SET) != 0) {
        LOG_RUN_ERR("seek file failed");
        return CM_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(buf, buf_len, value, buf_len));
    int32 total_write_size = 0;
    int32 write_size = 0;
    while (total_write_size < file_size) {
        write_size = write(file, buf, buf_len);
        if (write_size > 0) {
            total_write_size += write_size;
            continue;
        } else {
            CM_THROW_ERROR(ERR_WRITE_FILE, errno);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t cm_overwrite_file(const char *file_name)
{
    int buf_len = CM_MAX_INVALID_CHARSTR_LEN;
    char buf[CM_MAX_INVALID_CHARSTR_LEN];
    int32 handle = CM_INVALID_HANDLE;
    int64 file_size;
    uint32 value;

    if (cm_open_file(file_name, O_RDWR | O_EXCL | O_SYNC, &handle) != CM_SUCCESS) {
        LOG_RUN_ERR("failed to open key file %s", file_name);
        return CM_ERROR;
    }

    file_size = cm_file_size(handle);
    if (file_size > CM_MAX_INT32) {
        cm_close_file(handle);
        LOG_RUN_ERR("The file %s size is too big.", file_name);
        return CM_ERROR;
    }
    value = 0;
    if (cm_cyclewrite_file(handle, (int32)file_size, buf, buf_len, value) != CM_SUCCESS) {
        cm_close_file(handle);
        LOG_RUN_ERR("overwrite file failed :%s.", file_name);
        return CM_ERROR;
    }
    value = 1;
    if (cm_cyclewrite_file(handle, (int32)file_size, buf, buf_len, value) != CM_SUCCESS) {
        cm_close_file(handle);
        LOG_RUN_ERR("overwrite file failed :%s.", file_name);
        return CM_ERROR;
    }
    value = cm_random(CM_INVALID_ID8);
    if (cm_cyclewrite_file(handle, (int32)file_size, buf, buf_len, value) != CM_SUCCESS) {
        cm_close_file(handle);
        LOG_RUN_ERR("overwrite file failed :%s.", file_name);
        return CM_ERROR;
    }
    cm_close_file(handle);
    return CM_SUCCESS;
}
#ifdef __cplusplus
}
#endif
