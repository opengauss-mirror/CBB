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
 * cm_sec_file.h
 *
 *
 * IDENTIFICATION
 *    src/cm_security/cm_sec_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_SEC_FILE_H__
#define __CM_SEC_FILE_H__

#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_MAX_INVALID_CHARSTR_LEN 1024

status_t cm_overwrite_file(const char *file_name);

#ifdef __cplusplusfile_name
}
#endif

#endif
