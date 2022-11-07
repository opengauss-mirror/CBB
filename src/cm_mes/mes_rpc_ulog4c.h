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
 * mes_rpc_ulog4c.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_rpc_ulog4c.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef PLATFORM_UTILITIES_REMOTE_ULOG_H
#define PLATFORM_UTILITIES_REMOTE_ULOG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief initialize the normal ulog
 *
 * @param logType          - [IN] type of the ulog, could 0 or 1; 0: stdout, 1: file
 * @param minLogLevel      - [IN] min level of message, 0:trace, 1:debug, 2:info, 3:warn, 4:error, 5:critical
 * @param path             - [IN] full path of ulog file name
 * @param rotationFileSize - [IN] the max file size of a single rotation file
 * @param rotationFileSize - [IN] the max count of total rotated file
 *
 * @return 0 for success, non zero for failure
 */
int ULOG_Init(int logType, int minLogLevel, const char *path, int rotationFileSize, int rotationFileCount);

int InitUlogDl(char* path, unsigned int len);
void FinishUlogDl(void);

#if defined(__cplusplus)
}
#endif

#endif // PLATFORM_UTILITIES_REMOTE_ULOG_H
