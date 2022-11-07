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
    cmd_executor_t exec;
} perctrl_cmd_hdl_t;

#endif
