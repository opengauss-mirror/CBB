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
 * ddes_cap_exec.h
 *
 *
 * IDENTIFICATION
 *    src/ddes_cap/ddes_cap_exec.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_CAP_EXEC_H__
#define __DDES_CAP_EXEC_H__

#include "cm_error.h"
#include "cm_types.h"

#ifndef WIN32
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
    status_t agent_proc();
#endif // WIN32

typedef enum st_cmd_type {
    CAP_READ_RKEYS = 0,
}cmd_type_t;

typedef struct st_cap_cmd_head {
    cmd_type_t type;
    uint32 size;
}cap_cmd_head_t;

typedef struct st_cap_cmd {
    union {
        struct {
            cmd_type_t type;
            uint32 size;
        };
        cap_cmd_head_t head;
    };
    char data[];
}cap_cmd_t;

typedef struct st_cap_rslt_head {
    int errcode;
    uint32 size;
}cap_rslt_head_t;

typedef struct st_cap_rslt {
    union {
        struct {
            int errcode;
            uint32 size;
        };
        cap_rslt_head_t head;
    };
    char data[];
}cap_rslt_t;

typedef status_t (*cmd_executor_t)(cap_cmd_t *cmd);

typedef struct st_cap_oper {
    cmd_type_t type;
    cmd_executor_t excutor;
}cap_oper_t;

typedef union st_pipe {
    struct {
        int hread;
        int hwrite;
    };
    int pipe[2];
}pipe_t;

typedef struct st_cap_agent {
    pipe_t req_pipe; // for sending request
    pipe_t res_pipe; // for receiving response
    pid_t  pid;
}cap_agent_t;

status_t cap_exec_cmd(cap_agent_t *agent, cap_cmd_t *cmd, char *rslt, uint32 len);

status_t cap_agent_init(cap_agent_t *agent, const char *agent_name);

#ifdef __cplusplus
}
#endif

#endif
