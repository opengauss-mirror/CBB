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
 * ddes_cap_exec.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_cap/ddes_cap_exec.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddes_cap_exec.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include "cm_log.h"
#include "cm_scsi.h"
#include "cm_file.h"

#ifdef WIN32
#include <io.h>
#define read _read
#define write _write
#define open _open
#endif

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_COMMAND_LEN 1024
#define MAX_RESULT_LEN 128

static int res_wrfd;
static int req_rdfd;

static int read_message(int fd, char *buf, int size)
{
    int remain = size, offset = 0, rdsz = 0;
    while (remain > 0) {
        rdsz = read(fd, buf + offset, remain);
        if (rdsz == 0) {
            return CM_ERROR;
        }
        if (rdsz == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return CM_ERROR;
        }
        remain -= rdsz;
        offset += rdsz;
    }
    return CM_SUCCESS;
}

static int write_message(int fd, char *buf, int size)
{
    int remain = size, offset = 0, wrsz = 0;
    while (remain > 0) {
        wrsz = write(fd, buf + offset, remain);
        if (wrsz <= 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return CM_ERROR;
        }
        remain -= wrsz;
        offset += wrsz;
    }
    return CM_SUCCESS;
}

static void send_fail_response(int errcode, char *response, ...)
{
    va_list args;
    va_start(args, response);

    char buf[MAX_RESULT_LEN];
    cap_rslt_t *res = (cap_rslt_t *)buf;

    res->errcode = errcode;
    res->size = MAX_RESULT_LEN - sizeof(cap_rslt_t) - 1; // terminate character '\0'
    res->size = vsnprintf_s(res->data, res->size, res->size, response, args);
    res->data[res->size] = '\0';
    ++res->size;

    va_end(args);
    (void)write_message(res_wrfd, (char *)res, sizeof(cap_rslt_t) + res->size);
}

static void send_succ_response(char *buf, uint32 len)
{
    cap_rslt_t res = {CM_SUCCESS, len};
    if (CM_SUCCESS == write_message(res_wrfd, (char *)&res, sizeof(cap_rslt_t))) {
        if (len > 0) {
            (void)write_message(res_wrfd, buf, len);
        }
    }
}

static status_t check_exec_response(int fd, char *rslt, int32 len)
{
    char buf[MAX_RESULT_LEN];
    cap_rslt_t *response = (cap_rslt_t *)buf;
    if (CM_SUCCESS != read_message(fd, buf, sizeof(cap_rslt_t))) {
        LOG_RUN_ERR("failed to read response head.");
        return CM_ERROR;
    }
    if (response->size + sizeof(cap_rslt_t) > MAX_RESULT_LEN) {
        LOG_RUN_ERR("failed to response data, size exceed limit, size=%u, limit=%u.",
            response->size + sizeof(cap_rslt_t), MAX_RESULT_LEN);
        return CM_ERROR;
    }
    if (SECUREC_UNLIKELY(response->errcode != CM_SUCCESS)) {
        if (response->size == 0) { return CM_ERROR; }
        if (CM_SUCCESS != read_message(fd, response->data, response->size)) {
            LOG_RUN_ERR("failed to read error message.");
            return CM_ERROR;
        }
        LOG_RUN_ERR("failed to execute command, errmsg=%s", response->data);
        return CM_ERROR;
    }
    if (len == 0) { return CM_SUCCESS; }
    if (response->size != len) {
        LOG_RUN_ERR("result size returned is not valid, expected=%u, returned=%u", len, response->size);
        return CM_ERROR;
    }
    if (CM_SUCCESS != read_message(fd, rslt, len)) {
        LOG_RUN_ERR("failed to read result data.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cap_exec_cmd(cap_agent_t *agent, cap_cmd_t *cmd, char *rslt, uint32 len)
{
    int wrfd = agent->req_pipe.hwrite, rdfd = agent->res_pipe.hread;
    uint32 cmdsz = sizeof(cap_cmd_t) + cmd->size;

    if (CM_SUCCESS != write_message(wrfd, (char *)cmd, cmdsz)) {
        return CM_ERROR;
    }

    return check_exec_response(rdfd, rslt, len);
}

#define IOF_DEV_LEN 512
#define SET_CMD_SIZE(cmd) ((cmd).head.size = sizeof(cmd)-sizeof(cap_cmd_head_t))
#define SET_RSLT_SIZE(rslt)((rslt).head.size = sizeof(rslt) - sizeof(cap_rslt_head_t))
typedef struct st_cap_rkeys {
    cap_cmd_head_t head;
    char iof_dev[IOF_DEV_LEN];
}cap_rkeys_t;

typedef struct st_rkeys_rslt {
    cap_rslt_head_t head;
    int32 key_count;
    uint32 generation;
    int64 rkeys[CM_MAX_RKEY_COUNT];
}rkeys_rslt_t;

status_t cap_read_rkeys(cap_cmd_t *cmd)
{
    cap_rkeys_t *cmd_rkeys = (cap_rkeys_t *)cmd;
    rkeys_rslt_t rslt;

    SET_RSLT_SIZE(rslt);
    int32 fd = open(cmd_rkeys->iof_dev, O_RDWR);
    if (fd == -1) {
        cm_set_error(__FILE_NAME__, __LINE__, CM_ERROR,
            "failed to open iof device. errno=%d, name=%s.", errno, cmd_rkeys->iof_dev);
        return CM_ERROR;
    }

    status_t ret = cm_scsi3_rkeys(fd, rslt.rkeys, &rslt.key_count, &rslt.generation);
    if (CM_SUCCESS != ret) {
        cm_set_error(__FILE_NAME__, __LINE__, ret,
            "failed to get register keys. device name=%s.", cmd_rkeys->iof_dev);
        return CM_ERROR;
    }

    send_succ_response((char *)&rslt, sizeof(rkeys_rslt_t));
    return CM_SUCCESS;
}

static cap_oper_t g_cap_opers[] = {
    [CAP_READ_RKEYS] = { CAP_READ_RKEYS, cap_read_rkeys },
};

#ifndef WIN32

#define MAX_FD_LEN 6
status_t cap_agent_init(cap_agent_t *agent, const char *agent_name)
{
    if (-1 == pipe(agent->req_pipe || -1 == pipe(agent->res_pipe))) {
        return CM_ERROR;
    }
    agent->pid = fork();
    // application server send cap command as a request to cap agent
    // after executing, cap agent send a response
    if (0 == agent->pid) { // child process
        if (cm_fcntl(agent->req_pipe.hread, F_SETFL, O_NONBLOCK, CM_WAIT_FOREVER) != CM_SUCCESS) {
            send_fail_response(CM_ERROR,
                "failed to set reading end of request pipe to non-block. errno = %d.", errno);
            return CM_ERROR;
        }
        if (cm_fcntl(agent->res_pipe.hwrite, F_SETFL, O_NONBLOCK, CM_WAIT_FOREVER) != CM_SUCCESS) {
            send_fail_response(CM_ERROR,
                "failed to set writing end of response pipe to non-block. errno = %d.", errno);
            return CM_ERROR;
        }
        char req_rfd[MAX_FD_LEN + 1], res_wfd[MAX_FD_LEN + 1];
        int32 size = vsnprintf_s(req_rfd, MAX_FD_LEN, MAX_FD_LEN, agent->req_pipe.hread);
        if (SECUREC_UNLIKELY(size == -1)) {
            LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
            return CM_ERROR;
        }
        req_rfd[size] = '\0';
        size = vsnprintf_s(res_wfd, MAX_FD_LEN, MAX_FD_LEN, agent->res_pipe.hwrite);
        if (SECUREC_UNLIKELY(size == -1)) {
            LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
            return CM_ERROR;
        }
        res_wfd[size] = '\0';

        // close the sending end of the request pipe
        close(agent->req_pipe.hwrite);

        // close the receiving end of the response pipe
        close(agent->res_pipe.hread);

        if (-1 == execlp("/bin/sh", "sh", "-c", "./cap_agent", req_rfd, res_wfd, NULL)) {
            send_fail_response(CM_ERROR, "failed to replace execute image for cap agent.");
            return CM_ERROR;
        }
        return CM_SUCCESS;
    } else {
        // close the reading end of request pipe
        close(agent->req_pipe.hread);

        // close the write end of response pipe
        close(agent->res_pipe.hwrite);
        if (cm_fcntl(agent->req_pipe.hwrite, F_SETFL, O_NONBLOCK, CM_WAIT_FOREVER) != CM_SUCCESS) {
            send_fail_response(CM_ERROR,
                "failed to set writing end of request pipe to non-block. errno = %d.", errno);
            return CM_ERROR;
        }
        if (cm_fcntl(agent->res_pipe.hread, F_SETFL, O_NONBLOCK, CM_WAIT_FOREVER) != CM_SUCCESS) {
            send_fail_response(CM_ERROR,
                "failed to set reading end of response pipe to non-block. errno = %d.", errno);
            return CM_ERROR;
        }
        return check_exec_response(agent->res_pipe.hread, NULL, 0);
    }
}

/* logic below, for agent use only */
status_t agent_proc(int argc, char **argv)
{
    req_rdfd = atoi(argv[0]);
    res_wrfd = atoi(argv[1]);
    if (CM_SUCCESS != cm_regist_signal(SIGPIPE, SIG_IGN)) {
        send_fail_response(CM_ERROR, "failed to ignore signal SIGPIPE. errno=%d", errno);
        return CM_ERROR;
    }

    send_fail_response(CM_SUCCESS, "start cap agent succeeded.");

    char cmdbuf[MAX_COMMAND_LEN];
    cap_cmd_t *cmd = (cap_cmd_t *)cmdbuf;
    for (;;) {
        if (CM_SUCCESS != read_message(req_rdfd, (char *)cmd, sizeof(cap_cmd_t))) {
            send_fail_response(CM_ERROR, "reading command head failed.");
            continue;
        }

        if (cmd->size + sizeof(cap_cmd_t) > MAX_COMMAND_LEN) {
            send_fail_response(CM_ERROR, "reading command data failed. size exceed limit, size = %u, limit = %u",
                cmd->size + sizeof(cap_cmd_t), MAX_COMMAND_LEN);
            continue;
        }

        if (cmd->size > 0 && CM_SUCCESS != read_message(req_rdfd, cmd->data, cmd->size)) {
            send_fail_response(CM_ERROR, "reading command data failed. size = %u", cmd->size);
            continue;
        }

        if (CM_SUCCESS != g_cap_opers[cmd->type].excutor(cmd)) {
            send_fail_response(CM_ERROR, "executing cap command failed. errcode=%d, errmsg=%s",
                cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            continue;
        }
    }
}

#else

status_t cap_agent_init(cap_agent_t *agent, const char *agent_name)
{
    return CM_SUCCESS;
}

#endif

#ifdef __cplusplus
}
#endif
