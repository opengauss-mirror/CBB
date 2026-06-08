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
 * cm_iofence.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_iofence.c
 *
 * -------------------------------------------------------------------------
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <sys/wait.h>
#include <unistd.h>
#define CM_IOF_EXEC_FAILED_EXIT_CODE 127
#endif
#include "cm_file.h"
#include "cm_log.h"
#include "cm_iofence.h"

static bool32 cm_iof_validate_path(const char *path, const char *name)
{
    if (path == NULL || path[0] == '\0') {
        LOG_RUN_ERR("iofence %s is NULL or empty.", name);
        return CM_FALSE;
    }
    if (cm_check_exist_special_char(path, (uint32)strlen(path))) {
        LOG_RUN_ERR("iofence %s contains special characters, rejected.", name);
        return CM_FALSE;
    }
    return CM_TRUE;
}

#ifndef WIN32
static void cm_iof_close_pipe(int pipefd[2])
{
    (void)close(pipefd[0]);
    (void)close(pipefd[1]);
}

static void cm_iof_exec_child(char *const argv[], int write_fd)
{
    (void)dup2(write_fd, STDOUT_FILENO);
    (void)dup2(write_fd, STDERR_FILENO);
    (void)close(write_fd);
    (void)execvp(argv[0], argv);
    _exit(CM_IOF_EXEC_FAILED_EXIT_CODE);
}

static status_t cm_iof_spawn_cmd(const char *cmd, char *const argv[], int pipefd[2], pid_t *pid)
{
    if (pipe(pipefd) != 0) {
        LOG_RUN_ERR("multibus iofence pipe failed, cmd: %s.", cmd);
        return CM_ERROR;
    }

    *pid = fork();
    if (*pid < 0) {
        LOG_RUN_ERR("multibus iofence fork failed, cmd: %s.", cmd);
        cm_iof_close_pipe(pipefd);
        return CM_ERROR;
    }

    if (*pid == 0) {
        (void)close(pipefd[0]);
        cm_iof_exec_child(argv, pipefd[1]);
    }
    (void)close(pipefd[1]);
    return CM_SUCCESS;
}

static void cm_iof_read_cmd_result(int read_fd, char *buf, uint32 buf_len)
{
    char drain[128] = {0};
    uint32 offset = 0;

    while (CM_TRUE) {
        char *dst = (offset < buf_len - 1) ? (buf + offset) : drain;
        size_t dst_len = (offset < buf_len - 1) ? (buf_len - 1 - offset) : sizeof(drain);
        ssize_t read_len = read(read_fd, dst, dst_len);
        if (read_len > 0) {
            if (offset < buf_len - 1) {
                offset += (uint32)read_len;
            }
            continue;
        }
        if (read_len == 0) {
            break;
        }
        if (errno != EINTR && errno != EAGAIN) {
            break;
        }
    }
    buf[offset] = '\0';
}

static status_t cm_iof_wait_cmd(const char *cmd, pid_t pid, int *status)
{
    pid_t wait_ret;

    do {
        wait_ret = waitpid(pid, status, 0);
    } while (wait_ret < 0 && errno == EINTR);
    if (wait_ret < 0) {
        LOG_RUN_ERR("multibus iofence waitpid failed, cmd: %s.", cmd);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int32 cm_iof_parse_cmd_result(const char *buf)
{
    if (strstr(buf, "Reservation Conflict") != NULL) {
        LOG_RUN_INF("multibus iofence, execute succ. Reservation Conflict");
        return CM_SCSI_ERR_CONFLICT;
    }
    if (strstr(buf, "a password is required") != NULL || strstr(buf, "error opening file") != NULL ||
        strstr(buf, "reservation key doesn't match") != NULL || strstr(buf, "command failed") != NULL ||
        strstr(buf, "command not found") != NULL) {
        LOG_RUN_INF("multibus iofence, execute faild.");
        return (int32)CM_ERROR;
    }
    LOG_RUN_INF("multibus iofence, execute succ.");
    return (int32)CM_SUCCESS;
}
#endif

static int32 cm_iof_exec_cmd(const char *cmd, char *const argv[])
{
#ifdef WIN32
    (void)cmd;
    (void)argv;
    return CM_SUCCESS;
#else
    int pipefd[2] = {-1, -1};
    int status = 0;
    char buf[512] = {0};
    pid_t pid;

    if (cm_iof_spawn_cmd(cmd, argv, pipefd, &pid) != CM_SUCCESS) {
        return (int32)CM_ERROR;
    }
    cm_iof_read_cmd_result(pipefd[0], buf, (uint32)sizeof(buf));
    (void)close(pipefd[0]);
    if (cm_iof_wait_cmd(cmd, pid, &status) != CM_SUCCESS) {
        return (int32)CM_ERROR;
    }

    LOG_RUN_INF("multibus iofence, cmd: %s,result: %s.", cmd, buf);
    if ((!WIFEXITED(status) || WEXITSTATUS(status) != 0) && buf[0] == '\0') {
        LOG_RUN_ERR("multibus iofence exec failed, cmd: %s.", cmd);
        return (int32)CM_ERROR;
    }
    return cm_iof_parse_cmd_result(buf);
#endif
}

int32 cm_iof_multibus_register(const char *mpathpersist_path, const char *log_path, const char *iof_dev, int64 sark)
{
    if (!cm_iof_validate_path(mpathpersist_path, "mpathpersist_path") ||
        !cm_iof_validate_path(log_path, "log_path") ||
        !cm_iof_validate_path(iof_dev, "iof_dev")) {
        return (int32)CM_ERROR;
    }
    int32 ret;
    char cmd[MULTIBUS_MAX_CMD_LEN];
    char device_arg[MULTIBUS_MAX_CMD_LEN] = {0};
    char sark_arg[64] = {0};
    // device must be the 4th parameter,because mpathpersist_dss.sh will check device owner
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "sudo -n %s %s --out --register --device=%s --param-sark=%lld 2>&1",
        mpathpersist_path, log_path, iof_dev, sark);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(device_arg, sizeof(device_arg), sizeof(device_arg) - 1, "--device=%s", iof_dev);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(sark_arg, sizeof(sark_arg), sizeof(sark_arg) - 1, "--param-sark=%lld", sark);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    char *argv[] = {"sudo", "-n", (char *)mpathpersist_path, (char *)log_path,
        "--out", "--register", device_arg, sark_arg, NULL};
    return cm_iof_exec_cmd(cmd, argv);
}

int32 cm_iof_multibus_reserve(const char *mpathpersist_path, const char *log_path, const char *iof_dev,
    int64 rk, scsi_reserv_type_e type)
{
    if (!cm_iof_validate_path(mpathpersist_path, "mpathpersist_path") ||
        !cm_iof_validate_path(log_path, "log_path") ||
        !cm_iof_validate_path(iof_dev, "iof_dev")) {
        return (int32)CM_ERROR;
    }
    int32 ret;
    char cmd[MULTIBUS_MAX_CMD_LEN];
    char device_arg[MULTIBUS_MAX_CMD_LEN] = {0};
    char rk_arg[64] = {0};
    char type_arg[64] = {0};
    // device must be the 4th parameter,because mpathpersist_dss.sh will check device owner
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "sudo -n %s %s --out --reserve --device=%s --param-rk=%lld --prout-type=%d 2>&1",
        mpathpersist_path, log_path, iof_dev, rk, type);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(device_arg, sizeof(device_arg), sizeof(device_arg) - 1, "--device=%s", iof_dev);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(rk_arg, sizeof(rk_arg), sizeof(rk_arg) - 1, "--param-rk=%lld", rk);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(type_arg, sizeof(type_arg), sizeof(type_arg) - 1, "--prout-type=%d", type);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    char *argv[] = {"sudo", "-n", (char *)mpathpersist_path, (char *)log_path,
        "--out", "--reserve", device_arg, rk_arg, type_arg, NULL};
    return cm_iof_exec_cmd(cmd, argv);
}

int32 cm_iof_multibus_preempt(const char *mpathpersist_path, const char *log_path, const char *iof_dev, int64 rk,
    int64 sark, scsi_reserv_type_e type)
{
    if (!cm_iof_validate_path(mpathpersist_path, "mpathpersist_path") ||
        !cm_iof_validate_path(log_path, "log_path") ||
        !cm_iof_validate_path(iof_dev, "iof_dev")) {
        return (int32)CM_ERROR;
    }
    int32 ret;
    char cmd[MULTIBUS_MAX_CMD_LEN];
    char device_arg[MULTIBUS_MAX_CMD_LEN] = {0};
    char rk_arg[64] = {0};
    char sark_arg[64] = {0};
    char type_arg[64] = {0};
    // device must be the 4th parameter,because mpathpersist_dss.sh will check device owner
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "sudo -n %s %s --out --preempt --device=%s --param-rk=%lld --param-sark=%lld --prout-type=%d 2>&1",
        mpathpersist_path, log_path, iof_dev, rk, sark, type);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(device_arg, sizeof(device_arg), sizeof(device_arg) - 1, "--device=%s", iof_dev);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(rk_arg, sizeof(rk_arg), sizeof(rk_arg) - 1, "--param-rk=%lld", rk);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(sark_arg, sizeof(sark_arg), sizeof(sark_arg) - 1, "--param-sark=%lld", sark);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(type_arg, sizeof(type_arg), sizeof(type_arg) - 1, "--prout-type=%d", type);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    char *argv[] = {"sudo", "-n", (char *)mpathpersist_path, (char *)log_path,
        "--out", "--preempt", device_arg, rk_arg, sark_arg, type_arg, NULL};
    return cm_iof_exec_cmd(cmd, argv);
}

int32 cm_iof_multibus_unregister(const char *mpathpersist_path, const char *log_path, const char *iof_dev, int64 rk)
{
    if (!cm_iof_validate_path(mpathpersist_path, "mpathpersist_path") ||
        !cm_iof_validate_path(log_path, "log_path") ||
        !cm_iof_validate_path(iof_dev, "iof_dev")) {
        return (int32)CM_ERROR;
    }
    int32 ret;
    char cmd[MULTIBUS_MAX_CMD_LEN];
    char device_arg[MULTIBUS_MAX_CMD_LEN] = {0};
    char rk_arg[64] = {0};
    // device must be the 4th parameter,because mpathpersist_dss.sh will check device owner
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "sudo -n %s %s --out --register --device=%s --param-rk=%lld 2>&1",
        mpathpersist_path, log_path, iof_dev, rk);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(device_arg, sizeof(device_arg), sizeof(device_arg) - 1, "--device=%s", iof_dev);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    ret = snprintf_s(rk_arg, sizeof(rk_arg), sizeof(rk_arg) - 1, "--param-rk=%lld", rk);
    if (SECUREC_UNLIKELY(ret == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return (int32)CM_ERROR;
    }
    char *argv[] = {"sudo", "-n", (char *)mpathpersist_path, (char *)log_path,
        "--out", "--register", device_arg, rk_arg, NULL};
    return cm_iof_exec_cmd(cmd, argv);
}

int32 cm_iof_register(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    int32 ret;
    if (iof_out == NULL) {
        return CM_ERROR;
    }
    if (iof_out->linux_multibus) {
        ret = cm_iof_multibus_register(iof_out->mpathpersist_dss_path, iof_out->log_path,
            iof_out->dev, CM_OUT_SCSI_RK(iof_out));
    } else {
        ret = perctrl_scsi3_register(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
    }
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_CONFLICT == ret) {
            // ignore this fail
            LOG_RUN_INF(
                "Scsi3 register conflict, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
        } else {
            LOG_RUN_ERR(
                "Scsi3 register failed, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
            return CM_ERROR;
        }
    }

    // Any host can perform reservation operations, but at least one host must perform
    if (iof_out->linux_multibus) {
        ret = cm_iof_multibus_reserve(iof_out->mpathpersist_dss_path, iof_out->log_path, iof_out->dev,
            CM_OUT_SCSI_RK(iof_out), iof_out->type);
    } else {
        ret = perctrl_scsi3_reserve(iof_out->dev, CM_OUT_SCSI_RK(iof_out), iof_out->type);
    }
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_CONFLICT == ret) {
            // ignore this fail
            LOG_RUN_INF(
                "Scsi3 register conflict, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
        } else {
            LOG_RUN_ERR(
                "Scsi3 reserve failed, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("IOfence register succ, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);

#endif
    return CM_SUCCESS;
}

int32 cm_iof_unregister(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    int32 ret;
    if (iof_out == NULL) {
        return CM_ERROR;
    }

    if (iof_out->linux_multibus) {
        ret = cm_iof_multibus_unregister(iof_out->mpathpersist_dss_path, iof_out->log_path,
            iof_out->dev, CM_OUT_SCSI_RK(iof_out));
    } else {
        ret = perctrl_scsi3_unregister(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
    }
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_CONFLICT == ret) {
            // ignore this fail
            LOG_RUN_INF(
                "Scsi3 unregister conflict, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
        } else {
            LOG_RUN_ERR(
                "Scsi3 unregister failed, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("IOfence unregister succ, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);

#endif
    return CM_SUCCESS;
}

status_t cm_iof_kick(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    status_t status;

    if (iof_out == NULL) {
        return CM_ERROR;
    }
    if (iof_out->linux_multibus) {
        status = cm_iof_multibus_preempt(iof_out->mpathpersist_dss_path, iof_out->log_path,
            iof_out->dev, CM_OUT_SCSI_RK(iof_out), CM_OUT_SCSI_SARK(iof_out), iof_out->type);
    } else {
        status = perctrl_scsi3_preempt(iof_out->dev, CM_OUT_SCSI_RK(iof_out), CM_OUT_SCSI_SARK(iof_out), iof_out->type);
    }
    if (CM_SUCCESS != status) {
        LOG_RUN_ERR("Scsi3 preempt failed, rk %lld, rk_kick %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out),
            CM_OUT_SCSI_SARK(iof_out), iof_out->dev, errno);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence kick succ, rk %lld, rk_kick %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out),
        CM_OUT_SCSI_SARK(iof_out), iof_out->dev, errno);
#endif
    return CM_SUCCESS;
}

status_t cm_iof_clear(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    status_t status;

    if (iof_out == NULL) {
        return CM_ERROR;
    }
    status = perctrl_scsi3_clear(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
    if (CM_SUCCESS != status) {
        LOG_RUN_ERR("Scsi3 clear failed, rk %lld, dev %s, errno %d.", CM_OUT_SCSI_RK(iof_out), iof_out->dev, errno);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence clear succ, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);

#endif
    return CM_SUCCESS;
}

status_t cm_iof_inql(iof_reg_in_t *iof_in)
{
#ifdef WIN32
#else
    status_t status;

    if (iof_in == NULL) {
        return CM_ERROR;
    }
    iof_in->key_count = CM_MAX_RKEY_COUNT;
    status = perctrl_scsi3_rkeys(iof_in->dev, iof_in->reg_keys, &iof_in->key_count, &iof_in->generation);
    if (CM_SUCCESS != status) {
        LOG_RUN_ERR("Scsi3 inql rkeys failed, dev %s, errno %d.", iof_in->dev, errno);
        return CM_ERROR;
    }

    status = perctrl_scsi3_rres(iof_in->dev, &iof_in->resk, &iof_in->generation);
    if (CM_SUCCESS != status) {
        LOG_RUN_ERR("Scsi3 inql rres failed, dev %s, errno %d.", iof_in->dev, errno);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence inql succ, dev %s.", iof_in->dev);

#endif
    return CM_SUCCESS;
}
