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
 * ddes_perctrl_api.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/interface/ddes_perctrl_api.c
 *
 * -------------------------------------------------------------------------
 */

#ifdef WIN32
#else
#include <sys/types.h>
#include "sys/wait.h"
#endif

#include "cm_error.h"
#include "cm_defs.h"
#include "ddes_perctrl_api.h"

#ifdef __cplusplus
extern "C" {
#endif

static perctrl_pipes_t g_perctrl = {.req_pipe.fds = {0}, .res_pipe.fds = {0}, .pid = 0};
static bool32 g_is_init = CM_FALSE;
static spinlock_t g_init_lock = 0;

#ifdef WIN32
status_t perctrl_init(perctrl_pipes_t *perctrl, const char* name)
{
    return CM_SUCCESS;
}

status_t perctrl_uninit()
{
    return CM_SUCCESS;
}

status_t exec_perctrl_cmd(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    return CM_SUCCESS;
}

status_t perctrl_receive(int32 fd, perctrl_packet_t *msg)
{
    return CM_SUCCESS;
}

status_t perctrl_send(int32 fd, perctrl_packet_t *msg)
{
    return CM_SUCCESS;
}
#else
static status_t perctrl_read_pipe(int32 fd, char *buf, uint32 size)
{
    uint32 remain = size;
    uint32 offset = 0;
    ssize_t ret = 0;
    while (remain > 0) {
        ret = read(fd, buf + offset, remain);
        if (ret == 0) {
            return CM_PIPECLOSED;
        }
        if (ret == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return CM_ERROR;
        }
        remain -= (uint32)ret;
        offset += (uint32)ret;
    }
    return CM_SUCCESS;
}

status_t perctrl_receive(int32 fd, perctrl_packet_t *msg)
{
    // read head
    status_t ret = perctrl_read_pipe(fd, msg->buf, sizeof(perctrl_cmd_head_t));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32 size = ((perctrl_cmd_head_t *)msg->buf)->size;
    // read params
    if (size > sizeof(perctrl_cmd_head_t)) {
        ret = perctrl_read_pipe(fd, (msg->buf + sizeof(perctrl_cmd_head_t)), (size - sizeof(perctrl_cmd_head_t)));
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }

    return CM_SUCCESS;
}

status_t perctrl_send(int32 fd, perctrl_packet_t *msg)
{
    uint32 remain = msg->head->size;
    uint32 offset = 0;
    ssize_t ret = 0;
    while (remain > 0) {
        ret = write(fd, msg->buf + offset, remain);
        if (ret <= 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return CM_ERROR;
        }
        remain -= (uint32)ret;
        offset += (uint32)ret;
    }
    return CM_SUCCESS;
}

status_t perctrl_init(perctrl_pipes_t *perctrl, const char* name)
{
    uint32 wait_time = 10;
    if (pipe(perctrl->req_pipe.fds) == -1) {
        return CM_ERROR;
    }
    if (pipe(perctrl->res_pipe.fds) == -1) {
        return CM_ERROR;
    }

    perctrl->pid = fork();
    if (perctrl->pid < 0) {
        LOG_DEBUG_ERR("fork pertctrl fail.");
        return CM_ERROR;
    } else if (perctrl->pid == 0) { // child process
        g_is_init = CM_FALSE;
        char req_fd[MAX_FD_LEN];
        char ack_fd[MAX_FD_LEN];
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        int32 ret = snprintf_s(req_fd, sizeof(req_fd), sizeof(req_fd) - 1, "%d", perctrl->req_pipe.rfd);
        PRTS_RETURN_IFERR(ret);
        ret = snprintf_s(ack_fd, sizeof(ack_fd), sizeof(ack_fd) - 1, "%d", perctrl->res_pipe.wfd);
        PRTS_RETURN_IFERR(ret);
        
        (void)close(perctrl->res_pipe.rfd);
        (void)close(perctrl->req_pipe.wfd);

        if (execlp("perctrl", "perctrl", req_fd, ack_fd, NULL) == -1) {
            LOG_DEBUG_ERR("execl pertctrl fail.");
            exit(1); // exit child process
        }
        cm_sleep(wait_time);
        return CM_SUCCESS;
    }

    (void)close(perctrl->req_pipe.rfd);
    (void)close(perctrl->res_pipe.wfd);
    return CM_SUCCESS;
}

status_t exec_perctrl_send_and_receive(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    status_t status = perctrl_send(g_perctrl.req_pipe.wfd, req);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = perctrl_receive(g_perctrl.res_pipe.rfd, ack);
    if (status < 0) {
        return status;
    }
    return CM_SUCCESS;
}

status_t exec_perctrl_cmd(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    status_t status;
    if (!g_is_init) {
        cm_spin_lock(&g_init_lock, NULL);
        if (!g_is_init) {
            status = perctrl_init(&g_perctrl, NULL);
            if (status != CM_SUCCESS) {
                cm_spin_unlock(&g_init_lock);
                return status;
            }
            (void)exec_perctrl_init_logger();
            g_is_init = CM_TRUE;
        }
        cm_spin_unlock(&g_init_lock);
    }
    cm_spin_lock(&g_init_lock, NULL);
    status = exec_perctrl_send_and_receive(req, ack);
    cm_spin_unlock(&g_init_lock);
    return status;
}

__attribute__((destructor)) status_t perctrl_uninit();

status_t perctrl_uninit()
{
    if (g_is_init) {
        cm_spin_lock(&g_init_lock, NULL);
        if (g_is_init) {
            perctrl_packet_t req = {0};
            req.buf = req.buf_init;
            req.head = (perctrl_cmd_head_t *)req.buf;
            req.head->size = (uint32)sizeof(perctrl_cmd_head_t);
            req.head->cmd = PERCTRL_CMD_EXIT;
            if (perctrl_send(g_perctrl.req_pipe.wfd, &req) != CM_SUCCESS) {
                LOG_DEBUG_ERR("perctrl uninit failed.");
                cm_spin_unlock(&g_init_lock);
                return CM_ERROR;
            }
            (void)waitpid(g_perctrl.pid, NULL, 0);
        }
        g_is_init = CM_FALSE;
        cm_spin_unlock(&g_init_lock);
    }
    return CM_SUCCESS;
}

#endif

int32 exec_perctrl_init_logger()
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    int32 errcode = -1;
    char *errmsg = NULL;
    log_param_t *parent_log_param = cm_log_param_instance();
    req.head->cmd = PERCTRL_CMD_INIT_LOG;
    char buf[MAX_PACKET_LEN];
    PRTS_RETURN_IFERR(snprintf_s(buf, MAX_PACKET_LEN, MAX_PACKET_LEN - 1,
        "log_home=%s|log_level=%u|log_backup_file_count=%u|max_log_file_size=%llu|log_file_permissions=%u|log_path_permissions=%u|"
        "log_bak_file_permissions=%u|log_compressed=%hu",
        parent_log_param->log_home, parent_log_param->log_level,
        parent_log_param->log_backup_file_count, parent_log_param->max_log_file_size,
        parent_log_param->log_file_permissions, parent_log_param->log_path_permissions,
        parent_log_param->log_bak_file_permissions, (uint16)parent_log_param->log_compressed));
    CM_RETURN_IFERR(ddes_put_str(&req, buf));
    CM_RETURN_IFERR(exec_perctrl_send_and_receive(&req, &ack));
    ddes_init_get(&ack);
    if (ack.head->result != CM_SUCCESS) {
        (void)ddes_get_int32(&ack, &errcode);
        (void)ddes_get_str(&ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]init loggers failed, result:%d, %s.", ack.head->result, errmsg);
        return ack.head->result;
    }

    return CM_SUCCESS;
}

int32 perctrl_register_impl(const char *iof_dev, int64 sark, perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_REGISTER;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)sark));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));

    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]rgister failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

int32 perctrl_scsi3_register(const char *iof_dev, int64 sark)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_register_impl(iof_dev, sark, &req, &ack);
}

int32 perctrl_unregister_impl(const char *iof_dev, int64 rk, perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_UNREGISTER;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)rk));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));

    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]unrgister failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

int32 perctrl_scsi3_unregister(const char *iof_dev, int64 rk)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_unregister_impl(iof_dev, rk, &req, &ack);
}

status_t perctrl_reserve_impl(const char *iof_dev, int64 rk, scsi_reserv_type_e type,
    perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_REVERSE;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)rk));
    CM_RETURN_IFERR(ddes_put_int32(req, type));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);

    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]reverse failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_reserve(const char *iof_dev, int64 rk, scsi_reserv_type_e type)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_reserve_impl(iof_dev, rk, type, &req, &ack);
}

status_t perctrl_release_impl(const char *iof_dev, int64 rk, scsi_reserv_type_e type,
    perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_RELEASE;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)rk));
    CM_RETURN_IFERR(ddes_put_int32(req, (uint32)type));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);

    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]release failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_release(const char *iof_dev, int64 rk, scsi_reserv_type_e type)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_release_impl(iof_dev, rk, type, &req, &ack);
}

status_t perctrl_clear_impl(const char *iof_dev, int64 rk, perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_CLEAR;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)rk));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));

    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]clear failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_clear(const char *iof_dev, int64 rk)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_clear_impl(iof_dev, rk, &req, &ack);
}

status_t perctrl_preempt_impl(const char *iof_dev, int64 rk, int64 sark, scsi_reserv_type_e type,
    perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_PREEMPT;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)rk));
    CM_RETURN_IFERR(ddes_put_int64(req, (uint64)sark));
    CM_RETURN_IFERR(ddes_put_int32(req, (uint32)type));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_RUN_ERR("[PERCTRL]preempt failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_preempt(const char *iof_dev, int64 rk, int64 sark, scsi_reserv_type_e type)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_preempt_impl(iof_dev, rk, sark, type, &req, &ack);
}

int32 perctrl_caw_impl(const char *scsi_dev, ctrl_params_t *params, uint64 block_addr, perctrl_packet_t *req,
    perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_CAW;
    text_t text;
    text.str = params->buff;
    text.len = (uint32)params->buff_len;
    CM_RETURN_IFERR(ddes_put_str(req, scsi_dev));
    CM_RETURN_IFERR(ddes_put_int64(req, block_addr));
    CM_RETURN_IFERR(ddes_put_text(req, &text));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);

    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]caw failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

int32 perctrl_scsi3_caw(const char *scsi_dev, uint64 block_addr, char *buff, int32 buff_len)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ctrl_params_t params = {0};
    params.buff = buff;
    params.buff_len = buff_len;
    return perctrl_caw_impl(scsi_dev, &params, block_addr, &req, &ack);
}

status_t perctrl_read_impl(ctrl_params_t *params, const char *iof_dev, perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_READ;
    text_t text;
    text.str = params->buff;
    text.len = (uint32)params->buff_len;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int32(req, (uint32)params->block_addr));
    CM_RETURN_IFERR(ddes_put_int32(req, params->block_count));
    CM_RETURN_IFERR(ddes_put_text(req, &text));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]read failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_read(const char *iof_dev, int32 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ctrl_params_t params = {0};
    params.block_addr = block_addr;
    params.block_count = block_count;
    params.buff = buff;
    params.buff_len = buff_len;
    return perctrl_read_impl(&params, iof_dev, &req, &ack);
}

status_t perctrl_write_impl(ctrl_params_t *params, const char *iof_dev, perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_WRITE;
    text_t text;
    text.str = params->buff;
    text.len = (uint32)params->buff_len;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(ddes_put_int32(req, (uint32)params->block_addr));
    CM_RETURN_IFERR(ddes_put_int32(req, params->block_count));
    CM_RETURN_IFERR(ddes_put_text(req, &text));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]write failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    return CM_SUCCESS;
}

status_t perctrl_scsi3_write(const char *iof_dev, int32 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ctrl_params_t params = {0};
    params.block_addr = block_addr;
    params.block_count = block_count;
    params.buff = buff;
    params.buff_len = buff_len;
    return perctrl_write_impl(&params, iof_dev, &req, &ack);
}

status_t perctrl_inql_impl(const char *iof_dev, inquiry_data_t *inquiry_data, perctrl_packet_t *req,
    perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_INQL;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]inql failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    text_t extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(inquiry_data_t)) {
        return CM_ERROR;
    }

    errcode = memcpy_sp((void *)inquiry_data, sizeof(inquiry_data_t), extra_info.str, sizeof(inquiry_data_t));
    MEMS_RETURN_IFERR(errcode);
    return CM_SUCCESS;
}

status_t perctrl_scsi3_inql(const char *iof_dev, inquiry_data_t *inquiry_data)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_inql_impl(iof_dev, inquiry_data, &req, &ack);
}

status_t perctrl_rkeys_impl(ctrl_params_t *params, const char *iof_dev, int64 *reg_keys, perctrl_packet_t *req,
    perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_RKEYS;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]rkeys failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    text_t extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (extra_info.len == 0 || extra_info.len > MAX_PACKET_LEN) {
        return CM_ERROR;
    }

    int64 *value_str = (int64 *)extra_info.str;
    for (uint32 i = 0; i < CM_MAX_RKEY_COUNT; i++) {
        reg_keys[i] = value_str[i];
    }

    extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(int32)) {
        return CM_ERROR;
    }
    params->key_count = *(int32 *)extra_info.str;

    extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(uint32)) {
        return CM_ERROR;
    }
    params->generation = *(uint32 *)extra_info.str;
    return CM_SUCCESS;
}

status_t perctrl_scsi3_rkeys(const char *iof_dev, int64 *reg_keys, int32 *key_count, uint32 *generation)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ctrl_params_t params = {0};
    ret = perctrl_rkeys_impl(&params, iof_dev, reg_keys, &req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    *key_count = params.key_count;
    *generation = params.generation;
    return CM_SUCCESS;
}

status_t perctrl_rres_impl(const char *iof_dev, int64 *rk, uint32 *generation, perctrl_packet_t *req,
    perctrl_packet_t *ack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    req->head->cmd = PERCTRL_CMD_RRES;
    CM_RETURN_IFERR(ddes_put_str(req, iof_dev));
    CM_RETURN_IFERR(exec_perctrl_cmd(req, ack));
    ddes_init_get(ack);
    if (ack->head->result != CM_SUCCESS) {
        (void)ddes_get_int32(ack, &errcode);
        (void)ddes_get_str(ack, &errmsg);
        CM_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("[PERCTRL]rres failed, result:%d, %s.", ack->head->result, errmsg);
        return ack->head->result;
    }

    text_t extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(int64)) {
        return CM_ERROR;
    }
    *rk = *(int64 *)extra_info.str;

    extra_info = CM_NULL_TEXT;
    if (ddes_get_text(ack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(uint32)) {
        return CM_ERROR;
    }
    *generation = *(uint32 *)extra_info.str;

    return CM_SUCCESS;
}

status_t perctrl_scsi3_rres(const char *iof_dev, int64 *rk, uint32 *generation)
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};
    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return perctrl_rres_impl(iof_dev, rk, generation, &req, &ack);
}

#ifdef __cplusplus
}
#endif

