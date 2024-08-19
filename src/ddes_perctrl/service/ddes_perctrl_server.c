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
 * ddes_perctrl_server.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/service/ddes_perctrl_server.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_signal.h"
#include "cm_timer.h"
#include "ddes_perctrl_server.h"

#include <sys/ioctl.h>
#include "cm_utils/protocol/cm_nvme.h"

static int req_fd = 0;
static int ack_fd = 0;

#define PERCTRL_ALIGN_SIZE (uint32)512
#define PERCTRL_ARG_COUNT_1 1
#define PERCTRL_ARG_COUNT_2 2
#define PERCTRL_ARG_COUNT_3 3

#define PERCTRL_IO_PROTOCOL_SCSI3 0
#define PERCTRL_IO_PROTOCOL_NVME 1
#ifndef WIN32
static status_t ddes_open_scsi_dev(const char *scsi_dev, int32 *fd)
{
    if (scsi_dev == NULL) {
        return CM_ERROR;
    }
    *fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (*fd < 0) {
        LOG_DEBUG_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int32 ddes_open_iof_dev(const char *iof_dev, int32 *fd)
{
    if (iof_dev == NULL) {
        return CM_ERROR;
    }

    *fd = open(iof_dev, O_RDWR);
    if (*fd < 0) {
        LOG_DEBUG_ERR("Open dev %s failed, errno %d.", iof_dev, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void ddes_return_error(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 code;
    const char *message = NULL;

    ack->head->cmd = req->head->cmd;
    ack->head->result = (uint8)CM_ERROR;
    cm_get_error(&code, &message);

    (void)ddes_put_int32(ack, (uint32)code);
    (void)ddes_put_str(ack, message);
    cm_reset_error();
}

static void ddes_return_success(perctrl_packet_t *req, perctrl_packet_t *ack, int32 ret)
{
    ack->head->cmd = req->head->cmd;
    ack->head->result = ret;
}

int32 exec_scsi3_register(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 sark;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &sark));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    int32 ret = cm_scsi3_register(fd, sark);
    LOG_RUN_INF("Exec register ret %d, iof_dev: %s, sark: %lld, fd: %d.", ret, iof_dev, sark, fd);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_unregister(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    int32 ret = cm_scsi3_unregister(fd, rk);
    LOG_RUN_INF("Exec unregister ret %d, iof_dev: %s, rk: %lld, fd: %d.", ret, iof_dev, rk, fd);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_reserve(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd, type;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_get_int32(req, &type));

    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_reserve(fd, rk, type);
    LOG_RUN_INF("Exec reserve ret %d, iof_dev: %s, rk: %lld, fd: %d.", ret, iof_dev, rk, fd);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_release(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd, type;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_get_int32(req, &type));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_release(fd, rk, type);
    LOG_RUN_INF("Exec release ret %d, iof_dev: %s, rk: %lld, fd: %d.", ret, iof_dev, rk, fd);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_clear(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_clear(fd, rk);
    (void)close(fd);
    LOG_RUN_INF("Exec clear ret %d.", ret);
    return ret;
}

int32 exec_scsi3_preempt(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd, type;
    int64 rk;
    int64 sark;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_get_int64(req, &sark));
    CM_RETURN_IFERR(ddes_get_int32(req, &type));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_preempt(fd, rk, sark, type);
    LOG_RUN_INF("Exec preempt ret %d, iof_dev: %s, rk: %lld, sark: %lld, fd: %d,.", ret, iof_dev, rk, sark, fd);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_caw(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    uint64 block_addr;
    text_t text = CM_NULL_TEXT;
    char *scsi_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &scsi_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, (int64 *)&block_addr));
    CM_RETURN_IFERR(ddes_get_text(req, &text));

    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }
    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    int32 ret = ddes_open_scsi_dev(scsi_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_scsi3_caw(fd, block_addr, buff, (int32)text.len);
    LOG_DEBUG_INF("Exec caw ret %d.", ret);
    free(buff);
    (void)close(fd);
    return ret;
}

int32 exec_scsi3_read(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd, block_addr;
    uint16 block_count;
    text_t text = CM_NULL_TEXT;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int32(req, &block_addr));
    CM_RETURN_IFERR(ddes_get_int32(req, (int32 *)&block_count));
    CM_RETURN_IFERR(ddes_get_text(req, &text));
    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }

    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    status_t ret = ddes_open_scsi_dev(iof_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_scsi3_read(fd, block_addr, block_count, buff, (int32)text.len);
    free(buff);
    (void)close(fd);
    LOG_DEBUG_INF("Exec read ret %d.", ret);
    return ret;
}

int32 exec_scsi3_write(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int32 block_addr;
    uint16 block_count;
    text_t text = CM_NULL_TEXT;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int32(req, &block_addr));
    CM_RETURN_IFERR(ddes_get_int32(req, (int32 *)&block_count));
    CM_RETURN_IFERR(ddes_get_text(req, &text));
    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }

    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    status_t ret = ddes_open_scsi_dev(iof_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_scsi3_write(fd, block_addr, block_count, buff, (int32)text.len);
    free(buff);
    (void)close(fd);
    LOG_DEBUG_INF("Exec write ret %d.", ret);
    return ret;
}

int32 exec_scsi3_inql(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    inquiry_data_t inquiry_data;
    errno_t errcode = memset_sp(&inquiry_data, sizeof(inquiry_data), 0, sizeof(inquiry_data));
    securec_check_ret(errcode);
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_inql(fd, &inquiry_data);
    LOG_DEBUG_INF("Exec inql ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    errcode = memcpy_sp(text.str, MAX_PACKET_LEN, (char *)&inquiry_data, sizeof(inquiry_data_t));
    MEMS_RETURN_IFERR(errcode);
    text.len = sizeof(inquiry_data_t);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}

int32 exec_scsi3_rkeys(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int32 key_count = (int32)CM_MAX_RKEY_COUNT;
    uint32 generation;
    int64 reg_keys[CM_MAX_RKEY_COUNT] = {0};
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_rkeys(fd, reg_keys, &key_count, &generation);
    LOG_DEBUG_INF("Exec rkeys ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    errno_t errcode = memcpy_sp(text.str, sizeof(reg_keys), (char *)reg_keys, sizeof(reg_keys));
    MEMS_RETURN_IFERR(errcode);
    text.len = sizeof(reg_keys);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(int32 *)text.str = key_count;
    text.len = sizeof(int32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(uint32 *)text.str = generation;
    text.len = sizeof(uint32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}

int32 exec_scsi3_rres(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk = 0;
    uint32 generation;
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_scsi3_rres(fd, &rk, &generation);
    LOG_DEBUG_INF("Exec rres ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    *(int64 *)text.str = rk;
    text.len = sizeof(int64);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(uint32 *)text.str = generation;
    text.len = sizeof(uint32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}


int32 exec_nvme_register(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 sark;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &sark));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    int32 ret = cm_nvme_register(fd, sark);
    LOG_DEBUG_INF("Exec nvme register ret %d.", ret);
    (void)close(fd);
    return ret;
}

int32 exec_nvme_unregister(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    int32 ret = cm_nvme_unregister(fd, rk);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme unregister ret %d.", ret);
    return ret;
}

int32 exec_nvme_reserve(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_reserve(fd, rk);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme reserve ret %d.", ret);
    return ret;
}

int32 exec_nvme_release(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_release(fd, rk);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme release ret %d.", ret);
    return ret;
}

int32 exec_nvme_clear(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_clear(fd, rk);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme clear ret %d.", ret);
    return ret;
}

int32 exec_nvme_preempt(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk, sark;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, &rk));
    CM_RETURN_IFERR(ddes_get_int64(req, &sark));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_preempt(fd, rk, sark);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme preempt ret %d.", ret);
    return ret;
}

int32 exec_nvme_caw(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    uint64 block_addr;
    text_t text = CM_NULL_TEXT;
    char *scsi_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &scsi_dev));
    CM_RETURN_IFERR(ddes_get_int64(req, (int64 *)&block_addr));
    CM_RETURN_IFERR(ddes_get_text(req, &text));

    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }
    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    int32 ret = ddes_open_scsi_dev(scsi_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_nvme_caw(fd, block_addr, 2, buff, (int32)text.len);
    LOG_DEBUG_INF("Exec nvme caw ret %d.", ret);
    free(buff);
    (void)close(fd);
    return ret;
}

int32 exec_nvme_read(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int32 block_addr;
    uint16 block_count;
    text_t text = CM_NULL_TEXT;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int32(req, &block_addr));
    CM_RETURN_IFERR(ddes_get_int32(req, (int32 *)&block_count));
    CM_RETURN_IFERR(ddes_get_text(req, &text));
    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }

    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    status_t ret = ddes_open_scsi_dev(iof_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_nvme_read(fd, block_addr, block_count, buff, (int32)text.len);
    free(buff);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme read ret %d.", ret);
    return ret;
}

int32 exec_nvme_write(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd, block_addr;
    uint16 block_count;
    text_t text = CM_NULL_TEXT;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_get_int32(req, &block_addr));
    CM_RETURN_IFERR(ddes_get_int32(req, (int32 *)&block_count));
    CM_RETURN_IFERR(ddes_get_text(req, &text));
    char *buff = (char *)ddes_malloc_align(PERCTRL_ALIGN_SIZE, text.len);
    if (buff == NULL) {
        LOG_DEBUG_ERR("Failed to alloc memory.");
        return CM_ERROR;
    }

    errno_t errcode = memcpy_sp(buff, text.len, text.str, text.len);
    if (errcode != EOK) {
        free(buff);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    status_t ret = ddes_open_scsi_dev(iof_dev, &fd);
    if (ret != CM_SUCCESS) {
        free(buff);
        return CM_ERROR;
    }
    ret = cm_nvme_write(fd, block_addr, block_count, buff, (int32)text.len);
    free(buff);
    (void)close(fd);
    LOG_DEBUG_INF("Exec nvme write ret %d.", ret);
    return ret;
}

int32 exec_nvme_inql(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    inquiry_data_t inquiry_data;
    errno_t errcode = memset_sp(&inquiry_data, sizeof(inquiry_data), 0, sizeof(inquiry_data));
    securec_check_ret(errcode);
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_inql(fd, &inquiry_data);
    LOG_DEBUG_INF("Exec nvme inql ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    errcode = memcpy_sp(text.str, MAX_PACKET_LEN, (char *)&inquiry_data, sizeof(inquiry_data_t));
    MEMS_RETURN_IFERR(errcode);
    text.len = sizeof(inquiry_data_t);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}

int32 exec_nvme_rkeys(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int32 key_count = (int32)CM_MAX_RKEY_COUNT;
    uint32 generation;
    int64 reg_keys[CM_MAX_RKEY_COUNT] = {0};
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_rkeys(fd, reg_keys, &key_count, &generation);
    LOG_DEBUG_INF("Exec nvme rkeys ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    errno_t errcode = memcpy_sp(text.str, sizeof(reg_keys), (char *)reg_keys, sizeof(reg_keys));
    MEMS_RETURN_IFERR(errcode);
    text.len = sizeof(reg_keys);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(int32 *)text.str = key_count;
    text.len = sizeof(int32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(uint32 *)text.str = generation;
    text.len = sizeof(uint32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}

int32 exec_nvme_rres(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 fd;
    int64 rk = 0;
    uint32 generation;
    text_t text;
    char buff[MAX_PACKET_LEN] = {0};
    text.str = buff;
    char *iof_dev = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    CM_RETURN_IFERR(ddes_open_iof_dev(iof_dev, &fd));
    status_t ret = cm_nvme_rres(fd, &rk, &generation);
    LOG_DEBUG_INF("Exec nvme rres ret %d.", ret);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
    *(int64 *)text.str = rk;
    text.len = sizeof(int64);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));

    *(uint32 *)text.str = generation;
    text.len = sizeof(uint32);
    CM_RETURN_IFERR(ddes_put_text(ack, &text));
    return CM_SUCCESS;
}

status_t perctrl_init_loggers(cm_log_def_t *log_def, uint32 log_def_count, char *name)
{
    log_param_t *log_param = cm_log_param_instance();
    char file_name[CM_MAX_PATH_LEN];
    uint32 len = CM_MAX_PATH_LEN;
    int32 ret;
    status_t status;
    g_high_frequency_restrt_process = CM_TRUE;
    for (size_t i = 0; i < log_def_count; i++) {
        ret = snprintf_s(file_name, len, (len - 1), "%s/%s", log_param->log_home, log_def[i].log_filename);
        if (ret == -1) {
            CM_RETURN_IFERR_EX(CM_ERROR, (void)printf("Failed to copy, log_home:%s, filename:%s.\n",
                log_param->log_home, log_def[i].log_filename));
        }
        status = cm_log_init(log_def[i].log_id, file_name);
        CM_RETURN_IFERR_EX(status, (void)printf("Failed to init %u log def.\n", (uint32)i));
        cm_log_open_compress(log_def[i].log_id, CM_TRUE);
    }
    log_param->log_instance_startup = CM_TRUE;
    cm_init_error_handler(cm_set_log_error);
    status = cm_set_log_module_name(name, (int32)strlen(name));
    CM_RETURN_IFERR_EX(status, (void)printf("Failed to set module name %s.\n", name));
    errno_t rc = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, name);
    if (rc != EOK) {
        (void)printf("Failed to copy instance_name %s.\n", name);
        return CM_ERROR;
    }
    if (log_param->log_compressed) {
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            (void)printf("Failed to alloc log_compress_buf.\n");
            return CM_ERROR; 
        }
    }

    return CM_SUCCESS;
}

status_t perctrl_parse_param_inner(perctrl_log_param_id_t id, char *buf)
{
    log_param_t *log_param = cm_log_param_instance();
    status_t status = CM_SUCCESS;
    errno_t errcode = EOK;
    switch (id) {
        case PERCTRL_PARAM_LOG_HOME:
            errcode = memcpy_s(log_param->log_home, CM_MAX_LOG_HOME_LEN, buf, strlen(buf));
            if (errcode != EOK) {
                (void)printf("The value of log_home is invalid.\n");
                return CM_ERROR;
            }
            break;
        case PERCTRL_PARAM_LOG_LEVEL:
            status = cm_str2uint32(buf, (uint32 *)&log_param->log_level);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_level is invalid.\n"));
            break;
        case PERCTRL_PARAM_LOG_BACK_FILE_COUNT:
            status = cm_str2uint32(buf, (uint32 *)&log_param->log_backup_file_count);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_backup_file_count is invalid.\n"));
            break;
        case PERCTRL_PARAM_MAX_LOG_FILE_SIZE:
            status = cm_str2bigint(buf, (int64 *)&log_param->max_log_file_size);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of max_log_file_size is invalid.\n"));
            break;
        case PERCTRL_PARAM_LOG_FILE_PERMISS:
            status = cm_str2uint32(buf, (uint32 *)&log_param->log_file_permissions);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_file_permissions is invalid.\n"));
            break;
        case PERCTRL_PARAM_LOG_PATH_PERMISS:
            status = cm_str2uint32(buf, (uint32 *)&log_param->log_path_permissions);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_path_permissions is invalid.\n"));
            break;
        case PERCTRL_PARAM_LOG_BAK_FILE_PERMISS:
            status = cm_str2uint32(buf, (uint32 *)&log_param->log_bak_file_permissions);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_bak_file_permissions is invalid.\n"));
            break;
        case PERCTRL_PARAM_LOG_COMPRESSED:
            status = cm_str2uint16(buf, (uint16 *)&log_param->log_compressed);
            CM_RETURN_IFERR_EX(status, (void)printf("The value of log_compressed is invalid.\n"));
            break;
    default:
        (void)printf("Invalid perctrl id %u.\n", id);
        status = CM_ERROR;
        break;
    }
    return status;
}

status_t perctrl_parse_args(char *buf)
{
    char *next_info = NULL;
    char *key = strtok_s(buf, "=", &next_info);
    char *value = NULL;
    if (key != NULL) {
        value = strtok_s(NULL, "=", &next_info);
    }
    if (value == NULL) {
        (void)printf("Failed to split buf %s.\n", buf);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < sizeof(g_perctrl_log_param) / sizeof(perctrl_log_param_set_t); i++) {
        if (strcmp(g_perctrl_log_param[i].name, key) == 0) {
            return perctrl_parse_param_inner(g_perctrl_log_param[i].id, value);
        }
    }
    (void)printf("Invalid perctrl argument %s.\n", key);
    return CM_ERROR;
}

int32 exec_init_logger(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    char *buf = NULL;
    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &buf));
    status_t status = cm_start_timer(g_timer());
    CM_RETURN_IFERR_EX(status, (void)printf("Perctrl aborted due to starting timer thread.\n"));
    char *next_info = NULL;
    uint32 i = 0;
    char *temp = strtok_s(buf, "|", &next_info);
    while (temp != NULL) {
        CM_RETURN_IFERR(perctrl_parse_args(temp));
        temp = strtok_s(NULL, "|", &next_info);
        i++;
    }
    if (i != PERCTRL_PARAM_LOG_TOTAL_CNT) {
        (void)printf("Invalid split parameters count:%u.\n", i);
        (void)printf("except <log_home=value0|log_level=value1|log_backup_file_count=value2|max_log_file_size=value3|log_file_permissions=value4|log_path_permissions=value5"
        "|log_bak_file_permissions=value6|log_compressed=value7>\n");
        return CM_ERROR;
    }
    status = perctrl_init_loggers(g_perctrl_log, sizeof(g_perctrl_log) / sizeof(cm_log_def_t), "perctrl");
    CM_RETURN_IFERR_EX(status, (void)printf("Failed to init loggers.\n"));
    return status;   
}

static perctrl_cmd_hdl_t g_perctrl_cmd_handle[] = {
    { PERCTRL_CMD_REGISTER, { exec_scsi3_register, exec_nvme_register } },
    { PERCTRL_CMD_UNREGISTER, { exec_scsi3_unregister, exec_nvme_unregister } },
    { PERCTRL_CMD_REVERSE, { exec_scsi3_reserve, exec_nvme_reserve } },
    { PERCTRL_CMD_RELEASE, { exec_scsi3_release, exec_nvme_release } },
    { PERCTRL_CMD_CLEAR, { exec_scsi3_clear, exec_nvme_clear } },
    { PERCTRL_CMD_PREEMPT, { exec_scsi3_preempt, exec_nvme_preempt } },
    { PERCTRL_CMD_CAW, { exec_scsi3_caw, exec_nvme_caw } },
    { PERCTRL_CMD_READ, { exec_scsi3_read, exec_nvme_read } },
    { PERCTRL_CMD_WRITE, { exec_scsi3_write, exec_nvme_write } },
    { PERCTRL_CMD_INQL, { exec_scsi3_inql, exec_nvme_inql } },
    { PERCTRL_CMD_RKEYS, { exec_scsi3_rkeys, exec_nvme_rkeys } },
    { PERCTRL_CMD_RRES, { exec_scsi3_rres, exec_nvme_rres } },
    { PERCTRL_CMD_INIT_LOG, { exec_init_logger, exec_init_logger } }
};

static perctrl_cmd_hdl_t *get_cmd_handle(int32 cmd)
{
    int32 mid_pos = 0;
    int32 begin_pos = 0;
    int32 end_pos = ARRAY_NUM(g_perctrl_cmd_handle) - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        if (cmd == (int32)g_perctrl_cmd_handle[mid_pos].cmd) {
            return &g_perctrl_cmd_handle[mid_pos];
        } else if (cmd < (int32)g_perctrl_cmd_handle[mid_pos].cmd) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return NULL;
}

static int32 get_io_protocol(char *iof_dev)
{
    int32 fd;
    int32 nsid;
    int io_protocol = PERCTRL_IO_PROTOCOL_SCSI3;

    if (ddes_open_iof_dev(iof_dev, &fd) != CM_SUCCESS) {
        return io_protocol;
    }

    nsid = ioctl(fd, NVME_IOCTL_ID);
    if (nsid == -1) {
        LOG_DEBUG_INF("ioctl get nsid error : %s", strerror(errno));
        io_protocol = PERCTRL_IO_PROTOCOL_SCSI3;
    } else {
        io_protocol = PERCTRL_IO_PROTOCOL_NVME;
    }

    (void)close(fd);

    return io_protocol;
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static status_t exec_perctrl_req(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    int32 status = CM_ERROR;
    char *iof_dev = NULL;
    int io_protocol = PERCTRL_IO_PROTOCOL_SCSI3;

    req->head = (perctrl_cmd_head_t *)req->buf;
    int32 cmd = (int32)req->head->cmd;
    LOG_DEBUG_INF("Receive command : %d", cmd);
    if (cmd == PERCTRL_CMD_EXIT) {
        CM_FREE_PTR(cm_log_param_instance()->log_compress_buf);
        exit(1);
    }

    perctrl_cmd_hdl_t *handle = get_cmd_handle(cmd);
    if ((handle == NULL) || (handle->exec == NULL)) {
        LOG_DEBUG_ERR("The req command: %d is not valid.", cmd);
        ddes_return_error(req, ack);
        return CM_ERROR;
    }

    ddes_init_get(req);
    CM_RETURN_IFERR(ddes_get_str(req, &iof_dev));
    io_protocol = get_io_protocol(iof_dev);

    status = handle->exec[io_protocol](req, ack);
    if (status == CM_ERROR) {
        LOG_DEBUG_ERR("Failed to execute command: %d, status: %d.", cmd, status);
        ddes_return_error(req, ack);
        return CM_ERROR;
    }

    ddes_return_success(req, ack, status);
    return CM_SUCCESS;
}

static inline void reset_req_ack(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    req->head->size = 0;
    req->head->cmd = 0;
    ack->head->size = (uint32)sizeof(perctrl_cmd_head_t);
    ack->head->cmd = 0;
}

static int32 perctrl_proc()
{
    perctrl_packet_t req = {0};
    perctrl_packet_t ack = {0};

    status_t ret = init_req_and_ack(&req, &ack);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    for (;;) {
        reset_req_ack(&req, &ack);
        ret = perctrl_receive(req_fd, &req);
        if (ret == CM_PIPECLOSED) {
            LOG_RUN_INF("Pipe closed, perctrl exit.");
            exit(1);
        }
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to read from std input.");
            continue;
        }
        ret = exec_perctrl_req(&req, &ack);
        if (ret == CM_ERROR) {
            LOG_DEBUG_ERR("Failed to exec perctrl req.");
        }

        ret = perctrl_send(ack_fd, &ack);
        if (ret == CM_ERROR) {
            LOG_DEBUG_ERR("Failed to write to std output.");
            continue;
        }
    }
    return ret;
}
#endif

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the perctrl "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
    if (cm_regist_signal(SIGPIPE, SIG_IGN) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (argc != PERCTRL_ARG_COUNT_3) {
        (void)printf("Invalid parameters count:%d.\n", argc);
        (void)printf("perctrl <req_fd> <ack_fd>\n");
        return CM_ERROR;
    }
    req_fd = atoi(argv[PERCTRL_ARG_COUNT_1]);
    ack_fd = atoi(argv[PERCTRL_ARG_COUNT_2]);
    return perctrl_proc();
#else
    return CM_SUCCESS;
#endif
}

