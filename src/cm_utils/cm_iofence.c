/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
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
#include "cm_log.h"
#include "cm_iofence.h"

#define CM_OUT_SCSI_RK(reg) ((reg)->rk + 1)
#define CM_OUT_SCSI_SARK(reg) ((reg)->rk_kick + 1)

static int32 cm_iof_open_out(iof_reg_out_t *iof_out, int32 *fd)
{
#ifdef WIN32
#else
    if (iof_out == NULL || iof_out->dev == NULL) {
        return CM_ERROR;
    }

    *fd = open(iof_out->dev, O_RDWR);
    if (*fd < 0) {
        LOG_DEBUG_ERR("Open dev %s failed, errno %d.", iof_out->dev, errno);
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

static int32 cm_iof_open_in(iof_reg_in_t *iof_in, int32 *fd)
{
#ifdef WIN32
#else
    if (iof_in == NULL || iof_in->dev == NULL) {
        return CM_ERROR;
    }

    *fd = open(iof_in->dev, O_RDWR);
    if (*fd < 0) {
        LOG_DEBUG_ERR("Open dev %s failed, errno %d.", iof_in->dev, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

int32 cm_iof_register(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    int32 fd = 0;
    int32 ret;

    CM_RETURN_IFERR(cm_iof_open_out(iof_out, &fd));
    ret = cm_scsi3_register(fd, CM_OUT_SCSI_RK(iof_out));
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_CONFLICT == ret) {
            LOG_DEBUG_INF("Scsi3 register conflict, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
            close(fd);
            return CM_IOF_ERR_DUP_OP;
        } else {
            LOG_DEBUG_ERR("Scsi3 register failed, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
            close(fd);
            return CM_ERROR;
        }
    }

    // Any host can perform reservation operations, but at least one host must perform
    ret = cm_scsi3_reserve(fd, CM_OUT_SCSI_RK(iof_out));
    if (CM_SUCCESS != ret) {
        LOG_DEBUG_ERR("Scsi3 reserve failed, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
        close(fd);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence register succ, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);

    close(fd);
#endif
    return CM_SUCCESS;
}

int32 cm_iof_unregister(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    int32 ret;
    int32 fd = 0;

    CM_RETURN_IFERR(cm_iof_open_out(iof_out, &fd));
    ret = cm_scsi3_unregister(fd, CM_OUT_SCSI_RK(iof_out));
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_CONFLICT == ret) {
            LOG_DEBUG_INF("Scsi3 unregister conflict, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
            close(fd);
            return CM_IOF_ERR_DUP_OP;
        } else {
            LOG_DEBUG_ERR("Scsi3 unregister failed, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
            close(fd);
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("IOfence unregister succ, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);

    close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_iof_kick(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    status_t status;
    int32 fd = 0;

    CM_RETURN_IFERR(cm_iof_open_out(iof_out, &fd));
    status = cm_scsi3_preempt(fd, CM_OUT_SCSI_RK(iof_out), CM_OUT_SCSI_SARK(iof_out));
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Scsi3 preempt failed, rk %lld, rk_kick %lld, dev %s.", CM_OUT_SCSI_RK(iof_out),
            CM_OUT_SCSI_SARK(iof_out), iof_out->dev);
        close(fd);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence kick succ, rk %lld, rk_kick %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), CM_OUT_SCSI_SARK(iof_out),
        iof_out->dev);
    close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_iof_clear(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    status_t status;
    int32 fd = 0;

    CM_RETURN_IFERR(cm_iof_open_out(iof_out, &fd));
    status = cm_scsi3_clear(fd, CM_OUT_SCSI_RK(iof_out));
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Scsi3 clear failed, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);
        close(fd);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence clear succ, rk %lld, dev %s.", CM_OUT_SCSI_RK(iof_out), iof_out->dev);

    close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_iof_inql(iof_reg_in_t *iof_in)
{
#ifdef WIN32
#else
    status_t status;
    int32 fd = 0;

    CM_RETURN_IFERR(cm_iof_open_in(iof_in, &fd));
    iof_in->key_count = CM_MAX_RKEY_COUNT;
    status = cm_scsi3_rkeys(fd, iof_in->reg_keys, &iof_in->key_count, &iof_in->generation);
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Scsi3 inql rkeys failed, dev %s.", iof_in->dev);
        close(fd);
        return CM_ERROR;
    }

    status = cm_scsi3_rres(fd, &iof_in->resk, &iof_in->generation);
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Scsi3 inql rres failed, dev %s.", iof_in->dev);
        close(fd);
        return CM_ERROR;
    }
    LOG_RUN_INF("IOfence inql succ, dev %s.", iof_in->dev);

    close(fd);
#endif
    return CM_SUCCESS;
}
