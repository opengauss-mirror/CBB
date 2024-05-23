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
#include "cm_log.h"
#include "cm_iofence.h"

#define CM_OUT_SCSI_RK(reg) ((reg)->rk + 1)
#define CM_OUT_SCSI_SARK(reg) ((reg)->rk_kick + 1)

int32 cm_iof_register(iof_reg_out_t *iof_out)
{
#ifdef WIN32
#else
    int32 ret;
    if (iof_out == NULL) {
        return CM_ERROR;
    }
    ret = perctrl_scsi3_register(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
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
    ret = perctrl_scsi3_reserve(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
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

    ret = perctrl_scsi3_unregister(iof_out->dev, CM_OUT_SCSI_RK(iof_out));
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
    status = perctrl_scsi3_preempt(iof_out->dev, CM_OUT_SCSI_RK(iof_out), CM_OUT_SCSI_SARK(iof_out));
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
