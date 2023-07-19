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
 * cm_scsi.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_scsi.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_scsi.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_binary.h"
#ifdef WIN32
#else
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif

#ifdef WIN32
 // read register keys
status_t cm_scsi3_rkeys(int32 fd, int64 *reg_keys, int32 *key_count, uint32 *generation)
{
    return CM_SUCCESS;
}
#else

#define CM_SCSI_NUM_2 (2)

uint64 ntohll(uint64 val)
{
    if (!IS_BIG_ENDIAN) {
        return (((uint64)ntohl((uint32)((val << UINT32_BITS) >> UINT32_BITS))) << UINT32_BITS) |
            (uint32)ntohl((uint32)(val >> UINT32_BITS));
    } else {
        return val;
    }
}

uint64 htonll(uint64 val)
{
    if (!IS_BIG_ENDIAN) {
        return (((uint64)htonl((uint32)((val << UINT32_BITS) >> UINT32_BITS))) << UINT32_BITS) |
             (uint32)htonl((uint32)(val >> UINT32_BITS));
    } else {
        return val;
    }
}

void cm_set_xfer_data(struct sg_io_hdr *p_hdr, void *data, uint32 length)
{
    if (p_hdr) {
        p_hdr->dxferp = data;
        p_hdr->dxfer_len = length;
    }
}

void cm_set_sense_data(struct sg_io_hdr *p_hdr, uchar *data, uint32 length)
{
    if (p_hdr) {
        p_hdr->sbp = data;
        p_hdr->mx_sb_len = (uchar)length;
    }
}

// get scsi result category
int32 cm_get_scsi_result(const sg_io_hdr_t *p_hdr)
{
    // errors from software driver
    int32 driver_status = p_hdr->driver_status & CM_DRIVER_MASK;
    // scsi status
    int32 status = p_hdr->status & 0x7e;
    // errors from host adapte
    int32 host_status = p_hdr->host_status;

    if (host_status) {
        return CM_SCSI_RESULT_TRANSPORT_ERR;
    } else if (driver_status && (driver_status != CM_DRIVER_SENSE)) {
        return CM_SCSI_RESULT_TRANSPORT_ERR;
    } else if (driver_status == CM_DRIVER_SENSE || status == SAM_COMMAND_TERMINATED || status == SAM_CHECK_CONDITION) {
        return CM_SCSI_RESULT_SENSE;
    } else if (status) {
        return CM_SCSI_RESULT_STATUS;
    } else {
        return CM_SCSI_RESULT_GOOD;
    }
}

// normalize scsi sense descriptor
bool32 cm_get_scsi_sense_des(scsi_sense_hdr_t *ssh, const uchar *sbp, int32 sbp_len)
{
    errno_t errcode;
    uchar resp_code;

    errcode = memset_sp(ssh, sizeof(scsi_sense_hdr_t), 0, sizeof(scsi_sense_hdr_t));
    if (errcode != EOK) {
        return CM_FALSE;
    }

    if (sbp == NULL || sbp_len < 1) {
        return CM_FALSE;
    }

    resp_code = 0x7f & sbp[0];
    if (resp_code < 0x70 || resp_code > 0x73) {
        LOG_DEBUG_ERR("Invalid response code %d", resp_code);
        return CM_FALSE;
    }

    ssh->response_code = resp_code;
    if (ssh->response_code >= 0x72) {
        if (sbp_len > 1) {
            ssh->sense_key = (0xf & sbp[1]);
        }

        if (sbp_len > 2) {
            ssh->asc = sbp[2];
        }

        if (sbp_len > 3) {
            ssh->ascq = sbp[3];
        }

        if (sbp_len > 7) {
            ssh->add_length = sbp[7];
        }
    } else {
        if (sbp_len > 2) {
            ssh->sense_key = (0xf & sbp[2]);
        }

        if (sbp_len > 7) {
            sbp_len = (sbp_len < (sbp[7] + 8)) ? sbp_len : (sbp[7] + 8);
            if (sbp_len > 12) {
                ssh->asc = sbp[12];
            }
            if (sbp_len > 13) {
                ssh->ascq = sbp[13];
            }
        }
    }

    return CM_TRUE;
}

// scsi2 reserve(6)/release(6)
status_t cm_scsi2_reserve(int32 fd)
{
    uchar cdb[6] = {0};
    int32 status;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);

    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cdb[0] = 0x16;
    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 6;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI2 reserve command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI2 reserve failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi2_release(int32 fd)
{
    uchar cdb[6] = {0};
    int32 status;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);

    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cdb[0] = 0x17;
    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 6;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI2 release command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI2 release failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// scsi3 register/reserve/release/clear/preempt
int32 cm_scsi3_register(int32 fd, int64 sark)
{
    uchar cdb[10] = { 0 };
    int32 scope = 0;
    uint32 type = 0;
    int32 servact = 0x00;
    uint16 param_len = 24;
    int64 rk = 0;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = { 0 };
    uchar data_buffer[CM_SCSI_XFER_DATA] = { 0 };
    int32 status = 0;
    uint64 tmp = 0;
    sg_io_hdr_t hdr;
    errno_t errcode = EOK;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (uchar)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    // set reservation key, service action reservation key
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &rk, sizeof(int64));
    securec_check_ret(errcode);
    tmp = (int64)htonll(sark);
    errcode = memcpy_sp(hdr.dxferp + 8, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI register command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        if (hdr.status == SAM_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("SCSI register get reservation confict return, sark %lld.", sark);
            return CM_SCSI_ERR_CONFLICT;
        } else {
            LOG_DEBUG_ERR("SCSI register failed, status %d.", hdr.status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int32 cm_scsi3_unregister(int32 fd, int64 rk)
{
    uchar cdb[10] = { 0 };
    int32 scope = 0;
    uint32 type = 0;
    int32 servact = 0x00;
    uint16 param_len = 24;
    int64 sark = 0;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = { 0 };
    uchar data_buffer[CM_SCSI_XFER_DATA] = { 0 };
    int32 status = 0;
    int64 tmp = 0;
    sg_io_hdr_t hdr;
    errno_t errcode = EOK;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (uchar)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    tmp = (int64)htonll(rk);
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);
    errcode = memcpy_sp(hdr.dxferp + 8, sizeof(int64), &sark, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI unregister command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        if (hdr.status == SAM_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("SCSI unregister get reservation confict return, rk %lld.", rk);
            return CM_SCSI_ERR_CONFLICT;
        } else {
            LOG_DEBUG_ERR("SCSI unregister failed, status %d.", hdr.status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_reserve(int32 fd, int64 rk)
{
    uchar cdb[10] = { 0 };
    int32 scope = 0;
    uint32 type = 0x06;
    int32 servact = 0x01;
    uint16 param_len = 24;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = { 0 };
    uchar data_buffer[CM_SCSI_XFER_DATA] = { 0 };
    int32 status = 0;
    int64 tmp = 0;
    sg_io_hdr_t hdr;
    errno_t errcode = EOK;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (uchar)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    tmp = (int64)htonll(rk);
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI reserve command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        if (hdr.status == SAM_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("SCSI reserve get confict return, rk %lld.", rk);
        } else {
            LOG_DEBUG_ERR("SCSI reserve failed, status %d.", hdr.status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_release(int32 fd, int64 rk)
{
    uchar cdb[10] = { 0 };
    int32 scope = 0;
    uint32 type = 0x06;
    int32 servact = 0x02;
    uint16 param_len = 24;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = { 0 };
    uchar data_buffer[CM_SCSI_XFER_DATA] = { 0 };
    int32 status = 0;
    int64 tmp = 0;
    sg_io_hdr_t hdr;
    errno_t errcode = EOK;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (uchar)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    tmp = (int64)htonll(rk);
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI release command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI release failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_clear(int32 fd, int64 rk)
{
    uchar cdb[10] = { 0 };
    int32 scope = 0;
    uint32 type = 0;
    int32 servact = 0x03;
    uint16 param_len = 24;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = { 0 };
    uchar data_buffer[CM_SCSI_XFER_DATA] = { 0 };
    int32 status = 0;
    int64 tmp = 0;
    sg_io_hdr_t hdr;
    errno_t errcode = EOK;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (uchar)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    tmp = (int64)htonll(rk);
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI clear command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI clear failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_preempt(int32 fd, int64 rk, int64 sark)
{
    uchar cdb[10] = {0};
    uint32 scope = 0;
    uint32 type = 0x06;
    uint32 servact = 0x04;
    uint16 param_len = 24;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    int32 status;
    int64 tmp;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5F;
    cdb[1] = (unsigned char)(servact & 0x1f);
    cdb[2] = (((scope & 0xf) << 4) | (type & 0xf));
    param_len = htons(param_len);
    errcode = memcpy_sp(cdb + 7, sizeof(param_len), &param_len, sizeof(param_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;
    tmp = (int64)htonll((uint64)rk);
    errcode = memcpy_sp(hdr.dxferp, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);
    tmp = (int64)htonll((uint64)sark);
    errcode = memcpy_sp(hdr.dxferp + 8, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI preempt command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI preempt failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// scsi3 vaai compare and write, just support 1 block now
int32 cm_scsi3_caw(int32 fd, uint64 block_addr, char *buff, int32 buff_len)
{
    uchar cdb[16] = {0};
    uint32 blocks = 1;
    int32 xfer_len = buff_len;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    int32 status;
    int64 tmp;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, buff, (uint32)xfer_len);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x89;
    tmp = (int64)htonll((uint64)block_addr);
    errcode = memcpy_sp(cdb + 2, sizeof(int64), &tmp, sizeof(int64));
    securec_check_ret(errcode);
    cdb[13] = (unsigned char)(blocks & 0xff);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 16;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI caw command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    // Test p_hdr->driver_status for UltraPath, in case of error the p_hdr->status will be zero.
    scsi_sense_hdr_t ssh;
    // byte count actually written to sbp
    int32 response_len = hdr.sb_len_wr;
    int32 result;

    result = cm_get_scsi_result(&hdr);
    if (result == CM_SCSI_RESULT_GOOD) {
        return CM_SUCCESS;
    }
    if (result == CM_SCSI_RESULT_SENSE) {
        if (response_len > 2 && cm_get_scsi_sense_des(&ssh, sense_buffer, response_len)) {
            if (ssh.sense_key == CM_SPC_SK_MISCOMPARE) {
                return CM_SCSI_ERR_MISCOMPARE;
            } else {
                LOG_DEBUG_ERR("SCSI caw failed, response len %d, sense key %d, asc %d, ascq %d.", response_len,
                    ssh.sense_key, ssh.asc, ssh.ascq);
                return CM_ERROR;
            }
        } else {
            LOG_DEBUG_ERR("Get scsi sense keys failed, response len %d, driver status %d, status %d, host status "
                "%d, sb len wr %d.",
                response_len, hdr.driver_status, hdr.status, hdr.host_status, hdr.sb_len_wr);
            return CM_ERROR;
        }
    } else if (result == CM_SCSI_RESULT_TRANSPORT_ERR) {
        if (response_len > 0 && cm_get_scsi_sense_des(&ssh, sense_buffer, response_len)) {
            if (ssh.sense_key == CM_SPC_SK_MISCOMPARE) {
                return CM_SCSI_ERR_MISCOMPARE;
            } else {
                LOG_DEBUG_ERR("SCSI caw failed, response len %d, sense key %d, asc %d, ascq %d.", response_len,
                    ssh.sense_key, ssh.asc, ssh.ascq);
                return CM_ERROR;
            }
        } else {
            LOG_DEBUG_ERR("Get scsi sense keys failed, response len %d, driver status %d, status %d, host status "
                "%d, sb len wr %d.",
                response_len, hdr.driver_status, hdr.status, hdr.host_status, hdr.sb_len_wr);
            return CM_ERROR;
        }
    } else {
        LOG_DEBUG_ERR("Get scsi sense keys failed, scsi result %d, driver status %d, status %d, host status %d, sb "
            "len wr %d.",
            result, hdr.driver_status, hdr.status, hdr.host_status, hdr.sb_len_wr);
        return CM_ERROR;
    }
}

status_t cm_scsi3_read(int32 fd, int32 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    uchar cdb[10] = {0};
    int32 xfer_len = buff_len;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    int32 status;
    uint16 stmp;
    uint32 uitmp;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, buff, (uint32)xfer_len);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    if (block_count != buff_len / CM_DEF_BLOCK_SIZE || buff_len % CM_DEF_BLOCK_SIZE != 0) {
        LOG_DEBUG_ERR("Invalid input param, buff_len %d, block_count %d.", buff_len, block_count);
        return CM_ERROR;
    }

    cdb[0] = 0x28;
    uitmp = htonl((uint32)block_addr);
    errcode = memcpy_sp(cdb + 2, sizeof(uint32), &uitmp, sizeof(uint32));
    securec_check_ret(errcode);
    stmp = htons(block_count);
    errcode = memcpy_sp(cdb + 7, sizeof(uint16), &stmp, sizeof(uint16));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI read command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI read failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_write(int32 fd, int32 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    uchar cdb[CM_MAX_CDB_LEN] = {0};
    int32 xfer_len = buff_len;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    int32 status;
    uint16 stmp;
    uint32 uitmp;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, buff, (uint32)xfer_len);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    if (block_count != buff_len / CM_DEF_BLOCK_SIZE || buff_len % CM_DEF_BLOCK_SIZE != 0) {
        LOG_DEBUG_ERR("Invalid input param, buff_len %d, block_count %d.", buff_len, block_count);
        return CM_ERROR;
    }

    cdb[0] = 0x2a;
    uitmp = htonl((uint32)block_addr);
    errcode = memcpy_sp(cdb + 2, CM_MAX_CDB_LEN, &uitmp, sizeof(uint32));
    securec_check_ret(errcode);
    stmp = htons(block_count);
    errcode = memcpy_sp(cdb + 7, CM_MAX_CDB_LEN - sizeof(uint32), &stmp, sizeof(uint16));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI write command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI write failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_inql(int32 fd, inquiry_data_t *inquiry_data)
{
    int32 status;

    status = cm_scsi3_get_array(fd, &inquiry_data->array_info);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    status = cm_scsi3_get_vendor(fd, &inquiry_data->vendor_info);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    status = cm_scsi3_get_lun(fd, &inquiry_data->lun_info);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_scsi3_get_array(int32 fd, array_info_t *array_info)
{
    uchar cdb[6] = {0};
    int32 status;
    int32 page_len;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x12;
    cdb[1] = 1;
    cdb[2] = 0x80;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0;

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 6;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI get array info command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI get array info failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    page_len = data_buffer[3];
    if (page_len > CM_MAX_ARRAY_SN_LEN - 1) {
        LOG_DEBUG_ERR("SCSI 0x80 page len invalid, page len %d.", page_len);
        return CM_ERROR;
    }
    errcode = memcpy_s(array_info->array_sn, CM_MAX_ARRAY_SN_LEN, data_buffer + 4, page_len);
    securec_check_ret(errcode);
    array_info->array_sn[CM_HW_ARRAY_SN_LEN - 1] = '\0';

    return CM_SUCCESS;
}

status_t cm_scsi3_get_vendor(int32 fd, vendor_info_t *vendor_info)
{
    uchar cdb[6] = {0};
    int32 status;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x12;
    cdb[1] = 0;
    cdb[2] = 0;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0;

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 6;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI get vendor info command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI get vendor info failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    errcode = memcpy_s(vendor_info->vendor, CM_MAX_VENDOR_LEN, data_buffer + 8, 8);
    securec_check_ret(errcode);
    errcode = memcpy_s(vendor_info->product, CM_MAX_PRODUCT_LEN, data_buffer + 16, 16);
    securec_check_ret(errcode);

    return CM_SUCCESS;
}

status_t cm_scsi3_get_lun(int32 fd, lun_info_t *lun_info)
{
    uchar cdb[6] = {0};
    int32 status;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    char hex_str[CM_MAX_LUNID_LEN] = {0};
    int64 lunid = 0;
    int32 i;
    uchar *p_tmp = NULL;
    int32 page_len;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x12;
    cdb[1] = 1;
    cdb[2] = 0x83;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0;

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 6;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI get lun info command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI get lun info failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    // get lun id
    p_tmp = data_buffer + 20;
    int32 ret;
    for (i = 0; i < 9 / 2; i++) {
        ret = sprintf_s((char *)&hex_str[i * CM_SCSI_NUM_2], CM_MAX_LUNID_LEN, "%02x", p_tmp[i]);
        PRTS_RETURN_IFERR(ret);
    }

    status = cm_hex2int64(hex_str, strlen(hex_str), &lunid);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("SCSI convert lun id failed, status %d, hex str %s.", status, hex_str);
        return CM_ERROR;
    }
    lun_info->lun_id = (int32)lunid;

    // get lun wwn
    page_len = data_buffer[7];
    if (page_len * 2 > CM_MAX_WWN_LEN - 1) {
        LOG_DEBUG_ERR("SCSI 0x83 page len invalid, page len %d.", page_len);
        return CM_ERROR;
    }

    p_tmp = data_buffer + 8;
    for (i = 0; i < page_len; i++) {
        ret = sprintf_s(&lun_info->lun_wwn[i * 2], (size_t)CM_MAX_WWN_LEN - i * 2, "%02x", p_tmp[i]);
        PRTS_RETURN_IFERR(ret);
    }

    return CM_SUCCESS;
}

bool32 cm_scsi3_is_rkey_exist(const int64 *reg_keys, int32 key_count, int64 rkey)
{
    int32 i;

    for (i = 0; i < key_count; i++) {
        if (*(reg_keys + i) == rkey) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

status_t cm_scsi3_rkeys(int32 fd, int64 *reg_keys, int32 *key_count, uint32 *generation)
{
    uchar cdb[10] = {0};
    int32 servact = 0x00;
    int64 rk = 0;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    uint16 resp_len = CM_SCSI_XFER_DATA;
    uint16 utmp;
    int32 status;
    int32 add_len;
    int32 count;
    uchar *p_tmp = NULL;
    int32 i;
    sg_io_hdr_t hdr;
    errno_t errcode;
    int32 unique_keys_count = 0;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5E;
    cdb[1] = (uchar)servact;
    utmp = htons(resp_len);
    errcode = memcpy_sp(cdb + 7, sizeof(resp_len), &utmp, sizeof(resp_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI read keys command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI read keys failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    *generation = ntohl(*(uint32 *)data_buffer);
    add_len = (int32)ntohl(*(uint32 *)(data_buffer + 4));
    p_tmp = data_buffer + 8;
    count = add_len / 8;
    LOG_DEBUG_INF("SCSI read keys count %d, generations %u.", count, *generation);
    for (i = 0; i < count; i++, p_tmp += 8) {
        rk = (int64)ntohll(*(uint64 *)p_tmp);

        if (unique_keys_count >= *key_count) {
            LOG_DEBUG_ERR("SCSI read buff not engouth, rk %lld, key_count %d.", rk, *key_count);
            return CM_ERROR;
        }

        if (cm_scsi3_is_rkey_exist(reg_keys, *key_count, rk)) {
            LOG_DEBUG_INF("SCSI read duplicate key %lld.", rk);
            continue;
        }

        *(reg_keys + unique_keys_count) = rk;
        unique_keys_count++;
        LOG_DEBUG_INF("SCSI read key %lld.", rk);
    }

    *key_count = unique_keys_count;
    return CM_SUCCESS;
}

status_t cm_scsi3_rres(int32 fd, int64 *rk, uint32 *generation)
{
    uchar cdb[10] = {0};
    uint32 servact = 0x01;
    uchar sense_buffer[CM_SCSI_SENSE_LEN] = {0};
    uchar data_buffer[CM_SCSI_XFER_DATA] = {0};
    uint16 resp_len = CM_SCSI_XFER_DATA;
    uint16 utmp;
    int32 status;
    int32 add_len;
    int32 count;
    sg_io_hdr_t hdr;
    errno_t errcode;

    errcode = memset_sp(&hdr, sizeof(sg_io_hdr_t), 0, sizeof(sg_io_hdr_t));
    securec_check_ret(errcode);
    hdr.interface_id = 'S';
    hdr.flags = SG_FLAG_LUN_INHIBIT;

    cm_set_xfer_data(&hdr, data_buffer, CM_SCSI_XFER_DATA);
    cm_set_sense_data(&hdr, sense_buffer, CM_SCSI_SENSE_LEN);

    cdb[0] = 0x5E;
    cdb[1] = (uchar)(servact & 0x1f);
    utmp = htons(resp_len);
    errcode = memcpy_sp(cdb + 7, sizeof(resp_len), &utmp, sizeof(resp_len));
    securec_check_ret(errcode);

    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmdp = cdb;
    hdr.cmd_len = 10;
    hdr.timeout = CM_SCSI_TIMEOUT * 1000;

    status = ioctl(fd, SG_IO, &hdr);
    if (status < 0) {
        LOG_DEBUG_ERR("Sending SCSI read reservation command failed, status %d, errno %d.", status, errno);
        return CM_ERROR;
    }

    if (hdr.status != 0) {
        LOG_DEBUG_ERR("SCSI read reservation failed, status %d.", hdr.status);
        return CM_ERROR;
    }

    *generation = ntohl(*(uint32 *)data_buffer);
    add_len = (int32)ntohl(*(uint32 *)(data_buffer + 4));
    count = add_len / 8;
    LOG_DEBUG_INF("SCSI read reservation count %d, generations %u.", count, *generation);
    if (count > 0) {
        *rk = (int64)ntohll(*(uint64 *)(data_buffer + 8));
        LOG_DEBUG_INF("SCSI read reservation key %lld.", *rk);
    }

    return CM_SUCCESS;
}
#endif
