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
 * ddes_perctrl_api.h
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/interface/ddes_perctrl_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_PERCTRL_API_H__
#define __DDES_PERCTRL_API_H__

#include "cm_scsi.h"
#include "ddes_perctrl_comm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ctrl_params {
    int32 block_addr;
    uint16 block_count;
    char *buff;
    int32 buff_len;
    int64 *reg_keys;
    int32 key_count;
    uint32 generation;
} ctrl_params_t;

status_t perctrl_receive(int32 fd, perctrl_packet_t *msg);
status_t perctrl_send(int32 fd, perctrl_packet_t *msg);

// The upper-layer caller needs to process the signal SIGPIPE.
typedef enum en_scsi_reserv_type {
    RESERV_TYPE_EXC_WRITE = 0x01,        /* readable by all, only reserv owner can write */
    RESERV_TYPE_EXC_ACCESS = 0x03,       /* only reserv owner can read/write */
    RESERV_TYPE_REGISTER_WRITE = 0x05,   /* readable by all, only registers can write */
    RESERV_TYPE_REGISTER_ACCESS = 0x06,  /* only registers can read/write */
} scsi_reserv_type_e;

int32 perctrl_scsi3_register(const char *iof_dev, int64 sark);
int32 perctrl_scsi3_unregister(const char *iof_dev, int64 rk);
status_t perctrl_scsi3_reserve(const char *iof_dev, int64 rk, scsi_reserv_type_e type);
status_t perctrl_scsi3_release(const char *iof_dev, int64 rk, scsi_reserv_type_e type);
status_t perctrl_scsi3_clear(const char *iof_dev, int64 rk);
status_t perctrl_scsi3_preempt(const char *iof_dev, int64 rk, int64 sark, scsi_reserv_type_e type);
int32 perctrl_scsi3_caw(const char *scsi_dev, uint64 block_addr, char *buff, int32 buff_len);
status_t perctrl_scsi3_read(const char *iof_dev, int32 block_addr, uint16 block_count, char *buff, int32 buff_len);
status_t perctrl_scsi3_write(const char *iof_dev, int32 block_addr, uint16 block_count, char *buff, int32 buff_len);
status_t perctrl_scsi3_inql(const char *iof_dev, inquiry_data_t *inquiry_data);
status_t perctrl_scsi3_rkeys(const char *iof_dev, int64 *reg_keys, int32 *key_count, uint32 *generation);
status_t perctrl_scsi3_rres(const char *iof_dev, int64 *rk, uint32 *generation);

#ifdef __cplusplus
}
#endif

#endif