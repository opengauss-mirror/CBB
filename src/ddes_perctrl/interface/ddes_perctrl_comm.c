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
 * ddes_perctrl_comm.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_perctrl/interface/ddes_perctrl_comm.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddes_perctrl_comm.h"

status_t init_req_and_ack(perctrl_packet_t *req, perctrl_packet_t *ack)
{
    req->buf = req->buf_init;
    req->head = (perctrl_cmd_head_t *)req->buf;
    req->head->size = (uint32)sizeof(perctrl_cmd_head_t);

    ack->buf = ack->buf_init;
    ack->head = (perctrl_cmd_head_t *)ack->buf;

    return CM_SUCCESS;
}

status_t ddes_put_text(perctrl_packet_t *pack, text_t *text)
{
    errno_t errcode;
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    /* put the length of text */
    (void)ddes_put_int32(pack, text->len);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    errcode = memcpy_sp(DDES_WRITE_ADDR(pack), DDES_REMAIN_SIZE(pack), text->str, text->len);
    MEMS_RETURN_IFERR(errcode);

    pack->head->size += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

