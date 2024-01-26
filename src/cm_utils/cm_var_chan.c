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
 * cm_var_chan.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_var_chan.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_var_chan.h"
#include "cm_error.h"
#include "cm_num.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 cm_alloc_buf_valid(const var_chan_t *chan)
{
    uint32 i;
    for (i = 0; i < chan->buf_ctrl.buf_count; i++) {
        if (chan->buf_ctrl.bufs[i] == NULL) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static bool32 cm_var_chan_can_send(var_chan_t *chan, uint32 len)
{
    uint32 cur_buf_remain;
    // [end,begin] is remain area
    if (chan->buf_ctrl.end_buf_id == chan->buf_ctrl.beg_buf_id &&
        chan->ori_chan.end <= chan->ori_chan.begin &&
        chan->ori_chan.count > 0) {
        cur_buf_remain = (uint32)(chan->ori_chan.begin - chan->ori_chan.end);
        if (cur_buf_remain < (len + sizeof(uint32))) {
            return CM_FALSE;
        }
        return CM_TRUE;
    }
    cur_buf_remain = (uint32)(chan->buf_ctrl.bufs_end[chan->buf_ctrl.end_buf_id] - chan->ori_chan.end);
    uint32 next_buf_id = (chan->buf_ctrl.end_buf_id + 1) % chan->buf_ctrl.buf_count;
    if (cur_buf_remain < (len + sizeof(uint32))) {
        chan->buf_ctrl.available -= cur_buf_remain;
        chan->buf_ctrl.data_end[chan->buf_ctrl.end_buf_id] = chan->ori_chan.end;
        chan->ori_chan.end = chan->buf_ctrl.bufs[next_buf_id];
        chan->buf_ctrl.end_buf_id = next_buf_id;
    }

    if (chan->buf_ctrl.available < (len + sizeof(uint32))) {
        return CM_FALSE;
    }
    return CM_TRUE;
}
static inline void free_buf_ctrls(var_chan_t *chan, uint32 to_free_count)
{
    for (uint32 j = 0; j < to_free_count; j++) {
        CM_FREE_PROT_PTR(chan->buf_ctrl.bufs[j]);
    }
}
var_chan_t *cm_var_chan_new(uint64 total)
{
    var_chan_t *chan = NULL;
    uint32 i = 0;
    errno_t rc_memzero;

    // total must be (0, 64 * 128 * 1024]
    if (total > MAX_BUF_COUNT * SIZE_K(128) || total == 0) {
        return NULL;
    }

    chan = (var_chan_t *)cm_malloc_prot(sizeof(var_chan_t));
    if (chan == NULL) {
        return NULL;
    }

    rc_memzero = memset_sp(chan, sizeof(var_chan_t), 0, sizeof(var_chan_t));
    if (rc_memzero != EOK) {
        CM_FREE_PROT_PTR(chan);
        return NULL;
    }

    // alloc mem which is multiple of SIZE_K(128)
    uint32 page_count = (uint32)((uint64)total / SIZE_K(128));
    uint32 remain = (uint32)((uint64)total % SIZE_K(128));
    chan->buf_ctrl.buf_count = (remain == 0 ? page_count : page_count + 1);

    for (i = 0; i < chan->buf_ctrl.buf_count; i++) {
        chan->buf_ctrl.bufs[i] = (uint8 *)cm_malloc_prot(SIZE_K(128));
        if (chan->buf_ctrl.bufs[i] == NULL) {
            free_buf_ctrls(chan, i);
            CM_FREE_PROT_PTR(chan);
            return NULL;
        }
        rc_memzero = memset_sp(chan->buf_ctrl.bufs[i], SIZE_K(128), 0, SIZE_K(128));
        if (rc_memzero != EOK) {
            free_buf_ctrls(chan, i);
            CM_FREE_PROT_PTR(chan);
            return NULL;
        }

        chan->buf_ctrl.bufs_end[i] = chan->buf_ctrl.bufs[i] + SIZE_K(128);
        chan->buf_ctrl.data_end[i] = chan->buf_ctrl.bufs[i] + SIZE_K(128);
    }

    chan->ori_chan.begin = chan->buf_ctrl.bufs[0];
    chan->ori_chan.end = chan->buf_ctrl.bufs[0];
    chan->buf_ctrl.beg_buf_id = 0;
    chan->buf_ctrl.end_buf_id = 0;
    chan->ori_chan.count = 0;
    chan->buf_ctrl.total = chan->buf_ctrl.buf_count * SIZE_K(128);
    chan->buf_ctrl.available = chan->buf_ctrl.total;

    chan->ori_chan.lock = 0;
    (void)cm_event_init(&chan->ori_chan.event_send);
    (void)cm_event_init(&chan->ori_chan.event_recv);
    chan->ori_chan.waittime_ms = 100;

    chan->ori_chan.is_closed = CM_FALSE;
    chan->ori_chan.ref_count = 0;

    return chan;
}

status_t cm_var_chan_send_timeout(var_chan_t *chan, const void *elem, uint32 len, uint32 timeout_ms)
{
    errno_t errcode;
    if (chan == NULL || elem == NULL) {
        return CM_ERROR;
    }

    cm_spin_lock(&chan->ori_chan.lock, NULL);
    {
        if (!cm_alloc_buf_valid(chan) || chan->ori_chan.is_closed) {
            cm_spin_unlock(&chan->ori_chan.lock);
            return CM_ERROR;
        }

        // chan is full
        while (!cm_var_chan_can_send(chan, len)) {
            cm_spin_unlock(&chan->ori_chan.lock);

            // wait for the recv signal
            if (CM_TIMEDOUT == cm_event_timedwait(&chan->ori_chan.event_recv, timeout_ms)) {
                return CM_TIMEDOUT;
            }

            cm_spin_lock(&chan->ori_chan.lock, NULL);

            if (cm_var_chan_can_send(chan, len)) {
                break;
            }
        }

        // send
        *(uint32 *)chan->ori_chan.end = len;
        chan->ori_chan.end += sizeof(uint32);
        errcode = memcpy_sp(chan->ori_chan.end, len, elem, len);
        if (errcode != EOK) {
            cm_spin_unlock(&chan->ori_chan.lock);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        chan->ori_chan.end += len;
        chan->ori_chan.count++;
        chan->buf_ctrl.available -= (uint32)(len + sizeof(uint32));
    }
    cm_spin_unlock(&chan->ori_chan.lock);

    cm_event_notify(&chan->ori_chan.event_send);

    return CM_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_var_chan_send(var_chan_t *chan, const void *elem, uint32 len)
{
    return cm_var_chan_send_timeout(chan, elem, len, CM_MAX_UINT32);
}

// recv an element, will block until there are elems in the chan
status_t cm_var_chan_recv_timeout(var_chan_t *chan, void *elem, uint32 *len, uint32 timeout_ms)
{
    errno_t errcode;
    if (chan == NULL || elem == NULL) {
        return CM_ERROR;
    }

    cm_spin_lock(&chan->ori_chan.lock, NULL);
    {
        if (!cm_alloc_buf_valid(chan)) {
            cm_spin_unlock(&chan->ori_chan.lock);
            return CM_ERROR;
        }

        // chan is empty
        while (chan->ori_chan.count == 0) {
            if (chan->ori_chan.is_closed) {
                cm_spin_unlock(&chan->ori_chan.lock);
                return CM_ERROR;
            }

            cm_spin_unlock(&chan->ori_chan.lock);

            // wait for the send signal
            if (CM_TIMEDOUT == cm_event_timedwait(&chan->ori_chan.event_send, timeout_ms)) {
                return CM_TIMEDOUT;
            }

            cm_spin_lock(&chan->ori_chan.lock, NULL);

            if (chan->ori_chan.count > 0) {
                break;
            }
        }

        // ring
        uint32 cur_buf_id = chan->buf_ctrl.beg_buf_id;
        uint32 next_buf_id = (cur_buf_id + 1) % chan->buf_ctrl.buf_count;
        if (chan->ori_chan.begin >= chan->buf_ctrl.data_end[cur_buf_id]) {
            chan->buf_ctrl.available += (uint32)(chan->buf_ctrl.bufs_end[cur_buf_id] - (uint8 *)chan->ori_chan.begin);
            chan->buf_ctrl.data_end[cur_buf_id] = chan->buf_ctrl.bufs_end[cur_buf_id];
            chan->ori_chan.begin = chan->buf_ctrl.bufs[next_buf_id];
            chan->buf_ctrl.beg_buf_id = next_buf_id;
        }

        // recv
        *len = *(uint32 *)chan->ori_chan.begin;
        chan->ori_chan.begin += sizeof(uint32);
        errcode = memcpy_sp(elem, *len, chan->ori_chan.begin, *len);
        if (errcode != EOK) {
            cm_spin_unlock(&chan->ori_chan.lock);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        chan->ori_chan.begin += *len;
        chan->ori_chan.count--;
        chan->buf_ctrl.available += (uint32)(sizeof(uint32) + *len);
    }
    cm_spin_unlock(&chan->ori_chan.lock);

    cm_event_notify(&chan->ori_chan.event_recv);

    return CM_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_var_chan_recv(var_chan_t *chan, void *elem, uint32 *len)
{
    return cm_var_chan_recv_timeout(chan, elem, len, CM_MAX_UINT32);
}

void cm_var_chan_close(var_chan_t *chan)
{
    cm_chan_close(&chan->ori_chan);
}

void cm_var_chan_free(var_chan_t **chan_in)
{
    uint32 i;
    if (*chan_in == NULL) {
        return;
    }

    var_chan_t *chan = *chan_in;

    cm_event_destory(&chan->ori_chan.event_recv);
    cm_event_destory(&chan->ori_chan.event_send);

    for (i = 0; i < MAX_BUF_COUNT; i++) {
        CM_FREE_PROT_PTR(chan->buf_ctrl.bufs[i]);
        chan->buf_ctrl.bufs_end[i] = NULL;
        chan->buf_ctrl.data_end[i] = NULL;
    }
    chan->buf_ctrl.buf_count = 0;
    chan->buf_ctrl.available = 0;
    chan->buf_ctrl.beg_buf_id = 0;
    chan->buf_ctrl.end_buf_id = 0;
    chan->buf_ctrl.total = 0;
    chan->ori_chan.begin = NULL;
    chan->ori_chan.end = NULL;
    chan->ori_chan.count = 0;

    chan->ori_chan.is_closed = CM_TRUE;
    chan->ori_chan.ref_count = 0;

    CM_FREE_PROT_PTR(*chan_in);
}

bool32 cm_var_chan_empty(var_chan_t *chan)
{
    return cm_chan_empty(&chan->ori_chan);
}

#ifdef __cplusplus
}
#endif