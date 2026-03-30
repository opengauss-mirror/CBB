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
 * mes_shm_ring_buf.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_ring_buf.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef MES_SHM_RING_BUF_H
#define MES_SHM_RING_BUF_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CACHELINE_SIZE 64

typedef struct st_mpsc_entry {
    volatile uint8_t is_ready;
    uint32_t remaining_size;
    uint32_t dequeue_offset;
} mpsc_entry_t;

typedef struct st_mpsc_ring_buffer {
    uint64_t entry_struct_size;
    uint64_t entry_data_size;
    uint64_t entry_num;
    size_t entries_offset;

    volatile uint64_t head __attribute__((aligned(CACHELINE_SIZE)));
    volatile uint64_t tail __attribute__((aligned(CACHELINE_SIZE)));
    volatile uint64_t count __attribute__((aligned(CACHELINE_SIZE)));
} MPSCRingBuffer;

void MPSCRingBuffer_init(MPSCRingBuffer *self, uint64_t entry_data_sz, uint64_t entry_num_);

uint64_t MPSCRingBuffer_size(MPSCRingBuffer *self);

bool MPSCRingBuffer_enqueue(MPSCRingBuffer *self, const char *data, uint64_t data_size);

uint64_t MPSCRingBuffer_dequeue(MPSCRingBuffer *self, char *data_buffer, uint64_t buffer_size);

uint64_t MPSCRingBuffer_send(MPSCRingBuffer *self, const char *data, uint64_t data_size, uint32_t max_retries);

uint64_t MPSCRingBuffer_recv(MPSCRingBuffer *self, char *buffer, uint64_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* MES_SHM_RING_BUF_H */
