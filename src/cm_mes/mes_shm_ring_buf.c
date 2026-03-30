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
 * mes_shm_ring_buf.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_shm_ring_buf.c
 *
 * -------------------------------------------------------------------------
 */
#include <string.h>
#include <stdint.h>
#include "cm_defs.h"
#include "cm_log.h"
#include "mes_shm_ring_buf.h"

void MPSCRingBuffer_init(MPSCRingBuffer *self, uint64_t entry_data_sz, uint64_t entry_num_) {
    // 检查entry_num是否为2的幂
    if (entry_num_ == 0 || (entry_num_ & (entry_num_ - 1)) != 0) {
        entry_num_ = 1024;
    }
    
    self->entry_data_size = entry_data_sz;
    self->entry_num = entry_num_;
    self->head = 0;
    self->tail = 0;
    self->count = 0;

    self->entry_struct_size = (uint64_t)(sizeof(mpsc_entry_t) + entry_data_sz);
    self->entries_offset = (sizeof(MPSCRingBuffer) + (CACHELINE_SIZE - 1)) & ~(CACHELINE_SIZE - 1);
    // 不再设置self->entry_指针，避免在IPC共享内存中出现问题

    for (uint64_t i = 0; i < entry_num_; i++) {
        // 动态计算条目地址
        mpsc_entry_t *tmp = (mpsc_entry_t *)((char *)self + self->entries_offset + i * self->entry_struct_size);
        tmp->is_ready = 0;
        tmp->remaining_size = 0;
        tmp->dequeue_offset = 0;
        if (entry_data_sz > 0) {
            void *data_ptr = (char *)tmp + sizeof(mpsc_entry_t);
            memset_sp(data_ptr, entry_data_sz, 0, entry_data_sz);
        }
    }
}

uint64_t MPSCRingBuffer_size(MPSCRingBuffer *self)
{
    __sync_synchronize();
    uint64_t cur_head = self->head;
    uint64_t cur_tail = self->tail;
    __sync_synchronize();
    return cur_tail - cur_head;
}

bool MPSCRingBuffer_enqueue(MPSCRingBuffer *self, const char *data, uint64_t data_size)
{
    if (data_size > self->entry_data_size) {
        return false;
    }

    // Check if there's space available
    if (self->count >= self->entry_num) {
        return false;
    }

    uint64_t cur_tail = self->tail;
    uint64_t entry_index = cur_tail & (self->entry_num - 1);
    
    mpsc_entry_t *entry = (mpsc_entry_t *)((char *)self + self->entries_offset + entry_index * self->entry_struct_size);
    void *dst = (char *)entry + sizeof(mpsc_entry_t);
    
    // Write data first, before marking as ready
    entry->remaining_size = (uint32_t)data_size;
    entry->dequeue_offset = 0;
    
    if (memcpy_s(dst, self->entry_data_size, data, data_size) != 0) {
        return false;
    }
    
    // Memory barrier to ensure data is written before marking ready
    __sync_synchronize();
    
    // Now mark the entry as ready (data is fully written)
    __sync_lock_test_and_set(&entry->is_ready, 1);
    
    // Atomically update tail and count
    __sync_fetch_and_add(&self->tail, 1);
    __sync_fetch_and_add(&self->count, 1);
    
    return true;
}

uint64_t MPSCRingBuffer_dequeue(MPSCRingBuffer *self, char *data_buffer, uint64_t buffer_size)
{
    if (buffer_size == 0) return 0;
    
    __sync_synchronize();
    uint64_t cur_head = self->head;
    uint64_t cur_tail = self->tail;
    
    // 检查队列是否为空
    if (cur_head >= cur_tail) {
        return 0;
    }
    
    uint64_t entry_index = cur_head & (self->entry_num - 1);
    // 动态计算条目地址
    mpsc_entry_t *entry = (mpsc_entry_t *)((char *)self + self->entries_offset + entry_index * self->entry_struct_size);
    
    // 尝试获取锁，如果获取不到，说明消息可能还未完全写入
    if (__sync_lock_test_and_set(&entry->is_ready, 0) != 1) {
        return 0;
    }
    
    // 计算可以读取的数据量（支持部分读取）
    uint64_t dequeue_size = (buffer_size < entry->remaining_size) ? buffer_size : entry->remaining_size;
    void *src = (char *)entry + sizeof(mpsc_entry_t) + entry->dequeue_offset;
    
    // 读取数据，检查复制结果
    if (memcpy_sp(data_buffer, buffer_size, src, dequeue_size) != 0) {
        // 读取失败，恢复条目状态
        __sync_lock_test_and_set(&entry->is_ready, 1);
        return 0;
    }
    
    // 更新条目状态（支持部分读取）
    entry->dequeue_offset += (uint32_t)dequeue_size;
    entry->remaining_size -= (uint32_t)dequeue_size;
    
    if (entry->remaining_size != 0) {
        __sync_lock_test_and_set(&entry->is_ready, 1);
        return dequeue_size;
    }
    entry->dequeue_offset = 0;
    
    // 释放条目
    __sync_lock_test_and_set(&entry->is_ready, 0);
    
    // 原子更新head和count
    __sync_lock_test_and_set(&self->head, cur_head + 1);
    __sync_fetch_and_sub(&self->count, 1);
    return dequeue_size;
}

uint64_t MPSCRingBuffer_send(MPSCRingBuffer *self, const char *data, uint64_t data_size, uint32_t max_retries)
{
    while (!MPSCRingBuffer_enqueue(self, data, data_size))
        ;
    return data_size;
}

uint64_t MPSCRingBuffer_recv(MPSCRingBuffer *self, char *buffer, uint64_t buffer_size)
{
    return MPSCRingBuffer_dequeue(self, buffer, buffer_size);
}
