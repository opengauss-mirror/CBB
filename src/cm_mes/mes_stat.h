/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * mes_stat.h
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/mes_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_STAT_H__
#define __MES_STAT_H__

#include "mes_interface.h"
#include "mes_type.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_mes_command_stat {
    union {
        struct {
            uint32 cmd;
            int64 send_count;
            int64 recv_count;
            int64 local_count;
            atomic32_t occupy_buf;
            uint64 avg_size;
            spinlock_t lock;
        };
        char padding[CM_CACHE_LINE_SIZE];
    };
} mes_command_stat_t;

typedef struct st_mes_command_time_stat {
    union {
        struct {
            uint64 time;
            int64 count;
            spinlock_t lock;
        };
        char padding[CM_CACHE_LINE_SIZE];
    };
}mes_command_time_stat_t;

typedef struct st_mes_time_consume {
    mes_command_time_stat_t cmd_time_stats[MES_TIME_CEIL];
    union {
        uint32 cmd;
        char aligned1[CM_CACHE_LINE_SIZE];
    };
} mes_time_consume_t;

typedef struct st_mes_elapsed_stat {
    char aligned1[CM_CACHE_LINE_SIZE];
    union {
        bool8 mes_elapsed_switch;
        char aligned2[CM_CACHE_LINE_SIZE];
    };
    mes_time_consume_t time_consume_stat[CM_MAX_MES_MSG_CMD];
} mes_elapsed_stat_t;

typedef struct st_mes_stat {
    char aligned1[CM_CACHE_LINE_SIZE];
    union {
        bool8 mes_elapsed_switch;
        char aligned2[CM_CACHE_LINE_SIZE];
    };
    mes_command_stat_t mes_command_stat[CM_MAX_MES_MSG_CMD];
} mes_stat_t;

#define CMD_SIZE_HISTOGRAM_COUNT 10
#define CMD_SIZE_2_MIN_POWER 7
#define CMD_SIZE_2_MAX_POWER 15

typedef struct st_size_histogram {
    spinlock_t lock;
    uint64 min_size;
    uint64 max_size;
    uint64 avg_size;
    uint64 count;
    char reserved[CM_CACHE_LINE_SIZE - sizeof(spinlock_t) - 4 * sizeof(uint64)];
} size_histogram_t;

typedef struct st_mes_msg_size_stats {
    bool32 enable;
    /*
     * 0  --  128B
     * 1  --  256B
     * 2  --  512B
     * 3  --  1KB
     * 4  --  2KB
     * 5  --  4KB
     * 6  --  8KB
     * 7  --  16KB
     * 8  --  32KB
     * 9  --  > 32KB
     */
    size_histogram_t histograms[CMD_SIZE_HISTOGRAM_COUNT];
} mes_msg_size_stats_t;

extern mes_elapsed_stat_t g_mes_elapsed_stat;
extern mes_stat_t g_mes_stat;
extern mes_msg_size_stats_t g_mes_msg_size_stat;

void mes_init_stat(const mes_profile_t *profile);
void mes_send_stat(uint16 cmd, uint32 size);
void mes_recv_message_stat(const mes_message_t *msg);
void mes_local_stat(uint16 cmd);
void mes_elapsed_stat(uint16 cmd, mes_time_stat_t type);
void mes_release_buf_stat(uint16 cmd);
uint64 cm_get_time_usec();
void mes_consume_with_time(uint16 cmd, mes_time_stat_t type, uint64 start_time);
void mes_msg_size_stats(uint32 size);
void mes_get_wait_event(unsigned int cmd, unsigned long long *event_cnt, unsigned long long *event_time);

#ifdef __cplusplus  
}
#endif

#endif