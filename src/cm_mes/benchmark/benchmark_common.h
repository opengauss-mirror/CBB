/*
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * benchmark_common.h
 * Common definitions and utilities for MES benchmark tools
 *
 * IDENTIFICATION
 *    src/cm_mes/benchmark/benchmark_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef BENCHMARK_COMMON_H
#define BENCHMARK_COMMON_H

#include <stdint.h>
#include "../mes_interface.h"

#define BENCHMARK_MAGIC_PATTERN 0xAB
#define P99_PERCENTILE 99
#define P95_PERCENTILE 95

typedef struct {
    double rtt_us;
    uint64_t send_timestamp;
    uint64_t recv_timestamp;
    double send_latency_us;
    double network_req_us;
    double server_process_us;
    double network_resp_us;
} benchmark_rtt_result_t;

typedef struct {
    double avg_rtt_us;
    double min_rtt_us;
    double max_rtt_us;
    double p50_rtt_us;
    double p95_rtt_us;
    double p99_rtt_us;
    double std_dev_us;
    double avg_send_latency_us;
    double avg_network_req_us;
    double avg_server_process_us;
    double avg_network_resp_us;
    int success_count;
    int timeout_count;
    int checksum_failed;
} benchmark_statistics_t;

typedef struct {
    int verify_mode;
    int inject_error;
    int verbose;
} benchmark_verify_config_t;

#if defined(__GNUC__) && !defined(WIN32)
void benchmark_mes_log_output(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...) __attribute__((format(printf, 6, 7)));
#else
void benchmark_mes_log_output(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...);
#endif

extern uint64_t benchmark_get_time_us(void);

extern double benchmark_get_time_ms(void);

extern int benchmark_compare_double(const void *a, const void *b);

extern void benchmark_fill_verify_pattern(char *buffer, int size, uint32_t seq_num, 
    size_t header_size, benchmark_verify_config_t *config);

extern int benchmark_verify_payload_pattern(const char *buffer, int size, uint32_t seq_num,
    size_t header_size, benchmark_verify_config_t *config);

extern void benchmark_inject_noise_error(char *buffer, int size, uint32_t seq_num,
    size_t header_size, benchmark_verify_config_t *config);

extern void benchmark_calculate_statistics(benchmark_rtt_result_t *results, int count, 
    benchmark_statistics_t *stats);

extern void benchmark_print_statistics(const char *test_name, benchmark_statistics_t *stats, 
    double total_time_s, int verify_mode);

extern const char *benchmark_pipe_type_to_string(mes_pipe_type_t pipe_type);

#endif
