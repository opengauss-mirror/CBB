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
 * benchmark_common.c
 * Common utilities for MES benchmark tools
 *
 * IDENTIFICATION
 *    src/cm_mes/benchmark/benchmark_common.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <math.h>
#include "benchmark_common.h"

#define BENCHMARK_MAGIC_PATTERN 0xAB
#define P99_PERCENTILE 99
#define P95_PERCENTILE 95

void benchmark_mes_log_output(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...)
{
    va_list args;
    const char *level_str = "UNKNOWN";

    (void)log_type;
    (void)module_name;

    va_start(args, format);

    switch (log_level) {
        case 0: level_str = "DEBUG"; break;
        case 1: level_str = "INFO"; break;
        case 2: level_str = "WARNING"; break;
        case 3: level_str = "ERROR"; break;
        case 4: level_str = "FATAL"; break;
        default: level_str = "UNKNOWN"; break;
    }

    fprintf(stderr, "[MES_LOG][%s][%s:%u] ", level_str, code_file_name, code_line_num);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");

    va_end(args);
}

uint64_t benchmark_get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

double benchmark_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

int benchmark_compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

void benchmark_fill_verify_pattern(char *buffer, int size, uint32_t seq_num, 
    size_t header_size, benchmark_verify_config_t *config)
{
    if (!config->verify_mode || size <= (int)header_size) {
        return;
    }
    
    char *payload = buffer + header_size;
    int payload_size = size - (int)header_size;
    
    for (int i = 0; i < payload_size; i++) {
        payload[i] = (char)((seq_num + i) ^ BENCHMARK_MAGIC_PATTERN);
    }
}

int benchmark_verify_payload_pattern(const char *buffer, int size, uint32_t seq_num,
    size_t header_size, benchmark_verify_config_t *config)
{
    if (!config->verify_mode || size <= (int)header_size) {
        return 1;
    }
    
    const char *payload = buffer + header_size;
    int payload_size = size - (int)header_size;
    
    for (int i = 0; i < payload_size; i++) {
        char expected = (char)((seq_num + i) ^ BENCHMARK_MAGIC_PATTERN);
        if (payload[i] != expected) {
            if (config->verbose) {
                fprintf(stderr, "[VERIFY] Payload mismatch at offset %d: expected 0x%02X, got 0x%02X (seq=%u)\n",
                        i, (unsigned char)expected, (unsigned char)payload[i], seq_num);
            }
            return 0;
        }
    }
    return 1;
}

void benchmark_inject_noise_error(char *buffer, int size, uint32_t seq_num,
    size_t header_size, benchmark_verify_config_t *config)
{
    if (!config->inject_error || size <= (int)header_size) {
        return;
    }
    
    if (seq_num % 100 == 0) {
        int payload_size = size - (int)header_size;
        int error_offset = seq_num % payload_size;
        char *payload = buffer + header_size;
        payload[error_offset] ^= 0xFF;
        if (config->verbose) {
            printf("[NOISE] Injected error at offset %d for seq=%u\n", error_offset, seq_num);
        }
    }
}

void benchmark_calculate_statistics(benchmark_rtt_result_t *results, int count, 
    benchmark_statistics_t *stats)
{
    if (count == 0) {
        memset(stats, 0, sizeof(benchmark_statistics_t));
        return;
    }
    
    double *rtt_values = (double *)malloc(count * sizeof(double));
    if (!rtt_values) {
        memset(stats, 0, sizeof(benchmark_statistics_t));
        return;
    }
    
    double sum = 0.0;
    double sum_sq = 0.0;
    double sum_send_latency = 0.0;
    double sum_network_req = 0.0;
    double sum_server_process = 0.0;
    double sum_network_resp = 0.0;
    
    stats->min_rtt_us = results[0].rtt_us;
    stats->max_rtt_us = results[0].rtt_us;
    
    for (int i = 0; i < count; i++) {
        rtt_values[i] = results[i].rtt_us;
        sum += results[i].rtt_us;
        sum_sq += results[i].rtt_us * results[i].rtt_us;
        sum_send_latency += results[i].send_latency_us;
        sum_network_req += results[i].network_req_us;
        sum_server_process += results[i].server_process_us;
        sum_network_resp += results[i].network_resp_us;
        
        if (results[i].rtt_us < stats->min_rtt_us) {
            stats->min_rtt_us = results[i].rtt_us;
        }
        if (results[i].rtt_us > stats->max_rtt_us) {
            stats->max_rtt_us = results[i].rtt_us;
        }
    }
    
    stats->avg_rtt_us = sum / count;
    stats->std_dev_us = sqrt((sum_sq / count) - (stats->avg_rtt_us * stats->avg_rtt_us));
    stats->avg_send_latency_us = sum_send_latency / count;
    stats->avg_network_req_us = sum_network_req / count;
    stats->avg_server_process_us = sum_server_process / count;
    stats->avg_network_resp_us = sum_network_resp / count;
    
    qsort(rtt_values, count, sizeof(double), benchmark_compare_double);
    
    stats->p50_rtt_us = rtt_values[count / 2];
    stats->p95_rtt_us = rtt_values[count * P95_PERCENTILE / 100];
    stats->p99_rtt_us = rtt_values[count * P99_PERCENTILE / 100];
    
    free(rtt_values);
}

void benchmark_print_statistics(const char *test_name, benchmark_statistics_t *stats, 
    double total_time_s, int verify_mode)
{
    printf("\n==================================================\n");
    printf("%s\n", test_name);
    printf("==================================================\n");
    printf("| %-25s | %20d |\n", "Success count", stats->success_count);
    printf("| %-25s | %20d |\n", "Timeout count", stats->timeout_count);
    
    if (verify_mode) {
        printf("--------------------------------------------------\n");
        printf("| %-25s | %20s |\n", "Data Integrity Check", "");
        int verified_count = stats->success_count - stats->checksum_failed;
        printf("| %-25s | %20d |\n", "  Verified OK", verified_count);
        printf("| %-25s | %20d |\n", "  Checksum Failed", stats->checksum_failed);
        if (stats->checksum_failed == 0 && stats->success_count > 0) {
            printf("| %-25s | %20s |\n", "  Result", "ALL PASSED");
        } else if (stats->checksum_failed > 0) {
            printf("| %-25s | %20s |\n", "  Result", "FAILED");
        }
    }
    
    printf("--------------------------------------------------\n");
    printf("| %-25s | %20.2f |\n", "Average RTT (us)", stats->avg_rtt_us);
    printf("| %-25s | %20.2f |\n", "Min RTT (us)", stats->min_rtt_us);
    printf("| %-25s | %20.2f |\n", "Max RTT (us)", stats->max_rtt_us);
    printf("| %-25s | %20.2f |\n", "P50 RTT (us)", stats->p50_rtt_us);
    printf("| %-25s | %20.2f |\n", "P95 RTT (us)", stats->p95_rtt_us);
    printf("| %-25s | %20.2f |\n", "P99 RTT (us)", stats->p99_rtt_us);
    printf("| %-25s | %20.2f |\n", "Std Dev (us)", stats->std_dev_us);
    printf("--------------------------------------------------\n");
    printf("| %-25s | %20s |\n", "Latency Breakdown", "");
    printf("| %-25s | %20.2f |\n", "  Send Latency (us)", stats->avg_send_latency_us);
    printf("| %-25s | %20.2f |\n", "  Network Req (us)", stats->avg_network_req_us);
    printf("| %-25s | %20.2f |\n", "  Server Process (us)", stats->avg_server_process_us);
    printf("| %-25s | %20.2f |\n", "  Network Resp (us)", stats->avg_network_resp_us);
    printf("| %-25s | %20.2f |\n", "  Sum Check (us)", 
           stats->avg_send_latency_us + stats->avg_network_req_us + 
           stats->avg_server_process_us + stats->avg_network_resp_us);
    
    if (total_time_s > 0) {
        double throughput = stats->success_count / total_time_s;
        printf("--------------------------------------------------\n");
        printf("| %-25s | %20.2f |\n", "Total time (s)", total_time_s);
        printf("| %-25s | %20.2f |\n", "Throughput (req/s)", throughput);
    }
    printf("==================================================\n");
}

const char *benchmark_pipe_type_to_string(mes_pipe_type_t pipe_type)
{
    switch (pipe_type) {
        case MES_TYPE_TCP: return "TCP";
        case MES_TYPE_RDMA: return "RDMA";
        case MES_TYPE_IPC: return "IPC";
        case MES_TYPE_SHM: return "SHM";
        default: return "UNKNOWN";
    }
}
