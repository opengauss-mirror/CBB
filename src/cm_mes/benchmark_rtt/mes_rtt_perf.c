/*
 * Copyright Copyright 2026 Huawei Technologies Co.,Ltd.
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
 * mes_rtt_perf.c
 * Multi-node RTT performance verification tool using MES
 *
 * IDENTIFICATION
 *    src/cm_mes/benchmark/mes_rtt_perf.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <getopt.h>
#include <math.h>

#include "../mes_interface.h"

#define DEFAULT_PORT 12345
#define DEFAULT_TEST_COUNT 1000
#define DEFAULT_MESSAGE_SIZE 64
#define MAX_MESSAGE_SIZE (64 * 1024)
#define P99_PERCENTILE 99
#define P95_PERCENTILE 95
#define MAX_NODES 16
#define RTT_MAGIC_PATTERN 0xAB

typedef enum {
    MODE_SERVER,
    MODE_CLIENT
} run_mode_t;

typedef struct {
    inst_type inst_id;
    char ip[MES_MAX_IP_LEN];
    unsigned short port;
} node_config_t;

typedef struct {
    uint32_t seq_num;
    inst_type src_inst;
    inst_type dst_inst;
    uint64_t send_timestamp;
    uint64_t recv_timestamp;
    uint64_t reply_timestamp;
} rtt_perf_message_t;

typedef struct {
    double rtt_us;
    double send_latency_us;
    double network_req_us;
    double server_process_us;
    double network_resp_us;
    uint64_t send_timestamp;
    uint64_t recv_timestamp;
} rtt_result_t;

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
} test_statistics_t;

typedef struct {
    int thread_id;
    int start_idx;
    int count;
    rtt_result_t *results;
    int success_count;
    int timeout_count;
    int checksum_failed;
    pthread_mutex_t mutex;
} thread_context_t;

typedef struct {
    run_mode_t mode;
    mes_pipe_type_t pipe_type;
    inst_type local_inst_id;
    char local_ip[MES_MAX_IP_LEN];
    unsigned short local_port;
    inst_type target_inst_id;
    char target_ip[MES_MAX_IP_LEN];
    unsigned short target_port;
    int test_count;
    int message_size;
    int timeout_ms;
    int verbose;
    int verify_mode;
    int inject_error;
    int node_count;
    int thread_count;
    int channel_cnt;
    int recv_thread_cnt;
    int work_thread_cnt;
    int priority_cnt;
    int priority_hash;
    int send_directly;
    node_config_t nodes[MAX_NODES];
} test_config_t;

static test_config_t g_config = {0};
static volatile int g_running = 1;

static void mes_log_output(int log_type, int log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    
    const char *level_str = "UNKNOWN";
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

static const char *pipe_type_to_string(mes_pipe_type_t pipe_type)
{
    switch (pipe_type) {
        case MES_TYPE_TCP: return "TCP";
        case MES_TYPE_RDMA: return "RDMA";
        case MES_TYPE_IPC: return "IPC";
        default: return "UNKNOWN";
    }
}

static uint64_t get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static void fill_verify_pattern(char *buffer, int size, uint32_t seq_num)
{
    if (size <= (int)sizeof(rtt_perf_message_t)) {
        return;
    }
    
    char *payload = buffer + sizeof(rtt_perf_message_t);
    int payload_size = size - sizeof(rtt_perf_message_t);
    
    for (int i = 0; i < payload_size; i++) {
        payload[i] = (char)((seq_num + i) ^ RTT_MAGIC_PATTERN);
    }
}

static int verify_payload_pattern(const char *buffer, int size, uint32_t seq_num)
{
    if (size <= (int)sizeof(rtt_perf_message_t)) {
        return 1;
    }
    
    const char *payload = buffer + sizeof(rtt_perf_message_t);
    int payload_size = size - sizeof(rtt_perf_message_t);
    
    for (int i = 0; i < payload_size; i++) {
        char expected = (char)((seq_num + i) ^ RTT_MAGIC_PATTERN);
        if (payload[i] != expected) {
            if (g_config.verbose) {
                fprintf(stderr, "[VERIFY] Payload mismatch at offset %d: expected 0x%02X, got 0x%02X (seq=%u)\n",
                        i, (unsigned char)expected, (unsigned char)payload[i], seq_num);
            }
            return 0;
        }
    }
    return 1;
}

static void inject_noise_error(char *buffer, int size, uint32_t seq_num)
{
    if (!g_config.inject_error) {
        return;
    }
    
    if (seq_num % 100 == 0 && size > sizeof(rtt_perf_message_t)) {
        int payload_size = size - sizeof(rtt_perf_message_t);
        int error_offset = seq_num % payload_size;
        char *payload = buffer + sizeof(rtt_perf_message_t);
        payload[error_offset] ^= 0xFF;
        if (g_config.verbose) {
            printf("[NOISE] Injected error at offset %d for seq=%u\n", error_offset, seq_num);
        }
    }
}

static void calculate_statistics(rtt_result_t *results, int count, test_statistics_t *stats)
{
    if (count == 0) {
        memset(stats, 0, sizeof(test_statistics_t));
        return;
    }
    
    double *rtt_values = (double *)malloc(count * sizeof(double));
    if (!rtt_values) {
        memset(stats, 0, sizeof(test_statistics_t));
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
    
    qsort(rtt_values, count, sizeof(double), compare_double);
    
    stats->p50_rtt_us = rtt_values[count / 2];
    stats->p95_rtt_us = rtt_values[count * P95_PERCENTILE / 100];
    stats->p99_rtt_us = rtt_values[count * P99_PERCENTILE / 100];
    
    free(rtt_values);
}

static void print_statistics(const char *test_name, test_statistics_t *stats, double total_time_s)
{
    printf("\n==================================================\n");
    printf("%s\n", test_name);
    printf("==================================================\n");
    printf("| %-25s | %20.2f |\n", "Success count", (double)stats->success_count);
    printf("| %-25s | %20.2f |\n", "Timeout count", (double)stats->timeout_count);
    if (g_config.verify_mode) {
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
    printf("| %-25s | %20.2f |\n", "Average RTT (μs)", stats->avg_rtt_us);
    printf("| %-25s | %20.2f |\n", "Min RTT (μs)", stats->min_rtt_us);
    printf("| %-25s | %20.2f |\n", "Max RTT (μs)", stats->max_rtt_us);
    printf("| %-25s | %20.2f |\n", "P50 RTT (μs)", stats->p50_rtt_us);
    printf("| %-25s | %20.2f |\n", "P95 RTT (μs)", stats->p95_rtt_us);
    printf("| %-25s | %20.2f |\n", "P99 RTT (μs)", stats->p99_rtt_us);
    printf("| %-25s | %20.2f |\n", "Std Dev (μs)", stats->std_dev_us);
    printf("--------------------------------------------------\n");
    printf("| %-25s | %20s |\n", "Latency Breakdown", "");
    printf("| %-25s | %20.2f |\n", "Send Latency (μs)", stats->avg_send_latency_us);
    printf("| %-25s | %20.2f |\n", "Network Req (μs)", stats->avg_network_req_us);
    printf("| %-25s | %20.2f |\n", "Server Process (μs)", stats->avg_server_process_us);
    printf("| %-25s | %20.2f |\n", "Network Resp (μs)", stats->avg_network_resp_us);
    if (total_time_s > 0) {
        double throughput = stats->success_count / total_time_s;
        printf("--------------------------------------------------\n");
        printf("| %-25s | %20.2f |\n", "Total time (s)", total_time_s);
        printf("| %-25s | %20.2f |\n", "Throughput (req/s)", throughput);
    }
    printf("==================================================\n");
}

static void rtt_perf_msg_proc(unsigned int work_idx, ruid_type ruid, mes_msg_t* msg)
{
    if (msg == NULL || msg->buffer == NULL) {
        if (g_config.verbose) {
            fprintf(stderr, "Received NULL message\n");
        }
        return;
    }
    
    if (msg->size < sizeof(rtt_perf_message_t)) {
        if (g_config.verbose) {
            fprintf(stderr, "Message too small: %u bytes\n", msg->size);
        }
        return;
    }
    
    rtt_perf_message_t *rtt_msg = (rtt_perf_message_t *)msg->buffer;
    
    if (g_config.verbose) {
        printf("Received request: seq=%u, src_inst=%u, dst_inst=%u\n", 
               rtt_msg->seq_num, rtt_msg->src_inst, rtt_msg->dst_inst);
    }

    if (g_config.verify_mode) {
        if (!verify_payload_pattern(msg->buffer, msg->size, rtt_msg->seq_num)) {
            fprintf(stderr, "[VERIFY] Server: Payload verification failed for seq=%u\n", rtt_msg->seq_num);
        }
    }
    
    uint64_t recv_time = get_time_us();
    
    if (g_config.verify_mode && msg->size > (int)sizeof(rtt_perf_message_t)) {
        char *response_buf = (char *)malloc(msg->size);
        if (response_buf) {
            memcpy(response_buf, msg->buffer, msg->size);
            rtt_perf_message_t *reply = (rtt_perf_message_t *)response_buf;
            reply->recv_timestamp = recv_time;
            reply->reply_timestamp = get_time_us();
            
            mes_send_response(msg->src_inst, 0, ruid, response_buf, msg->size);
            free(response_buf);
        } else {
            rtt_perf_message_t reply;
            reply.seq_num = rtt_msg->seq_num;
            reply.src_inst = rtt_msg->src_inst;
            reply.dst_inst = rtt_msg->dst_inst;
            reply.send_timestamp = rtt_msg->send_timestamp;
            reply.recv_timestamp = recv_time;
            reply.reply_timestamp = get_time_us();
            mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(rtt_perf_message_t));
        }
    } else {
        rtt_perf_message_t reply;
        reply.seq_num = rtt_msg->seq_num;
        reply.src_inst = rtt_msg->src_inst;
        reply.dst_inst = rtt_msg->dst_inst;
        reply.send_timestamp = rtt_msg->send_timestamp;
        reply.recv_timestamp = recv_time;
        reply.reply_timestamp = get_time_us();
        
        mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(rtt_perf_message_t));
    }
    
    if (g_config.verbose) {
        printf("Sent response: seq=%u\n", rtt_msg->seq_num);
    }
}

static int setup_mes_profile(mes_profile_t *profile)
{
    memset(profile, 0, sizeof(mes_profile_t));
    
    profile->inst_id = g_config.local_inst_id;
    profile->inst_cnt = g_config.node_count;
    profile->pipe_type = g_config.pipe_type;
    
    int queue_multiplier = (g_config.thread_count > 1) ? g_config.thread_count : 1;
    int pool_size_multiplier = (g_config.thread_count > 1) ? g_config.thread_count : 1;
    
    profile->msg_pool_attr.total_size = 1024 * 1024 * 100 * pool_size_multiplier;
    profile->msg_pool_attr.enable_inst_dimension = 1;
    profile->msg_pool_attr.buf_pool_count = 3;
    
    profile->msg_pool_attr.buf_pool_attr[0].buf_size = 256;
    profile->msg_pool_attr.buf_pool_attr[0].proportion = 0.1;
    profile->msg_pool_attr.buf_pool_attr[0].priority_pool_attr[0].queue_num = 8 * queue_multiplier;
    profile->msg_pool_attr.buf_pool_attr[0].shared_pool_attr.queue_num = 8 * queue_multiplier;
    
    profile->msg_pool_attr.buf_pool_attr[1].buf_size = 512;
    profile->msg_pool_attr.buf_pool_attr[1].proportion = 0.1;
    profile->msg_pool_attr.buf_pool_attr[1].priority_pool_attr[0].queue_num = 8 * queue_multiplier;
    profile->msg_pool_attr.buf_pool_attr[1].shared_pool_attr.queue_num = 8 * queue_multiplier;
    
    profile->msg_pool_attr.buf_pool_attr[2].buf_size = 32768;
    profile->msg_pool_attr.buf_pool_attr[2].proportion = 0.8;
    profile->msg_pool_attr.buf_pool_attr[2].priority_pool_attr[0].queue_num = 8 * queue_multiplier;
    profile->msg_pool_attr.buf_pool_attr[2].shared_pool_attr.queue_num = 8 * queue_multiplier;
    
    profile->msg_pool_attr.max_buf_size[0] = 32768;
    profile->frag_size = 32832;
    
    profile->channel_cnt = g_config.channel_cnt;
    profile->priority_cnt = g_config.priority_cnt;
    
    for (unsigned int p = 0; p < g_config.priority_cnt; p++) {
        profile->recv_task_count[p] = g_config.recv_thread_cnt;
        profile->work_task_count[p] = g_config.work_thread_cnt;
    }
    
    profile->conn_created_during_init = 1;
    profile->tpool_attr.enable_threadpool = 0;
    
    profile->connect_timeout = 30000;
    profile->socket_timeout = 30000;
    profile->send_directly = g_config.send_directly;
    
    for (int i = 0; i < g_config.node_count; i++) {
        profile->inst_net_addr[i].inst_id = g_config.nodes[i].inst_id;
        snprintf(profile->inst_net_addr[i].ip, MES_MAX_IP_LEN, "%s", g_config.nodes[i].ip);
        profile->inst_net_addr[i].port = g_config.nodes[i].port;
        profile->inst_net_addr[i].need_connect = (g_config.nodes[i].inst_id != g_config.local_inst_id) ? 1 : 0;
    }
    
    return 0;
}

static void *worker_thread_func(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    
    char *buffer = (char *)malloc(g_config.message_size);
    if (!buffer) {
        fprintf(stderr, "Thread %d: Failed to allocate buffer\n", ctx->thread_id);
        return NULL;
    }
    
    memset(buffer, 0, g_config.message_size);
    rtt_perf_message_t *rtt_msg = (rtt_perf_message_t *)buffer;
    
    int local_success = 0;
    int local_timeout = 0;
    int local_checksum_failed = 0;
    
    for (int i = 0; i < ctx->count && g_running; i++) {
        int rtt_idx = ctx->start_idx + i;
        ruid_type ruid;
        rtt_msg->seq_num = rtt_idx;
        rtt_msg->src_inst = g_config.local_inst_id;
        rtt_msg->dst_inst = g_config.target_inst_id;
        rtt_msg->send_timestamp = get_time_us();
        
        if (g_config.verify_mode) {
            fill_verify_pattern(buffer, g_config.message_size, rtt_idx);
        }
        
        if (g_config.inject_error) {
            inject_noise_error(buffer, g_config.message_size, rtt_idx);
        }
        
        flag_type flag = 0;
        if (g_config.priority_hash && g_config.priority_cnt > 1) {
            flag = (flag_type)(rtt_idx % g_config.priority_cnt);
        }
        
        mes_msg_t response;
        int ret = mes_send_request(g_config.target_inst_id, flag, &ruid, buffer, g_config.message_size);
        uint64_t send_complete_time = get_time_us();
        
        if (ret != 0) {
            if (g_config.verbose) {
                fprintf(stderr, "Thread %d: Failed to send request %d: %d (errno=%d)\n", 
                        ctx->thread_id, rtt_idx, ret, errno);
            }
            local_timeout++;
            usleep(10000);
            continue;
        }
        
        ret = mes_get_response(ruid, &response, g_config.timeout_ms);
        uint64_t response_time = get_time_us();
        
        if (ret != 0) {
            if (g_config.verbose) {
                fprintf(stderr, "Thread %d: Timeout waiting for response %d\n", ctx->thread_id, rtt_idx);
            }
            local_timeout++;
            usleep(10000);
            continue;
        }
        
        if (response.buffer != NULL && response.size >= sizeof(rtt_perf_message_t)) {
            rtt_perf_message_t *resp_msg = (rtt_perf_message_t *)response.buffer;
            
            if (g_config.verify_mode) {
                if (!verify_payload_pattern(response.buffer, response.size, resp_msg->seq_num)) {
                    fprintf(stderr, "[VERIFY] Client: Response payload verification failed for seq=%u\n", resp_msg->seq_num);
                    local_checksum_failed++;
                }
            }
            
            pthread_mutex_lock(&ctx->mutex);
            ctx->results[local_success].rtt_us = response_time - rtt_msg->send_timestamp;
            ctx->results[local_success].send_timestamp = rtt_msg->send_timestamp;
            ctx->results[local_success].recv_timestamp = response_time;
            
            double send_latency = send_complete_time - rtt_msg->send_timestamp;
            double server_process = resp_msg->reply_timestamp - resp_msg->recv_timestamp;
            double network_latency = ctx->results[local_success].rtt_us - send_latency - server_process;
            
            ctx->results[local_success].send_latency_us = send_latency;
            ctx->results[local_success].network_req_us = network_latency / 2.0;
            ctx->results[local_success].server_process_us = server_process;
            ctx->results[local_success].network_resp_us = network_latency / 2.0;
            
            local_success++;
            pthread_mutex_unlock(&ctx->mutex);
            
            if (g_config.verbose && rtt_idx % 100 == 0) {
                printf("Thread %d: Request %d: RTT=%.2f μs\n", 
                       ctx->thread_id, rtt_idx, ctx->results[local_success - 1].rtt_us);
            }
        }
        
        mes_release_msg(&response);
    }
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->success_count = local_success;
    ctx->timeout_count = local_timeout;
    ctx->checksum_failed = local_checksum_failed;
    pthread_mutex_unlock(&ctx->mutex);
    
    free(buffer);
    return NULL;
}

static int run_client_test(void)
{
    rtt_result_t *results = (rtt_result_t *)calloc(g_config.test_count, sizeof(rtt_result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate RTT results array\n");
        return -1;
    }
    
    printf("\nStarting RTT performance test: Client -> Server\n");
    printf("Test count: %d, Message size: %d bytes, Threads: %d, Direct send: %s\n", 
           g_config.test_count, g_config.message_size, g_config.thread_count, 
           g_config.send_directly ? "enabled" : "disabled");
    fflush(stdout);
    
    pthread_t *threads = (pthread_t *)malloc(g_config.thread_count * sizeof(pthread_t));
    thread_context_t *contexts = (thread_context_t *)calloc(g_config.thread_count, sizeof(thread_context_t));
    
    if (!threads || !contexts) {
        fprintf(stderr, "Failed to allocate threads or contexts\n");
        free(results);
        free(threads);
        free(contexts);
        return -1;
    }
    
    int base_count = g_config.test_count / g_config.thread_count;
    int remainder = g_config.test_count % g_config.thread_count;
    int current_start = 0;
    
    uint64_t start_time = get_time_us();
    
    for (int i = 0; i < g_config.thread_count; i++) {
        contexts[i].thread_id = i;
        contexts[i].start_idx = current_start;
        contexts[i].count = base_count + (i < remainder ? 1 : 0);
        contexts[i].results = results + current_start;
        contexts[i].success_count = 0;
        contexts[i].timeout_count = 0;
        pthread_mutex_init(&contexts[i].mutex, NULL);
        
        current_start += contexts[i].count;
        
        if (pthread_create(&threads[i], NULL, worker_thread_func, &contexts[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(results);
            free(threads);
            free(contexts);
            return -1;
        }
    }
    
    int total_success = 0;
    int total_timeout = 0;
    
    for (int i = 0; i < g_config.thread_count; i++) {
        pthread_join(threads[i], NULL);
        total_success += contexts[i].success_count;
        total_timeout += contexts[i].timeout_count;
        pthread_mutex_destroy(&contexts[i].mutex);
        
        if (g_config.verbose) {
            printf("Thread %d: Success=%d, Timeout=%d, ChecksumFailed=%d\n", 
                   i, contexts[i].success_count, contexts[i].timeout_count, contexts[i].checksum_failed);
        }
    }
    
    uint64_t end_time = get_time_us();
    double total_time_s = (end_time - start_time) / 1000000.0;
    
    free(threads);
    free(contexts);
    
    int total_checksum_failed = 0;
    for (int i = 0; i < g_config.thread_count; i++) {
        total_checksum_failed += contexts[i].checksum_failed;
    }
    
    test_statistics_t stats;
    calculate_statistics(results, total_success, &stats);
    stats.success_count = total_success;
    stats.timeout_count = total_timeout;
    stats.checksum_failed = total_checksum_failed;
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "RTT Performance Test (%s): Client %d -> Server %d (%d threads)", 
             pipe_type_to_string(g_config.pipe_type),
             g_config.local_inst_id, g_config.target_inst_id, g_config.thread_count);
    print_statistics(test_name, &stats, total_time_s);
    
    free(results);
    return 0;
}

static int run_server_mode(void)
{
    printf("\nServer mode started. Waiting for client requests...\n");
    printf("Press Ctrl+C to stop.\n");
    
    while (g_running) {
        sleep(1);
    }
    
    printf("\nServer mode stopped.\n");
    return 0;
}

static void signal_handler(int sig)
{
    printf("\nReceived signal %d, stopping...\n", sig);
    g_running = 0;
}

static int parse_node_list(const char *node_list_str)
{
    char *str_copy = strdup(node_list_str);
    if (!str_copy) {
        return -1;
    }
    
    char *token = strtok(str_copy, ",");
    while (token != NULL && g_config.node_count < MAX_NODES) {
        char *id_str = token;
        char *ip_str = strchr(token, ':');
        char *port_str = NULL;
        
        if (ip_str) {
            *ip_str = '\0';
            ip_str++;
            port_str = strchr(ip_str, ':');
            if (port_str) {
                *port_str = '\0';
                port_str++;
            }
        }
        
        if (id_str && ip_str) {
            g_config.nodes[g_config.node_count].inst_id = atoi(id_str);
            snprintf(g_config.nodes[g_config.node_count].ip, MES_MAX_IP_LEN, "%s", ip_str);
            g_config.nodes[g_config.node_count].port = port_str ? atoi(port_str) : DEFAULT_PORT;
            g_config.node_count++;
        }
        
        token = strtok(NULL, ",");
    }
    
    free(str_copy);
    
    if (g_config.node_count == 0) {
        fprintf(stderr, "No valid nodes found in node list\n");
        return -1;
    }
    
    return 0;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nMulti-node RTT performance verification tool using MES\n\n");
    printf("Options:\n");
    printf("  -m, --mode MODE          Run mode: server|client (required)\n");
    printf("  -p, --pipe-type TYPE     Communication type: tcp|ipc|rdma (default: tcp)\n");
    printf("  -i, --inst-id ID         Local instance ID (required)\n");
    printf("      --target-id ID       Target instance ID (required for client mode)\n");
    printf("      --local-ip IP        Local IP address (default: 127.0.0.1)\n");
    printf("      --local-port PORT    Local port (default: %d)\n", DEFAULT_PORT);
    printf("      --nodes LIST          Node list format: id1:ip1:port1,id2:ip2:port2,...\n");
    printf("                           Example: 1:192.168.1.1:12345,2:192.168.1.2:12345\n");
    printf("  -c, --count COUNT        Number of test iterations (default: %d)\n", DEFAULT_TEST_COUNT);
    printf("  -s, --size SIZE          Message size in bytes (default: %d)\n", DEFAULT_MESSAGE_SIZE);
    printf("  -t, --threads COUNT       Number of concurrent threads (default: 1)\n");
    printf("  -d, --direct-send        Enable direct send mode (default: disabled)\n");
    printf("      --channel-cnt COUNT   MES channel count (default: 1)\n");
    printf("      --recv-threads COUNT  MES receive thread count per priority (default: 1)\n");
    printf("      --work-threads COUNT  MES work thread count per priority (default: 1)\n");
    printf("      --priority-cnt COUNT  Number of priorities to use (default: 1, max: 8)\n");
    printf("      --priority-hash       Enable priority hash distribution across queues\n");
    printf("  -T, --timeout MS         Response timeout in milliseconds (default: 5000)\n");
    printf("  -V, --verify             Enable payload verification (checksum)\n");
    printf("  -E, --inject-error       Inject noise errors for testing verification (every 100 msgs)\n");
    printf("  -v, --verbose            Enable verbose output\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExamples:\n");
    printf("  # IPC mode test (same node, requires server and client in separate terminals)\n");
    printf("  Terminal 1: %s -m server -p ipc -i 1\n", prog_name);
    printf("  Terminal 2: %s -m client -p ipc -i 2 --target-id 1 -c 1000 -s 64\n", prog_name);
    printf("\n  # TCP mode test (cross-node)\n");
    printf("  %s -m server -p tcp -i 1 --nodes 1:192.168.1.1:12345,2:192.168.1.2:12345\n", prog_name);
    printf("  %s -m client -p tcp -i 2 --nodes 1:192.168.1.1:12345,2:192.168.1.2:12345 -c 1000\n", prog_name);
    printf("\n  # Direct send mode test\n");
    printf("  %s -m client -p ipc -i 2 --target-id 1 -c 1000 -s 64 -d\n", prog_name);
    printf("\n  # Test with payload verification\n");
    printf("  %s -m client -p ipc -i 2 --target-id 1 -c 1000 -s 8192 -V\n", prog_name);
    printf("\n  # Test with payload verification and error injection\n");
    printf("  %s -m client -p ipc -i 2 --target-id 1 -c 1000 -s 8192 -V -E\n", prog_name);
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"pipe-type", required_argument, 0, 'p'},
        {"inst-id", required_argument, 0, 'i'},
        {"local-ip", required_argument, 0, 1001},
        {"local-port", required_argument, 0, 1002},
        {"target-id", required_argument, 0, 1003},
        {"target-ip", required_argument, 0, 1004},
        {"target-port", required_argument, 0, 1005},
        {"nodes", required_argument, 0, 1006},
        {"count", required_argument, 0, 'c'},
        {"size", required_argument, 0, 's'},
        {"threads", required_argument, 0, 't'},
        {"direct-send", no_argument, 0, 'd'},
        {"channel-cnt", required_argument, 0, 1007},
        {"recv-threads", required_argument, 0, 1008},
        {"work-threads", required_argument, 0, 1009},
        {"priority-cnt", required_argument, 0, 1010},
        {"priority-hash", no_argument, 0, 1011},
        {"timeout", required_argument, 0, 'T'},
        {"verify", no_argument, 0, 'V'},
        {"inject-error", no_argument, 0, 'E'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    g_config.test_count = DEFAULT_TEST_COUNT;
    g_config.message_size = DEFAULT_MESSAGE_SIZE;
    g_config.thread_count = 1;
    g_config.timeout_ms = 5000;
    g_config.verbose = 0;
    g_config.verify_mode = 0;
    g_config.inject_error = 0;
    g_config.node_count = 0;
    g_config.pipe_type = MES_TYPE_TCP;
    g_config.channel_cnt = 1;
    g_config.recv_thread_cnt = 1;
    g_config.work_thread_cnt = 1;
    g_config.priority_cnt = 1;
    g_config.priority_hash = 0;
    g_config.send_directly = 0;
    snprintf(g_config.local_ip, MES_MAX_IP_LEN, "127.0.0.1");
    g_config.local_port = DEFAULT_PORT;
    
    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:i:c:s:t:dT:VEvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "server") == 0) {
                    g_config.mode = MODE_SERVER;
                } else if (strcmp(optarg, "client") == 0) {
                    g_config.mode = MODE_CLIENT;
                } else {
                    fprintf(stderr, "Invalid mode: %s\n", optarg);
                    return -1;
                }
                break;
            case 'd':
                g_config.send_directly = 1;
                break;
            case 'p':
                if (strcmp(optarg, "tcp") == 0) {
                    g_config.pipe_type = MES_TYPE_TCP;
                } else if (strcmp(optarg, "ipc") == 0) {
                    g_config.pipe_type = MES_TYPE_IPC;
                } else if (strcmp(optarg, "rdma") == 0) {
                    g_config.pipe_type = MES_TYPE_RDMA;
                } else {
                    fprintf(stderr, "Invalid pipe type: %s\n", optarg);
                    return -1;
                }
                break;
            case 'i':
                g_config.local_inst_id = atoi(optarg);
                break;
            case 1001:
                snprintf(g_config.local_ip, MES_MAX_IP_LEN, "%s", optarg);
                break;
            case 1002:
                g_config.local_port = atoi(optarg);
                break;
            case 1003:
                g_config.target_inst_id = atoi(optarg);
                break;
            case 1004:
                snprintf(g_config.target_ip, MES_MAX_IP_LEN, "%s", optarg);
                break;
            case 1005:
                g_config.target_port = atoi(optarg);
                break;
            case 1006:
                if (parse_node_list(optarg) != 0) {
                    return -1;
                }
                break;
            case 'c':
                g_config.test_count = atoi(optarg);
                if (g_config.test_count <= 0) {
                    fprintf(stderr, "Invalid test count: %s\n", optarg);
                    return -1;
                }
                break;
            case 's':
                g_config.message_size = atoi(optarg);
                if (g_config.message_size <= 0 || g_config.message_size > MAX_MESSAGE_SIZE) {
                    fprintf(stderr, "Invalid message size: %s\n", optarg);
                    return -1;
                }
                break;
            case 't':
                g_config.thread_count = atoi(optarg);
                if (g_config.thread_count <= 0 || g_config.thread_count > 64) {
                    fprintf(stderr, "Invalid thread count: %s (must be 1-64)\n", optarg);
                    return -1;
                }
                break;
            case 1007:
                g_config.channel_cnt = atoi(optarg);
                if (g_config.channel_cnt <= 0 || g_config.channel_cnt > 256) {
                    fprintf(stderr, "Invalid channel count: %s (must be 1-256)\n", optarg);
                    return -1;
                }
                break;
            case 1008:
                g_config.recv_thread_cnt = atoi(optarg);
                if (g_config.recv_thread_cnt <= 0 || g_config.recv_thread_cnt > 128) {
                    fprintf(stderr, "Invalid recv thread count: %s (must be 1-128)\n", optarg);
                    return -1;
                }
                break;
            case 1009:
                g_config.work_thread_cnt = atoi(optarg);
                if (g_config.work_thread_cnt <= 0 || g_config.work_thread_cnt > 128) {
                    fprintf(stderr, "Invalid work thread count: %s (must be 1-128)\n", optarg);
                    return -1;
                }
                break;
            case 1010:
                g_config.priority_cnt = atoi(optarg);
                if (g_config.priority_cnt <= 0 || g_config.priority_cnt > 8) {
                    fprintf(stderr, "Invalid priority count: %s (must be 1-8)\n", optarg);
                    return -1;
                }
                break;
            case 1011:
                g_config.priority_hash = 1;
                break;
            case 'T':
                g_config.timeout_ms = atoi(optarg);
                if (g_config.timeout_ms <= 0) {
                    fprintf(stderr, "Invalid timeout: %s\n", optarg);
                    return -1;
                }
                break;
            case 'V':
                g_config.verify_mode = 1;
                break;
            case 'E':
                g_config.inject_error = 1;
                break;
            case 'v':
                g_config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    if (g_config.local_inst_id == 0) {
        fprintf(stderr, "Local instance ID is required\n");
        print_usage(argv[0]);
        return -1;
    }
    
    if (g_config.node_count == 0) {
        if (g_config.mode == MODE_CLIENT) {
            if (g_config.target_inst_id == 0) {
                fprintf(stderr, "Target instance ID is required for client mode\n");
                print_usage(argv[0]);
                return -1;
            }
            
            if (g_config.pipe_type != MES_TYPE_IPC) {
                if (strlen(g_config.target_ip) == 0) {
                    fprintf(stderr, "Target IP is required for client mode (TCP/RDMA)\n");
                    print_usage(argv[0]);
                    return -1;
                }
                if (g_config.target_port == 0) {
                    fprintf(stderr, "Target port is required for client mode (TCP/RDMA)\n");
                    print_usage(argv[0]);
                    return -1;
                }
            }
            
            g_config.node_count = 2;
            g_config.nodes[0].inst_id = g_config.local_inst_id;
            snprintf(g_config.nodes[0].ip, MES_MAX_IP_LEN, "%s", g_config.local_ip);
            g_config.nodes[0].port = g_config.local_port;
            
            g_config.nodes[1].inst_id = g_config.target_inst_id;
            snprintf(g_config.nodes[1].ip, MES_MAX_IP_LEN, "%s", g_config.target_ip);
            g_config.nodes[1].port = g_config.target_port;
        } else {
            g_config.node_count = 1;
            g_config.nodes[0].inst_id = g_config.local_inst_id;
            snprintf(g_config.nodes[0].ip, MES_MAX_IP_LEN, "%s", g_config.local_ip);
            g_config.nodes[0].port = g_config.local_port;
        }
    } else {
        if (g_config.mode == MODE_CLIENT && g_config.target_inst_id == 0) {
            for (int i = 0; i < g_config.node_count; i++) {
                if (g_config.nodes[i].inst_id != g_config.local_inst_id) {
                    g_config.target_inst_id = g_config.nodes[i].inst_id;
                    break;
                }
            }
        }
    }
    
    if (g_config.message_size < sizeof(rtt_perf_message_t)) {
        fprintf(stderr, "Message size %d is too small, minimum required: %zu bytes\n", 
                g_config.message_size, sizeof(rtt_perf_message_t));
        fprintf(stderr, "Auto-adjusting message size to %zu bytes\n", sizeof(rtt_perf_message_t));
        g_config.message_size = sizeof(rtt_perf_message_t);
    }
    
    int local_node_found = 0;
    for (int i = 0; i < g_config.node_count; i++) {
        if (g_config.nodes[i].inst_id == g_config.local_inst_id) {
            local_node_found = 1;
            break;
        }
    }
    
    if (!local_node_found) {
        fprintf(stderr, "Local instance ID %d not found in node list\n", g_config.local_inst_id);
        return -1;
    }
    
    if (g_config.mode == MODE_CLIENT) {
        int target_found = 0;
        for (int i = 0; i < g_config.node_count; i++) {
            if (g_config.nodes[i].inst_id == g_config.target_inst_id) {
                target_found = 1;
                break;
            }
        }
        
        if (!target_found) {
            fprintf(stderr, "Target instance ID %d not found in node list\n", g_config.target_inst_id);
            return -1;
        }
    }
    
    return 0;
}

static void print_config(void)
{
    unsigned short local_port = g_config.local_port;
    unsigned short target_port = g_config.target_port;
    
    for (int i = 0; i < g_config.node_count; i++) {
        if (g_config.nodes[i].inst_id == g_config.local_inst_id) {
            local_port = g_config.nodes[i].port;
        }
        if (g_config.nodes[i].inst_id == g_config.target_inst_id) {
            target_port = g_config.nodes[i].port;
        }
    }
    
    printf("\n========================================\n");
    printf("MES RTT Performance Test Configuration\n");
    printf("========================================\n");
    printf("Mode: %s\n", g_config.mode == MODE_SERVER ? "Server" : "Client");
    printf("Pipe Type: %s\n", pipe_type_to_string(g_config.pipe_type));
    printf("Local instance ID: %d\n", g_config.local_inst_id);
    printf("Local IP: %s\n", g_config.local_ip);
    printf("Local port: %d\n", local_port);
    printf("MES Channel count: %d\n", g_config.channel_cnt);
    printf("MES Recv threads: %d\n", g_config.recv_thread_cnt);
    printf("MES Work threads: %d\n", g_config.work_thread_cnt);
    printf("MES Priority count: %d\n", g_config.priority_cnt);
    printf("Priority hash: %s\n", g_config.priority_hash ? "enabled" : "disabled");
    printf("Verify mode: %s\n", g_config.verify_mode ? "enabled" : "disabled");
    printf("Inject error: %s\n", g_config.inject_error ? "enabled" : "disabled");
    if (g_config.mode == MODE_CLIENT) {
        printf("Target instance ID: %d\n", g_config.target_inst_id);
        printf("Target IP: %s\n", g_config.target_ip);
        printf("Target port: %d\n", target_port);
        printf("Test count: %d\n", g_config.test_count);
        printf("Message size: %d bytes\n", g_config.message_size);
        printf("Thread count: %d\n", g_config.thread_count);
        printf("Timeout: %d ms\n", g_config.timeout_ms);
    }
    printf("========================================\n");
}

int main(int argc, char *argv[])
{
    if (parse_arguments(argc, argv) != 0) {
        return 1;
    }
    
    print_config();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    mes_profile_t profile;
    if (setup_mes_profile(&profile) != 0) {
        fprintf(stderr, "Failed to setup MES profile\n");
        return 1;
    }
    
    printf("\nInitializing MES...\n");
    mes_register_proc_func(rtt_perf_msg_proc);
    
    int ret = mes_init(&profile);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize MES: %d\n", ret);
        return 1;
    }
    
    printf("MES initialized successfully\n");
    
    if (g_config.verbose) {
        mes_init_log();
        mes_register_log_output(mes_log_output);
    }
    
    if (g_config.mode == MODE_CLIENT) {
        printf("\nWaiting for connection to server...\n");
        int wait_count = 0;
        while (!mes_connection_ready(g_config.target_inst_id) && wait_count < 600) {
            usleep(100000);
            wait_count++;
            if (wait_count % 10 == 0) {
                printf("Waiting for connection... %d seconds\n", wait_count / 10);
            }
        }
        
        if (mes_connection_ready(g_config.target_inst_id)) {
            printf("Connected to server %d\n", g_config.target_inst_id);
        } else {
            fprintf(stderr, "Timeout waiting for connection to server %d\n", g_config.target_inst_id);
            mes_uninit();
            return 1;
        }
        
        printf("Waiting 1 second before starting test...\n");
        sleep(1);
        
        printf("\nStarting RTT performance test...\n");
        fflush(stdout);
        if (run_client_test() != 0) {
            fprintf(stderr, "RTT performance test failed\n");
            mes_uninit();
            return 1;
        }
    } else {
        if (run_server_mode() != 0) {
            fprintf(stderr, "Server mode failed\n");
            mes_uninit();
            return 1;
        }
    }
    
    printf("\nCleaning up...\n");
    mes_uninit();
    
    printf("RTT performance test completed!\n");
    return 0;
}
