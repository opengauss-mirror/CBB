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
 * mes_benchmark.c
 *
 *
 * IDENTIFICATION
 *    src/cm_mes/benchmark/mes_benchmark.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>

#include "../mes_interface.h"
#include "../mes_type.h"

#define BENCHMARK_INST_ID_1 1
#define BENCHMARK_INST_ID_2 2
#define BENCHMARK_PORT 12345
#define LATENCY_MESSAGE_SIZE 64
#define BANDWIDTH_MESSAGE_SIZE (16 * 1024)
#define LATENCY_TEST_COUNT 1000
#define MAX_MESSAGE_SIZE (64 * 1024)
#define P99_PERCENTILE 99
#define P95_PERCENTILE 95

typedef enum {
    TEST_MODE_SEND_ONLY,
    TEST_MODE_REQUEST_RESPONSE
} test_mode_t;

typedef struct {
    volatile int received_count;
    volatile int benchmark_done;
    volatile int validation_failed;
    volatile uint64_t send_timestamps[LATENCY_TEST_COUNT];
    volatile uint64_t recv_timestamps[LATENCY_TEST_COUNT];
    volatile double total_send_latency;
    volatile double total_recv_latency;
} shared_state_t;

typedef struct {
    uint32_t seq_num;
    inst_type src_inst;
    inst_type dst_inst;
    uint64_t send_timestamp;
    uint64_t recv_timestamp;
    uint64_t reply_timestamp;
} benchmark_message_t;

typedef struct {
    double rtt_us;
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
    int success_count;
    int timeout_count;
} test_statistics_t;

static shared_state_t *g_shared_state = NULL;
static test_mode_t g_test_mode = TEST_MODE_REQUEST_RESPONSE;
static mes_pipe_type_t g_pipe_type = MES_TYPE_IPC;
static int g_verbose = 0;
static int g_test_count = LATENCY_TEST_COUNT;
static int g_message_size = LATENCY_MESSAGE_SIZE;
static int g_timeout_ms = 5000;

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

static double get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
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
    stats->min_rtt_us = results[0].rtt_us;
    stats->max_rtt_us = results[0].rtt_us;
    
    for (int i = 0; i < count; i++) {
        rtt_values[i] = results[i].rtt_us;
        sum += results[i].rtt_us;
        sum_sq += results[i].rtt_us * results[i].rtt_us;
        
        if (results[i].rtt_us < stats->min_rtt_us) {
            stats->min_rtt_us = results[i].rtt_us;
        }
        if (results[i].rtt_us > stats->max_rtt_us) {
            stats->max_rtt_us = results[i].rtt_us;
        }
    }
    
    stats->avg_rtt_us = sum / count;
    stats->std_dev_us = sqrt((sum_sq / count) - (stats->avg_rtt_us * stats->avg_rtt_us));
    
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
    printf("| %-25s | %20d |\n", "Success count", stats->success_count);
    printf("| %-25s | %20d |\n", "Timeout count", stats->timeout_count);
    printf("| %-25s | %20.2f |\n", "Average RTT (μs)", stats->avg_rtt_us);
    printf("| %-25s | %20.2f |\n", "Min RTT (μs)", stats->min_rtt_us);
    printf("| %-25s | %20.2f |\n", "Max RTT (μs)", stats->max_rtt_us);
    printf("| %-25s | %20.2f |\n", "P50 RTT (μs)", stats->p50_rtt_us);
    printf("| %-25s | %20.2f |\n", "P95 RTT (μs)", stats->p95_rtt_us);
    printf("| %-25s | %20.2f |\n", "P99 RTT (μs)", stats->p99_rtt_us);
    printf("| %-25s | %20.2f |\n", "Std Dev (μs)", stats->std_dev_us);
    if (total_time_s > 0) {
        double throughput = stats->success_count / total_time_s;
        printf("| %-25s | %20.2f |\n", "Total time (s)", total_time_s);
        printf("| %-25s | %20.2f |\n", "Throughput (req/s)", throughput);
    }
    printf("==================================================\n");
}

static void benchmark_msg_proc(unsigned int work_idx, ruid_type ruid, mes_msg_t* msg)
{
    if (msg == NULL || msg->buffer == NULL) {
        fprintf(stderr, "Received NULL message\n");
        return;
    }
    
    if (msg->size < sizeof(uint32_t)) {
        fprintf(stderr, "Message too small: %u bytes\n", msg->size);
        if (g_shared_state != NULL) {
            g_shared_state->validation_failed = 1;
        }
        return;
    }
    
    benchmark_message_t *bench_msg = (benchmark_message_t *)msg->buffer;
    
    if (g_verbose) {
        printf("Received message: seq=%u, src_inst=%u, dst_inst=%u\n", 
               bench_msg->seq_num, bench_msg->src_inst, bench_msg->dst_inst);
    }

    if (g_test_mode == TEST_MODE_REQUEST_RESPONSE) {
        uint64_t recv_time = get_time_us();
        
        benchmark_message_t reply;
        reply.seq_num = bench_msg->seq_num;
        reply.src_inst = bench_msg->src_inst;
        reply.dst_inst = bench_msg->dst_inst;
        reply.send_timestamp = bench_msg->send_timestamp;
        reply.recv_timestamp = recv_time;
        reply.reply_timestamp = get_time_us();
        
        mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(benchmark_message_t));
        
        if (g_verbose) {
            printf("Sent response: seq=%u\n", reply.seq_num);
        }
    } else {
        if (g_shared_state != NULL) {
            uint64_t recv_complete_time = get_time_ms();
            g_shared_state->recv_timestamps[bench_msg->seq_num] = recv_complete_time;
            g_shared_state->received_count++;
        }
    }
}

static void setup_mes_profile(mes_profile_t *profile, inst_type inst_id, mes_pipe_type_t pipe_type)
{
    memset(profile, 0, sizeof(mes_profile_t));
    
    profile->inst_id = inst_id;
    profile->inst_cnt = 2;
    profile->pipe_type = pipe_type;
    
    profile->msg_pool_attr.total_size = 1024 * 1024 * 100;
    profile->msg_pool_attr.enable_inst_dimension = 1;
    profile->msg_pool_attr.buf_pool_count = 2;
    
    profile->msg_pool_attr.buf_pool_attr[0].buf_size = 1024;
    profile->msg_pool_attr.buf_pool_attr[0].proportion = 0.5;
    profile->msg_pool_attr.buf_pool_attr[0].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[0].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.buf_pool_attr[1].buf_size = 64 * 1024;
    profile->msg_pool_attr.buf_pool_attr[1].proportion = 0.5;
    profile->msg_pool_attr.buf_pool_attr[1].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[1].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.max_buf_size[0] = 64 * 1024;
    /*
     * mes_send_* checks head->size against MES_MESSAGE_BUFFER_SIZE(profile),
     * which is derived from profile->frag_size. If frag_size is left as 0,
     * any payload larger than MES_MESSAGE_TINY_SIZE will be rejected with
     * ERR_MES_MSG_TOO_LARGE.
     */
    profile->frag_size = profile->msg_pool_attr.max_buf_size[0] + (unsigned int)sizeof(mes_message_head_t);
    
    profile->channel_cnt = 1;
    profile->priority_cnt = 1;
    
    profile->conn_created_during_init = 1;
    profile->tpool_attr.enable_threadpool = 0;
    
    profile->connect_timeout = 30000;
    profile->socket_timeout = 30000;
    
    profile->inst_net_addr[0].inst_id = BENCHMARK_INST_ID_1;
    snprintf(profile->inst_net_addr[0].ip, MES_MAX_IP_LEN, "127.0.0.1");
    profile->inst_net_addr[0].port = BENCHMARK_PORT;
    profile->inst_net_addr[0].need_connect = (inst_id == BENCHMARK_INST_ID_1) ? 0 : 1;
    
    profile->inst_net_addr[1].inst_id = BENCHMARK_INST_ID_2;
    snprintf(profile->inst_net_addr[1].ip, MES_MAX_IP_LEN, "127.0.0.1");
    profile->inst_net_addr[1].port = BENCHMARK_PORT + 1;
    profile->inst_net_addr[1].need_connect = (inst_id == BENCHMARK_INST_ID_2) ? 0 : 1;
}

static int run_request_response_test(inst_type dest_inst)
{
    rtt_result_t *results = (rtt_result_t *)calloc(g_test_count, sizeof(rtt_result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate RTT results array\n");
        return -1;
    }
    
    char *buffer = (char *)malloc(g_message_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for request-response test\n");
        free(results);
        return -1;
    }
    
    memset(buffer, 0, g_message_size);
    benchmark_message_t *bench_msg = (benchmark_message_t *)buffer;
    
    int success_count = 0;
    int timeout_count = 0;
    
    printf("\nStarting Request-Response Test: Instance %d -> Instance %d\n", 
           BENCHMARK_INST_ID_1, dest_inst);
    printf("Test count: %d, Message size: %d bytes, Timeout: %d ms\n", 
           g_test_count, g_message_size, g_timeout_ms);
    
    uint64_t start_time = get_time_us();
    
    for (int i = 0; i < g_test_count; i++) {
        ruid_type ruid;
        bench_msg->seq_num = i;
        bench_msg->src_inst = BENCHMARK_INST_ID_1;
        bench_msg->dst_inst = dest_inst;
        bench_msg->send_timestamp = get_time_us();
        
        int ret = mes_send_request(dest_inst, 0, &ruid, buffer, g_message_size);
        
        if (ret != 0) {
            if (g_verbose) {
                fprintf(stderr, "Failed to send request %d: %d (errno=%d)\n", i, ret, errno);
            }
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        mes_msg_t response;
        ret = mes_get_response(ruid, &response, g_timeout_ms);
        uint64_t response_time = get_time_us();
        
        if (ret != 0) {
            if (g_verbose) {
                fprintf(stderr, "Timeout waiting for response %d\n", i);
            }
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        if (response.buffer != NULL && response.size >= sizeof(benchmark_message_t)) {
            benchmark_message_t *resp_msg = (benchmark_message_t *)response.buffer;
            
            results[success_count].rtt_us = response_time - bench_msg->send_timestamp;
            results[success_count].send_timestamp = bench_msg->send_timestamp;
            results[success_count].recv_timestamp = response_time;
            success_count++;
            
            if (g_verbose && i % 100 == 0) {
                printf("Request %d: RTT=%.2f μs\n", i, results[success_count - 1].rtt_us);
            }
        }
        
        mes_release_msg(&response);
    }
    
    uint64_t end_time = get_time_us();
    double total_time_s = (end_time - start_time) / 1000000.0;
    
    test_statistics_t stats;
    calculate_statistics(results, success_count, &stats);
    stats.success_count = success_count;
    stats.timeout_count = timeout_count;
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "Request-Response Test (Pipe Type: %d)", g_pipe_type);
    print_statistics(test_name, &stats, total_time_s);
    
    free(results);
    free(buffer);
    return 0;
}

static int run_bidirectional_latency_test(inst_type dest_inst)
{
    char *buffer = (char *)malloc(g_message_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for latency test\n");
        return -1;
    }
    
    memset(buffer, 0, g_message_size);
    uint32_t *seq_num = (uint32_t *)buffer;
    
    if (g_shared_state != NULL) {
        g_shared_state->received_count = 0;
        g_shared_state->validation_failed = 0;
    }
    
    double start_time = get_time_ms();
    double *latencies = (double *)malloc(g_test_count * sizeof(double));
    if (!latencies) {
        fprintf(stderr, "Failed to allocate latency array\n");
        free(buffer);
        return -1;
    }
    
    for (int i = 0; i < g_test_count; i++) {
        *seq_num = i;
        
        double send_time = get_time_ms();
        g_shared_state->send_timestamps[i] = send_time;
        int gret = mes_send_data(dest_inst, 0, buffer, g_message_size);
        double send_complete_time = get_time_ms();
        
        if (gret != 0) {
            fprintf(stderr, "Failed to send message %d: %d (errno=%d)\n", i, gret, errno);
            free(latencies);
            free(buffer);
            return -1;
        }
        
        while (g_shared_state != NULL && g_shared_state->received_count <= i) {
        }
        
        double recv_time = get_time_ms();
        latencies[i] = recv_time - send_time;
        
        if (g_shared_state != NULL) {
            g_shared_state->total_send_latency += (send_complete_time - send_time);
            g_shared_state->total_recv_latency += (g_shared_state->recv_timestamps[i] - g_shared_state->send_timestamps[i]);
        }
        
        if (i % 1000 == 0) {
            printf("Sent %d messages...\n", i + 1);
        }
    }
    
    double end_time = get_time_ms();
    double total_time = end_time - start_time;
    
    double min_latency = latencies[0];
    double max_latency = latencies[0];
    double sum_latency = 0.0;
    
    for (int i = 0; i < g_test_count; i++) {
        if (latencies[i] < min_latency) min_latency = latencies[i];
        if (latencies[i] > max_latency) max_latency = latencies[i];
        sum_latency += latencies[i];
    }
    
    double avg_latency = sum_latency / g_test_count;
    
    printf("\n========================================\n");
    printf("Bidirectional Latency Test Results\n");
    printf("========================================\n");
    printf("| %-25s | %-20s |\n", "Metric", "Value");
    printf("-------------------------------------------\n");
    printf("| %-25s | %-20d |\n", "Messages sent", g_test_count);
    printf("| %-25s | %-20d |\n", "Message size (bytes)", g_message_size);
    printf("| %-25s | %-20.2f |\n", "Total time (ms)", total_time);
    printf("| %-25s | %-20.2f |\n", "Average latency (μs)", avg_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Min latency (μs)", min_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Max latency (μs)", max_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Throughput (msg/s)", g_test_count / (total_time / 1000.0));
    
    if (g_shared_state != NULL) {
        double avg_send_latency = g_shared_state->total_send_latency / g_test_count;
        double avg_recv_latency = g_shared_state->total_recv_latency / g_test_count;
        printf("-------------------------------------------\n");
        printf("| %-25s | %-20.2f |\n", "Avg send latency (μs)", avg_send_latency * 1000);
        printf("| %-25s | %-20.2f |\n", "Avg recv latency (μs)", avg_recv_latency * 1000);
    }
    
    if (g_shared_state != NULL && g_shared_state->validation_failed) {
        printf("-------------------------------------------\n");
        printf("| %-25s | %-20s |\n", "WARNING", "Some messages failed validation!");
    }
    printf("========================================\n");
    
    free(latencies);
    free(buffer);
    return 0;
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

static int run_benchmark(mes_pipe_type_t pipe_type)
{
    printf("[DEBUG] Starting benchmark with pipe type: %s (%d)\n", 
           pipe_type_to_string(pipe_type), pipe_type);
    
    int shm_fd = shm_open("/mes_benchmark_shm", O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        fprintf(stderr, "Failed to create shared memory: %s\n", strerror(errno));
        return -1;
    }
    
    if (ftruncate(shm_fd, sizeof(shared_state_t)) == -1) {
        fprintf(stderr, "Failed to set shared memory size: %s\n", strerror(errno));
        close(shm_fd);
        shm_unlink("/mes_benchmark_shm");
        return -1;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to fork process\n");
        close(shm_fd);
        shm_unlink("/mes_benchmark_shm");
        return -1;
    }
    
    if (pid == 0) {
        g_shared_state = (shared_state_t *)mmap(NULL, sizeof(shared_state_t), 
                                             PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (g_shared_state == MAP_FAILED) {
            fprintf(stderr, "Failed to map shared memory in child: %s\n", strerror(errno));
            exit(1);
        }
        
        g_shared_state->received_count = 0;
        g_shared_state->benchmark_done = 0;
        g_shared_state->validation_failed = 0;
        g_shared_state->total_send_latency = 0.0;
        g_shared_state->total_recv_latency = 0.0;
        
        close(shm_fd);
        
        printf("[DEBUG] Child process (Instance %d) starting\n", BENCHMARK_INST_ID_2);
        mes_profile_t profile;
        setup_mes_profile(&profile, BENCHMARK_INST_ID_2, pipe_type);
        
        printf("[DEBUG] Child process: registering proc func\n");
        mes_register_proc_func(benchmark_msg_proc);
        
        printf("[DEBUG] Child process: calling mes_init, pipe_type=%d\n", profile.pipe_type);
        int ret = mes_init(&profile);
        if (ret != 0) {
            fprintf(stderr, "Failed to initialize MES in child process: %d\n", ret);
            munmap(g_shared_state, sizeof(shared_state_t));
            exit(1);
        }
        
        printf("[DEBUG] Child process: MES initialized successfully\n");
        
        printf("[DEBUG] Child process: waiting for parent to finish\n");
        
        while (!g_shared_state->benchmark_done) {
            usleep(100000);
        }
        
        printf("[DEBUG] Child process: uninitializing MES\n");
        mes_uninit();
        munmap(g_shared_state, sizeof(shared_state_t));
        exit(0);
    } else {
        // 延后初始化，使两个进程日志错开
        sleep(1);
        g_shared_state = (shared_state_t *)mmap(NULL, sizeof(shared_state_t), 
                                             PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (g_shared_state == MAP_FAILED) {
            fprintf(stderr, "Failed to map shared memory in parent: %s\n", strerror(errno));
            close(shm_fd);
            shm_unlink("/mes_benchmark_shm");
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            return -1;
        }
        
        g_shared_state->received_count = 0;
        g_shared_state->benchmark_done = 0;
        g_shared_state->validation_failed = 0;
        g_shared_state->total_send_latency = 0.0;
        g_shared_state->total_recv_latency = 0.0;
        
        close(shm_fd);
        
        printf("[DEBUG] Parent process: waiting for child to initialize\n");
        
        printf("[DEBUG] Parent process (Instance %d) starting\n", BENCHMARK_INST_ID_1);
        mes_profile_t profile;
        setup_mes_profile(&profile, BENCHMARK_INST_ID_1, pipe_type);
        
        printf("[DEBUG] Parent process: registering proc func\n");
        mes_register_proc_func(benchmark_msg_proc);
        
        printf("[DEBUG] Parent process: calling mes_init\n");
        int ret = mes_init(&profile);
        if (ret != 0) {
            fprintf(stderr, "Failed to initialize MES in parent process: %d\n", ret);
            munmap(g_shared_state, sizeof(shared_state_t));
            shm_unlink("/mes_benchmark_shm");
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            return -1;
        }
        
        printf("[DEBUG] Parent process: MES initialized successfully\n");
        
        printf("[DEBUG] Parent process: waiting for connection to be ready\n");
        int wait_count = 0;
        while (!mes_connection_ready(BENCHMARK_INST_ID_2)) {
            usleep(100000);
            wait_count++;
            if (wait_count > 300) {
                fprintf(stderr, "Timeout waiting for connection\n");
                mes_uninit();
                munmap(g_shared_state, sizeof(shared_state_t));
                shm_unlink("/mes_benchmark_shm");
                kill(pid, SIGTERM);
                waitpid(pid, NULL, 0);
                return -1;
            }
        }
        printf("[DEBUG] Parent process: connection is ready\n");
        sleep(1);
        
        printf("\n========================================\n");
        printf("Instance 1 -> Instance 2 (A -> B)\n");
        printf("Pipe Type: %s\n", pipe_type_to_string(pipe_type));
        printf("Test Mode: %s\n", g_test_mode == TEST_MODE_REQUEST_RESPONSE ? "Request-Response" : "Send-Only");
        printf("========================================\n");
        
        if (g_test_mode == TEST_MODE_REQUEST_RESPONSE) {
            if (run_request_response_test(BENCHMARK_INST_ID_2) != 0) {
                mes_uninit();
                munmap(g_shared_state, sizeof(shared_state_t));
                shm_unlink("/mes_benchmark_shm");
                kill(pid, (int)SIGTERM);
                waitpid(pid, NULL, 0);
                return -1;
            }
        } else {
            if (run_bidirectional_latency_test(BENCHMARK_INST_ID_2) != 0) {
                mes_uninit();
                munmap(g_shared_state, sizeof(shared_state_t));
                shm_unlink("/mes_benchmark_shm");
                kill(pid, (int)SIGTERM);
                waitpid(pid, NULL, 0);
                return -1;
            }
        }
        
        g_shared_state->benchmark_done = 1;
        sleep(1);
        
        printf("[DEBUG] Parent process: uninitializing MES\n");
        mes_uninit();
        waitpid(pid, NULL, 0);
        
        munmap(g_shared_state, sizeof(shared_state_t));
        shm_unlink("/mes_benchmark_shm");
    }
    
    return 0;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nMES Communication Benchmark Tool\n\n");
    printf("Options:\n");
    printf("  -t, --type TYPE          Communication type: tcp|rdma|ipc (default: ipc)\n");
    printf("  -m, --mode MODE          Test mode: reqresp|sendonly (default: reqresp)\n");
    printf("  -c, --count COUNT        Number of test iterations (default: %d)\n", LATENCY_TEST_COUNT);
    printf("  -s, --size SIZE          Message size in bytes (default: %d)\n", LATENCY_MESSAGE_SIZE);
    printf("  -T, --timeout MS         Response timeout in milliseconds (default: 5000)\n");
    printf("  -v, --verbose            Enable verbose output\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExamples:\n");
    printf("  # IPC Request-Response test (default)\n");
    printf("  %s\n", prog_name);
    printf("\n  # TCP Request-Response test\n");
    printf("  %s -t tcp -m reqresp\n", prog_name);
    printf("\n  # RDMA Request-Response test with 10000 iterations\n");
    printf("  %s -t rdma -m reqresp -c 10000\n", prog_name);
    printf("\n  # IPC Send-Only test\n");
    printf("  %s -t ipc -m sendonly\n", prog_name);
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"mode", required_argument, 0, 'm'},
        {"count", required_argument, 0, 'c'},
        {"size", required_argument, 0, 's'},
        {"timeout", required_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "t:m:c:s:T:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                if (strcmp(optarg, "tcp") == 0) {
                    g_pipe_type = MES_TYPE_TCP;
                } else if (strcmp(optarg, "rdma") == 0) {
                    g_pipe_type = MES_TYPE_RDMA;
                } else if (strcmp(optarg, "ipc") == 0) {
                    g_pipe_type = MES_TYPE_IPC;
                } else {
                    fprintf(stderr, "Invalid pipe type: %s\n", optarg);
                    return -1;
                }
                break;
            case 'm':
                if (strcmp(optarg, "reqresp") == 0) {
                    g_test_mode = TEST_MODE_REQUEST_RESPONSE;
                } else if (strcmp(optarg, "sendonly") == 0) {
                    g_test_mode = TEST_MODE_SEND_ONLY;
                } else {
                    fprintf(stderr, "Invalid test mode: %s\n", optarg);
                    return -1;
                }
                break;
            case 'c':
                g_test_count = atoi(optarg);
                if (g_test_count <= 0) {
                    fprintf(stderr, "Invalid test count: %s\n", optarg);
                    return -1;
                }
                break;
            case 's':
                g_message_size = atoi(optarg);
                if (g_message_size <= 0 || g_message_size > MAX_MESSAGE_SIZE) {
                    fprintf(stderr, "Invalid message size: %s\n", optarg);
                    return -1;
                }
                break;
            case 'T':
                g_timeout_ms = atoi(optarg);
                if (g_timeout_ms <= 0) {
                    fprintf(stderr, "Invalid timeout: %s\n", optarg);
                    return -1;
                }
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    if (g_message_size < sizeof(benchmark_message_t)) {
        fprintf(stderr, "Message size %d is too small, minimum required: %zu bytes\n", 
                g_message_size, sizeof(benchmark_message_t));
        fprintf(stderr, "Auto-adjusting message size to %zu bytes\n", sizeof(benchmark_message_t));
        g_message_size = sizeof(benchmark_message_t);
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_arguments(argc, argv) != 0) {
        return 1;
    }
    
    printf("MES Communication Benchmark\n");
    printf("==========================\n");
    printf("Pipe Type: %s\n", pipe_type_to_string(g_pipe_type));
    printf("Test Mode: %s\n", g_test_mode == TEST_MODE_REQUEST_RESPONSE ? "Request-Response" : "Send-Only");
    printf("Test Count: %d\n", g_test_count);
    printf("Message Size: %d bytes\n", g_message_size);
    if (g_test_mode == TEST_MODE_REQUEST_RESPONSE) {
        printf("Timeout: %d ms\n", g_timeout_ms);
    }
    printf("\n");
    
    if (g_verbose) {
        mes_init_log();
        mes_register_log_output(mes_log_output);
    }
    
    if (run_benchmark(g_pipe_type) != 0) {
        fprintf(stderr, "Benchmark failed\n");
        return 1;
    }
    
    printf("\nBenchmark completed successfully!\n");
    return 0;
}
