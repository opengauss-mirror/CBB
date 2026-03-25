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
 * MES communication benchmark tool
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
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#include "../mes_interface.h"
#include "../mes_type.h"
#include "benchmark_common.h"

#define BENCHMARK_INST_ID_1 1
#define BENCHMARK_INST_ID_2 2
#define BENCHMARK_PORT 12345
#define LATENCY_MESSAGE_SIZE 64
#define LATENCY_TEST_COUNT 1000
#define MAX_MESSAGE_SIZE (128 * 1024)
#define MAX_TEST_COUNT 100000

typedef enum {
    TEST_MODE_SEND_ONLY,
    TEST_MODE_REQUEST_RESPONSE
} test_mode_t;

typedef struct {
    volatile int received_count;
    volatile int benchmark_done;
    volatile int validation_failed;
    volatile int checksum_failed;
    volatile uint64_t send_timestamps[MAX_TEST_COUNT];
    volatile uint64_t recv_timestamps[MAX_TEST_COUNT];
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
    uint64_t reply_send_timestamp;
} benchmark_message_t;

typedef struct {
    test_mode_t test_mode;
    mes_pipe_type_t pipe_type;
    int verbose;
    int send_directly;
    int test_count;
    int message_size;
    int timeout_ms;
    benchmark_verify_config_t verify_config;
} benchmark_config_t;

static shared_state_t *g_shared_state = NULL;
static benchmark_config_t g_config = {
    .test_mode = TEST_MODE_REQUEST_RESPONSE,
    .pipe_type = MES_TYPE_IPC,
    .verbose = 0,
    .send_directly = 1,
    .test_count = LATENCY_TEST_COUNT,
    .message_size = LATENCY_MESSAGE_SIZE,
    .timeout_ms = 5000,
    .verify_config = {0, 0, 0}
};

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
    
    if (g_config.verbose) {
        printf("Received message: seq=%u, src_inst=%u, dst_inst=%u\n", 
               bench_msg->seq_num, bench_msg->src_inst, bench_msg->dst_inst);
    }

    if (!benchmark_verify_payload_pattern(msg->buffer, msg->size, bench_msg->seq_num,
        sizeof(benchmark_message_t), &g_config.verify_config)) {
        fprintf(stderr, "[VERIFY] Server: Payload verification failed for seq=%u\n", bench_msg->seq_num);
        if (g_shared_state != NULL) {
            __sync_fetch_and_add(&g_shared_state->checksum_failed, 1);
        }
    }

    if (g_config.test_mode == TEST_MODE_REQUEST_RESPONSE) {
        uint64_t recv_time = benchmark_get_time_us();
        
        if (g_config.verify_config.verify_mode && msg->size > (int)sizeof(benchmark_message_t)) {
            char *response_buf = (char *)malloc(msg->size);
            if (response_buf) {
                memcpy(response_buf, msg->buffer, msg->size);
                benchmark_message_t *reply = (benchmark_message_t *)response_buf;
                reply->recv_timestamp = recv_time;
                reply->reply_timestamp = benchmark_get_time_us();
                reply->reply_send_timestamp = benchmark_get_time_us();
                
                mes_send_response(msg->src_inst, 0, ruid, response_buf, msg->size);
                free(response_buf);
            } else {
                benchmark_message_t reply;
                reply.seq_num = bench_msg->seq_num;
                reply.src_inst = bench_msg->src_inst;
                reply.dst_inst = bench_msg->dst_inst;
                reply.send_timestamp = bench_msg->send_timestamp;
                reply.recv_timestamp = recv_time;
                reply.reply_timestamp = benchmark_get_time_us();
                reply.reply_send_timestamp = benchmark_get_time_us();
                mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(benchmark_message_t));
            }
        } else {
            benchmark_message_t reply;
            reply.seq_num = bench_msg->seq_num;
            reply.src_inst = bench_msg->src_inst;
            reply.dst_inst = bench_msg->dst_inst;
            reply.send_timestamp = bench_msg->send_timestamp;
            reply.recv_timestamp = recv_time;
            reply.reply_timestamp = benchmark_get_time_us();
            reply.reply_send_timestamp = benchmark_get_time_us();
            
            mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(benchmark_message_t));
        }
        
        if (g_config.verbose) {
            printf("Sent response: seq=%u\n", bench_msg->seq_num);
        }
    } else {
        if (g_shared_state != NULL) {
            uint64_t recv_complete_time = (uint64_t)(benchmark_get_time_ms() * 1000);
            g_shared_state->recv_timestamps[bench_msg->seq_num] = recv_complete_time;
            __sync_synchronize();
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
    
    profile->msg_pool_attr.buf_pool_attr[1].buf_size = 128 * 1024;
    profile->msg_pool_attr.buf_pool_attr[1].proportion = 0.5;
    profile->msg_pool_attr.buf_pool_attr[1].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[1].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.max_buf_size[0] = 128 * 1024;
    profile->frag_size = profile->msg_pool_attr.max_buf_size[0] + (unsigned int)sizeof(mes_message_head_t);
    
    profile->channel_cnt = 1;
    profile->priority_cnt = 1;
    
    profile->recv_task_count[0] = 1;
    profile->work_task_count[0] = 1;
    
    profile->conn_created_during_init = 1;
    profile->tpool_attr.enable_threadpool = 0;
    profile->send_directly = 1;
    
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
    benchmark_rtt_result_t *results = (benchmark_rtt_result_t *)calloc(g_config.test_count, sizeof(benchmark_rtt_result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate RTT results array\n");
        return -1;
    }
    
    char *buffer = (char *)malloc(g_config.message_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for request-response test\n");
        free(results);
        return -1;
    }
    
    memset(buffer, 0, g_config.message_size);
    benchmark_message_t *bench_msg = (benchmark_message_t *)buffer;
    
    int success_count = 0;
    int timeout_count = 0;
    int checksum_failed = 0;
    
    printf("\nStarting Request-Response Test: Instance %d -> Instance %d\n", 
           BENCHMARK_INST_ID_1, dest_inst);
    printf("Test count: %d, Message size: %d bytes, Timeout: %d ms\n", 
           g_config.test_count, g_config.message_size, g_config.timeout_ms);
    if (g_config.verify_config.verify_mode) {
        printf("Verify mode: ENABLED (payload checksum verification)\n");
    }
    
    uint64_t start_time = benchmark_get_time_us();
    
    for (int i = 0; i < g_config.test_count; i++) {
        ruid_type ruid;
        bench_msg->seq_num = i;
        bench_msg->src_inst = BENCHMARK_INST_ID_1;
        bench_msg->dst_inst = dest_inst;
        bench_msg->send_timestamp = benchmark_get_time_us();
        
        benchmark_fill_verify_pattern(buffer, g_config.message_size, i, 
            sizeof(benchmark_message_t), &g_config.verify_config);
        
        benchmark_inject_noise_error(buffer, g_config.message_size, i, 
            sizeof(benchmark_message_t), &g_config.verify_config);
        
        int ret = mes_send_request(dest_inst, 0, &ruid, buffer, g_config.message_size);
        uint64_t send_complete_time = benchmark_get_time_us();
        
        if (ret != 0) {
            if (g_config.verbose) {
                fprintf(stderr, "Failed to send request %d: %d (errno=%d)\n", i, ret, errno);
            }
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        mes_msg_t response;
        ret = mes_get_response(ruid, &response, g_config.timeout_ms);
        uint64_t response_time = benchmark_get_time_us();
        
        if (ret != 0) {
            if (g_config.verbose) {
                fprintf(stderr, "Timeout waiting for response %d\n", i);
            }
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        if (response.buffer != NULL && response.size >= sizeof(benchmark_message_t)) {
            benchmark_message_t *resp_msg = (benchmark_message_t *)response.buffer;
            
            if (!benchmark_verify_payload_pattern(response.buffer, response.size, resp_msg->seq_num,
                sizeof(benchmark_message_t), &g_config.verify_config)) {
                fprintf(stderr, "[VERIFY] Client: Response payload verification failed for seq=%u\n", resp_msg->seq_num);
                checksum_failed++;
            }
            
            results[success_count].rtt_us = (double)(response_time - bench_msg->send_timestamp);
            results[success_count].send_timestamp = bench_msg->send_timestamp;
            results[success_count].recv_timestamp = response_time;
            results[success_count].send_latency_us = (double)(send_complete_time - bench_msg->send_timestamp);
            results[success_count].network_req_us = (double)(resp_msg->recv_timestamp - send_complete_time);
            results[success_count].server_process_us = (double)(resp_msg->reply_send_timestamp - resp_msg->recv_timestamp);
            results[success_count].network_resp_us = (double)(response_time - resp_msg->reply_send_timestamp);
            success_count++;
            
            if (g_config.verbose && i % 100 == 0) {
                printf("Request %d: RTT=%.2f us (send=%.2f, net_req=%.2f, server=%.2f, net_resp=%.2f)\n", 
                       i, results[success_count - 1].rtt_us,
                       results[success_count - 1].send_latency_us,
                       results[success_count - 1].network_req_us,
                       results[success_count - 1].server_process_us,
                       results[success_count - 1].network_resp_us);
            }
        }
        
        mes_release_msg(&response);
    }
    
    uint64_t end_time = benchmark_get_time_us();
    double total_time_s = (end_time - start_time) / 1000000.0;
    
    benchmark_statistics_t stats;
    benchmark_calculate_statistics(results, success_count, &stats);
    stats.success_count = success_count;
    stats.timeout_count = timeout_count;
    stats.checksum_failed = checksum_failed;
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "Request-Response Test (Pipe Type: %d)", g_config.pipe_type);
    benchmark_print_statistics(test_name, &stats, total_time_s, g_config.verify_config.verify_mode);
    
    free(results);
    free(buffer);
    return 0;
}

static int run_bidirectional_latency_test(inst_type dest_inst)
{
    char *buffer = (char *)malloc(g_config.message_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for latency test\n");
        return -1;
    }
    
    memset(buffer, 0, g_config.message_size);
    benchmark_message_t *bench_msg = (benchmark_message_t *)buffer;
    
    if (g_shared_state != NULL) {
        g_shared_state->received_count = 0;
        g_shared_state->validation_failed = 0;
        g_shared_state->checksum_failed = 0;
    }
    
    printf("\nStarting Bidirectional Latency Test: Instance %d -> Instance %d\n", 
           BENCHMARK_INST_ID_1, dest_inst);
    printf("Test count: %d, Message size: %d bytes\n", g_config.test_count, g_config.message_size);
    if (g_config.verify_config.verify_mode) {
        printf("Verify mode: ENABLED (payload checksum verification)\n");
    }
    
    double start_time = benchmark_get_time_ms();
    double *latencies = (double *)malloc(g_config.test_count * sizeof(double));
    if (!latencies) {
        fprintf(stderr, "Failed to allocate latency array\n");
        free(buffer);
        return -1;
    }
    
    for (int i = 0; i < g_config.test_count; i++) {
        bench_msg->seq_num = i;
        bench_msg->src_inst = BENCHMARK_INST_ID_1;
        bench_msg->dst_inst = dest_inst;
        
        benchmark_fill_verify_pattern(buffer, g_config.message_size, i, 
            sizeof(benchmark_message_t), &g_config.verify_config);
        
        benchmark_inject_noise_error(buffer, g_config.message_size, i, 
            sizeof(benchmark_message_t), &g_config.verify_config);
        
        double send_time = benchmark_get_time_ms();
        uint64_t send_ts_us = (uint64_t)(send_time * 1000);
        g_shared_state->send_timestamps[i] = send_ts_us;
        int gret = mes_send_data(dest_inst, 0, buffer, g_config.message_size);
        double send_complete_time = benchmark_get_time_ms();
        
        if (gret != 0) {
            fprintf(stderr, "Failed to send message %d: %d (errno=%d)\n", i, gret, errno);
            free(latencies);
            free(buffer);
            return -1;
        }
        
        while (g_shared_state != NULL && g_shared_state->received_count <= i) {
        }
        
        __sync_synchronize();
        
        double recv_time = benchmark_get_time_ms();
        latencies[i] = recv_time - send_time;
        
        if (g_shared_state != NULL) {
            uint64_t stored_send_ts = g_shared_state->send_timestamps[i];
            uint64_t recv_ts = g_shared_state->recv_timestamps[i];
            double latency_ms = (double)(recv_ts - stored_send_ts) / 1000.0;
            
            g_shared_state->total_send_latency += (send_complete_time - send_time);
            g_shared_state->total_recv_latency += latency_ms;
        }
        
        if (i % 1000 == 0) {
            printf("Sent %d messages...\n", i + 1);
        }
    }
    
    double end_time = benchmark_get_time_ms();
    double total_time = end_time - start_time;
    
    double min_latency = latencies[0];
    double max_latency = latencies[0];
    double sum_latency = 0.0;
    
    for (int i = 0; i < g_config.test_count; i++) {
        if (latencies[i] < min_latency) min_latency = latencies[i];
        if (latencies[i] > max_latency) max_latency = latencies[i];
        sum_latency += latencies[i];
    }
    
    double avg_latency = sum_latency / g_config.test_count;
    
    printf("\n========================================\n");
    printf("Bidirectional Latency Test Results\n");
    printf("========================================\n");
    printf("| %-25s | %-20s |\n", "Metric", "Value");
    printf("-------------------------------------------\n");
    printf("| %-25s | %-20d |\n", "Messages sent", g_config.test_count);
    printf("| %-25s | %-20d |\n", "Message size (bytes)", g_config.message_size);
    printf("| %-25s | %-20.2f |\n", "Total time (ms)", total_time);
    printf("| %-25s | %-20.2f |\n", "Average latency (us)", avg_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Min latency (us)", min_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Max latency (us)", max_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Throughput (msg/s)", g_config.test_count / (total_time / 1000.0));
    
    if (g_shared_state != NULL) {
        double avg_send_latency = g_shared_state->total_send_latency / g_config.test_count;
        double avg_recv_latency = g_shared_state->total_recv_latency / g_config.test_count;
        printf("-------------------------------------------\n");
        printf("| %-25s | %-20.2f |\n", "Avg send latency (us)", avg_send_latency * 1000);
        printf("| %-25s | %-20.2f |\n", "Avg recv latency (us)", avg_recv_latency * 1000);
    }
    
    if (g_config.verify_config.verify_mode && g_shared_state != NULL) {
        printf("-------------------------------------------\n");
        printf("| %-25s | %-20s |\n", "Data Integrity Check", "");
        int verified_count = g_config.test_count - g_shared_state->checksum_failed;
        printf("| %-25s | %-20d |\n", "  Verified OK", verified_count);
        printf("| %-25s | %-20d |\n", "  Checksum Failed", g_shared_state->checksum_failed);
        if (g_shared_state->checksum_failed == 0) {
            printf("| %-25s | %-20s |\n", "  Result", "ALL PASSED");
        } else {
            printf("| %-25s | %-20s |\n", "  Result", "FAILED");
        }
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

static int run_benchmark(mes_pipe_type_t pipe_type)
{
    printf("[DEBUG] Starting benchmark with pipe type: %s (%d)\n", 
           benchmark_pipe_type_to_string(pipe_type), pipe_type);
    
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
        g_shared_state->checksum_failed = 0;
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
        g_shared_state->checksum_failed = 0;
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
        printf("Pipe Type: %s\n", benchmark_pipe_type_to_string(pipe_type));
        printf("Test Mode: %s\n", g_config.test_mode == TEST_MODE_REQUEST_RESPONSE ? "Request-Response" : "Send-Only");
        printf("========================================\n");
        
        if (g_config.test_mode == TEST_MODE_REQUEST_RESPONSE) {
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
    printf("  -d, --direct              Send directly without queue (default: enabled)\n");
    printf("  -q, --queue              Send via queue (disable direct send)\n");
    printf("  -V, --verify             Enable payload verification (checksum)\n");
    printf("  -E, --inject-error       Inject noise errors for testing verification (every 100 msgs)\n");
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
    printf("\n  # IPC test with queue-based sending (for accurate RTT)\n");
    printf("  %s -t ipc -q\n", prog_name);
    printf("\n  # IPC test with payload verification\n");
    printf("  %s -t ipc -V\n", prog_name);
    printf("\n  # IPC test with payload verification and error injection\n");
    printf("  %s -t ipc -V -E\n", prog_name);
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"mode", required_argument, 0, 'm'},
        {"count", required_argument, 0, 'c'},
        {"size", required_argument, 0, 's'},
        {"timeout", required_argument, 0, 'T'},
        {"direct", no_argument, 0, 'd'},
        {"queue", no_argument, 0, 'q'},
        {"verify", no_argument, 0, 'V'},
        {"inject-error", no_argument, 0, 'E'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "t:m:c:s:T:dqVEvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                if (strcmp(optarg, "tcp") == 0) {
                    g_config.pipe_type = MES_TYPE_TCP;
                } else if (strcmp(optarg, "rdma") == 0) {
                    g_config.pipe_type = MES_TYPE_RDMA;
                } else if (strcmp(optarg, "ipc") == 0) {
                    g_config.pipe_type = MES_TYPE_IPC;
                } else {
                    fprintf(stderr, "Invalid pipe type: %s\n", optarg);
                    return -1;
                }
                break;
            case 'm':
                if (strcmp(optarg, "reqresp") == 0) {
                    g_config.test_mode = TEST_MODE_REQUEST_RESPONSE;
                } else if (strcmp(optarg, "sendonly") == 0) {
                    g_config.test_mode = TEST_MODE_SEND_ONLY;
                } else {
                    fprintf(stderr, "Invalid test mode: %s\n", optarg);
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
            case 'T':
                g_config.timeout_ms = atoi(optarg);
                if (g_config.timeout_ms <= 0) {
                    fprintf(stderr, "Invalid timeout: %s\n", optarg);
                    return -1;
                }
                break;
            case 'd':
                g_config.send_directly = 1;
                break;
            case 'q':
                g_config.send_directly = 0;
                break;
            case 'V':
                g_config.verify_config.verify_mode = 1;
                break;
            case 'E':
                g_config.verify_config.inject_error = 1;
                break;
            case 'v':
                g_config.verbose = 1;
                g_config.verify_config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    if (g_config.message_size < sizeof(benchmark_message_t)) {
        fprintf(stderr, "Message size %d is too small, minimum required: %zu bytes\n", 
                g_config.message_size, sizeof(benchmark_message_t));
        fprintf(stderr, "Auto-adjusting message size to %zu bytes\n", sizeof(benchmark_message_t));
        g_config.message_size = sizeof(benchmark_message_t);
    }
    
    if (g_config.test_mode == TEST_MODE_SEND_ONLY && g_config.test_count > MAX_TEST_COUNT) {
        fprintf(stderr, "Warning: Send-only mode test count %d exceeds maximum %d\n", 
                g_config.test_count, MAX_TEST_COUNT);
        fprintf(stderr, "Auto-adjusting test count to %d\n", MAX_TEST_COUNT);
        g_config.test_count = MAX_TEST_COUNT;
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
    printf("Pipe Type: %s\n", benchmark_pipe_type_to_string(g_config.pipe_type));
    printf("Test Mode: %s\n", g_config.test_mode == TEST_MODE_REQUEST_RESPONSE ? "Request-Response" : "Send-Only");
    printf("Test Count: %d\n", g_config.test_count);
    printf("Message Size: %d bytes\n", g_config.message_size);
    if (g_config.test_mode == TEST_MODE_REQUEST_RESPONSE) {
        printf("Timeout: %d ms\n", g_config.timeout_ms);
    }
    printf("Verify Mode: %s\n", g_config.verify_config.verify_mode ? "Enabled" : "Disabled");
    printf("Inject Error: %s\n", g_config.verify_config.inject_error ? "Enabled" : "Disabled");
    printf("\n");
    
    if (g_config.verbose) {
        mes_init_log();
        mes_register_log_output(mes_log_output);
    }
    
    if (run_benchmark(g_config.pipe_type) != 0) {
        fprintf(stderr, "Benchmark failed\n");
        return 1;
    }
    
    printf("\nBenchmark completed successfully!\n");
    return 0;
}
