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

#include "../mes_interface.h"

#define BENCHMARK_INST_ID_1 1
#define BENCHMARK_INST_ID_2 2
#define BENCHMARK_PORT 12345
#define LATENCY_MESSAGE_SIZE 64
#define BANDWIDTH_MESSAGE_SIZE (16 * 1024)
#define LATENCY_TEST_COUNT 10000
#define BANDWIDTH_TEST_COUNT 1000

typedef struct {
    volatile int received_count;
    volatile int benchmark_done;
    volatile int validation_failed;
    volatile uint64_t send_timestamps[LATENCY_TEST_COUNT];
    volatile uint64_t recv_timestamps[LATENCY_TEST_COUNT];
    volatile double total_send_latency;
    volatile double total_recv_latency;
} shared_state_t;

static shared_state_t *g_shared_state = NULL;

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
    
    uint32_t *seq_num = (uint32_t *)msg->buffer;
    
    if (*seq_num % 10000 == 0) {
        printf("Received message: seq=%u, size=%u\n", *seq_num, msg->size);
    }
    
    if (g_shared_state != NULL) {
        uint64_t recv_complete_time = get_time_ms();
        g_shared_state->recv_timestamps[*seq_num] = recv_complete_time;
        g_shared_state->received_count++;
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
    
    profile->channel_cnt = 1;
    profile->priority_cnt = 1;
    
    profile->conn_created_during_init = 1;
    profile->tpool_attr.enable_threadpool = 0;
    
    profile->connect_timeout = 30000; // 30 seconds
    profile->socket_timeout = 30000; // 30 seconds
    
    profile->inst_net_addr[0].inst_id = BENCHMARK_INST_ID_1;
    snprintf(profile->inst_net_addr[0].ip, MES_MAX_IP_LEN, "127.0.0.1");
    profile->inst_net_addr[0].port = BENCHMARK_PORT;
    profile->inst_net_addr[0].need_connect = (inst_id == BENCHMARK_INST_ID_1) ? 0 : 1;
    
    profile->inst_net_addr[1].inst_id = BENCHMARK_INST_ID_2;
    snprintf(profile->inst_net_addr[1].ip, MES_MAX_IP_LEN, "127.0.0.1");
    profile->inst_net_addr[1].port = BENCHMARK_PORT + 1;
    profile->inst_net_addr[1].need_connect = (inst_id == BENCHMARK_INST_ID_2) ? 0 : 1;
}

static int run_bidirectional_latency_test(inst_type dest_inst)
{
    char *buffer = (char *)malloc(LATENCY_MESSAGE_SIZE);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for latency test\n");
        return -1;
    }
    
    memset(buffer, 0, LATENCY_MESSAGE_SIZE);
    uint32_t *seq_num = (uint32_t *)buffer;
    
    if (g_shared_state != NULL) {
        g_shared_state->received_count = 0;
        g_shared_state->validation_failed = 0;
    }
    
    double start_time = get_time_ms();
    double *latencies = (double *)malloc(LATENCY_TEST_COUNT * sizeof(double));
    if (!latencies) {
        fprintf(stderr, "Failed to allocate latency array\n");
        free(buffer);
        return -1;
    }
    
    for (int i = 0; i < LATENCY_TEST_COUNT; i++) {
        *seq_num = i;
        
        double send_time = get_time_ms();
        g_shared_state->send_timestamps[i] = send_time;
        int gret = mes_send_data(dest_inst, 0, buffer, LATENCY_MESSAGE_SIZE);
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
    
    for (int i = 0; i < LATENCY_TEST_COUNT; i++) {
        if (latencies[i] < min_latency) min_latency = latencies[i];
        if (latencies[i] > max_latency) max_latency = latencies[i];
        sum_latency += latencies[i];
    }
    
    double avg_latency = sum_latency / LATENCY_TEST_COUNT;
    
    printf("\n========================================\n");
    printf("Bidirectional Latency Test Results\n");
    printf("========================================\n");
    printf("| %-25s | %-20s |\n", "Metric", "Value");
    printf("-------------------------------------------\n");
    printf("| %-25s | %-20d |\n", "Messages sent", LATENCY_TEST_COUNT);
    printf("| %-25s | %-20d |\n", "Message size (bytes)", LATENCY_MESSAGE_SIZE);
    printf("| %-25s | %-20.2f |\n", "Total time (ms)", total_time);
    printf("| %-25s | %-20.2f |\n", "Average latency (μs)", avg_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Min latency (μs)", min_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Max latency (μs)", max_latency * 1000);
    printf("| %-25s | %-20.2f |\n", "Throughput (msg/s)", LATENCY_TEST_COUNT / (total_time / 1000.0));
    
    if (g_shared_state != NULL) {
        double avg_send_latency = g_shared_state->total_send_latency / LATENCY_TEST_COUNT;
        double avg_recv_latency = g_shared_state->total_recv_latency / LATENCY_TEST_COUNT;
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

static int run_benchmark(mes_pipe_type_t pipe_type)
{
    printf("[DEBUG] Starting benchmark with pipe type: %d\n", pipe_type);
    
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
        
        printf("[DEBUG] Child process: calling mes_init\n");
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
        sleep(3);
        
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
        printf("========================================\n");
        
        if (run_bidirectional_latency_test(BENCHMARK_INST_ID_2) != 0) {
            mes_uninit();
            munmap(g_shared_state, sizeof(shared_state_t));
            shm_unlink("/mes_benchmark_shm");
            kill(pid, (int)SIGTERM);
            waitpid(pid, NULL, 0);
            return -1;
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

int main(int argc, char *argv[])
{
    int show_mes_log = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            show_mes_log = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-v|--verbose] [-h|--help]\n", argv[0]);
            printf("  -v, --verbose  Show MES library logs\n");
            printf("  -h, --help     Show this help message\n");
            return 0;
        }
    }
    
    if (show_mes_log) {
        mes_init_log();
        mes_register_log_output(mes_log_output);
    }
    
    printf("MES Communication Benchmark\n");
    printf("==========================\n");
    printf("Testing MES_TYPE_TCP communication...\n\n");
    
    if (run_benchmark(MES_TYPE_TCP) != 0) {
        fprintf(stderr, "Benchmark failed\n");
        return 1;
    }
    
    printf("\nBenchmark completed successfully!\n");
    return 0;
}
