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
 * mes_rtt_perf.c
 * MES RTT Performance Test Tool
 *
 * IDENTIFICATION
 *    src/cm_mes/benchmark_rtt/mes_rtt_perf.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

#include "../mes_interface.h"
#include "../mes_type.h"
#include "benchmark/benchmark_common.h"

#define RTT_MAGIC_PATTERN 0xAB
#define RTT_DEFAULT_PORT 12345
#define RTT_MAX_NODES 16
#define RTT_MAX_THREADS 64
#define RTT_MAX_MESSAGE_SIZE (128 * 1024)

typedef enum {
    MODE_SERVER,
    MODE_CLIENT
} test_mode_t;

typedef enum {
    PROTOCOL_IPC,
    PROTOCOL_TCP
} protocol_type_t;

typedef struct {
    uint32_t seq_num;
    uint32_t flags;
    uint64_t send_timestamp;
    uint64_t recv_timestamp;
    uint64_t reply_timestamp;
} rtt_perf_message_t;

typedef struct {
    test_mode_t mode;
    protocol_type_t protocol;
    int inst_id;
    int target_id;
    int test_count;
    int message_size;
    int thread_count;
    int timeout_ms;
    int direct_send;
    int priority_hash;
    int node_count;
    benchmark_verify_config_t verify_config;
    struct {
        int inst_id;
        char ip[64];
        int port;
    } nodes[RTT_MAX_NODES];
} test_config_t;

typedef struct {
    int thread_id;
    int success_count;
    int timeout_count;
    int checksum_failed;
    benchmark_rtt_result_t *results;
    test_config_t *config;
} thread_context_t;

static test_config_t g_config;
static volatile int g_running = 1;
static int g_checksum_failed_total = 0;

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

static void rtt_perf_msg_proc(unsigned int work_idx, ruid_type ruid, mes_msg_t* msg)
{
    if (msg == NULL || msg->buffer == NULL) {
        return;
    }
    
    if (msg->size < sizeof(rtt_perf_message_t)) {
        fprintf(stderr, "Message too small: %u bytes\n", msg->size);
        return;
    }
    
    rtt_perf_message_t *req = (rtt_perf_message_t *)msg->buffer;
    
    if (!benchmark_verify_payload_pattern(msg->buffer, msg->size, req->seq_num,
        sizeof(rtt_perf_message_t), &g_config.verify_config)) {
        fprintf(stderr, "[VERIFY] Server: Payload verification failed for seq=%u\n", req->seq_num);
        __sync_fetch_and_add(&g_checksum_failed_total, 1);
    }
    
    uint64_t recv_time = benchmark_get_time_us();
    
    if (g_config.verify_config.verify_mode && msg->size > sizeof(rtt_perf_message_t)) {
        char *response_buf = (char *)malloc(msg->size);
        if (response_buf) {
            memcpy(response_buf, msg->buffer, msg->size);
            rtt_perf_message_t *resp = (rtt_perf_message_t *)response_buf;
            resp->recv_timestamp = recv_time;
            resp->reply_timestamp = benchmark_get_time_us();
            
            mes_send_response(msg->src_inst, 0, ruid, response_buf, msg->size);
            free(response_buf);
        } else {
            rtt_perf_message_t resp;
            resp.seq_num = req->seq_num;
            resp.recv_timestamp = recv_time;
            resp.reply_timestamp = benchmark_get_time_us();
            mes_send_response(msg->src_inst, 0, ruid, (char *)&resp, sizeof(rtt_perf_message_t));
        }
    } else {
        rtt_perf_message_t resp;
        resp.seq_num = req->seq_num;
        resp.recv_timestamp = recv_time;
        resp.reply_timestamp = benchmark_get_time_us();
        
        mes_send_response(msg->src_inst, 0, ruid, (char *)&resp, sizeof(rtt_perf_message_t));
    }
}

static void setup_mes_profile(mes_profile_t *profile)
{
    memset(profile, 0, sizeof(mes_profile_t));
    
    profile->inst_id = g_config.inst_id;
    profile->inst_cnt = g_config.node_count > 0 ? g_config.node_count : 2;
    profile->pipe_type = (g_config.protocol == PROTOCOL_IPC) ? MES_TYPE_IPC : MES_TYPE_TCP;
    
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
    profile->send_directly = g_config.direct_send ? 1 : 0;
    
    profile->connect_timeout = 30000;
    profile->socket_timeout = 30000;
    
    if (g_config.node_count > 0) {
        for (int i = 0; i < g_config.node_count && i < RTT_MAX_NODES; i++) {
            profile->inst_net_addr[i].inst_id = g_config.nodes[i].inst_id;
            snprintf(profile->inst_net_addr[i].ip, MES_MAX_IP_LEN, "%s", g_config.nodes[i].ip);
            profile->inst_net_addr[i].port = g_config.nodes[i].port;
            profile->inst_net_addr[i].need_connect = (g_config.nodes[i].inst_id == g_config.inst_id) ? 0 : 1;
        }
    } else {
        profile->inst_net_addr[0].inst_id = 1;
        snprintf(profile->inst_net_addr[0].ip, MES_MAX_IP_LEN, "127.0.0.1");
        profile->inst_net_addr[0].port = RTT_DEFAULT_PORT;
        profile->inst_net_addr[0].need_connect = (g_config.inst_id == 1) ? 0 : 1;
        
        profile->inst_net_addr[1].inst_id = 2;
        snprintf(profile->inst_net_addr[1].ip, MES_MAX_IP_LEN, "127.0.0.1");
        profile->inst_net_addr[1].port = RTT_DEFAULT_PORT + 1;
        profile->inst_net_addr[1].need_connect = (g_config.inst_id == 2) ? 0 : 1;
    }
}

static void *worker_thread_func(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    test_config_t *config = ctx->config;
    
    char *buffer = (char *)malloc(config->message_size);
    if (!buffer) {
        fprintf(stderr, "Thread %d: Failed to allocate buffer\n", ctx->thread_id);
        return NULL;
    }
    
    memset(buffer, 0, config->message_size);
    rtt_perf_message_t *msg = (rtt_perf_message_t *)buffer;
    
    int rtt_idx = 0;
    int per_thread_count = config->test_count / config->thread_count;
    
    for (int i = 0; i < per_thread_count && g_running; i++) {
        ruid_type ruid;
        msg->seq_num = ctx->thread_id * per_thread_count + i;
        msg->send_timestamp = benchmark_get_time_us();
        
        benchmark_fill_verify_pattern(buffer, config->message_size, msg->seq_num, 
            sizeof(rtt_perf_message_t), &config->verify_config);
        
        benchmark_inject_noise_error(buffer, config->message_size, msg->seq_num, 
            sizeof(rtt_perf_message_t), &config->verify_config);
        
        flag_type flag = 0;
        if (config->priority_hash) {
            flag = msg->seq_num;
        }
        
        int ret = mes_send_request(config->target_id, flag, &ruid, buffer, config->message_size);
        
        uint64_t send_complete_time = benchmark_get_time_us();
        
        if (ret != 0) {
            if (config->verify_config.verbose) {
                fprintf(stderr, "Thread %d: Send failed for seq=%u, ret=%d\n", 
                        ctx->thread_id, msg->seq_num, ret);
            }
            ctx->timeout_count++;
            continue;
        }
        
        mes_msg_t response;
        ret = mes_get_response(ruid, &response, config->timeout_ms);
        uint64_t response_time = benchmark_get_time_us();
        
        if (ret != 0) {
            if (config->verify_config.verbose) {
                fprintf(stderr, "Thread %d: Timeout for seq=%u\n", ctx->thread_id, msg->seq_num);
            }
            ctx->timeout_count++;
            continue;
        }
        
        if (response.buffer != NULL && response.size >= sizeof(rtt_perf_message_t)) {
            rtt_perf_message_t *resp = (rtt_perf_message_t *)response.buffer;
            
            if (!benchmark_verify_payload_pattern(response.buffer, response.size, resp->seq_num,
                sizeof(rtt_perf_message_t), &config->verify_config)) {
                fprintf(stderr, "[VERIFY] Client: Response payload verification failed for seq=%u\n", resp->seq_num);
                ctx->checksum_failed++;
            }
            
            if (rtt_idx < config->test_count) {
                ctx->results[rtt_idx].rtt_us = (double)(response_time - msg->send_timestamp);
                ctx->results[rtt_idx].send_timestamp = msg->send_timestamp;
                ctx->results[rtt_idx].recv_timestamp = response_time;
                ctx->results[rtt_idx].send_latency_us = (double)(send_complete_time - msg->send_timestamp);
                ctx->results[rtt_idx].network_req_us = (double)(resp->recv_timestamp - send_complete_time);
                ctx->results[rtt_idx].server_process_us = (double)(resp->reply_timestamp - resp->recv_timestamp);
                ctx->results[rtt_idx].network_resp_us = (double)(response_time - resp->reply_timestamp);
                rtt_idx++;
            }
            ctx->success_count++;
        }
        
        mes_release_msg(&response);
    }
    
    free(buffer);
    return NULL;
}

static int run_client_mode(void)
{
    printf("Waiting for connection to server (inst_id=%d)...\n", g_config.target_id);
    
    int wait_count = 0;
    while (!mes_connection_ready(g_config.target_id)) {
        usleep(100000);
        wait_count++;
        if (wait_count > 300) {
            fprintf(stderr, "Timeout waiting for connection to server\n");
            return -1;
        }
    }
    printf("Connection established!\n");
    
    pthread_t threads[RTT_MAX_THREADS];
    thread_context_t contexts[RTT_MAX_THREADS];
    benchmark_rtt_result_t *all_results = (benchmark_rtt_result_t *)calloc(g_config.test_count, sizeof(benchmark_rtt_result_t));
    if (!all_results) {
        fprintf(stderr, "Failed to allocate results array\n");
        return -1;
    }
    
    int per_thread = g_config.test_count / g_config.thread_count;
    
    for (int i = 0; i < g_config.thread_count; i++) {
        contexts[i].thread_id = i;
        contexts[i].success_count = 0;
        contexts[i].timeout_count = 0;
        contexts[i].checksum_failed = 0;
        contexts[i].results = all_results + i * per_thread;
        contexts[i].config = &g_config;
    }
    
    printf("\nStarting RTT test: %d messages, %d bytes each, %d threads\n", 
           g_config.test_count, g_config.message_size, g_config.thread_count);
    
    uint64_t start_time = benchmark_get_time_us();
    
    for (int i = 0; i < g_config.thread_count; i++) {
        pthread_create(&threads[i], NULL, worker_thread_func, &contexts[i]);
    }
    
    for (int i = 0; i < g_config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    uint64_t end_time = benchmark_get_time_us();
    double total_time_s = (end_time - start_time) / 1000000.0;
    
    int total_success = 0;
    int total_timeout = 0;
    int total_checksum_failed = g_checksum_failed_total;
    
    for (int i = 0; i < g_config.thread_count; i++) {
        total_success += contexts[i].success_count;
        total_timeout += contexts[i].timeout_count;
        total_checksum_failed += contexts[i].checksum_failed;
    }
    
    benchmark_statistics_t stats;
    benchmark_calculate_statistics(all_results, total_success, &stats);
    stats.success_count = total_success;
    stats.timeout_count = total_timeout;
    stats.checksum_failed = total_checksum_failed;
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "RTT Performance Test (%s): Client %d -> Server %d (%d threads)",
             g_config.protocol == PROTOCOL_IPC ? "IPC" : "TCP",
             g_config.inst_id, g_config.target_id, g_config.thread_count);
    benchmark_print_statistics(test_name, &stats, total_time_s, g_config.verify_config.verify_mode);
    
    free(all_results);
    return 0;
}

static int run_server_mode(void)
{
    printf("Server mode: Instance %d listening...\n", g_config.inst_id);
    printf("Press Ctrl+C to stop\n");
    
    while (g_running) {
        sleep(1);
    }
    
    return 0;
}

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nMES RTT Performance Test Tool\n\n");
    printf("Required arguments:\n");
    printf("  -m, --mode MODE          Test mode: server|client\n");
    printf("  -p, --protocol PROTO     Protocol: ipc|tcp (default: ipc)\n");
    printf("  -i, --inst-id ID         Instance ID (1-%d)\n", RTT_MAX_NODES);
    printf("\nServer mode required:\n");
    printf("  --nodes NODES            Node list: id1:ip1:port1,id2:ip2:port2,...\n");
    printf("\nClient mode required:\n");
    printf("  --target-id ID           Target server instance ID\n");
    printf("\nOptional arguments:\n");
    printf("  -c, --count COUNT        Number of test iterations (default: 1000)\n");
    printf("  -s, --size SIZE          Message size in bytes (default: 64)\n");
    printf("  -t, --threads NUM        Number of worker threads (default: 1)\n");
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

static int parse_nodes(const char *nodes_str)
{
    char *str = strdup(nodes_str);
    if (!str) {
        return -1;
    }
    
    g_config.node_count = 0;
    char *token = strtok(str, ",");
    
    while (token != NULL && g_config.node_count < RTT_MAX_NODES) {
        int id, port;
        char ip[64];
        
        if (sscanf(token, "%d:%63[^:]:%d", &id, ip, &port) == 3) {
            g_config.nodes[g_config.node_count].inst_id = id;
            snprintf(g_config.nodes[g_config.node_count].ip, sizeof(g_config.nodes[g_config.node_count].ip), "%s", ip);
            g_config.nodes[g_config.node_count].port = port;
            g_config.node_count++;
        }
        
        token = strtok(NULL, ",");
    }
    
    free(str);
    return (g_config.node_count > 0) ? 0 : -1;
}

static void init_config(void)
{
    memset(&g_config, 0, sizeof(g_config));
    g_config.mode = MODE_SERVER;
    g_config.protocol = PROTOCOL_IPC;
    g_config.inst_id = 1;
    g_config.target_id = 0;
    g_config.test_count = 1000;
    g_config.message_size = 64;
    g_config.thread_count = 1;
    g_config.timeout_ms = 5000;
    g_config.direct_send = 1;
    g_config.priority_hash = 0;
    g_config.node_count = 0;
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"protocol", required_argument, 0, 'p'},
        {"inst-id", required_argument, 0, 'i'},
        {"target-id", required_argument, 0, 'T' + 100},
        {"nodes", required_argument, 0, 'n' + 100},
        {"count", required_argument, 0, 'c'},
        {"size", required_argument, 0, 's'},
        {"threads", required_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"direct", no_argument, 0, 'd'},
        {"priority-hash", no_argument, 0, 'P' + 100},
        {"verify", no_argument, 0, 'V'},
        {"inject-error", no_argument, 0, 'E'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int target_id_specified = 0;
    
    while ((opt = getopt_long(argc, argv, "m:p:i:c:s:t:T:dVEvh", long_options, NULL)) != -1) {
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
            case 'p':
                if (strcmp(optarg, "ipc") == 0) {
                    g_config.protocol = PROTOCOL_IPC;
                } else if (strcmp(optarg, "tcp") == 0) {
                    g_config.protocol = PROTOCOL_TCP;
                } else {
                    fprintf(stderr, "Invalid protocol: %s\n", optarg);
                    return -1;
                }
                break;
            case 'i':
                g_config.inst_id = atoi(optarg);
                break;
            case 'T' + 100:
                g_config.target_id = atoi(optarg);
                target_id_specified = 1;
                break;
            case 'n' + 100:
                if (parse_nodes(optarg) != 0) {
                    fprintf(stderr, "Invalid nodes format: %s\n", optarg);
                    return -1;
                }
                break;
            case 'c':
                g_config.test_count = atoi(optarg);
                break;
            case 's':
                g_config.message_size = atoi(optarg);
                break;
            case 't':
                g_config.thread_count = atoi(optarg);
                break;
            case 'T':
                g_config.timeout_ms = atoi(optarg);
                break;
            case 'd':
                g_config.direct_send = 1;
                break;
            case 'P' + 100:
                g_config.priority_hash = 1;
                break;
            case 'V':
                g_config.verify_config.verify_mode = 1;
                break;
            case 'E':
                g_config.verify_config.inject_error = 1;
                break;
            case 'v':
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
    
    if (g_config.mode == MODE_CLIENT && !target_id_specified) {
        fprintf(stderr, "Error: --target-id is required for client mode\n");
        return -1;
    }
    
    if (g_config.message_size < sizeof(rtt_perf_message_t)) {
        g_config.message_size = sizeof(rtt_perf_message_t);
    }
    
    if (g_config.thread_count > RTT_MAX_THREADS) {
        g_config.thread_count = RTT_MAX_THREADS;
    }
    
    return 0;
}

static void print_config(void)
{
    printf("\n========================================\n");
    printf("MES RTT Performance Test Configuration\n");
    printf("========================================\n");
    printf("Mode: %s\n", g_config.mode == MODE_SERVER ? "server" : "client");
    printf("Protocol: %s\n", g_config.protocol == PROTOCOL_IPC ? "IPC" : "TCP");
    printf("Instance ID: %d\n", g_config.inst_id);
    printf("Direct send: %s\n", g_config.direct_send ? "enabled" : "disabled");
    printf("Priority hash: %s\n", g_config.priority_hash ? "enabled" : "disabled");
    printf("Verify mode: %s\n", g_config.verify_config.verify_mode ? "enabled" : "disabled");
    printf("Inject error: %s\n", g_config.verify_config.inject_error ? "enabled" : "disabled");
    if (g_config.mode == MODE_CLIENT) {
        printf("Target ID: %d\n", g_config.target_id);
        printf("Test count: %d\n", g_config.test_count);
        printf("Message size: %d bytes\n", g_config.message_size);
        printf("Thread count: %d\n", g_config.thread_count);
        printf("Timeout: %d ms\n", g_config.timeout_ms);
    }
    if (g_config.node_count > 0) {
        printf("Nodes:\n");
        for (int i = 0; i < g_config.node_count; i++) {
            printf("  %d: %s:%d\n", g_config.nodes[i].inst_id, g_config.nodes[i].ip, g_config.nodes[i].port);
        }
    }
    printf("========================================\n\n");
}

int main(int argc, char *argv[])
{
    init_config();
    
    if (parse_arguments(argc, argv) != 0) {
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_config();
    
    if (g_config.verify_config.verbose) {
        mes_init_log();
        mes_register_log_output(mes_log_output);
    }
    
    mes_profile_t profile;
    setup_mes_profile(&profile);
    
    mes_register_proc_func(rtt_perf_msg_proc);
    
    printf("Initializing MES...\n");
    int ret = mes_init(&profile);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize MES: %d\n", ret);
        return 1;
    }
    printf("MES initialized successfully\n");
    
    int result;
    if (g_config.mode == MODE_SERVER) {
        result = run_server_mode();
    } else {
        result = run_client_mode();
    }
    
    printf("Uninitializing MES...\n");
    mes_uninit();
    
    return result;
}
