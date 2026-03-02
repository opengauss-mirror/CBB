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

typedef struct {
    run_mode_t mode;
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
    int node_count;
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

static void print_statistics(const char *test_name, test_statistics_t *stats)
{
    printf("\n==================================================\n");
    printf("%s\n", test_name);
    printf("==================================================\n");
    printf("| %-25s | %20.2f |\n", "Success count", (double)stats->success_count);
    printf("| %-25s | %20.2f |\n", "Timeout count", (double)stats->timeout_count);
    printf("| %-25s | %20.2f |\n", "Average RTT (μs)", stats->avg_rtt_us);
    printf("| %-25s | %20.2f |\n", "Min RTT (μs)", stats->min_rtt_us);
    printf("| %-25s | %20.2f |\n", "Max RTT (μs)", stats->max_rtt_us);
    printf("| %-25s | %20.2f |\n", "P50 RTT (μs)", stats->p50_rtt_us);
    printf("| %-25s | %20.2f |\n", "P95 RTT (μs)", stats->p95_rtt_us);
    printf("| %-25s | %20.2f |\n", "P99 RTT (μs)", stats->p99_rtt_us);
    printf("| %-25s | %20.2f |\n", "Std Dev (μs)", stats->std_dev_us);
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
    
    uint64_t recv_time = get_time_us();
    
    rtt_perf_message_t reply;
    reply.seq_num = rtt_msg->seq_num;
    reply.src_inst = rtt_msg->src_inst;
    reply.dst_inst = rtt_msg->dst_inst;
    reply.send_timestamp = rtt_msg->send_timestamp;
    reply.recv_timestamp = recv_time;
    reply.reply_timestamp = get_time_us();
    
    mes_send_response(msg->src_inst, 0, ruid, (char *)&reply, sizeof(rtt_perf_message_t));
    
    if (g_config.verbose) {
        printf("Sent response: seq=%u\n", reply.seq_num);
    }
}

static int setup_mes_profile(mes_profile_t *profile)
{
    memset(profile, 0, sizeof(mes_profile_t));
    
    profile->inst_id = g_config.local_inst_id;
    profile->inst_cnt = g_config.node_count;
    profile->pipe_type = MES_TYPE_TCP;
    
    profile->msg_pool_attr.total_size = 1024 * 1024 * 100;
    profile->msg_pool_attr.enable_inst_dimension = 1;
    profile->msg_pool_attr.buf_pool_count = 3;
    
    profile->msg_pool_attr.buf_pool_attr[0].buf_size = 256;
    profile->msg_pool_attr.buf_pool_attr[0].proportion = 0.1;
    profile->msg_pool_attr.buf_pool_attr[0].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[0].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.buf_pool_attr[1].buf_size = 512;
    profile->msg_pool_attr.buf_pool_attr[1].proportion = 0.1;
    profile->msg_pool_attr.buf_pool_attr[1].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[1].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.buf_pool_attr[2].buf_size = 32768;
    profile->msg_pool_attr.buf_pool_attr[2].proportion = 0.8;
    profile->msg_pool_attr.buf_pool_attr[2].priority_pool_attr[0].queue_num = 8;
    profile->msg_pool_attr.buf_pool_attr[2].shared_pool_attr.queue_num = 8;
    
    profile->msg_pool_attr.max_buf_size[0] = 32768;
    profile->frag_size = 32832;
    
    profile->channel_cnt = 1;
    profile->priority_cnt = 1;
    
    profile->conn_created_during_init = 1;
    profile->tpool_attr.enable_threadpool = 0;
    
    profile->connect_timeout = 30000;
    profile->socket_timeout = 30000;
    
    for (int i = 0; i < g_config.node_count; i++) {
        profile->inst_net_addr[i].inst_id = g_config.nodes[i].inst_id;
        snprintf(profile->inst_net_addr[i].ip, MES_MAX_IP_LEN, "%s", g_config.nodes[i].ip);
        profile->inst_net_addr[i].port = g_config.nodes[i].port;
        profile->inst_net_addr[i].need_connect = (g_config.nodes[i].inst_id != g_config.local_inst_id) ? 1 : 0;
    }
    
    return 0;
}

static int run_client_test(void)
{
    rtt_result_t *results = (rtt_result_t *)calloc(g_config.test_count, sizeof(rtt_result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate RTT results array\n");
        return -1;
    }
    
    char *buffer = (char *)malloc(g_config.message_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        free(results);
        return -1;
    }
    
    memset(buffer, 0, g_config.message_size);
    rtt_perf_message_t *rtt_msg = (rtt_perf_message_t *)buffer;
    
    printf("\nStarting RTT performance test: Client -> Server\n");
    printf("Test count: %d, Message size: %d bytes\n", g_config.test_count, g_config.message_size);
    fflush(stdout);
    
    int success_count = 0;
    int timeout_count = 0;
    
    for (int i = 0; i < g_config.test_count && g_running; i++) {
        ruid_type ruid;
        rtt_msg->seq_num = i;
        rtt_msg->src_inst = g_config.local_inst_id;
        rtt_msg->dst_inst = g_config.target_inst_id;
        rtt_msg->send_timestamp = get_time_us();
        
        mes_msg_t response;
        int ret = mes_send_request(g_config.target_inst_id, 0, &ruid, buffer, g_config.message_size);
        
        if (ret != 0) {
            fprintf(stderr, "Failed to send request %d: %d (errno=%d)\n", i, ret, errno);
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        ret = mes_get_response(ruid, &response, g_config.timeout_ms);
        uint64_t response_time = get_time_us();
        
        if (ret != 0) {
            if (g_config.verbose) {
                fprintf(stderr, "Timeout waiting for response %d\n", i);
            }
            timeout_count++;
            usleep(10000);
            continue;
        }
        
        if (response.buffer != NULL && response.size >= sizeof(rtt_perf_message_t)) {
            (void)(rtt_perf_message_t *)response.buffer;
            
            results[success_count].rtt_us = response_time - rtt_msg->send_timestamp;
            results[success_count].send_timestamp = rtt_msg->send_timestamp;
            results[success_count].recv_timestamp = response_time;
            
            if (g_config.verbose && i % 100 == 0) {
                printf("Request %d: RTT=%.2f μs\n", i, results[success_count].rtt_us);
            }
            
            success_count++;
        }
        
        mes_release_msg(&response);
        
        if (i % 1000 == 0 && i > 0) {
            printf("Progress: %d/%d (%.1f%%)\n", i, g_config.test_count, (double)i / g_config.test_count * 100);
            fflush(stdout);
        }
        
        usleep(1000);
    }
    
    free(buffer);
    
    test_statistics_t stats;
    calculate_statistics(results, success_count, &stats);
    stats.success_count = success_count;
    stats.timeout_count = timeout_count;
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "RTT Performance Test: Client %d -> Server %d", 
             g_config.local_inst_id, g_config.target_inst_id);
    print_statistics(test_name, &stats);
    
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
    printf("  -i, --inst-id ID         Local instance ID (required)\n");
    printf("      --local-ip IP        Local IP address (default: 127.0.0.1)\n");
    printf("      --local-port PORT    Local port (default: %d)\n", DEFAULT_PORT);
    printf("      --nodes LIST          Node list format: id1:ip1:port1,id2:ip2:port2,...\n");
    printf("                           Example: 1:192.168.1.1:12345,2:192.168.1.2:12345\n");
    printf("  -c, --count COUNT        Number of test iterations (default: %d)\n", DEFAULT_TEST_COUNT);
    printf("  -s, --size SIZE          Message size in bytes (default: %d)\n", DEFAULT_MESSAGE_SIZE);
    printf("  -T, --timeout MS         Response timeout in milliseconds (default: 5000)\n");
    printf("  -v, --verbose            Enable verbose output\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExamples:\n");
    printf("  # Server mode (cross-node)\n");
    printf("  %s -m server -i 1 --nodes 1:192.168.1.1:12345,2:192.168.1.2:12345\n", prog_name);
    printf("\n  # Client mode (cross-node)\n");
    printf("  %s -m client -i 2 --nodes 1:192.168.1.1:12345,2:192.168.1.2:12345 -c 1000 -s 64\n", prog_name);
    printf("\n  # Same-node test (same IP, different ports)\n");
    printf("  # Terminal 1 - Server:\n");
    printf("  %s -m server -i 1 --nodes 1:127.0.0.1:12345,2:127.0.0.1:12346\n", prog_name);
    printf("  # Terminal 2 - Client:\n");
    printf("  %s -m client -i 2 --nodes 1:127.0.0.1:12345,2:127.0.0.1:12346 -c 1000 -s 64\n", prog_name);
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"inst-id", required_argument, 0, 'i'},
        {"local-ip", required_argument, 0, 1001},
        {"local-port", required_argument, 0, 1002},
        {"target-id", required_argument, 0, 1003},
        {"target-ip", required_argument, 0, 1004},
        {"target-port", required_argument, 0, 1005},
        {"nodes", required_argument, 0, 1006},
        {"count", required_argument, 0, 'c'},
        {"size", required_argument, 0, 's'},
        {"timeout", required_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    g_config.test_count = DEFAULT_TEST_COUNT;
    g_config.message_size = DEFAULT_MESSAGE_SIZE;
    g_config.timeout_ms = 5000;
    g_config.verbose = 0;
    g_config.node_count = 0;
    snprintf(g_config.local_ip, MES_MAX_IP_LEN, "127.0.0.1");
    g_config.local_port = DEFAULT_PORT;
    
    int opt;
    while ((opt = getopt_long(argc, argv, "m:i:c:s:T:vh", long_options, NULL)) != -1) {
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
            case 'T':
                g_config.timeout_ms = atoi(optarg);
                if (g_config.timeout_ms <= 0) {
                    fprintf(stderr, "Invalid timeout: %s\n", optarg);
                    return -1;
                }
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
            if (strlen(g_config.target_ip) == 0) {
                fprintf(stderr, "Target IP is required for client mode\n");
                print_usage(argv[0]);
                return -1;
            }
            if (g_config.target_port == 0) {
                fprintf(stderr, "Target port is required for client mode\n");
                print_usage(argv[0]);
                return -1;
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
    printf("\n========================================\n");
    printf("MES RTT Performance Test Configuration\n");
    printf("========================================\n");
    printf("Mode: %s\n", g_config.mode == MODE_SERVER ? "Server" : "Client");
    printf("Local instance ID: %d\n", g_config.local_inst_id);
    printf("Local IP: %s\n", g_config.local_ip);
    printf("Local port: %d\n", g_config.local_port);
    if (g_config.mode == MODE_CLIENT) {
        printf("Target instance ID: %d\n", g_config.target_inst_id);
        printf("Target IP: %s\n", g_config.target_ip);
        printf("Target port: %d\n", g_config.target_port);
        printf("Test count: %d\n", g_config.test_count);
        printf("Message size: %d bytes\n", g_config.message_size);
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
