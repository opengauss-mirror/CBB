# mes_rtt_perf 测试指南

## 概述

mes_rtt_perf 是一个多节点RTT性能验证工具，支持多种通信模式：

### 支持的通信类型
- **TCP**: 网络通信，适用于跨节点测试
- **IPC**: 共享内存通信，适用于同节点测试（无需配置IP/端口）
- **RDMA**: 远程直接内存访问（需要硬件支持）

## 编译步骤

### 方法1：使用 CMake 构建（推荐）

```bash
cd CBB

# 运行构建脚本
./build/linux/opengauss/build.sh -3rd $BINARYLIBS

# 编译完成后，可执行文件位于：
# <CBB_PATH>/output/bin/mes_rtt_perf
```

### 方法2：手动编译（如果已有 CBB 库）

```bash
cd CBB

gcc -std=c99 -D_POSIX_C_SOURCE=199309L -Wall -Wno-error -g -ggdb -O0 \
    -Isrc \
    -Isrc/cm_defines \
    -Isrc/cm_concurrency \
    -Isrc/cm_struct \
    -Isrc/cm_time \
    -Isrc/cm_types \
    -Isrc/cm_utils \
    -Isrc/cm_security \
    -Isrc/cm_protocol \
    -Isrc/cm_mes \
    -Ilibrary/huawei_security/include \
    -Ilibrary/openssl/include \
    -Ilibrary/zlib/include \
    -Ilibrary/lz4/include \
    -o output/bin/mes_rtt_perf \
    src/cm_mes/benchmark_rtt/mes_rtt_perf.c \
    -Loutput/lib \
    -Llibrary/openssl/lib \
    -Llibrary/zlib/lib \
    -Llibrary/lz4/lib \
    -Llibrary/huawei_security/lib \
    -lcbb -lssl -lcrypto -lz -llz4 -lsecurec -lpthread -ldl -lrt -lm
```

## IPC 模式测试（同节点）

### 测试场景
在同一台机器上使用共享内存进行高性能RTT测试，无需配置IP和端口。

### 测试步骤

#### 步骤1：启动服务器（终端1）

```bash
cd CBB

# 设置库路径
export LD_LIBRARY_PATH=<CBB_PATH>/output/lib:<THIRD_PARTY_LIB_PATH>:$LD_LIBRARY_PATH

# 启动IPC服务器
./output/bin/mes_rtt_perf -m server -p ipc -i 1
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Server
Pipe Type: IPC
Local instance ID: 1
Local IP: 127.0.0.1
Local port: 12345
========================================

Initializing MES...
MES initialized successfully

Server mode started. Waiting for client requests...
Press Ctrl+C to stop.
```

#### 步骤2：启动客户端（终端2）

```bash
cd CBB

# 设置库路径
export LD_LIBRARY_PATH=<CBB_PATH>/output/lib:<THIRD_PARTY_LIB_PATH>:$LD_LIBRARY_PATH

# 启动IPC客户端
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 1000 -s 64
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Client
Pipe Type: IPC
Local instance ID: 2
...
========================================

Initializing MES...
MES initialized successfully

Waiting for connection to server...
Connected to server 1

Starting RTT performance test...
Test count: 1000, Message size: 64 bytes, Threads: 1

==================================================
RTT Performance Test (IPC): Client 2 -> Server 1 (1 threads)
==================================================
| Success count            | 1000                 |
| Timeout count            | 0                     |
| Average RTT (μs)         | 150.43                |
| Min RTT (μs)             | 28.00                 |
| Max RTT (μs)             | 1456.00               |
| P50 RTT (μs)             | 148.00                |
| P95 RTT (μs)             | 180.00                |
| P99 RTT (μs)             | 220.00                |
| Std Dev (μs)             | 89.12                 |
| Total time (s)           | 0.15                  |
| Throughput (req/s)       | 6629.54               |
==================================================

Cleaning up...
RTT performance test completed!
```

### IPC模式注意事项

1. **无需配置IP/端口**: IPC模式使用共享内存通信，不需要网络配置
2. **清理共享内存**: 如果测试异常退出，需要手动清理：
   ```bash
   ipcs -m | grep 0x88880000 | awk '{print $2}' | xargs -r ipcrm -m
   ipcs -s | grep 0x88880001 | awk '{print $2}' | xargs -r ipcrm -s
   ```
3. **性能优势**: IPC模式RTT约150μs，比TCP快约25%

## 同节点 RTT 测试

### 测试场景
在同一台机器上使用相同 IP 不同端口进行 RTT 测试。

### 测试步骤

#### 步骤1：启动服务器（终端1）

```bash
cd CBB

./output/bin/mes_rtt_perf -m server -i 1 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT>
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Server
Local instance ID: 1
Local IP: <SERVER_IP>
Local port: <SERVER_PORT>
========================================

Initializing MES...
MES initialized successfully

Server mode started. Waiting for client requests...
Press Ctrl+C to stop.
```

#### 步骤2：启动客户端（终端2）- 单线程测试

```bash
cd CBB

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Client
Local instance ID: 2
Local IP: <CLIENT_IP>
Local port: <CLIENT_PORT>
Target instance ID: 1
Target IP: 
Target port: 0
Test count: 1000
Message size: 64 bytes
Thread count: 1
Timeout: 5000 ms
========================================

Initializing MES...
MES initialized successfully

Waiting for connection to server...
Connected to server 1

Starting RTT performance test: Client -> Server
Test count: 1000, Message size: 64 bytes, Threads: 1

==================================================
RTT Performance Test: Client 2 -> Server 1 (1 threads)
==================================================
| Success count            | 1000                 |
| Timeout count            | 0                     |
| Average RTT (μs)         | 46.99                 |
| Min RTT (μs)             | 40.00                 |
| Max RTT (μs)             | 788.00                |
| P50 RTT (μs)             | 46.00                 |
| P95 RTT (μs)             | 52.00                 |
| P99 RTT (μs)             | 60.00                 |
| Std Dev (μs)             | 21.61                 |
| Total time (s)           | 0.47                  |
| Throughput (req/s)       | 21131.69              |
==================================================

Cleaning up...
RTT performance test completed!
```

#### 步骤3：启动客户端（终端3）- 多线程并发测试

```bash
cd CBB

# 使用 4 个并发线程进行测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 4
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Client
Local instance ID: 2
Local IP: <CLIENT_IP>
Local port: <CLIENT_PORT>
Target instance ID: 1
Target IP: 
Target port: 0
Test count: 1000
Message size: 64 bytes
Thread count: 4
Timeout: 5000 ms
========================================

Initializing MES...
MES initialized successfully

Waiting for connection to server...
Connected to server 1

Starting RTT performance test: Client -> Server
Test count: 1000, Message size: 64 bytes, Threads: 4

==================================================
RTT Performance Test: Client 2 -> Server 1 (4 threads)
==================================================
| Success count            | 1000                 |
| Timeout count            | 0                     |
| Average RTT (μs)         | 48.12                 |
| Min RTT (μs)             | 42.00                 |
| Max RTT (μs)             | 820.00                |
| P50 RTT (μs)             | 47.00                 |
| P95 RTT (μs)             | 54.00                 |
| P99 RTT (μs)             | 62.00                 |
| Std Dev (μs)             | 22.34                 |
| Total time (s)           | 0.12                  |
| Throughput (req/s)       | 8333.33               |
==================================================

Cleaning up...
RTT performance test completed!
```

## 跨节点 RTT 测试

### 测试场景
在不同机器上进行 RTT 测试。

### 测试步骤

#### 步骤1：在节点1上启动服务器

```bash
# 在节点1 (<SERVER_IP>) 上运行
cd CBB

./output/bin/mes_rtt_perf -m server -i 1 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT>
```

#### 步骤2：在节点2上启动客户端（单线程）

```bash
# 在节点2 (<CLIENT_IP>) 上运行
cd CBB

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64
```

#### 步骤3：在节点2上启动客户端（多线程并发）

```bash
# 在节点2 (<CLIENT_IP>) 上运行
# 使用 8 个并发线程进行高负载测试
cd CBB

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 8
```

## 命令行参数说明

### 基本参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `-m, --mode` | 运行模式：server 或 client | 无 | 是 |
| `-p, --pipe-type` | 通信类型：tcp / ipc / rdma | tcp | 否 |
| `-i, --inst-id` | 本地实例 ID | 无 | 是 |
| `--target-id` | 目标实例 ID（客户端模式必需） | 无 | 客户端必需 |
| `--nodes` | 节点列表格式：id1:ip1:port1,id2:ip2:port2,... | 无 | TCP/RDMA模式需要 |

### 客户端模式参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `-c, --count` | 测试迭代次数 | 1000 | 否 |
| `-s, --size` | 消息大小（字节） | 64 | 否 |
| `-t, --threads` | 并发线程数 | 1 | 否 |
| `-T, --timeout` | 响应超时（毫秒） | 5000 | 否 |
| `-V, --verify` | 启用消息校验：验证payload数据完整性 | 关闭 | 否 |
| `-E, --inject-error` | 注入噪声错误：每100条消息注入一次错误，用于测试校验功能 | 关闭 | 否 |

### MES线程配置参数

| 参数 | 说明 | 默认值 | 范围 |
|------|------|--------|------|
| `--channel-cnt` | MES通道数量 | 1 | 1-256 |
| `--recv-threads` | MES接收线程数（每个优先级） | 1 | 1-128 |
| `--work-threads` | MES工作线程数（每个优先级） | 1 | 1-128 |
| `--priority-cnt` | 使用的优先级数量 | 1 | 1-8 |
| `--priority-hash` | 启用优先级散列分布 | 关闭 | - |

**参数说明：**
- **channel_cnt**: 控制MES通信通道数量，影响并发发送能力。增加通道数可提高多线程场景下的发送性能。
- **recv_task_count**: 控制每个优先级的接收线程数量，影响消息接收处理能力。增加接收线程可提高高负载场景下的处理吞吐量。
- **work_task_count**: 控制每个优先级的工作线程数量，影响消息处理能力。
- **priority_cnt**: 控制使用的优先级队列数量。MES支持8个优先级（0-7），增加优先级数量可以更好地分散负载。
- **priority_hash**: 启用后，消息会根据序号散列到不同优先级队列，实现负载均衡。

**优先级散列分布原理：**
```
消息序号 % 优先级数量 = 优先级
例如：priority_cnt=4 时
  消息0 -> 优先级0
  消息1 -> 优先级1
  消息2 -> 优先级2
  消息3 -> 优先级3
  消息4 -> 优先级0
  ...
```

### 可选参数

| 参数 | 说明 |
|------|------|
| `-V, --verify` | 启用消息校验：验证payload数据完整性 |
| `-E, --inject-error` | 注入噪声错误：每100条消息注入一次错误，用于测试校验功能 |
| `-v, --verbose` | 启用详细输出 |
| `-h, --help` | 显示帮助信息 |

## 性能指标说明

| 指标 | 说明 |
|------|------|
| Success count | 成功的请求数量 |
| Timeout count | 超时的请求数量 |
| Average RTT (μs) | 平均往返时间（微秒） |
| Min RTT (μs) | 最小往返时间（微秒） |
| Max RTT (μs) | 最大往返时间（微秒） |
| P50 RTT (μs) | 50分位往返时间（微秒） |
| P95 RTT (μs) | 95分位往返时间（微秒） |
| P99 RTT (μs) | 99分位往返时间（微秒） |
| Std Dev (μs) | 标准差（微秒） |
| Total time (s) | 总测试时间（秒） |
| Throughput (req/s) | 吞吐量（每秒请求数） |

### 数据完整性校验指标（启用 -V 时显示）

| 指标 | 说明 |
|------|------|
| Verified OK | 校验通过的消息数量 |
| Checksum Failed | 校验失败的消息数量 |
| Result | 校验结果（ALL PASSED 或 FAILED） |

## 并发测试场景

### 测试不同并发级别

```bash
# 单线程测试（基准测试）
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 1

# 2 线程并发测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 2

# 4 线程并发测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 4

# 8 线程并发测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 8

# 16 线程高并发测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 16
```

### 高负载并发测试

```bash
# 高并发 + 大消息量测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 50000 -s 1024 -t 16

# 极限压力测试
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 100000 -s 64 -t 32
```

## 故障排除

### 问题1：连接超时

**症状：** 客户端显示 "Timeout waiting for connection to server"

**解决方案：**
1. 检查服务器是否正常运行
2. 检查防火墙设置，确保端口开放
3. 检查网络连接
4. 验证 IP 地址和端口配置正确

### 问题2：MES 初始化失败

**症状：** 显示 "Failed to initialize MES"

**解决方案：**
1. 检查 CBB 库是否正确编译
2. 检查端口是否被占用
3. 使用 `-v` 参数启用详细日志

### 问题3：编译错误

**症状：** 编译时出现 undefined reference 错误

**解决方案：**
1. 确保使用 CMake 构建系统
2. 检查 CBB 库是否已编译
3. 验证库路径配置正确

### 问题4：高并发时出现超时

**症状：** 使用多线程测试时出现大量超时

**解决方案：**
1. 检查服务器端处理能力
2. 适当增加超时时间 `-T` 参数
3. 减少并发线程数
4. 检查网络带宽和延迟

## 高级测试场景

### MES线程配置测试

通过配置MES内部线程数来优化高并发场景下的性能：

```bash
# 使用4通道、4接收线程、2工作线程
./output/bin/mes_rtt_perf -m server -p ipc -i 1 --channel-cnt 4 --recv-threads 4 --work-threads 2

# 客户端测试
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 10000 -t 8 \
    --channel-cnt 4 --recv-threads 4 --work-threads 2
```

**配置建议：**
- 低并发场景（1-4线程）：使用默认配置即可
- 中等并发（4-16线程）：建议 `--channel-cnt 4 --recv-threads 4`
- 高并发场景（16+线程）：建议 `--channel-cnt 8 --recv-threads 8 --work-threads 4`

### 优先级散列分布测试

启用优先级散列分布，将消息均匀分布到多个优先级队列：

```bash
# 服务端：使用4个优先级，每个优先级2个接收线程
./output/bin/mes_rtt_perf -m server -p ipc -i 1 \
    --priority-cnt 4 --recv-threads 2 --work-threads 2

# 客户端：启用优先级散列分布
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 10000 -t 8 \
    --priority-cnt 4 --priority-hash \
    --channel-cnt 4 --recv-threads 2 --work-threads 2
```

**优先级散列分布的优势：**
1. **负载均衡**：消息均匀分布到多个队列，避免单队列瓶颈
2. **减少锁竞争**：不同优先级的消息由不同线程处理
3. **提高吞吐量**：多队列并行处理，提升整体吞吐量

**配置建议：**
- `priority_cnt` 建议设置为 2-8 的2的幂次方
- `recv_threads` 和 `work_threads` 根据 `priority_cnt` 相应调整
- 高并发场景建议启用 `--priority-hash`

### 测试不同消息大小

```bash
# 测试 1KB 消息
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 1024 -t 4

# 测试 4KB 消息
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 4096 -t 4

# 测试 16KB 消息
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 16384 -t 4
```

### 测试不同负载

```bash
# 轻量测试（100 次请求）
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 100 -s 64 -t 1

# 中等测试（1000 次请求）
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 4

# 重量测试（10000 次请求）
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 8
```

### 详细日志模式

```bash
# 启用详细日志查看 MES 内部操作
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 100 -s 64 -t 4 -v
```

### 数据校验测试

启用消息校验功能，验证数据传输的完整性：

```bash
# 服务端（终端1）
./output/bin/mes_rtt_perf -m server -p ipc -i 1

# 客户端（终端2）- 启用校验
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 1000 -s 1024 -V
```

输出示例：
```
==================================================
RTT Performance Test (IPC): Client 2 -> Server 1 (1 threads)
==================================================
| Success count            | 1000                 |
| Timeout count            | 0                     |
--------------------------------------------------
| Data Integrity Check     |                       |
|   Verified OK            | 1000                  |
|   Checksum Failed        | 0                     |
|   Result                 | ALL PASSED            |
--------------------------------------------------
| Average RTT (μs)         | 150.43                |
...
```

### 校验功能验证测试

启用噪声注入功能，验证校验功能是否正常工作（每100条消息注入一次错误）：

```bash
# 服务端（终端1）
./output/bin/mes_rtt_perf -m server -p ipc -i 1

# 客户端（终端2）- 启用校验和噪声注入
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 1000 -s 1024 -V -E
```

输出示例：
```
[VERIFY] Server: Payload verification failed for seq=0
[VERIFY] Client: Response payload verification failed for seq=0
[VERIFY] Server: Payload verification failed for seq=100
[VERIFY] Client: Response payload verification failed for seq=100
...

==================================================
RTT Performance Test (IPC): Client 2 -> Server 1 (1 threads)
==================================================
| Success count            | 1000                 |
| Timeout count            | 0                     |
--------------------------------------------------
| Data Integrity Check     |                       |
|   Verified OK            | 990                   |
|   Checksum Failed        | 10                    |
|   Result                 | FAILED                |
--------------------------------------------------
...
```

### 性能对比测试

```bash
# 对比单线程和多线程性能
echo "=== 单线程测试 ==="
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 1

echo "=== 4 线程测试 ==="
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 4

echo "=== 8 线程测试 ==="
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 8
```

## 总结

mes_rtt_perf 工具提供了一个简单而强大的方式来测试 CBB MES 通信框架的 RTT 性能。通过使用请求-响应模式，它可以准确测量网络往返时间，并提供详细的统计信息。

**关键特性：**
- 支持客户端-服务器模式
- 支持多种通信类型（TCP/IPC/RDMA）
- 支持跨节点和同节点测试
- 支持多线程并发压测
- 使用 CBB MES 通信框架
- 提供详细的性能统计信息
- 支持可配置的测试参数
- 提供吞吐量统计

**通信类型对比：**

| 类型 | 平均RTT | 吞吐量 | 适用场景 | 配置要求 |
|------|---------|--------|---------|---------|
| IPC | ~150μs | ~6600 req/s | 同节点进程间通信 | 无需IP/端口 |
| TCP | ~200μs | ~5000 req/s | 跨节点网络通信 | 需要IP/端口 |

**使用建议：**
1. 同节点测试优先使用IPC模式，性能更优
2. 跨节点测试使用TCP模式
3. 先在同节点测试验证功能
4. 然后在跨节点测试网络性能
5. 使用不同消息大小和负载进行压力测试
6. 使用多线程并发测试评估系统吞吐量
7. 使用详细日志模式进行故障排除
8. 对比不同并发级别的性能表现

**并发测试最佳实践：**
1. 从单线程开始，逐步增加并发数
2. 观察吞吐量和延迟的权衡
3. 注意 P95 和 P99 延迟在高并发下的变化
4. 监控超时率，确保系统稳定性
5. 根据实际应用场景选择合适的并发级别

**注意：**
- 请将 `<SERVER_IP>`、`<SERVER_PORT>`、`<CLIENT_IP>`、`<CLIENT_PORT>` 替换为实际的服务器和客户端 IP 地址及端口号