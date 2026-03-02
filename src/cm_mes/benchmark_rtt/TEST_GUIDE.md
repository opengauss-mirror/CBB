# mes_rtt_perf 测试指南

## 编译步骤

### 方法1：使用 CMake 构建（推荐）

```bash
cd /usr1/wyc/source_code/CBB

# 运行构建脚本
./build/linux/opengauss/build.sh -3rd $BINARYLIBS -m Debug -t cmake

# 编译完成后，可执行文件位于：
# /usr1/wyc/source_code/CBB/output/bin/mes_rtt_perf
```

### 方法2：手动编译（如果已有 CBB 库）

```bash
cd /usr1/wyc/source_code/CBB

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
    src/cm_mes/benchmark/mes_rtt_perf.c \
    -Loutput/lib \
    -Llibrary/openssl/lib \
    -Llibrary/zlib/lib \
    -Llibrary/lz4/lib \
    -Llibrary/huawei_security/lib \
    -lcbb -lssl -lcrypto -lz -llz4 -lsecurec -lpthread -ldl -lrt
```

## 同节点 RTT 测试

### 测试场景
在同一台机器上使用相同 IP 不同端口进行 RTT 测试。

### 测试步骤

#### 步骤1：启动服务器（终端1）

```bash
cd /usr1/wyc/source_code/CBB/output/bin

./mes_rtt_perf -m server -i 1 --local-ip 127.0.0.1 --local-port 12345
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Server
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
cd /usr1/wyc/source_code/CBB/output/bin

./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 1000 -s 64
```

**预期输出：**
```
========================================
MES RTT Performance Test Configuration
========================================
Mode: Client
Local instance ID: 2
Local IP: 127.0.0.1
Local port: 12346
Target instance ID: 1
Target IP: 127.0.0.1
Target port: 12345
Test count: 1000
Message size: 64 bytes
Timeout: 5000 ms
========================================

Initializing MES...
MES initialized successfully

Waiting for connection to server...
Connected to server 1

Starting RTT performance test...

Starting RTT performance test: Client -> Server
Test count: 1000, Message size: 64 bytes
Progress: 100/1000 (10.0%)
Progress: 200/1000 (20.0%)
Progress: 300/1000 (30.0%)
Progress: 400/1000 (40.0%)
Progress: 500/1000 (50.0%)
Progress: 600/1000 (60.0%)
Progress: 700/1000 (70.0%)
Progress: 800/1000 (80.0%)
Progress: 900/1000 (90.0%)

========================================
RTT Performance Test: Client 2 -> Server 1
========================================
| Metric                   | Value                |
-------------------------------------------
| Success count            | 1000                 |
| Timeout count            | 0                     |
| Average RTT (μs)         | 123.45                |
| Min RTT (μs)             | 45.67                 |
| Max RTT (μs)             | 567.89                |
| P50 RTT (μs)             | 110.34                |
| P95 RTT (μs)             | 234.56                |
| P99 RTT (μs)             | 456.78                |
| Std Dev (μs)             | 45.67                 |
========================================

Cleaning up...
RTT performance test: completed!
```

## 跨节点 RTT 测试

### 测试场景
在不同机器上进行 RTT 测试。

### 测试步骤

#### 步骤1：在节点1上启动服务器

```bash
# 在节点1 (192.168.1.1) 上运行
cd /usr1/wyc/source_code/CBB/output/bin

./mes_rtt_perf -m server -i 1 --local-ip 192.168.1.1 --local-port 12345
```

#### 步骤2：在节点2上启动客户端

```bash
# 在节点2 (192.168.1.2) 上运行
cd /usr1/wyc/source_code/CBB/output/bin

./mes_rtt_perf -m client -i 2 --local-ip 192.168.1.2 --local-port 12346 \
               --target-id 1 --target-ip 192.168.1.1 --target-port 12345 \
               -c 1000 -s 64 -T 5000
```

## 命令行参数说明

### 基本参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `-m, --mode` | 运行模式：server 或 client | 无 | 是 |
| `-i, --inst-id` | 本地实例 ID | 无 | 是 |
| `--local-ip` | 本地 IP 地址 | 127.0.0.1 | 否 |
| `--local-port` | 本地端口 | 12345 | 否 |

### 客户端模式参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `--target-id` | 目标实例 ID | 无 | 是（客户端模式） |
| `--target-ip` | 目标 IP 地址 | 无 | 是（客户端模式） |
| `--target-port` | 目标端口 | 无 | 是（客户端模式） |
| `-c, --count` | 测试迭代次数 | 1000 | 否 |
| `-s, --size` | 消息大小（字节） | 64 | 否 |
| `-T, --timeout` | 响应超时（毫秒） | 5000 | 否 |

### 可选参数

| 参数 | 说明 |
|------|------|
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

## 高级测试场景

### 测试不同消息大小

```bash
# 测试 1KB 消息
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 1000 -s 1024

# 测试 4KB 消息
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 1000 -s 4096

# 测试 16KB 消息
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 1000 -s 16384
```

### 测试不同负载

```bash
# 轻量测试（100 次请求）
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 100 -s 64

# 中等测试（1000 次请求）
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 1000 -s 64

# 重量测试（10000 次请求）
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 10000 -s 64
```

### 详细日志模式

```bash
# 启用详细日志查看 MES 内部操作
./mes_rtt_perf -m client -i 2 --local-ip 127.0.0.1 --local-port 12346 \
               --target-id 1 --target-ip 127.0.0.1 --target-port 12345 \
               -c 100 -s 64 -v
```

## 总结

mes_rtt_perf 工具提供了一个简单而强大的方式来测试 CBB MES 通信框架的 RTT 性能。通过使用请求-响应模式，它可以准确测量网络往返时间，并提供详细的统计信息。

**关键特性：**
- 支持客户端-服务器模式
- 支持跨节点和同节点测试
- 使用 CBB MES 通信框架
- 提供详细的性能统计信息
- 支持可配置的测试参数

**使用建议：**
1. 先在同节点测试验证功能
2. 然后在跨节点测试网络性能
3. 使用不同消息大小和负载进行压力测试
4. 使用详细日志模式进行故障排除
