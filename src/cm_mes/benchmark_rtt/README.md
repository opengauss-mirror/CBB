# mes_rtt_perf（多节点 RTT 压测）

**`<CBB_PATH>`** 表示本仓库 CBB 根目录的绝对路径，请替换为实际路径。

## 作用

`mes_rtt_perf` 用于多进程/多节点场景下的消息往返时延（RTT）与吞吐统计，与 `mes_benchmark` 共用 `src/cm_mes/benchmark/benchmark_common.c`（时间戳、RTT 统计、校验负载、MES 日志回调等）。

## 概述

mes_rtt_perf 是一个多节点 RTT 性能验证工具，支持多种通信模式：

### 支持的通信类型

- **TCP**：网络通信，适用于跨节点测试
- **IPC**：共享内存通信，适用于同节点测试（无需配置 IP/端口）
- **RDMA**：远程直接内存访问（需要硬件支持）

## 构建与运行

### 方式一：使用工程构建脚本（推荐）

```bash
cd <CBB_PATH>/build/linux/opengauss
./build.sh
```

若需在仓库根目录配合三方库构建，可执行：

```bash
cd <CBB_PATH>
./build/linux/opengauss/build.sh -3rd $BINARYLIBS
```

可执行文件：`<CBB_PATH>/output/bin/mes_rtt_perf`（以工程实际输出为准）。

### 方式二：手动编译（若已有 CBB 库）

```bash
cd <CBB_PATH>

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

## 环境变量（运行前）

**建议将 `output/lib` 放在 `LD_LIBRARY_PATH` 最前面**，避免加载系统中的旧版本库。请将示例中的三方库路径替换为本机 openGauss/third_party 实际布局：

```bash
export LD_LIBRARY_PATH=<CBB_PATH>/output/lib:<THIRD_PARTY_CBB_LIB>:<THIRD_PARTY_OPENSSL_LIB>:$LD_LIBRARY_PATH
```

下文 IPC 示例中给出了具体路径写法，可按环境改写。

## IPC 模式测试（同节点）

### 测试场景

在同一台机器上使用共享内存进行高性能 RTT 测试，无需配置 IP 和端口。

### 测试步骤

#### 步骤 1：启动服务器（终端 1）

```bash
cd <CBB_PATH>

export LD_LIBRARY_PATH=<CBB_PATH>/output/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/component/cbb/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/dependency/openssl/comm/lib

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

#### 步骤 2：启动客户端（终端 2）

```bash
cd <CBB_PATH>

export LD_LIBRARY_PATH=<CBB_PATH>/output/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/component/cbb/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/dependency/openssl/comm/lib

./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 1000 -s 64
```

**预期输出（示例）：** 配置块、`Connected to server 1`、RTT 统计表（Success/Timeout/Avg/P50/P95/P99 等）、`RTT performance test completed!`。

### IPC 模式注意事项

1. **无需配置 IP/端口**：IPC 模式使用共享内存通信，不需要网络配置。
2. **清理共享内存**：若测试异常退出，可手动清理：

   ```bash
   ipcs -m | grep 0x88880000 | awk '{print $2}' | xargs -r ipcrm -m
   ipcs -s | grep 0x88880001 | awk '{print $2}' | xargs -r ipcrm -s
   ```

3. **性能参考**：同环境下 IPC 模式 RTT 通常优于 TCP（具体数值依机器而定）。

## 同节点 RTT 测试（TCP）

### 测试场景

在同一台机器上使用相同或不同端口进行 TCP RTT 测试。

### 测试步骤

#### 步骤 1：启动服务器（终端 1）

```bash
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m server -i 1 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT>
```

#### 步骤 2：启动客户端（终端 2）— 单线程

```bash
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64
```

#### 步骤 3：启动客户端 — 多线程并发

```bash
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 4
```

请将 `<SERVER_IP>`、`<SERVER_PORT>`、`<CLIENT_IP>`、`<CLIENT_PORT>` 替换为实际地址与端口。

## 跨节点 RTT 测试

### 测试场景

在不同机器上进行 RTT 测试。

### 测试步骤

#### 步骤 1：在节点 1 上启动服务器

```bash
# 在节点 1 (<SERVER_IP>) 上运行
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m server -i 1 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT>
```

#### 步骤 2：在节点 2 上启动客户端（单线程）

```bash
# 在节点 2 (<CLIENT_IP>) 上运行
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64
```

#### 步骤 3：在节点 2 上启动客户端（多线程）

```bash
# 在节点 2 (<CLIENT_IP>) 上运行
cd <CBB_PATH>

./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 8
```

## 命令行参数说明

### 基本参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `-m, --mode` | 运行模式：server 或 client | 无 | 是 |
| `-p, --pipe-type` | 通信类型：tcp / ipc / rdma | tcp | 否 |
| `-i, --inst-id` | 本地实例 ID | 无 | 是 |
| `--target-id` | 目标实例 ID（客户端模式） | 无 | 客户端必需 |
| `--nodes` | 节点列表：`id1:ip1:port1,id2:ip2:port2,...` | 无 | TCP/RDMA 模式需要 |

### 客户端模式参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|---------|------|
| `-c, --count` | 测试迭代次数 | 1000 | 否 |
| `-s, --size` | 消息大小（字节） | 64 | 否 |
| `-t, --threads` | 并发线程数 | 1 | 否 |
| `-T, --timeout` | 响应超时（毫秒） | 5000 | 否 |

### MES 线程配置参数

| 参数 | 说明 | 默认值 | 范围 |
|------|------|--------|------|
| `--channel-cnt` | MES 通道数量 | 1 | 1-256 |
| `--recv-threads` | MES 接收线程数（每个优先级） | 1 | 1-128 |
| `--work-threads` | MES 工作线程数（每个优先级） | 1 | 1-128 |
| `--priority-cnt` | 使用的优先级数量 | 1 | 1-8 |
| `--priority-hash` | 启用优先级散列分布 | 关闭 | - |

**参数说明：**

- **channel_cnt**：控制 MES 通信通道数量，影响并发发送能力；多线程场景可适当增大。
- **recv_task_count**：每个优先级的接收线程数，影响接收处理能力。
- **work_task_count**：每个优先级的工作线程数，影响消息处理。
- **priority_cnt**：优先级队列数量（MES 支持 0-7）；增大可分散负载。
- **priority_hash**：启用后消息按序号散列到不同优先级队列，利于负载均衡。

**优先级散列示例：**

```
消息序号 % 优先级数量 = 优先级
例如 priority_cnt=4 时：消息 0→优先级 0，消息 1→优先级 1，…
```

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
| P50 RTT (μs) | 50 分位往返时间（微秒） |
| P95 RTT (μs) | 95 分位往返时间（微秒） |
| P99 RTT (μs) | 99 分位往返时间（微秒） |
| Std Dev (μs) | 标准差（微秒） |
| Total time (s) | 总测试时间（秒） |
| Throughput (req/s) | 吞吐量（每秒请求数） |

## 并发测试场景

### 不同并发级别

```bash
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 1
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 2
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 4
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 64 -t 8
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 10000 -s 64 -t 16
```

### 高负载

```bash
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 50000 -s 1024 -t 16
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 100000 -s 64 -t 32
```

## 故障排除

### 连接超时

**症状：** 客户端显示 `Timeout waiting for connection to server`。

**处理：** 确认服务端已启动；检查防火墙与端口；核对 `--nodes` 中 IP/端口；检查网络连通性。

### MES 初始化失败

**症状：** `Failed to initialize MES`。

**处理：** 确认 CBB 已正确编译；端口未被占用；使用 `-v` 查看详细日志。

### 编译链接错误

**症状：** undefined reference 等。

**处理：** 优先用工程 `build.sh` 构建；确认 `output/lib` 与三方库路径正确。

### 高并发大量超时

**处理：** 适当增大 `-T`；降低 `-t`；检查服务端与网络带宽；必要时调整 `--channel-cnt` / `--recv-threads` 等。

## 高级测试场景

### MES 线程配置（IPC 示例）

```bash
./output/bin/mes_rtt_perf -m server -p ipc -i 1 --channel-cnt 4 --recv-threads 4 --work-threads 2
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 10000 -t 8 \
    --channel-cnt 4 --recv-threads 4 --work-threads 2
```

**经验参考：** 低并发可默认；中等并发可尝试 `--channel-cnt 4 --recv-threads 4`；高并发可增大通道与接收线程，并视情况增加 `--work-threads`。

### 优先级散列（IPC 示例）

```bash
./output/bin/mes_rtt_perf -m server -p ipc -i 1 \
    --priority-cnt 4 --recv-threads 2 --work-threads 2
./output/bin/mes_rtt_perf -m client -p ipc -i 2 --target-id 1 -c 10000 -t 8 \
    --priority-cnt 4 --priority-hash \
    --channel-cnt 4 --recv-threads 2 --work-threads 2
```

### 不同消息大小

```bash
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 1024 -t 4
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 4096 -t 4
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 1000 -s 16384 -t 4
```

### 详细日志

```bash
./output/bin/mes_rtt_perf -m client -i 2 --nodes 1:<SERVER_IP>:<SERVER_PORT>,2:<CLIENT_IP>:<CLIENT_PORT> -c 100 -s 64 -t 4 -v
```

## 总结与使用建议

mes_rtt_perf 通过请求-响应模式测量 MES 的 RTT，并输出统计与吞吐。

**要点：**

- 支持 server/client、TCP/IPC/RDMA、同机与跨机、多线程压测。
- 同机优先可试 IPC；跨机用 TCP；先同机验证再测网络。
- 并发压测可从单线程逐步增加线程数，关注 P95/P99 与超时率。

**通信类型参考（数值依环境变化）：**

| 类型 | 典型场景 | 配置 |
|------|----------|------|
| IPC | 同节点进程间 | 无需 IP/端口 |
| TCP | 跨节点 | 需 `--nodes` 中 IP/端口 |

## 相关文档

- **单节点吞吐/延迟压测（mes_benchmark）**：见 `../benchmark/README.md`。
