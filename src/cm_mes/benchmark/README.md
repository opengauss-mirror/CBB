# MES Benchmark 测试指南

## 概述

本工具用于测试MES (Message Exchange System) 的性能，支持多种通信模式和测试模式：

### 支持的通信类型
- **IPC** (Inter-Process Communication): 共享内存通信，适用于同节点进程间通信
- **TCP**: 网络通信，适用于跨节点通信
- **RDMA**: 远程直接内存访问（需要硬件支持）

### 支持的测试模式
- **Send-Only**: 单向消息发送测试
- **Request-Response**: 请求-响应双向通信测试（RTT测量）

## 性能对比

| 通信类型 | 发送模式 | 平均RTT | 吞吐量 | 适用场景 |
|---------|---------|---------|--------|---------|
| IPC | 直接发送 | ~70μs | ~14000 req/s | 同节点高性能通信 |
| IPC | 队列发送 | ~75μs | ~13000 req/s | 精确RTT测量 |
| TCP | 直接发送 | ~200μs | ~5000 req/s | 跨节点网络通信 |

> 注：IPC模式经过优化后，性能比TCP快约2-3倍。

## 编译

```bash
cd /usr1/wyc/source_code/CBB
cmake -DUSE_GM_TLS=OFF .
make -sj
```

编译成功后，可执行文件位于：`output/bin/mes_benchmark`

## 环境配置

### 重要：设置正确的库路径

**必须将output/lib放在LD_LIBRARY_PATH的最前面**，否则会加载系统中的旧版本库：

```bash
export LD_LIBRARY_PATH=/usr1/wyc/source_code/CBB/output/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/component/cbb/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/dependency/openssl/comm/lib:$LD_LIBRARY_PATH
```

### 清理旧的共享内存（可选）

如果之前测试异常退出，可能需要清理共享内存：

```bash
ipcs -m | grep 0x88880000 | awk '{print $2}' | xargs -r ipcrm -m
ipcs -s | grep 0x88880001 | awk '{print $2}' | xargs -r ipcrm -s
```

## 使用方法

### 基本命令格式

```bash
./output/bin/mes_benchmark [OPTIONS]
```

### 命令行参数详解

| 参数 | 简写 | 说明 | 默认值 | 示例 |
|------|------|------|--------|------|
| --type | -t | 通信类型：<br>- `ipc`: 共享内存通信，同节点高性能<br>- `tcp`: 网络通信，跨节点<br>- `rdma`: RDMA通信（需硬件支持） | ipc | `-t ipc` |
| --mode | -m | 测试模式：<br>- `reqresp`: 请求-响应模式，测量RTT<br>- `sendonly`: 单向发送模式，测量吞吐量 | reqresp | `-m reqresp` |
| --count | -c | 测试消息数量，建议值：<br>- 功能验证: 10-100<br>- 性能测试: 1000-10000 | 1000 | `-c 1000` |
| --size | -s | 消息大小（字节），范围：64-131072<br>注意：小于64字节会自动调整 | 64 | `-s 1024` |
| --timeout | -T | 响应超时时间（毫秒），仅reqresp模式有效 | 5000 | `-T 10000` |
| --direct | -d | 直接发送模式：不经过发送队列，直接调用发送接口（推荐） | 启用 | `-d` |
| --queue | -q | 队列发送模式：消息先入队列，由后台线程发送 | 禁用 | `-q` |
| --verbose | -v | 启用详细输出，显示每条消息的日志 | 关闭 | `-v` |
| --help | -h | 显示帮助信息 | - | `-h` |

### 参数组合建议

| 测试场景 | 推荐参数组合 |
|---------|-------------|
| 快速功能验证 | `-t ipc -m reqresp -c 10` |
| IPC性能测试 | `-t ipc -m reqresp -c 1000` |
| TCP性能测试 | `-t tcp -m reqresp -c 1000` |
| 大消息测试 | `-t ipc -m reqresp -c 100 -s 4096` |
| 吞吐量测试 | `-t ipc -m sendonly -c 10000` |
| 调试模式 | `-t ipc -m reqresp -c 10 -v` |

## 测试示例

### 1. IPC Send-Only 测试（推荐入门）

```bash
./output/bin/mes_benchmark -t ipc -m sendonly -c 10
```

输出示例：
```
========================================
Instance 1 -> Instance 2 (A -> B)
Pipe Type: IPC
Test Mode: Send-Only
========================================

========================================
Bidirectional Latency Test Results
========================================
| Metric                    | Value                |
-------------------------------------------
| Messages sent             | 10                   |
| Message size (bytes)      | 64                   |
| Total time (ms)           | 98.59                |
| Average latency (μs)     | 9858.89              |
| Min latency (μs)         | 5948.00              |
| Max latency (μs)         | 10409.91             |
| Throughput (msg/s)        | 101.43               |
-------------------------------------------
| Avg send latency (μs)    | 391.89               |
| Avg recv latency (μs)    | 9900.00              |
========================================

Benchmark completed successfully!
```

### 2. IPC Request-Response 测试

```bash
./output/bin/mes_benchmark -t ipc -m reqresp -c 10
```

输出示例：
```
==================================================
Request-Response Test (Pipe Type: 2)
==================================================
| Success count             |                 8192 |
| Timeout count             |                    0 |
| Average RTT (μs)         |                39.79 |
| Min RTT (μs)             |                37.00 |
| Max RTT (μs)             |               961.00 |
| P50 RTT (μs)             |                39.00 |
| P95 RTT (μs)             |                41.00 |
| P99 RTT (μs)             |                45.00 |
| Std Dev (μs)             |                18.77 |
--------------------------------------------------
| Latency Breakdown         |                      |
|   Send Latency (μs)      |                 9.39 |
|   Network Req (μs)       |                25.17 |
|   Server Process (μs)    |                 0.07 |
|   Network Resp (μs)      |                 5.16 |
|   Sum Check (μs)         |                39.79 |
--------------------------------------------------
| Total time (s)            |                 0.33 |
| Throughput (req/s)        |             24926.29 |
==================================================
```

### 3. 大批量测试

```bash
./output/bin/mes_benchmark -t ipc -m sendonly -c 100
```

### 4. 详细日志模式

```bash
./output/bin/mes_benchmark -t ipc -m sendonly -c 10 -v
```

### 5. 自定义消息大小

```bash
./output/bin/mes_benchmark -t ipc -m reqresp -c 100 -s 1024
```

## 性能指标说明

### Send-Only 模式指标

- **Messages sent**: 发送的消息总数
- **Message size**: 消息大小（字节）
- **Total time**: 总测试时间（毫秒）
- **Average latency**: 平均延迟（微秒）
- **Min/Max latency**: 最小/最大延迟（微秒）
- **Throughput**: 吞吐量（消息/秒）
- **Avg send latency**: 平均发送延迟（微秒）
- **Avg recv latency**: 平均接收延迟（微秒）

### Request-Response 模式指标

- **Success count**: 成功的请求-响应次数
- **Timeout count**: 超时次数
- **Average RTT**: 平均往返时间（微秒）
- **Min/Max RTT**: 最小/最大往返时间（微秒）
- **P50/P95/P99 RTT**: 第50/95/99百分位往返时间（微秒）
- **Std Dev**: 标准差（微秒）

#### 时延分解（Latency Breakdown）

RTT可以分解为以下四个部分，帮助定位性能瓶颈：

| 指标 | 含义 | 计算方式 |
|------|------|---------|
| **Send Latency** | 发送端发送时间 | `发送完成时间 - 发送开始时间` |
| **Network Req** | 请求网络传输时间 | `接收端收到时间 - 发送完成时间` |
| **Server Process** | 服务端处理时间 | `响应发送时间 - 请求收到时间` |
| **Network Resp** | 响应网络传输时间 | `收到响应时间 - 响应发送时间` |

**验证公式**: `Send Latency + Network Req + Server Process + Network Resp = RTT`

- **Throughput**: 吞吐量（请求/秒）

## 故障排查

### 问题1: "queue push failed, queue full"

**原因**: 
- IPC队列容量不足
- 接收线程处理速度慢

**解决方案**:
- 确保使用正确的库路径（output/lib在前）
- 清理旧的共享内存后重新测试

### 问题2: "Failed to initialize MES"

**原因**:
- 共享内存初始化失败
- 库版本不匹配

**解决方案**:
```bash
# 清理共享内存
ipcs -m | grep 0x88880000 | awk '{print $2}' | xargs -r ipcrm -m
ipcs -s | grep 0x88880001 | awk '{print $2}' | xargs -r ipcrm -s

# 确认库路径
ldd ./output/bin/mes_benchmark | grep cbb
# 应该显示: libcbb.so => /usr1/wyc/source_code/CBB/output/lib/libcbb.so
```

### 问题3: 测试卡死不退出

**原因**:
- 进程间通信异常
- 共享内存残留

**解决方案**:
```bash
# 使用timeout命令
timeout 15 ./output/bin/mes_benchmark -t ipc -m sendonly -c 10

# 如果卡死，手动清理
pkill -9 mes_benchmark
ipcs -m | grep 0x88880000 | awk '{print $2}' | xargs -r ipcrm -m
```

## 技术细节

### IPC队列配置

- **队列容量**: 256个消息
- **最大消息大小**: 64KB
- **接收策略**: 自适应轮询（自旋 -> 轻量休眠 -> 深度休眠）

### IPC性能优化

IPC接收线程采用自适应轮询策略，根据空闲程度动态调整：
1. **自旋等待**（前10次空闲）：无延迟，立即响应
2. **轻量休眠**（10-100次）：`epoll_wait`超时0ms
3. **深度休眠**（100次后）：`epoll_wait`超时1ms

此优化将IPC RTT从~9700μs降低到~150μs，性能提升约64倍。

### 共享内存

- **Key**: 0x88880000
- **信号量Key**: 0x88880001
- **权限**: 0666

## 注意事项

1. **首次运行**: 建议先用小数据量测试（-c 10）
2. **库路径**: 务必将output/lib放在LD_LIBRARY_PATH最前面
3. **共享内存**: 异常退出后需要手动清理
4. **性能测试**: 大批量测试建议使用100或1000条消息
5. **日志模式**: 调试时使用-v参数，正常测试可省略

## 相关文件

- 源代码: `src/cm_mes/benchmark/mes_benchmark.c`
- IPC实现: `src/cm_mes/mes_ipc.c`, `src/cm_mes/mes_ipc.h`
- 编译输出: `output/bin/mes_benchmark`
- 动态库: `output/lib/libcbb.so`
