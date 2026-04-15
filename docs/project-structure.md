# 远程命令执行系统设计方案

## 1. 系统概述

设计一个后台常驻程序，通过WebSocket长连接实现远程命令执行和服务端-客户端双向文件传输。服务端可以主动向客户端下发命令，客户端执行后返回结果。

## 2. 架构概览

### 2.1 架构模式

**星型架构（客户端主动连接）**：

```
                    ┌─────────────┐
                    │  控制中心   │
                    │  (服务端)   │
                    └──────┬──────┘
                           │ WebSocket长连接
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────┴──────┐ ┌──────┴──────┐ ┌──────┴──────┐
    │  机器A      │ │  机器B      │ │  机器C      │
    │  (客户端)   │ │  (客户端)   │ │  (客户端)   │
    └─────────────┘ └─────────────┘ └─────────────┘
```

**特点**：
- 客户端（被控机器）运行agent程序，主动连接控制中心
- 防火墙友好：只需客户端出方向连接服务端（443端口）
- NAT友好：客户端主动发起连接，不受NAT影响

### 2.2 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| 语言 | Go | 跨平台、内嵌WebSocket、性能好 |
| WebSocket库 | gorilla/websocket | Go最成熟，文档完善 |
| 命令执行 | os/exec | 标准库，跨平台 |
| 日志 | log/slog | Go 1.21+内置 |
| 配置 | viper | 支持多种格式，环境变量 |

## 3. 详细设计文档

- **[服务端设计文档](./server-design.md)** - 服务端架构、消息协议、接口设计
- **[客户端设计文档](./agent-design.md)** - 客户端架构、命令执行、重连机制
- **[服务端测试方案](./server-test.md)** - 服务端单元/集成/端到端测试
- **[客户端测试方案](./agent-test.md)** - 客户端单元/集成/端到端测试

## 4. 消息协议

### 4.1 消息格式 (JSON)

```json
// 客户端注册
{
  "type": "register",
  "key": "your-secret-key",
  "hostname": "server-01",
  "os": "linux"
}

// 服务端响应注册成功
{
  "type": "register_ok",
  "client_id": "uuid"
}

// 服务端下发命令
{
  "type": "exec",
  "task_id": "uuid",
  "command": "ls -la /tmp",
  "timeout": 30
}

// 客户端执行结果
{
  "type": "result",
  "task_id": "uuid",
  "exit_code": 0,
  "stdout": "total 0\n",
  "stderr": ""
}

// 心跳
{"type": "ping"}
{"type": "pong"}
```

### 4.2 消息类型汇总

| type | 方向 | 说明 |
|------|------|------|
| register | Client → Server | 客户端注册 |
| register_ok | Server → Client | 注册成功响应 |
| register_fail | Server → Client | 注册失败（密钥错误等） |
| exec | Server → Client | 服务端下发命令 |
| result | Client → Server | 客户端返回执行结果 |
| ping | Client → Server | 心跳请求 |
| pong | Server → Client | 心跳响应 |
| upload | Server → Client | 上传文件（服务端→客户端） |
| upload_data | Server → Client | 上传文件数据 |
| upload_complete | Client → Server | 上传完成确认 |
| download | Client → Server | 下载文件请求（客户端→服务端） |
| download_data | Server → Client | 下载文件数据 |
| download_complete | Server → Client | 下载完成确认 |

### 4.3 文件传输消息格式

**上传（服务端 → 客户端）**：
```json
// 发起上传
{
  "type": "upload",
  "task_id": "file-001",
  "file_id": "uuid",
  "filename": "app.tar.gz",
  "size": 104857600,
  "offset": 0
}

// 分片数据
{
  "type": "upload_data",
  "file_id": "uuid",
  "offset": 0,
  "data": "base64 encoded data...",
  "eof": false
}

// 最后一个分片
{
  "type": "upload_data",
  "file_id": "uuid",
  "offset": 104857600,
  "data": "base64 encoded data...",
  "eof": true
}

// 上传完成确认（客户端发送）
{
  "type": "upload_complete",
  "file_id": "uuid",
  "success": true
}
```

**下载（客户端 → 服务端）**：
```json
// 发起下载请求
{
  "type": "download",
  "task_id": "file-002",
  "file_id": "uuid",
  "filename": "/var/log/syslog",
  "offset": 0
}

// 分片数据（服务端返回）
{
  "type": "download_data",
  "file_id": "uuid",
  "offset": 0,
  "data": "base64 encoded data...",
  "eof": false
}

// 下载完成（服务端发送）
{
  "type": "download_complete",
  "file_id": "uuid",
  "success": true
}
```

## 5. 安全性

### 5.1 传输安全
- 使用 TLS/WSS 加密通信
- 防止中间人攻击

### 5.2 认证
- 客户端使用预共享密钥连接
- 服务端验证密钥后才允许连接

### 5.3 命令安全
- 建议客户端限制可执行命令范围
- 可扩展：白名单模式

## 6. 项目结构

```
project/
├── cmd/
│   ├── server/
│   │   └── main.go        # 服务端入口
│   └── agent/
│       └── main.go        # 客户端入口
├── internal/
│   ├── server/            # 服务端实现 (Gin + WebSocket)
│   ├── agent/             # 客户端实现 (见 agent-design.md)
│   └── common/
│       ├── message.go     # 消息定义
│       └── util.go        # 工具函数
├── docs/
│   ├── docs.go            # Swagger 文档生成代码
│   ├── swagger.json       # Swagger JSON 文档
│   ├── swagger.yaml       # Swagger YAML 文档
│   ├── server-design.md   # 服务端详细设计
│   ├── agent-design.md    # 客户端详细设计
│   ├── server-test.md     # 服务端测试方案
│   └── agent-test.md      # 客户端测试方案
├── config/
│   ├── server.yaml        # 服务端配置示例
│   └── agent.yaml         # 客户端配置示例
├── go.mod
└── go.sum
```

## 7. 部署方式

### 7.1 二进制部署

- 单一二进制文件，无依赖
- 配置文件（config.yaml）放密钥和服务器地址

**服务端**：
```bash
./server --config config.yaml
```

**客户端**：
```bash
# Linux
./agent --config /etc/agent/config.yaml

# Windows
agent.exe --config agent.yaml
```

### 7.2 进程管理

- 服务端：systemd 或 直接后台运行
- 客户端：systemd (Linux) / NSSM (Windows)
