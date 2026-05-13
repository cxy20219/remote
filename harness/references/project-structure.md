# 项目结构与协议设计

## 1. 系统概述

GoRemote 是一个基于 WebSocket 的内网穿透系统，通过 SSH 隧道实现公网访问内网服务。

**核心功能**：
- Agent 部署在内网，主动连接公网服务端的 WebSocket
- 通过 HTTP API 创建端口映射隧道
- 外部用户通过公网端口访问内网服务（如 SSH、HTTP）

## 2. 架构概览

### 2.1 架构模式

**星型架构（客户端主动连接）**：

```
                         ┌─────────────┐
                         │   公网      │
                         │   服务端    │
                         └──────┬──────┘
                                │ WebSocket 长连接
            ┌───────────────────┼───────────────────┐
            │                   │                   │
     ┌──────┴──────┐   ┌──────┴──────┐   ┌──────┴──────┐
     │  内网机器A   │   │  内网机器B   │   │  内网机器C   │
     │  (Agent)   │   │  (Agent)   │   │  (Agent)   │
     └─────────────┘   └─────────────┘   └─────────────┘
```

**特点**：
- Agent（被控机器）运行程序，主动连接公网服务端
- 防火墙友好：只需 Agent 出方向连接服务端 WebSocket 端口
- NAT 友好：Agent 主动发起连接，不受 NAT 影响
- 支持 SSH、HTTP 等任意 TCP 协议

### 2.2 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| 语言 | Go | 跨平台、内嵌 WebSocket、性能好 |
| WebSocket库 | gorilla/websocket | Go 最成熟，文档完善 |
| HTTP 框架 | Gin | 高性能路由和中间件 |
| 日志 | log/slog | Go 1.21+ 内置 |
| 配置 | viper | 支持多种格式，环境变量 |

## 3. 详细设计文档

- **[服务端设计文档](./server-design.md)** - 服务端架构、消息协议、接口设计
- **[客户端设计文档](./agent-design.md)** - 客户端架构、重连机制
- **[隧道设计文档](./tunnel-design.md)** - 隧道架构、数据传输、安全机制
- **[SSH 隧道直通测试用例](./ssh-tunnel-test-cases.md)** - SSH 隧道测试用例
- **[GoRemote 调试开发经验](../experience/go-remote-debugging.md)** - 开发调试经验总结

## 4. 消息协议

### 4.1 消息格式 (JSON)

```json
// 客户端注册
{
  "type": "register",
  "key": "your-secret-key",
  "hostname": "internal-server",
  "os": "linux"
}

// 服务端响应注册成功
{
  "type": "register_ok",
  "client_id": "uuid"
}

// 服务端响应注册失败
{
  "type": "register_fail",
  "reason": "invalid key"
}

// 心跳
{"type": "ping"}
{"type": "pong"}

// 隧道申请
{
  "type": "tunnel_open",
  "tunnel_id": "uuid",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}

// 隧道创建确认
{
  "type": "tunnel_open_ack",
  "tunnel_id": "uuid",
  "public_port": 15001,
  "success": true
}
```

### 4.2 消息类型汇总

| type | 方向 | 说明 |
|------|------|------|
| register | Client → Server | 客户端注册 |
| register_ok | Server → Client | 注册成功响应 |
| register_fail | Server → Client | 注册失败（密钥错误等） |
| ping | Client → Server | 心跳请求 |
| pong | Server → Client | 心跳响应 |
| tunnel_open | Client → Server | 申请创建隧道 |
| tunnel_open_ack | Server → Client | 隧道创建确认 |
| tunnel_close | C↔S | 关闭隧道 |
| tunnel_data | C↔S | 隧道数据（双向） |
| tunnel_error | Server → Client | 隧道错误通知 |

## 5. 安全性

### 5.1 传输安全
- 使用 TLS/WSS 加密通信（可选）
- 防止中间人攻击

### 5.2 认证
- Agent 使用预共享密钥连接
- 服务端验证密钥后才允许连接

### 5.3 隧道安全
- 隧道端口范围可配置
- 每客户端最大隧道数可限制

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
│   │   ├── server.go     # 主逻辑
│   │   ├── client.go     # 客户端管理
│   │   ├── handler.go    # 消息处理
│   │   ├── tunnel.go     # 隧道管理
│   │   ├── api.go       # HTTP API
│   │   └── config.go    # 配置加载
│   ├── agent/             # 客户端实现
│   │   ├── agent.go      # 主控逻辑
│   │   ├── connector.go  # WebSocket 连接
│   │   ├── handler.go   # 消息处理
│   │   ├── tunnel.go    # 隧道管理
│   │   ├── reconnect.go # 重连机制
│   │   └── config.go    # 配置加载
│   └── common/
│       └── message.go    # 消息定义
├── docs/
│   ├── docs.go           # Swagger 文档生成代码
│   ├── swagger.json      # Swagger JSON 文档
│   ├── swagger.yaml      # Swagger YAML 文档
│   ├── server-design.md  # 服务端详细设计
│   ├── agent-design.md   # 客户端详细设计
│   ├── tunnel-design.md  # 隧道详细设计
│   ├── project-structure.md # 项目结构本文档
│   ├── experience/       # 开发经验总结
│   │   └── go-remote-debugging.md
│   └── test/            # 测试文档
│       └── ssh-tunnel-test-cases.md
├── web/
│   └── static.go         # go:embed 嵌入 static/ 文件到二进制
├── config/
│   ├── server.yaml       # 服务端配置示例
│   └── agent.yaml        # 客户端配置示例
├── go.mod
└── go.sum
```

## 7. 部署方式

### 7.1 二进制部署

- 单一二进制文件，无依赖
- 配置文件（config.yaml）放密钥和服务端地址

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

- 服务端：systemd 或直接后台运行
- 客户端：systemd (Linux) / NSSM (Windows)

## 8. HTTP API

| Method | Path | 描述 |
|--------|------|------|
| GET | /health | 健康检查 |
| GET | /api/clients | 在线客户端列表 |
| GET | /api/clients/:id | 客户端详情 |
| GET | /api/clients/:client_id/tunnels | 客户端隧道列表 |
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 所有隧道列表 |
| GET | /api/tunnels/:tunnel_id | 隧道详情 |
| DELETE | /api/tunnels/:tunnel_id | 删除端口映射 |