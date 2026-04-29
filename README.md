# GoRemote

SSH 隧道内网穿透系统 - 通过 WebSocket 隧道暴露内网服务。

## 功能特性

- **SSH 隧道** - 通过 WebSocket 隧道暴露内网 SSH 端口
- **心跳保活** - 客户端定期发送心跳，服务端检测超时断开
- **自动重连** - 客户端支持断线自动重连（指数退避）
- **跨平台** - 支持 Linux 和 Windows
- **TLS 加密** - 支持 WebSocket TLS 加密传输

## 项目结构

```
go-remote/
├── cmd/
│   ├── server/main.go       # 服务端入口
│   └── agent/main.go        # 客户端入口
├── internal/
│   ├── common/              # 公共定义（消息结构）
│   ├── server/              # 服务端实现 (Gin + WebSocket)
│   │   ├── server.go       # Gin 引擎与路由
│   │   ├── client.go       # 客户端管理
│   │   ├── handler.go      # 消息处理
│   │   ├── tunnel.go       # 隧道管理
│   │   ├── api.go          # HTTP API
│   │   └── config.go       # 配置加载
│   └── agent/              # 客户端实现
│       ├── agent.go        # 主控逻辑
│       ├── connector.go    # WebSocket 连接
│       ├── handler.go      # 消息处理
│       ├── reconnect.go    # 重连机制
│       ├── tunnel.go       # 隧道管理
│       └── config.go       # 配置加载
├── config/
│   ├── server.yaml          # 服务端配置（开发）
│   ├── agent.yaml          # 客户端配置（开发）
│   ├── server-deploy.yaml  # 服务端配置（生产）
│   └── agent-deploy.yaml  # 客户端配置（生产）
├── docs/
│   ├── workflow/           # 操作流程文档
│   └── experience/         # 调试经验文档
└── README.md
```

## 编译

### Windows

```bash
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent
```

### Linux（跨编译）

```bash
GOOS=linux GOARCH=amd64 go build -o bin/server ./cmd/server
GOOS=linux GOARCH=amd64 go build -o bin/agent ./cmd/agent
```

## 配置

### 服务端配置 (server.yaml)

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false

auth:
  key: "test-secret-key"

heartbeat:
  interval: 30
  timeout: 90

log:
  level: "info"

tunnel:
  public_host: "your-public-host"
  port_range_start: 10000
  port_range_end: 20000
  max_tunnels_per_client: 10
```

### 客户端配置 (agent.yaml)

```yaml
server:
  address: "localhost:8080"

auth:
  key: "test-secret-key"

heartbeat:
  interval: 30

reconnect:
  interval: 5
  max_interval: 60

log:
  level: "info"
```

## 使用

### 1. 启动服务端

```bash
./bin/server.exe --config config/server.yaml
```

### 2. 启动客户端

```bash
./bin/agent.exe --config config/agent.yaml
```

### 3. Swagger UI

```
http://localhost:8080/swagger/index.html
```

### 4. API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/clients` | GET | 查看在线客户端 |
| `/api/tunnels` | GET | 查看所有隧道 |
| `/api/tunnels` | POST | 创建隧道 |
| `/api/tunnels/:id` | PUT | 更新隧道端口 |
| `/api/tunnels/:id` | DELETE | 删除隧道 |

### 5. 创建隧道

```bash
# 查看客户端
curl http://localhost:8080/api/clients

# 创建隧道
curl -X POST http://localhost:8080/api/tunnels \
  -H "Content-Type: application/json" \
  -d '{"client_id":"xxx","local_port":22,"protocol":"tcp"}'
```

## 消息协议

| type | 方向 | 说明 |
|------|------|------|
| register | C→S | 客户端注册 |
| register_ok | S→C | 注册成功 |
| ping | C→S | 心跳 |
| pong | S→C | 心跳响应 |
| tunnel_open | S→C | 创建隧道 |
| tunnel_open_ack | C→S | 隧道创建确认 |
| tunnel_close | C↔S | 关闭隧道 |
| tunnel_data | C↔S | 隧道数据 |

## 架构

```
外部用户 ──▶ [服务端:公网端口] ──▶ [WebSocket隧道] ──▶ [Agent:本地端口]
             (端口映射)              (数据透传)          (内网服务)
```

## 文档

- [服务端设计文档](./docs/server-design.md)
- [客户端设计文档](./docs/agent-design.md)
- [隧道设计文档](./docs/tunnel-design.md)
- [SSH 隧道直通内网服务流程](./docs/workflow/ssh-tunnel-direct-access.md)
- [GoRemote 调试开发经验](./docs/experience/go-remote-debugging.md)