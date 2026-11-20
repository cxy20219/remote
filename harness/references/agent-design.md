# 客户端 (Agent) 设计文档

## 1. 功能概述

客户端是一个后台常驻程序（Agent），部署在需要被管理的机器上，负责：
- 与服务端建立 WebSocket 长连接
- 认证注册
- 维持心跳保活
- 创建和管理隧道（内网穿透）

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                       Agent                                  │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Connector  │──│    Agent    │──│   TunnelManager     │ │
│  │ (WebSocket) │  │  (主控)     │  │    (隧道管理)        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                │                    │              │
│         ▼                ▼                    ▼              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Reconnect  │  │   Handler   │  │      Logger        │ │
│  │  (重连)     │  │  (消息处理) │  │                    │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

| 组件 | 职责 |
|------|------|
| Connector | WebSocket 连接管理，断线重连；TLS 启用时要求 TLS 1.3，TextMessage 使用严格 JSON 解码 |
| Agent | 主控逻辑，协调各组件 |
| Handler | 消息解析和路由 |
| TunnelManager | 隧道管理（内网穿透） |
| Logger | 日志记录 |

## 3. 消息协议

### 3.1 消息类型

| Type | 方向 | 描述 |
|------|------|------|
| register | C→S | 客户端注册 |
| register_ok | S→C | 注册成功 |
| register_fail | S→C | 注册失败 |
| ping | C→S | 心跳请求 |
| pong | S→C | 心跳响应 |
| tunnel_open | S→C | 服务端下发隧道目标 |
| tunnel_close | S→C | 服务端关闭/重建隧道 |
| tunnel_data_bin | C↔S | 隧道数据（双向，WebSocket Binary frame） |
| tunnel_error | C→S | Agent 报告本地拨号/写失败 |

### 3.2 消息格式

**Payload 数据结构**：

```go
type RegisterPayload struct {
    ReAuth         bool   `json:"reauth"`
    ClientID       string `json:"client_id,omitempty"`
    DevicePubkey   string `json:"device_pubkey"`
    DeviceDHPubkey string `json:"device_dh_pubkey,omitempty"`
    Hostname       string `json:"hostname"`
    OS             string `json:"os"`
    Timestamp      int64  `json:"timestamp,omitempty"`
    Signature      string `json:"signature,omitempty"`
}

// 隧道消息
type TunnelOpenPayload struct {
    TunnelID  string `json:"tunnel_id"`  // 服务端生成的隧道唯一ID
    LocalAddr string `json:"local_addr"` // Agent 侧目标地址，如 "127.0.0.1"
    LocalPort int    `json:"local_port"` // Agent 侧目标端口，如 22
    Protocol  string `json:"protocol"`   // 当前仅 "tcp"
}

type TunnelClosePayload struct {
    TunnelID string `json:"tunnel_id"`
}

type TunnelErrorPayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id,omitempty"`
    Error    string `json:"error"`
}
```

**发送的消息**：

```go
// 注册消息
{
  "type": "register",
  "key": "your-secret-key",
  "hostname": "server-01",
  "os": "linux"
}

// 心跳
{"type": "ping"}

// 隧道申请
{
  "type": "tunnel_open",
  "tunnel_id": "uuid",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}
```

**接收的消息**：

```go
// 注册成功
{
  "type": "register_ok",
  "client_id": "uuid"
}

// 注册失败
{
  "type": "register_fail",
  "reason": "invalid key"
}

// 服务端下发隧道目标
{
  "type": "tunnel_open",
  "tunnel_id": "uuid",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}

// 心跳响应
{"type": "pong"}
```

## 4. 详细设计

### 4.1 Connector 连接器

```go
type Connector struct {
    serverAddr string
    tlsEnabled bool
    authKey    string

    conn    *websocket.Conn
    mu      sync.Mutex
    done    chan struct{}
}

func (c *Connector) Connect() error
func (c *Connector) Close() error
func (c *Connector) Send(msg *Message) error
func (c *Connector) Receive() (*Message, error)
```

**主要职责**：
- 建立 WebSocket 连接
- 发送/接收消息
- TLS 加密（可选）
- 连接关闭处理

### 4.2 Agent 主控

```go
type Agent struct {
    config       *Config
    connector    *Connector
    handler      *Handler
    reconnect    *Reconnect
    tunnelManager *TunnelManager
    hostname     string
    os           string
}

func (a *Agent) Run() error {
    for {
        if err := a.connect(); err != nil {
            log.Printf("connection failed: %v", err)
            if !a.reconnect.shouldRetry() {
                return err
            }
            a.reconnect.wait()
            continue
        }

        if err := a.handleConnection(); err != nil {
            log.Printf("connection error: %v", err)
        }

        a.connector.Close()
        a.reconnect.beforeRetry()
    }
}
```

### 4.3 Handler 消息处理

```go
type Handler struct {
    agent *Agent
}

func (h *Handler) Handle(msg *Message) error {
    switch msg.Type {
    case "register_ok":
        return h.handleRegisterOK(msg)
    case "register_fail":
        return h.handleRegisterFail(msg)
    case "pong":
        return nil  // 心跳响应，无需处理
    case "register_update":
        return h.handleRegisterUpdate(msg)
    case "device_deleted":
        return h.handleDeviceDeleted(msg)
    case "tunnel_open":
        return h.handleTunnelOpen(msg)
    case "tunnel_close":
        return h.handleTunnelClose(msg)
    case "tunnel_data_bin":
        return h.handleTunnelDataBinary(msg)
    case "tunnel_error":
        return h.handleTunnelError(msg)
    default:
        return fmt.Errorf("unknown message type: %s", msg.Type)
    }
}
```

### 4.4 Reconnect 重连机制

```go
type Reconnect struct {
    interval     time.Duration  // 重连间隔
    maxAttempts  int            // 最大重试次数，0=无限
    attempts     int
    nextWaitTime time.Duration
}

func (r *Reconnect) shouldRetry() bool {
    if r.maxAttempts == 0 {
        return true
    }
    return r.attempts < r.maxAttempts
}

func (r *Reconnect) wait() {
    time.Sleep(r.interval)
    r.attempts++
}
```

**重连策略**：
- 初始间隔：5秒
- 失败后指数退避：5s, 10s, 20s, 40s, 最大60s
- 达到最大重试次数后退出程序

### 4.5 心跳机制

```go
func (a *Agent) startHeartbeat() {
    ticker := time.NewTicker(a.config.Heartbeat.Interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := a.connector.Send(&Message{Type: "ping"}); err != nil {
                log.Printf("heartbeat failed: %v", err)
                return
            }
        case <-a.connector.done:
            return
        }
    }
}
```

## 5. 配置设计

### 5.1 config.yaml

```yaml
server:
  address: "server.example.com:8080"
  tls:
    enabled: false
    ca: "ca.crt"           # 可选，验证服务端证书

auth:
  key: "your-secret-key"

agent:
  hostname: ""              # 空则自动获取
  os: ""                    # 空则自动识别

heartbeat:
  interval: 30              # 心跳间隔(秒)

reconnect:
  interval: 5               # 初始重连间隔(秒)
  max_attempts: 0           # 0=无限重试
  max_interval: 60           # 最大重连间隔(秒)

log:
  level: "info"
  file: ""
```

## 6. 启动流程

```
Agent 启动
    │
    ▼
读取配置文件
    │
    ▼
获取主机名和操作系统
    │
    ▼
创建 Connector
    │
    ▼
进入连接循环
    │
    ├──► Connect() ──► WebSocket 握手
    │                      │
    │                      ▼
    │                 发送 register
    │                      │
    │                      ▼
    │                 接收 register_ok / register_fail
    │                      │
    │              ┌───────┴───────┐
    │            成功            失败
    │              │              │
    │              ▼              ▼
    │         启动心跳        记录日志
    │              │           关闭连接
    │              ▼              │
    │         启动主循环           │
    │              │               │
    │    ┌────────┴────────┐    │
    │    │                 │     │
    │    ▼                 ▼     │
    │  接收消息          连接断开  │
    │    │                 │     │
    │    ▼                 ▼     │
    │  处理消息          等待重连  │
    │    │                 │     │
    │    └────────┬────────┘     │
    │             │               │
    │             ▼               │
    └───── 继续重连 ◄────────────┘
```

## 7. 错误处理

| 错误场景 | 处理方式 |
|----------|----------|
| 连接失败 | 等待后重连 |
| 注册失败 | 记录日志，关闭连接，等待重连 |
| 消息解析失败 | 记录日志，忽略该消息 |

## 8. 日志设计

```go
slog.Info("agent starting", "server", serverAddr)
slog.Info("connected to server", "server", serverAddr)
slog.Info("registered successfully", "client_id", clientID)
slog.Warn("connection lost", "error", err)
slog.Error("reconnect failed", "attempt", attempt, "error", err)
```

## 9. 项目结构

```
internal/agent/
├── agent.go       # 主控逻辑
├── connector.go   # WebSocket连接管理
├── handler.go     # 消息处理
├── reconnect.go   # 重连机制
├── tunnel.go      # 隧道管理（每连接有序队列）
├── identity.go    # 本地身份与 ECDH 解密
└── config.go      # 配置加载
```

## 10. 隧道管理（内网穿透）

详见 [隧道设计文档](./tunnel-design.md)。
