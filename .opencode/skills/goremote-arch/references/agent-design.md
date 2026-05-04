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
| Connector | WebSocket 连接管理，断线重连 |
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
| tunnel_open | C→S | 申请创建隧道 |
| tunnel_open_ack | S→C | 隧道创建确认 |
| tunnel_close | C↔S | 关闭隧道 |
| tunnel_data | C↔S | 隧道数据（双向） |
| tunnel_error | S→C | 隧道错误通知 |

### 3.2 Payload 数据结构

```go
type RegisterPayload struct {
    Key      string `json:"key"`
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
}

type TunnelOpenPayload struct {
    TunnelID  string `json:"tunnel_id"`
    LocalAddr string `json:"local_addr"`
    LocalPort int    `json:"local_port"`
    Protocol  string `json:"protocol"`
}

type TunnelOpenAckPayload struct {
    TunnelID   string `json:"tunnel_id"`
    PublicPort int    `json:"public_port"`
    Success    bool   `json:"success"`
    Error      string `json:"error,omitempty"`
}

type TunnelClosePayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id,omitempty"`
}

type TunnelDataPayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id"`
    Data     string `json:"data"`     // base64 encoded
    IsEOF    bool   `json:"is_eof"`
}

type TunnelErrorPayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id,omitempty"`
    Error    string `json:"error"`
}
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
```

**主要职责**：
- 建立 WebSocket 连接
- 发送/接收消息
- TLS 加密（可选）
- 连接关闭处理

### 4.2 Agent 主控

```go
func (a *Agent) Run() error {
    for {
        if err := a.connect(); err != nil {
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

### 4.3 Reconnect 重连机制

**重连策略**：
- 初始间隔：5秒
- 失败后指数退避：5s, 10s, 20s, 40s, 最大60s
- 达到最大重试次数后退出程序

### 4.4 心跳机制

```go
func (a *Agent) startHeartbeat() {
    ticker := time.NewTicker(a.config.Heartbeat.Interval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            if err := a.connector.Send(&Message{Type: "ping"}); err != nil {
                return
            }
        case <-a.connector.done:
            return
        }
    }
}
```

## 5. 配置设计

```yaml
server:
  address: "server.example.com:8080"
  tls:
    enabled: false
    ca: "ca.crt"

auth:
  key: "your-secret-key"

agent:
  hostname: ""
  os: ""

heartbeat:
  interval: 30

reconnect:
  interval: 5
  max_attempts: 0
  max_interval: 60

log:
  level: "info"
  file: ""
```

## 6. 启动流程

```
Agent 启动 → 读取配置文件 → 获取主机名和操作系统
     ↓
创建 Connector → 进入连接循环
     ↓
  ┌─► Connect() ──► WebSocket 握手
  │        ↓
  │   发送 register → 接收 register_ok / register_fail
  │        ↓
  │  ┌────┴────┐
  │ 成功      失败
  │   ↓         ↓
  │ 启动心跳   记录日志关闭连接
  │   ↓         ↓
  │ 启动主循环  等待重连
  │   ↓
  └──► 继续重连 ◄─┘
```

## 7. 项目结构

```
internal/agent/
├── agent.go       # 主控逻辑
├── connector.go   # WebSocket连接管理
├── handler.go     # 消息处理
├── reconnect.go   # 重连机制
├── tunnel.go      # 隧道管理
├── config.go      # 配置加载
└── logger.go      # 日志配置
```