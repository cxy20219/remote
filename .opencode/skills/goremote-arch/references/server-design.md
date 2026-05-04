# 服务端设计文档

## 1. 功能概述

服务端是整个系统的控制中心，负责：
- 接收客户端 WebSocket 连接
- 验证客户端身份
- 管理在线客户端
- 提供隧道管理 API（创建/删除端口映射）

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                      Server                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  WebSocket  │  │   Client    │  │      Handler        │ │
│  │   Server    │──│   Manager   │──│   (消息分发)        │ │
│  │  ( :8080 )  │  │ (在线状态)  │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                │                    │              │
│         │                ▼                    ▼              │
│         │         ┌─────────────┐  ┌─────────────────────┐ │
│         │         │   Tunnel    │  │   Tunnel           │ │
│         │         │   Manager   │  │   Handler          │ │
│         │         └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

| 组件 | 职责 |
|------|------|
| WebSocket Server | 监听端口，接收客户端连接 |
| Client Manager | 维护客户端在线状态，client_id ↔ 连接映射 |
| Tunnel Manager | 管理端口映射隧道 |
| Handler | 消息路由，分发给对应处理函数 |
| Logger | 日志记录 |

## 3. 数据结构

### 3.1 Client 客户端信息

```go
type Client struct {
    ClientID  string           // 唯一标识 (UUID)
    Hostname  string           // 主机名
    OS        string           // 操作系统 (linux/windows)
    Conn      *websocket.Conn  // WebSocket连接
    RegTime   time.Time        // 注册时间
    LastPing  time.Time        // 最后心跳时间
    Status    string           // online/offline
}
```

### 3.2 Message 消息结构

```go
type Message struct {
    Type    string          `json:"type"`
    Payload json.RawMessage  `json:"payload,omitempty"`
}

// 注册消息
type RegisterPayload struct {
    Key     string `json:"key"`
    Hostname string `json:"hostname"`
    OS      string `json:"os"`
}

type RegisterOKPayload struct {
    ClientID string `json:"client_id"`
}

type RegisterFailPayload struct {
    Reason string `json:"reason"`
}

// 隧道消息
type TunnelOpenPayload struct {
    TunnelID  string `json:"tunnel_id"`
    LocalAddr string `json:"local_addr"` // 本地地址，如 "127.0.0.1"
    LocalPort int    `json:"local_port"` // 本地端口，如 22
    Protocol  string `json:"protocol"`   // "tcp" / "udp"
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

## 4. 消息协议

### 4.1 消息类型

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

### 4.2 消息流程

```
客户端连接
     │
     ▼
┌─────────────────┐
│  发送 register  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 验证 key 是否正确 │
└────────┬────────┘
         │
    ┌────┴────┐
    │ 验证结果  │
    └────┬────┘
         │
    ┌────┴────┐
    │         │
  成功      失败
    │         │
    ▼         ▼
register_ok  register_fail
    │         │
    ▼         (关闭连接)
  进入主循环
    │
    ├─ 发送 ping ──────────── 接收 pong
    │
    └─ 断开连接 ── 标记 offline
```

## 5. 详细设计

### 5.1 Gin Web Server

使用 Gin 框架提供 HTTP 管理 API 和 WebSocket 端点：

```go
type Server struct {
    Addr       string
    tlsEnabled bool
    tlsCert    string
    tlsKey     string
    config     *Config
    clients       *ClientManager
    handler       *Handler
    tunnelManager *TunnelManager
    upgrader websocket.Upgrader
    engine   *gin.Engine
}
```

### 5.2 Client Manager

```go
type ClientManager struct {
    mu      sync.RWMutex
    clients map[string]*Client  // clientID -> Client
}
```

### 5.3 Handler 消息处理

```go
func (h *Handler) Handle(client *Client, msg *Message) error {
    switch msg.Type {
    case "register":
        return h.handleRegister(client, msg)
    case "ping":
        return h.handlePing(client, msg)
    case "tunnel_open":
        return h.handleTunnelOpen(client, msg)
    case "tunnel_close":
        return h.handleTunnelClose(client, msg)
    case "tunnel_data":
        return h.handleTunnelData(client, msg)
    default:
        return fmt.Errorf("unknown message type: %s", msg.Type)
    }
}
```

### 5.4 心跳机制

客户端主动发送心跳，服务端检测超时：
1. 客户端定期发送 ping 消息
2. 服务端收到后更新客户端的 LastPing 时间
3. 服务端启动goroutine定期检查
4. 超过`hbTimeout`未收到ping的客户端标记为offline
5. 关闭对应连接

## 6. 配置设计

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert: "server.crt"
    key: "server.key"

auth:
  key: "your-secret-key"

heartbeat:
  interval: 30      # 心跳检测间隔(秒)
  timeout: 90       # 心跳超时(秒)

log:
  level: "info"    # debug/info/warn/error
  file: ""         # 空则输出到stdout
```

## 7. HTTP管理API

| Method | Path | 描述 |
|--------|------|------|
| GET | /api/clients | 获取在线客户端列表 |
| GET | /api/clients/:id | 获取客户端详情 |
| GET | /api/clients/:client_id/tunnels | 获取指定客户端的隧道 |
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 获取所有隧道 |
| GET | /api/tunnels/:tunnel_id | 获取隧道详情 |
| DELETE | /api/tunnels/:tunnel_id | 删除端口映射 |
| GET | /health | 健康检查 |

## 8. 项目结构

```
internal/server/
├── server.go      # WebSocket服务端主逻辑
├── client.go      # ClientManager 客户端管理
├── handler.go     # 消息处理
├── tunnel.go      # 隧道管理（内网穿透）
├── api.go         # HTTP管理接口
├── config.go      # 配置加载
└── logger.go      # 日志配置
```