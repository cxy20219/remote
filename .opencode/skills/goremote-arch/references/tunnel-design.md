# 隧道设计文档

## 1. 概述

### 1.1 功能目标

在现有 go-remote 远程命令执行系统基础上，新增内网穿透/端口映射功能：

- 暴露内网 SSH 端口，让外部能通过服务端端口访问内网 SSH
- 暴露内网 HTTP 服务，让外部能访问内网 Web 服务
- 提供 HTTP API 让用户动态创建/删除端口映射

### 1.2 架构模式

采用**反向隧道**模式，Agent 部署在内网，主动连接服务端的 WebSocket：

```
外部用户 ──▶ [服务端:公网端口] ──▶ [WebSocket隧道] ──▶ [Agent:本地端口]
                 (端口映射)          (数据透传)          (内网服务)
```

**特点**：
- 利用现有 WebSocket 连接传输隧道数据，无需额外端口
- Agent 在内网，防火墙友好
- 支持 SSH、HTTP 等任意 TCP 协议

## 2. 消息协议

### 2.1 新增消息类型

| Type | 方向 | 说明 |
|------|------|------|
| tunnel_open | C→S | 客户端申请创建隧道 |
| tunnel_open_ack | S→C | 服务端返回分配的公网端口 |
| tunnel_close | C↔S | 任一方关闭隧道 |
| tunnel_data | C↔S | 隧道数据（双向） |
| tunnel_error | S→C | 隧道错误通知 |

### 2.2 消息格式

```go
type TunnelOpenPayload struct {
    TunnelID  string `json:"tunnel_id"`
    LocalAddr string `json:"local_addr"`
    LocalPort int    `json:"local_port"`
    Protocol  string `json:"protocol"`   // "tcp" / "udp"
}

type TunnelOpenAckPayload struct {
    TunnelID   string `json:"tunnel_id"`
    PublicPort int    `json:"public_port"`
    Success    bool   `json:"success"`
    Error      string `json:"error,omitempty"`
}

type TunnelDataPayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id"`
    Data     string `json:"data"`     // base64 encoded
    IsEOF    bool   `json:"is_eof"`
}
```

### 2.3 conn_id 的作用

- 同一隧道可能有多并发个外部连接（如 SSH keep-alive）
- conn_id 用于区分和追踪每个外部连接的生命周期

## 3. 服务端设计

### 3.1 数据结构

```go
type Tunnel struct {
    TunnelID   string
    ClientID   string
    Client     *Client        // WebSocket 连接
    Protocol   string
    PublicPort int            // 监听的公网端口
    LocalAddr  string         // 客户端本地地址
    LocalPort  int
    CreatedAt  time.Time
    Status     string         // "active" / "closing"
}

type TunnelManager struct {
    mu          sync.RWMutex
    tunnels     map[string]*Tunnel
    publicPorts map[int]string
    portStart   int
    portEnd     int
    listeners   map[int]net.Listener
}
```

### 3.2 端口监听架构

Server 监听两种端口：

| 端口类型 | 用途 | 实现方式 |
|----------|------|----------|
| Gin HTTP 端口 | WebSocket 连接、HTTP API | Gin 框架（默认 8080） |
| 公网映射端口 | 隧道流量（外部用户访问入口） | 独立的 `net.Listener` |

### 3.3 核心流程

**创建隧道**：
1. Agent 发送 `tunnel_open`（包含 localAddr:localPort）
2. Server 分配公网端口，调用 `Listen()` 启动监听
3. Server 返回 `tunnel_open_ack`（包含 tunnelID, publicPort）

**数据转发**：
```
外部用户 ──TCP连接──▶ [Server:15001] ──accept──┐
                         │
                         │ Server 推送 tunnel_data(conn_id=x, data=请求)
                         ▼
                   Agent 收到 tunnel_data
                         │ 首次收到该 conn_id → 连接本地服务
                         │ Agent 发送 tunnel_data(conn_id=x, data=响应)
                         ▼
                   Server 收到 tunnel_data → 写入外部 TCP 连接
```

## 4. Agent 端设计

### 4.1 数据结构

```go
type Tunnel struct {
    TunnelID   string
    LocalAddr  string
    LocalPort  int
    Protocol   string
    publicPort int            // 服务端分配的公网端口
}

type TunnelManager struct {
    mu        sync.RWMutex
    tunnels   map[string]*Tunnel
    localConns map[string]*LocalConn // conn_id -> LocalConn
}
```

### 4.2 核心流程

**按需连接本地服务**：
- Agent **不预先连接**本地服务
- 收到 `tunnel_data(conn_id=x)` 时，**首次**为该 conn_id 创建到本地服务的连接
- 将 data 写入 localConn，读取响应后发送 `tunnel_data(conn_id=x, data=响应)`

**连接复用**：
- 同一 conn_id 的后续 `tunnel_data` 复用已建立的 localConn
- 收到 `is_eof=true` 时关闭 localConn

## 5. HTTP API 设计

| Method | Path | 描述 |
|--------|------|------|
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 列出所有隧道 |
| GET | /api/tunnels/:tunnel_id | 获取隧道详情 |
| DELETE | /api/tunnels/:tunnel_id | 删除端口映射 |
| GET | /api/clients/:client_id/tunnels | 获取指定客户端的隧道 |

## 6. 配置设计

### 6.1 服务端配置

```yaml
tunnel:
  enabled: true
  public_host: "server.example.com"
  default_local_addr: "127.0.0.1"
  port_range_start: 10000
  port_range_end: 20000
  max_tunnels_per_client: 10
```

## 7. 技术要点

1. **端口监听架构**：Server 需要在 Gin HTTP 服务器（8080）**之外**，使用独立的 `net.Listener` 监听公网映射端口

2. **base64 编码**：复用文件传输的 base64 编码方式，确保 JSON 消息格式正确

3. **Goroutine 管理**：
   - Server：每个公网端口监听独立 goroutine
   - Agent：每个 conn_id 的本地连接独立 goroutine

4. **按需连接**：Agent 在收到 `tunnel_data` 之前不连接本地服务，确保有数据消费方

5. **conn_id 设计**：用于区分同一隧道上的多个并发外部连接（如 SSH keep-alive、HTTP keep-alive）