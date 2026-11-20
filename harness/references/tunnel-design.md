# 内网穿透/端口映射功能设计方案

## 1. 概述

### 1.1 功能目标

在现有 go-remote 远程命令执行系统基础上，新增内网穿透/端口映射功能：

- 暴露内网 SSH 端口，让外部能通过服务端端口访问内网 SSH
- 暴露内网 HTTP 服务，让外部能访问内网 Web 服务
- 支持服务端本机代理模式，仅监听 `127.0.0.1`，不向公网暴露入口
- 提供 HTTP API 让用户动态创建/删除端口映射

### 1.2 架构模式

采用**反向隧道**模式，Agent 部署在内网，主动连接服务端的 WebSocket：

```
外部用户  ──▶  [服务端:公网端口]  ──▶  [WebSocket隧道]  ──▶  [Agent:本地端口]
                (端口映射)          (数据透传)          (内网服务)

服务端本机用户 ─▶ [服务端:127.0.0.1端口] ─▶ [WebSocket隧道] ─▶ [Agent:本地端口]
                  (本机代理，不对公网监听)
```

**特点**：
- 利用现有 WebSocket 连接传输隧道数据，无需额外端口
- Agent 在内网，防火墙友好
- 支持 SSH、HTTP 等任意 TCP 协议
- 通过 `exposure` 区分公网映射和服务端本机代理：`public` 监听公网入口，`server_local` 仅监听服务端 `127.0.0.1`

---

## 2. 消息协议

### 2.1 新增消息类型

| Type | 方向 | 说明 |
|------|------|------|
| tunnel_open | S→C | 服务端分配公网端口后，通知 Agent 隧道目标 |
| tunnel_close | S→C | 服务端关闭/重建隧道时通知 Agent |
| tunnel_data_bin | C↔S | 隧道数据（二进制 WebSocket frame，唯一数据路径） |
| tunnel_error | C→S | Agent 报告本地拨号/写失败，服务端据此关闭外部连接 |

### 2.2 消息格式

```go
// TunnelOpenPayload - 服务端下发隧道目标
type TunnelOpenPayload struct {
    TunnelID  string `json:"tunnel_id"`  // 服务端生成的隧道唯一ID
    LocalAddr string `json:"local_addr"` // Agent 侧目标地址，如 "127.0.0.1"
    LocalPort int    `json:"local_port"` // Agent 侧目标端口，如 22
    Protocol  string `json:"protocol"`   // 当前仅 "tcp"
}

// TunnelClosePayload - 关闭隧道
type TunnelClosePayload struct {
    TunnelID string `json:"tunnel_id"`
}

// TunnelErrorPayload - 隧道错误
type TunnelErrorPayload struct {
    TunnelID string `json:"tunnel_id"`
    ConnID   string `json:"conn_id,omitempty"`
    Error    string `json:"error"`
}
```

当前只使用 WebSocket BinaryMessage 传输隧道数据，避免 JSON/base64 对大吞吐 SSH/SCP 的额外开销。控制消息仍使用 JSON text frame。

二进制帧布局（`internal/common/message.go`）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | version | 当前为 `1` |
| 1 | 1 | flags | bit0=`is_eof` |
| 2 | 2 | tunnel_id_len | big endian uint16 |
| 4 | 2 | conn_id_len | big endian uint16 |
| 6 | 4 | data_len | big endian uint32 |
| 10 | N | tunnel_id | UTF-8 字符串 |
| 10+N | M | conn_id | UTF-8 字符串 |
| ... | K | data | `enc_enabled=true` 时为 AES-GCM nonce+ciphertext 原始字节；`enc_enabled=false` 时为明文原始字节 |

`flags` 当前只允许 bit0。收到未知 bit 必须拒绝该帧，避免畸形帧或未来协议扩展被旧逻辑静默接受。解析长度时必须按 tunnel_id、conn_id、data 三段逐步扣减剩余字节，不用 `10 + N + M + K` 直接相加作为唯一判断，避免畸形长度在不同架构上触发整数边界问题。

服务端和 Agent 的 `ReadMessage()` 会按 frame type 分流：

- TextMessage → `common.Message` JSON 控制消息，使用严格 JSON 解码，拒绝未知字段和尾随多个 JSON 文档。
- BinaryMessage → `DecodeBinaryTunnelDataFrame`，包装为内部消息类型 `tunnel_data_bin`。

旧 `tunnel_data` JSON/base64 路径已移除；旧 Agent/Server 必须升级后才能互通。`EncEnabled` 是设备级运行时开关，关闭后服务端和 Agent 都必须移除该设备运行时密钥，并在隧道数据路径跳过加解密。

### 2.4 注册与密钥更新签名

`register_ok` 和 `register_update` 会携带服务端签名字段，保护 ECDH 返回的服务端 DH 公钥和加密后的设备密钥不被中间人替换：

```go
type RegisterOKPayload struct {
    ClientID         string
    EncKeyEncrypted  string
    ServerDHPubkey   string
    EncEnabled       bool
    ServerSignPubkey string
    ServerSignature  string
}
```

签名语义为 `client_id + enc_enabled + server_dh_pubkey + enc_key_encrypted`。Agent 首次看到 `server_sign_pubkey` 时执行 TOFU pin；已 pin 后的 `register_ok` / `register_update` 缺签名、签名不匹配或服务端签名公钥变化都应拒绝。为兼容旧服务端，首次未 pin 且响应无签名时允许通过，但不会建立 pin。

reauth 仍使用设备 ed25519 签名 `client_id:timestamp`，服务端接受秒/毫秒/微秒/纳秒时间戳，并缓存 5 分钟窗口内已见签名，防止同一签名重放。

### 2.3 数据流说明

**tunnel_data_bin 双向含义**：
- **Server → Agent**：外部用户的请求数据
- **Agent → Server**：本地服务的响应数据

**conn_id 的作用**：
- 同一隧道可能有多并发个外部连接（如 SSH keep-alive）
- conn_id 用于区分和追踪每个外部连接的生命周期

---

## 3. 服务端设计

### 3.0 端口防扫描（anti-scanning）

每个隧道端口连接受独立限流保护：同一 IP 每分钟最多发起 `max_conn_per_min` 次 TCP 连接（默认 10），超限连接被立即拒绝并记录 WARN 日志。IP 白名单中的地址绕过此限制。

```
TCP Conn —▶ 端口 10000
                │
                ▼
         ┌──────────────┐
         │ portLimiter  │
         │ .Allow(ip)   │──── 允许 ──▶ acceptLoop → 转发 Agent
         └──────┬───────┘
                │ 拒绝
                ▼
         WARN "rate limited (anti-scanning)"
         关闭连接
```

**实现**：`internal/server/tunnel.go` 中 `acceptLoop` 在 `net.Listener.Accept()` 后立即检查 `portLimiter.Allow(remoteIP)`，白名单 IP 调用 `IsIPWhitelisted()` 做 passthrough。

### 3.1 数据结构

```go
// Tunnel 隧道信息
type Tunnel struct {
    TunnelID   string
    ClientID   string
    Client     *Client        // WebSocket 连接，不参与 JSON
    Protocol   string
    PublicPort int            // 监听的公网端口
    Exposure   string         // "public" / "server_local"
    BindAddr   string         // 实际监听地址
    LocalAddr  string         // Agent 侧目标地址
    LocalPort  int
    CreatedAt  time.Time
}

// ExternalConn 外部连接信息
type ExternalConn struct {
    ConnID   string
    TunnelID string
    Conn     net.Conn         // TCP 连接
    queue    chan extChunk    // 32 槽有序写队列
    done     chan struct{}
}

// TunnelManager 隧道管理器
type TunnelManager struct {
    mu               sync.RWMutex
    tunnels          map[string]*Tunnel    // tunnelID -> Tunnel
    publicPorts      map[int]string        // publicPort -> tunnelID
    extConns         map[string]*ExternalConn // connID -> ExternalConn
    unavailablePorts map[int]struct{}      // 系统占用的端口（惰性检测）
    portStart        int
    portEnd          int
    listeners        map[int]net.Listener  // publicPort -> 监听器
}
```

### 3.2 端口监听架构

**Server 监听两种端口**：

| 端口类型 | 用途 | 实现方式 |
|----------|------|----------|
| Gin HTTP 端口 | WebSocket 连接、HTTP API | Gin 框架（默认 8080） |
| 公网映射端口 | 隧道流量（外部用户访问入口） | 独立的 `net.Listener` |

```go
// 创建公网端口监听
func (tm *TunnelManager) Listen(publicPort int, tunnelID string) error {
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", publicPort))
    if err != nil {
        return err
    }
    tm.listeners[publicPort] = listener
    tm.publicPorts[publicPort] = tunnelID

    // 启动 accept goroutine
    go tm.acceptLoop(publicPort, tunnelID)
    return nil
}
```

### 3.3 核心流程

**创建隧道（含端口占用检测）**：
1. 管理员通过 `POST /api/tunnels` 指定 `client_id/local_addr/local_port/exposure`
2. Server 根据 `exposure` 选择监听地址：
   - `public` → 监听公网入口（默认等价于 `0.0.0.0`）
   - `server_local` → 仅监听 `127.0.0.1`
3. Server `AllocatePortForExposure()` 遍历端口范围，对每个候选端口直接 `net.Listen` 实绑：
   - 绑定成功 → 保留 listener，标记为已分配
   - 绑定失败 → 记录到 `unavailablePorts`，跳过
4. Server 调用 `AcceptOnListener()` 启动 accept 循环，并向 Agent 发送 `tunnel_open`
5. 若 `tunnel_open` 写失败，Server 回滚关闭 listener、释放端口并返回错误

**端口释放（联动清理）**：
- `ReleasePort()` 清除 `publicPorts` 和 `unavailablePorts` 中的标记
- 删除隧道后，之前被系统占用的端口可被重新检测

**数据转发**：
```
外部用户 ──TCP连接──▶ [Server:15001] ──accept──▶ 外部连接读 goroutine
                                                    │
                         每连接有序队列(32槽) ◀──────┘
                                                    │ Server 推送 tunnel_data_bin(conn_id=x, data=加密请求)
                                                    ▼
                                              Agent WebSocket 收包
                                                    │ 解密后进入该 conn_id 的本地有序队列
                                                    ▼
                                              独立 writer 连接本地服务并写入
                                                    │ 本地响应 → tunnel_data_bin(加密)
                                                    ▼
                    Server 解密 → 写入该 conn_id 的外部连接独立 writer
```

两侧都不在 WebSocket 收包 goroutine 里直接做本地拨号或大块 TCP 写；每连接写队列满时等待 15s 让 writer 排空，仍无空间才关闭该连接。这样慢客户端不会截断其他隧道的数据。

服务端处理 Agent 返回数据时必须同时校验 `tunnel_id` 归属和 `conn_id` 归属：`ExternalConn.TunnelID` 必须等于当前帧的 `tunnel_id`，且 EOF 帧也不能跳过该检查。设备重连、pending 转 authorized、WebSocket readLoop 退出、删除设备时必须关闭该 client 的所有隧道和 listener，避免旧公网端口泄漏。

### 3.6 端口状态查询

`GET /api/port-status` 返回端口范围的使用状况（需认证）：

```json
{
  "range_start": 10000,
  "range_end": 20000,
  "total_ports": 10001,
  "allocated": 5,
  "unavailable": [10002, 10005, 10010],
  "available_count": 9993
}
```

| 字段 | 说明 |
|------|------|
| `range_start` / `range_end` | 配置的端口范围 |
| `total_ports` | 端口总数 = end - start + 1 |
| `allocated` | 已由隧道占用的端口数 |
| `unavailable` | 被系统其他进程占用的端口列表（惰性检测，仅在 `AllocatePortForExposure` 尝试时发现） |
| `available_count` | 可用端口数 = total - allocated - len(unavailable) |

**实现**：`internal/server/tunnel.go` 中的 `GetPortStatus()` 方法，读锁保护。`unavailablePorts` 通过 `AllocatePortForExposure` 的实绑 `net.Listen` 试探填充，`ReleasePort` 释放时同时清除标记。

---

## 4. Agent 端设计

### 4.1 数据结构

```go
// Tunnel 隧道信息
type Tunnel struct {
    TunnelID   string
    LocalAddr  string
    LocalPort  int
    Protocol   string
    publicPort int            // 服务端分配的公网端口
}

// LocalConn 本地连接（按 conn_id 区分）
type LocalConn struct {
    ConnID    string
    TunnelID  string
    LocalConn net.Conn        // 连接本地服务的 conn
}

// TunnelManager 隧道管理器
type TunnelManager struct {
    mu        sync.RWMutex
    tunnels    map[string]*Tunnel     // tunnelID -> Tunnel
    localConns map[string]*localConn  // connID -> 有序写队列 + net.Conn
    agent      *Agent
}
```

### 4.2 核心流程

**创建隧道**：
1. Server 在 `POST /api/tunnels` 成功后发送 `tunnel_open`
2. Agent 记录 tunnelID → localAddr/localPort/protocol
3. Agent 不返回 ack；数据面首个 `tunnel_data_bin` 会触发本地拨号

**按需连接本地服务**：
- Agent **不预先连接**本地服务
- 收到 `tunnel_data_bin(conn_id=x)` 时，**首次**为该 conn_id 创建到本地服务的连接
- 解密 data 写入 localConn，读取响应后加密并发送 `tunnel_data_bin(conn_id=x, data=响应)`

**连接复用**：
- 同一 conn_id 的后续 `tunnel_data_bin` 进入同一有序队列，复用已建立的 localConn
- 收到 `is_eof=true`（且无数据）时关闭 localConn
- 本地读端先 EOF 时，Agent 发送 EOF 帧并清理本地连接；服务端先关闭时，Agent 不再回送无意义 EOF

---

## 5. HTTP API 设计

### 5.1 API 端点

| Method | Path | 描述 |
|--------|------|------|
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 列出所有隧道 |
| GET | /api/tunnels/:tunnel_id | 获取隧道详情 |
| PUT | /api/tunnels/:tunnel_id | 更新隧道 |
| DELETE | /api/tunnels/:tunnel_id | 删除端口映射 |
| GET | /api/clients/:client_id/tunnels | 获取指定客户端的隧道 |
| GET | /api/port-status | 端口范围使用状况 |

### 5.2 API 详情

**POST /api/tunnels** - 创建端口映射

请求：
```json
{
  "client_id": "client-xxx",
  "exposure": "public",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}
```

`exposure` 可选，默认 `public`。设为 `server_local` 时，服务端只监听 `127.0.0.1:<public_port>`，外部公网无法直接访问。

响应：
```json
{
  "tunnel_id": "uuid",
  "public_port": 15001,
  "access_addr": "server.example.com:15001",
  "exposure": "public",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}
```

服务端本机代理响应示例：
```json
{
  "tunnel_id": "uuid",
  "public_port": 15001,
  "access_addr": "127.0.0.1:15001",
  "exposure": "server_local",
  "local_addr": "127.0.0.1",
  "local_port": 22,
  "protocol": "tcp"
}
```

**GET /api/tunnels** - 列出所有隧道

响应：
```json
{
  "tunnels": [
    {
      "tunnel_id": "tunnel-xxx",
      "client_id": "client-xxx",
      "local_addr": "127.0.0.1",
      "local_port": 22,
      "public_port": 15001,
      "exposure": "public",
      "bind_addr": "0.0.0.0",
      "protocol": "tcp",
      "created_at": "2026-04-17T10:00:00Z"
    }
  ]
}
```

**DELETE /api/tunnels/:tunnel_id** - 删除端口映射

响应：
```json
{
  "success": true
}
```

---

## 6. 配置设计

### 6.1 服务端配置

```yaml
server:
  host: "0.0.0.0"
  port: 8080

tunnel:
  enabled: true
  public_host: "server.example.com"   # API 返回给外部调用方的主机名/IP
  default_local_addr: "127.0.0.1"     # 未显式传入 local_addr 时的默认目标地址
  port_range_start: 10000  # 分配的公网端口起始
  port_range_end: 20000     # 分配的公网端口结束
  max_tunnels_per_client: 10 # 每个客户端最大隧道数

heartbeat:
  interval: 30
  timeout: 90
```

### 6.2 Agent 端配置

```yaml
server:
  address: "server.example.com:8080"

tunnel:
  enabled: true
  # 可选：预设固定的本地端口映射
  # mappings:
  #   - local_port: 22
  #     protocol: tcp
  #   - local_port: 80
  #     protocol: tcp

heartbeat:
  interval: 30
```

---

## 7. 项目文件修改

### 7.1 新增文件

| 文件 | 说明 |
|------|------|
| internal/server/tunnel.go | 服务端隧道管理核心逻辑 |
| internal/agent/tunnel.go | Agent 端隧道管理核心逻辑 |
| docs/tunnel-design.md | 本设计文档 |

### 7.2 修改文件

| 文件 | 修改内容 |
|------|----------|
| internal/common/message.go | 新增 Tunnel*Payload 结构体 |
| internal/server/handler.go | 新增 tunnel_* case 处理 |
| internal/server/server.go | 集成 TunnelManager，启动端口监听 |
| internal/server/api.go | 新增 /api/tunnels 端点 |
| internal/agent/handler.go | 新增 tunnel_* case 处理 |
| internal/agent/agent.go | 集成 TunnelManager |
| config/server.yaml | 新增 tunnel 配置段 |
| config/agent.yaml | 新增 tunnel 配置段 |
| docs/server-design.md | 新增隧道协议章节 |
| docs/agent-design.md | 新增隧道模块章节 |

---

## 8. 实现顺序

### Phase 1: 协议定义
1. 修改 internal/common/message.go 添加消息结构
2. 更新设计文档

### Phase 2: 服务端隧道管理
1. 新增 internal/server/tunnel.go 实现 TunnelManager
2. 修改 internal/server/handler.go 添加 tunnel_* 处理
3. 修改 internal/server/server.go 集成 TunnelManager

### Phase 3: Agent 隧道管理
1. 新增 internal/agent/tunnel.go 实现 TunnelManager
2. 修改 internal/agent/handler.go 添加 tunnel_* 处理
3. 修改 internal/agent/agent.go 集成 TunnelManager

### Phase 4: HTTP API
1. 修改 internal/server/api.go 添加 /api/tunnels 端点

### Phase 5: 配置和测试
1. 修改配置文件
2. 端到端测试 SSH/HTTP 映射

---

## 9. 验证方案

### 9.1 SSH 隧道测试

```bash
# 1. 通过 API 创建 SSH 隧道
curl -X POST http://server:8080/api/tunnels \
  -H "Content-Type: application/json" \
  -d '{"client_id": "client-xxx", "local_addr": "127.0.0.1", "local_port": 22, "protocol": "tcp"}'

# 返回: {"tunnel_id": "xxx", "public_port": 15001, ...}

# 2. 外部用户连接内网 SSH
ssh -p 15001 user@server.example.com
```

### 9.2 HTTP 隧道测试

```bash
# 1. 创建 HTTP 隧道
curl -X POST http://server:8080/api/tunnels \
  -H "Content-Type: application/json" \
  -d '{"client_id": "client-xxx", "local_addr": "127.0.0.1", "local_port": 80, "protocol": "tcp"}'

# 返回: {"tunnel_id": "xxx", "public_port": 15002, ...}

# 2. 访问内网 Web 服务
curl http://server.example.com:15002/
```

---

## 10. 技术要点

1. **端口监听架构**：Server 需要在 Gin HTTP 服务器（8080）**之外**，使用独立的 `net.Listener` 监听公网映射端口

2. **二进制数据帧**：隧道数据只使用 WebSocket Binary frame 传输 AES-GCM nonce+ciphertext，控制消息仍为 JSON；旧 `tunnel_data` JSON/base64 路径已移除

3. **Goroutine 管理**：
   - Server：每个公网端口监听独立 goroutine
   - Agent：每个 conn_id 的本地连接独立 goroutine

4. **按需连接**：Agent 在收到 `tunnel_data_bin` 之前不连接本地服务，确保有数据消费方

5. **conn_id 设计**：用于区分同一隧道上的多个并发外部连接（如 SSH keep-alive、HTTP keep-alive）

6. **错误处理**：
   - Agent 本地连接失败：发送 `tunnel_error` 给 Server
   - Server 关闭隧道：发送 `tunnel_close` 给 Agent，关闭所有外部连接
