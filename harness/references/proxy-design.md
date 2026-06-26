# 代理功能设计方案

## 目标

在现有端口映射之外，提供一种让其他机器通过 Server 借用某台 Agent 所在网络出站访问能力的代理模式。

典型链路：

```text
外部机器 -> Server 代理入口 -> WebSocket 隧道 -> Agent -> 目标地址
```

这与端口映射的差异是：端口映射的目标是固定的 `local_addr:local_port`，代理模式的目标由每个客户端请求动态决定。

## 推荐方案

优先实现 Server 侧 SOCKS5 代理入口，Agent 侧执行动态拨号。

- Server 在独立端口监听 SOCKS5，例如 `0.0.0.0:1080` 或 `127.0.0.1:1080`。
- 外部机器把浏览器、curl、ssh 等工具配置为 SOCKS5 代理，连接 Server。
- Server 完成 SOCKS5 握手，解析每个请求的目标 `host:port`。
- Server 通过现有 WebSocket 连接把动态目标信息发给指定 Agent。
- Agent 根据目标 `host:port` 从 Worker 网络发起 `net.Dial`，后续数据继续复用二进制 WebSocket 帧转发。

## 复用与新增边界

应复用：

- 设备审批、在线状态、WebSocket 长连接、心跳与重连。
- 每设备 AES-GCM 加密开关和 `encryptTunnelBytes` / `decryptTunnelBytes` 数据路径。
- `tunnel_id` / `conn_id` 的多连接复用模型。
- IP 白名单、黑名单、限流和端口监听管理思路。

需要新增：

- Proxy 运行时资源，独立于固定端口映射 Tunnel。
- 动态目标控制消息，例如 `proxy_open` / `proxy_close` / `proxy_error`。
- Agent 侧按 `conn_id` 保存动态目标连接，而不是依赖 Tunnel 的固定 `LocalAddr` / `LocalPort`。
- Server 侧 SOCKS5 入口管理、认证和目标访问策略。

## 协议设计

建议不要把动态目标塞进现有 `TunnelOpenPayload`，否则会模糊端口映射和代理的语义。

当前 Go 实现已采用独立 `ProxyManager`，数据面仍复用现有 `BinaryTunnelData` wire frame；因此 `BinaryTunnelData.TunnelID` 在代理模式下承载 `proxy_id`，Server/Agent handler 必须先按 proxy ID 分流，找不到 proxy 时再走 tunnel 路径。

新增控制消息：

```go
type ProxyOpenPayload struct {
    ProxyID string `json:"proxy_id"`
    ConnID  string `json:"conn_id"`
    Host    string `json:"host"`
    Port    int    `json:"port"`
}

type ProxyClosePayload struct {
    ProxyID string `json:"proxy_id"`
    ConnID  string `json:"conn_id"`
}

type ProxyErrorPayload struct {
    ProxyID string `json:"proxy_id"`
    ConnID  string `json:"conn_id,omitempty"`
    Error   string `json:"error"`
}
```

二进制数据可复用现有帧格式，但需要明确 `TunnelID` 字段在代理模式下承载 `proxy_id`。如果希望协议语义更干净，可以把字段命名泛化为 `stream_id`，但这会影响现有 wire 协议和测试，首版不建议改。

## Server 侧设计

新增 `ProxyManager`：

- 管理 `proxy_id -> Proxy`，包含 `client_id`、监听地址、监听端口、`exposure`、状态和创建时间。
- 管理 `conn_id -> net.Conn`，保存外部代理客户端连接。
- 监听 SOCKS5 TCP 入口，完成握手后生成 `conn_id`。
- 向目标 Agent 发送 `proxy_open`，再转发外部连接数据。
- 收到 Agent 返回数据后，根据 `conn_id` 写回外部代理客户端。

API 建议独立于 `/api/tunnels`：

- `POST /api/proxies`：创建某个设备的代理入口。
- `GET /api/proxies`：列出代理入口。
- `DELETE /api/proxies/:proxy_id`：关闭代理入口。
- `GET /api/proxy-subscription`：查看 Clash 代理订阅链接状态。
- `POST /api/proxy-subscription/reset`：生成或重置订阅 token。
- `GET /proxy-subscription/:token`：公开拉取 Clash YAML 订阅。

创建请求示例：

```json
{
  "client_id": "device-id",
  "exposure": "server_local",
  "protocol": "socks5",
  "auth": {
    "username": "user",
    "password": "CHANGE-ME"
  }
}
```

首版默认建议 `exposure=server_local`，公网开放必须显式配置认证、白名单和限流。

当前 API 形态：

```json
{
  "client_id": "device-id",
  "public_port": 0,
  "exposure": "server_local",
  "username": "user",
  "password": "CHANGE-ME"
}
```

`public_port=0` 使用现有隧道端口范围自动分配；`public` 暴露不允许无 SOCKS5 username/password 创建。

Clash 订阅只输出当前运行时 `public` 且带认证的 SOCKS5 代理，`server_local` 不进入订阅。订阅链接使用 256-bit URL-safe 随机 token；普通 `/api/proxies` 列表不返回 SOCKS5 密码，密码只会在创建响应和持有订阅 token 的 YAML 中出现。`/api/settings` 这类通用设置响应也不能返回 `proxy_subscribe_token`，否则管理操作会把订阅凭据写入日志或终端输出。

## Agent 侧设计

新增 `ProxyManager` 或在现有 `TunnelManager` 内拆出共享的连接转发能力：

- 收到 `proxy_open` 后校验 `network=tcp`、host、port 和访问策略。
- 使用 `net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)` 从 Agent 机器发起连接。
- 按 `conn_id` 保存目标连接，启动读循环把响应写回 Server。
- 收到 `proxy_close` 或 EOF 后关闭对应连接。

首版不要实现 UDP ASSOCIATE。SOCKS5 的 TCP CONNECT 已覆盖浏览器、curl、git、ssh、npm、apt 等大部分代理场景。

## Web 管理入口

Server Web UI 已在 `web/static/index.html` 增加独立 `SOCKS5 代理` 卡片，不复用 `创建隧道` 表单，避免把固定端口映射和动态目标代理混在一起。

- 在线授权设备行提供 `代理` 快捷按钮，会预选目标设备并滚动到代理卡片。
- 代理卡片支持选择设备、入口类型、监听端口、SOCKS5 用户名和密码。
- 创建成功后展示 Clash `proxies` 配置片段，并提供复制按钮。
- 支持生成、复制和重置 Clash 订阅链接；该链接可供其它机器 Clash 拉取当前公网 SOCKS5 节点。
- 代理列表支持查看 Clash 配置和删除代理；历史代理列表不返回密码，展示配置时使用 `CHANGE-ME` 占位。
- 前端渲染 Clash 配置和代理列表时必须对用户可控文本做 HTML 转义，避免用户名、密码或设备名造成注入。

## 安全边界

代理功能比端口映射风险更高，因为它能访问 Worker 所在网络中的任意目标。

首版必须具备：

- 代理入口认证，至少支持 SOCKS5 username/password。
- `exposure` 默认 `server_local`，公网 `public` 需要显式开启。
- 每代理入口或每设备的目标 ACL，例如允许 CIDR、拒绝 CIDR、拒绝本机敏感地址。
- 复用现有外部来源 IP 白名单、黑名单和连接速率限制。
- 禁止把认证密码写入 harness 文档和日志。
- 订阅 token 是访问凭据，启用状态加密时必须纳入加密块；重置 token 后旧订阅链接立即失效。
- 全局/设备白名单应优先于黑名单和端口限流判断；否则 Clash 并发测速触发黑名单后，即使管理员把测试 IP 加入白名单也仍会被拒绝。

当前实现已在 Server 和 Agent 两侧默认拒绝 `localhost`、loopback、unspecified、multicast、link-local 和 `169.254.169.254`，防止伪造控制消息绕过 Server 侧校验。

建议默认拒绝 Agent 机器本机高危地址，除非管理员显式允许：

- `127.0.0.0/8`
- `::1/128`
- 云厂商 metadata 地址，例如 `169.254.169.254`

是否允许访问 Worker 的内网网段应由管理员配置，而不是硬编码全放开。

## 实现顺序

1. 新增 Proxy 数据结构、API 和 Server SOCKS5 握手，仅支持 TCP CONNECT。
2. 新增 `proxy_open` / `proxy_close` / `proxy_error` 控制消息。
3. Agent 增加动态拨号连接表和读写循环。
4. 复用现有二进制帧传输代理数据，服务端按 `proxy_id` 分流到 `ProxyManager`。
5. 增加认证、ACL、限流和公网暴露保护。
6. 最后补 Web UI 管理入口。

## 验证闭环

- 代码验证：`go test ./internal/common ./internal/server ./internal/agent`，最终再跑 `go test ./...`。
- Web UI 验证：打开管理后台，确认 `SOCKS5 代理` 统计、创建表单、代理列表、Clash 配置复制和删除后端口释放均正常。
- Clash 订阅验证：生成订阅链接，确认 `GET /proxy-subscription/:token` 返回 `proxies:` YAML，错误 token 返回 404，删除代理后订阅内容随运行时列表更新。
- Clash 客户端验证：重置订阅 token 或重建代理后必须在 Clash 中更新订阅；旧 token 或旧节点密码会表现为节点超时或认证失败。
- 本机代理：创建 `server_local` SOCKS5 代理，用 `curl --socks5 127.0.0.1:<port> http://目标地址` 验证。
- Worker 网络验证：访问仅 Agent 机器可达、Server 不可直连的内网 HTTP 服务。
- 出口验证：分别用每个 SOCKS5 节点访问 `ipinfo.io/ip`、`ifconfig.me/ip` 等，出口 IP 应等于目标 Agent 所在网络出口；如果单个目标站点超时，先在 Agent 机器直连同一目标确认是否为网络环境问题。
- 并发验证：多个 curl 并发请求确认 `conn_id` 不串流。
- 断线验证：Agent 重连后旧代理连接关闭，旧 listener 不泄漏。
- 安全验证：未认证请求失败，黑名单 IP 被拒绝，禁止目标被 ACL 拦截。
