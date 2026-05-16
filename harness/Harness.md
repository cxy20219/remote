# GoRemote 项目开发指南

## 技术栈

- **语言**: Go 1.26.2
- **模块名**: `goremote`
- **Web框架**: Gin
- **WebSocket**: gorilla/websocket
- **架构**: 审批制内网穿透（Agent 主动 WebSocket 连接服务端）
- **加密**: AES-256-GCM 隧道数据加密，每设备独立密钥（X25519 ECDH 协商）
- **身份**: ed25519 设备身份 + x25519 密钥交换

## 目录结构

```
go-remote/
├── cmd/
│   ├── server/main.go      # 服务端入口（零配置 CLI 参数）
│   └── agent/main.go       # Agent 入口（仅需 --server 地址）
├── internal/
│   ├── common/
│   │   ├── message.go      # 消息协议定义
│   │   ├── crypto.go       # CryptoContext + CryptoManager（每设备密钥管理）
│   │   ├── identity.go     # ed25519/x25519 密钥对、签名验证、ECDH 密钥交换
│   │   └── util.go         # 工具函数
│   ├── server/
│   │   ├── server.go       # Gin 引擎、WebSocket 处理（集成 DeviceManager/StateStore）
│   │   ├── persist.go      # ServerState 持久化（异步原子写 server-state.json）
│   │   ├── device_mgr.go   # 设备管理（pending/authorized 状态机、审批/拒绝/密钥轮换）
│   │   ├── tunnel.go       # 隧道管理核心（加密数据转发，通过 CryptoManager 每设备加密）
│   │   ├── handler.go      # 消息分发（register → pending/reauth 审批制流程）
│   │   ├── config.go       # CLI 参数解析（--port/--host/--data/--tls-*）
│   │   ├── api.go          # HTTP 管理 API（含设备、设置接口）
│   │   ├── admin_auth.go   # 管理员 bcrypt 密码认证
│   │   ├── security.go     # 安全中间件（限流、黑名单、白名单、请求头）
│   │   └── client.go       # 运行时 WebSocket 连接管理器（简化，不管理持久状态）
│   └── agent/
│       ├── agent.go        # Agent 主控（支持 pending 等待审批、reauth 重连）
│       ├── identity.go     # Agent 本地身份管理（ed25519+x25519、ECDH 解密 enc_key）
│       ├── connector.go    # WebSocket 连接（RegisterNew/RegisterReauth）
│       ├── handler.go      # 消息处理（支持 register_update、device_deleted 等新类型）
│       ├── tunnel.go       # Agent 端隧道（通过 CryptoManager 加解密）
│       ├── config.go       # Agent 默认配置（可兼容 yaml 或 CLI 重写）
│       └── reconnect.go    # 指数退避重连
├── web/
│   └── static.go            # go:embed 嵌入 static/ 到二进制
├── harness/
│   ├── Harness.md           # 本文件
│   ├── workflow/            # 直通流程
│   ├── experience/          # 经验教训与排查记录
│   ├── scripts/             # 自动化部署和运维脚本
│   ├── references/          # 设计文档、配置参考
│   └── assets/              # 配置模板、静态模板资源
└── go.mod
```

## 常用命令

```bash
# 编译（Windows）
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent

# 交叉编译（Linux）
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o bin/server-linux-amd64 ./cmd/server

# 生成 Swagger docs（首次或 API 变更后）
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/server/main.go -o docs

# 测试
go test ./...

# 静态检查
go vet ./internal/...
```

> `go test -race ./internal/...` 需要 gcc/cgo。Windows 本机没有 gcc 时会报 `C compiler "gcc" not found`，属于环境限制。

## 关键文件

| 文件 | 功能 |
|------|------|
| `internal/common/crypto.go` | `CryptoManager` 每设备密钥管理，`CryptoContext` AES-256-GCM 加解密 |
| `internal/common/identity.go` | ed25519 签名/验证、x25519 ECDH 密钥交换、HKDF 派生 |
| `internal/server/persist.go` | `StateStore` 异步原子写入 `server-state.json` |
| `internal/server/device_mgr.go` | `DeviceManager` pending/authorized 审批状态机 |
| `internal/server/tunnel.go` | 隧道管理，`bufPool` sync.Pool 复用 256KB chunk，支持 WebSocket Binary 隧道数据帧 |
| `internal/server/client.go` | `ClientManager`+`DeviceQuerier` 接口，支持设备级 IP 白名单查询 |
| `internal/agent/identity.go` | Agent 本地 `~/.goremote/identity` 管理，ECDH 解密 enc_key |
| `internal/agent/agent.go` | Agent 主循环（pending 等待审批 → reauth 重连，含 pendingApproval 标志） |
| `internal/agent/connector.go` | WebSocket 连接（128KB buffer），JSON 控制消息 + Binary 隧道数据帧收发 |
| `web/static.go` | `go:embed static` 嵌入 Web 界面到服务端二进制 |

## harness 资源路由

| 任务类型 | 首选资源 | 备用资源 |
|----------|----------|----------|
| 零配置部署验证 | [workflow/zero-config-deploy-verify.md](workflow/zero-config-deploy-verify.md) | [scripts/deploy-server.ps1](scripts/deploy-server.ps1) |
| 稳定性/性能/完整性综合验收 | [workflow/stability-performance-completeness-verify.md](workflow/stability-performance-completeness-verify.md) | [experience/multi-platform-testing.md#16-2026-05-15-稳定性性能完整性优化复盘](experience/multi-platform-testing.md#16-2026-05-15-稳定性性能完整性优化复盘) |
| 加密隧道（旧版）部署 | [workflow/encrypted-tunnel-deploy-verify.md](workflow/encrypted-tunnel-deploy-verify.md) | [scripts/deploy-server.ps1](scripts/deploy-server.ps1) |
| SSH 隧道直通内网 | [workflow/ssh-tunnel-direct-access.md](workflow/ssh-tunnel-direct-access.md) | [references/tunnel-design.md](references/tunnel-design.md) |
| 零配置架构理解 | [references/zero-config-design.md](references/zero-config-design.md) | [workflow/zero-config-deploy-verify.md](workflow/zero-config-deploy-verify.md) |
| 零配置测试踩坑 | [experience/zero-config-testing-lessons.md](experience/zero-config-testing-lessons.md) | [workflow/zero-config-deploy-verify.md](workflow/zero-config-deploy-verify.md) |
| 多平台集成测试经验 | [experience/multi-platform-testing.md](experience/multi-platform-testing.md) | [experience/zero-config-testing-lessons.md](experience/zero-config-testing-lessons.md) |
| 代码安全与性能优化审查 | [experience/multi-platform-testing.md#9-已修正的代码问题列表](experience/multi-platform-testing.md#9-已修正的代码问题列表) | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) |
| 高并发 SSH 吞吐测试 | [workflow/stability-performance-completeness-verify.md#6-ssh-并发验证](workflow/stability-performance-completeness-verify.md#6-ssh-并发验证) | [experience/multi-platform-testing.md#15-高并发-ssh-吞吐测试结果](experience/multi-platform-testing.md#15-高并发-ssh-吞吐测试结果) |
| 服务端重启恢复流程 | [workflow/zero-config-deploy-verify.md#8b-验证服务端重启后的设备恢复](workflow/zero-config-deploy-verify.md) | [experience/multi-platform-testing.md#14-服务器重启导致-agent-身份漂移](experience/multi-platform-testing.md#14-服务器重启导致-agent-身份漂移) |
| pending 连接超时排查 | [experience/multi-platform-testing.md#13-agent-pending-状态-60-秒超时困境已修复](experience/multi-platform-testing.md#13-agent-pending-状态-60-秒超时困境已修复) | [experience/zero-config-testing-lessons.md#6-pending-连接的生命周期](experience/zero-config-testing-lessons.md#6-pending-连接的生命周期) |
| 隧道协议/二进制帧理解 | [references/tunnel-design.md#2-消息协议](references/tunnel-design.md#2-消息协议) | [experience/multi-platform-testing.md#16-2026-05-15-稳定性性能完整性优化复盘](experience/multi-platform-testing.md#16-2026-05-15-稳定性性能完整性优化复盘) |
| 编译/部署报错排查 | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) | [experience/encrypted-tunnel-lessons.md](experience/encrypted-tunnel-lessons.md) |
| 部署环境运维坑 | [experience/remote-deployment-pitfalls.md](experience/remote-deployment-pitfalls.md) | — |
| Gin 路由/认证问题 | [experience/gin-auth-route-tips.md](experience/gin-auth-route-tips.md) | — |
| 系统架构理解 | [references/project-structure.md](references/project-structure.md) | [references/server-design.md](references/server-design.md) |
| 制作 Release | [workflow/gitee-release-publish.md](workflow/gitee-release-publish.md) | [experience/gitee-release-utf8.md](experience/gitee-release-utf8.md) |
| TLS 证书问题 | [references/tls-setup.md](references/tls-setup.md) | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) |
| 端口扫描/限流排查 | [references/tunnel-design.md](references/tunnel-design.md#30-端口防扫描anti-scanning) | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) |
| Android Agent 部署 | [experience/multi-platform-testing.md](experience/multi-platform-testing.md#7-android-agent-部署要点) | [workflow/zero-config-deploy-verify.md](workflow/zero-config-deploy-verify.md) |
| 密码/密钥/公网地址 | **禁止写入 harness 文档**，使用占位符 | `CHANGE-ME` / `your-server-ip` |

## 安全机制

| 机制 | 位置 | 说明 |
|------|------|------|
| 隧道数据加密 | `common/crypto.go` | AES-256-GCM，每设备密钥，ECDH 安全传输 |
| 隧道数据帧 | `common/message.go` / `server/tunnel.go` / `agent/tunnel.go` | WebSocket Binary frame 传输 nonce+ciphertext；仅允许已定义 flags，并分段校验 tunnel_id/conn_id/data 长度；旧 JSON/base64 `tunnel_data` 路径已移除 |
| WS 控制消息 | `common/message.go` / `server/server.go` / `agent/connector.go` | TextMessage 使用严格 JSON 解码，拒绝未知字段和尾随多个 JSON 文档 |
| 设备身份认证 | `common/identity.go` | ed25519 签名 `client_id:timestamp`，5 分钟窗口防重放 |
| X25519 密钥交换 | `common/identity.go` / `server/device_mgr.go` | 审批时 ECDH + HKDF-SHA256 派生密钥，加密传输 enc_key；设备 DH 公钥必须是 32 字节 hex |
| 审批制注册 | `server/device_mgr.go` | 新设备需管理员批准才能接入，pending → authorized |
| 密钥轮换 | `server/device_mgr.go` | Web UI 一键重新生成密钥，Agent 通过 `register_update` 自动接收 |
| 管理员会话 | `server/admin_auth.go` | 256-bit 随机 token，HttpOnly Cookie，24 小时过期，最多保留 64 个会话并清理过期会话 |
| CheckOrigin | `server/server.go` | `allowed_origins` 白名单；空配置只允许无 Origin 的 Agent 请求，拒绝浏览器 Origin |
| 管理 API 写保护 | `server/security.go` / `server/api.go` | 已认证 POST/PUT/DELETE 会校验浏览器 Origin/Referer；写接口严格 JSON 解码，拒绝未知字段和多 JSON 文档；CLI/脚本无 Origin 请求仍可用 |
| 真实客户端 IP | `server/server.go` | 默认 `SetTrustedProxies(nil)`，公网直连时限流/黑名单只信任 TCP RemoteAddr，避免伪造 `X-Forwarded-For` |
| HTTPS 判定 | `server/api.go` / `server/security.go` | Cookie Secure 和同源判断只信任真实 TLS，不信任 `X-Forwarded-Proto` |
| HTTP 服务硬化 | `server/server.go` | 显式设置 ReadHeaderTimeout、ReadTimeout、WriteTimeout、IdleTimeout 和 32KB MaxHeaderBytes，降低慢连接和超大请求头风险 |
| 安全响应头 | `server/security.go` | X-Content-Type-Options、X-Frame-Options 等 |
| Body 大小限制 | `server/security.go` | `max_body_size_mb`，默认 10MB；运行时修改立即生效，0 表示禁用限制 |
| 登录速率限制 | `server/security.go` | `login_rate_limit`，默认 5/min/IP |
| WS 连接限流 | `server/security.go` | `max_conn_per_min`，默认 10/min/IP |
| 隧道端口防扫描 | `server/tunnel.go` | 同上，黑名单联动 |
| IP 白名单绕过限流 | `server/security.go` | 设备级 + 全局白名单，支持 CIDR |
| 自动黑名单 | `server/security.go` | 累计限流违规达阈值自动拉黑 |
| TLS 传输加密 | `server/server.go` / `agent/connector.go` | `--tls-cert/--tls-key` 启用；服务端和 Agent 默认要求 TLS 1.3 |

## 构建部署

1. `swag init -g cmd/server/main.go -o docs` — 生成 Swagger 文档
2. 交叉编译对应平台二进制
3. 上传二进制至服务器（**无需任何配置文件**）
4. 启动服务端：`./server --data /path/to/data`
5. 查看 admin 密码：`grep "Admin password" server.log`
6. 启动 Agent：`./agent --server <ip>:8080`
7. 在 Web UI 审批设备
8. 创建隧道验证数据贯通

详见: `harness/workflow/zero-config-deploy-verify.md`

## API 端点

### 系统
| Method | Path | 说明 |
|--------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/login` | 管理员登录 |
| POST | `/api/logout` | 登出 |
| GET | `/api/check-auth` | 认证状态检查 |

### 设备管理
| Method | Path | 说明 |
|--------|------|------|
| GET | `/api/devices` | 全部设备列表（含在线/离线状态） |
| GET | `/api/devices/pending` | 待审批设备列表 |
| POST | `/api/devices/pending/:id/approve` | 批准注册 |
| POST | `/api/devices/pending/:id/deny` | 拒绝注册 |
| DELETE | `/api/devices/:id` | 删除设备 |
| PUT | `/api/devices/:id/config` | 更新设备配置（别名、加密开关、IP 白名单） |
| PUT | `/api/devices/:id/regen-key` | 重新生成加密密钥 |
| GET/PUT | `/api/clients/:id/whitelist` | 设备级 IP 白名单 |

### 隧道
| Method | Path | 说明 |
|--------|------|------|
| GET/POST | `/api/tunnels` | 隧道列表 / 创建 |
| GET/PUT/DELETE | `/api/tunnels/:id` | 详情 / 编辑 / 删除 |
| GET | `/api/client-tunnels/:client_id` | 指定设备的所有隧道 |
| GET | `/api/port-status` | 端口范围使用状况 |

### 安全
| Method | Path | 说明 |
|--------|------|------|
| GET/PUT | `/api/security/global-whitelist` | 全局 IP 白名单 |
| GET/POST | `/api/security/blacklist` | 黑名单列表 / 添加 |
| DELETE | `/api/security/blacklist/:ip` | 解除黑名单 |
| GET/PUT | `/api/security/blacklist-threshold` | 自动拉黑阈值 |

### 系统设置
| Method | Path | 说明 |
|--------|------|------|
| GET/PUT | `/api/settings` | 服务端运行时设置（端口范围、限流、心跳等） |

## 常见问题

| 问题 | 解决 |
|------|------|
| 服务端启动报端口占用 | `fuser -k 8080/tcp` 再启动 |
| Agent 注册被拒绝 | 管理员拒绝或设备被删除，清空 `~/.goremote/identity` 重新注册 |
| 审批后 Agent 无反应 | 重启 Agent（携带已有 identity 重连自动获取密钥） |
| 隧道不通 | 确认本地服务监听，`ss -tlnp | grep <port>` 检查 |
| **隧道偶尔断开**隧道 EOF 导致 Agent 重连 | Agent 日志搜 `ciphertext too short`，已修复（跳过 EOF 解密） |
| server-state.json 损坏 | 手工修复或删除重启（设备信息丢失） |
| **plink/pscp 首次连接失败** | 使用 `-hostkey` 参数缓存主机密钥，`echo y \| plink` 无效 |
| **nc 隧道测试无响应** | 127.0.0.1 被黑名单误伤，加入全局白名单或应用 localhost 跳过修复 |
| PowerShell 命令转义问题 | 远程 plink 命令用单引号包裹 |
| Start-Process 无法重定向 | 使用 `-WindowStyle Hidden` 或 PowerShell Job 替代 |
| 密码遗忘 | 删除 `server-state.json` 重启重新生成 |
| 扫描器连接日志噪音 | 不影响运行，是正常行为 |
| Agent 日志出现 `non-fatal message error, continuing` | 正常行为，端口扫描器短连接造成，不影响 Agent |
| Agent 不断注册新的 pending ID | 确认是否运行新版 pending 心跳；清理未知旧 Agent/pending；检查服务端状态是否被重置 |
| 服务端重启后 Agent 无法重连 | server-state.json 丢失导致设备消失，清空 Agent identity 文件重新注册 |
| 高并发 SSH 部分报 `Connection closed` | 先确认压测来源已加入全局白名单，再判断 SSHD `MaxStartups` 或公网入口瞬时超时 |
| 大文件下载慢 | 先做公网服务端直连下载和内网 SSH 直连对照；若公网直连也慢，瓶颈不在隧道协议 |
| pending 超时断开 | 新版已通过 pending heartbeat 修复；若复现，多半是旧二进制或未知旧 Agent 持续重连 |
| SSH 隧道握手卡死且 Agent 报 `encryption key not found` | 检查 reauth 降级注册路径是否携带/刷新 `DeviceDHPubkey`，坏授权设备需删除后重新审批 |

## 测试注意

- `go test ./internal/...` 运行所有单元测试
- `go vet ./internal/...` 静态检查
- `go build ./...` 确认编译通过
