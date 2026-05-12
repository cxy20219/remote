# GoRemote 项目开发指南

## 技术栈

- **语言**: Go 1.26.2
- **模块名**: `goremote` (不是 `go-remote`)
- **Web框架**: Gin
- **WebSocket**: gorilla/websocket
- **架构**: SSH 隧道内网穿透（服务端/Agent C/S 架构）
- **加密**: AES-256-GCM 隧道数据加密（密钥由 `auth.key` 通过 SHA-256 派生）

## 目录结构

```
go-remote/
├── cmd/
│   ├── server/main.go       # 服务端入口
│   └── agent/main.go        # Agent 入口
├── internal/
│   ├── common/
│   │   ├── message.go       # 消息协议定义
│   │   ├── crypto.go        # AES-256-GCM 隧道加密
│   │   └── util.go          # 工具函数
│   ├── server/
│   │   ├── server.go        # Gin 引擎、WebSocket、CheckOrigin
│   │   ├── config.go        # 服务端配置（含 SecurityConfig）
│   │   ├── tunnel.go        # 隧道管理核心（加密数据转发）
│   │   ├── handler.go       # 消息分发（加密解密）
│   │   ├── api.go           # HTTP 管理 API
│   │   ├── admin_auth.go    # 管理员认证
│   │   ├── security.go      # 安全中间件（头、限流、Body限制）
│   │   └── client.go        # 客户端管理
│   └── agent/
│       ├── agent.go         # Agent 主控（含 crypto 上下文）
│       ├── connector.go     # WebSocket 连接（含 TLS）
│       ├── handler.go       # 消息处理（加密解密）
│       ├── tunnel.go        # Agent 端隧道（加密数据转发）
│       ├── config.go        # Agent 配置
│       └── reconnect.go     # 指数退避重连
├── config/                   # 配置文件（含 security 段）
├── docs/                     # swag init 自动生成（构建依赖）
├── web/
│   └── static.go             # go:embed 嵌入 static/ 到二进制
├── harness/
│   ├── Harness.md            # 本文件 — 项目总览与资源路由
│   ├── workflow/             # 直通流程（稳定可执行路径）
│   ├── experience/           # 经验教训与排查记录
│   ├── scripts/              # 自动化部署和运维脚本
│   ├── references/           # 设计文档、配置参考、API 规范
│   └── assets/               # 配置模板、预编译二进制
└── go.mod
```

## 常用命令

```bash
# 编译（Windows）
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent

# 交叉编译（Linux，瘦身二进制）
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o bin/server-linux-amd64 ./cmd/server

# 生成 Swagger docs（首次或 API 变更后）
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/server/main.go -o docs

# 测试
go test ./internal/...

# 静态检查
go vet ./internal/...
```

## 关键文件

| 文件 | 功能 |
|------|------|
| `internal/common/crypto.go` | AES-256-GCM 加解密，密钥由 `auth.key` 派生 |
| `internal/server/security.go` | 安全响应头、请求体大小限制、IP 速率限制 |
| `internal/server/tunnel.go` | 隧道管理，端口占用检测，`handleExternalConn` 加密外发数据 |
| `internal/server/handler.go` | 消息路由，`handleTunnelData` 解密接收数据 |
| `internal/agent/tunnel.go` | Agent 端隧道，`HandleLocalResponse` 加密数据 |
| `internal/agent/handler.go` | Agent 消息处理，`handleTunnelData` 解密 |
| `web/static.go` | `go:embed static` 嵌入 Web 界面到服务端二进制 |

## harness 资源路由

执行任何开发、部署、调试任务前，优先查阅对应资源：

| 任务类型 | 首选资源 | 备用资源 |
|----------|----------|----------|
| 首次部署服务端 | [workflow/encrypted-tunnel-deploy-verify.md](workflow/encrypted-tunnel-deploy-verify.md) | [scripts/deploy-server.ps1](scripts/deploy-server.ps1) |
| SSH 隧道直通内网 | [workflow/ssh-tunnel-direct-access.md](workflow/ssh-tunnel-direct-access.md) | [references/tunnel-design.md](references/tunnel-design.md) |
| 编译/部署报错排查 | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) | [experience/encrypted-tunnel-lessons.md](experience/encrypted-tunnel-lessons.md) |
| 部署环境纯运维坑 | [experience/remote-deployment-pitfalls.md](experience/remote-deployment-pitfalls.md) | — |
| Gin 路由/认证问题 | [experience/gin-auth-route-tips.md](experience/gin-auth-route-tips.md) | — |
| 配置字段说明 | [references/config-reference.md](references/config-reference.md) | [assets/server.yaml.template](assets/server.yaml.template) |
| TLS 证书问题 | [references/tls-setup.md](references/tls-setup.md) | [experience/go-remote-debugging.md](experience/go-remote-debugging.md) |
| 系统架构理解 | [references/project-structure.md](references/project-structure.md) | [references/server-design.md](references/server-design.md) |
| 制作 Release 发布包 | [workflow/encrypted-tunnel-deploy-verify.md](workflow/encrypted-tunnel-deploy-verify.md#步骤八制作-release-发布包) | — |
| 隧道功能端到端验证 | [references/ssh-tunnel-test-cases.md](references/ssh-tunnel-test-cases.md) | — |
| 端口占用检测与排除 | [references/tunnel-design.md](references/tunnel-design.md#36-端口状态查询) | [experience/port-occupancy-testing.md](experience/port-occupancy-testing.md) |
| 制作 Gitee Release 中文乱码 | [experience/gitee-release-utf8.md](experience/gitee-release-utf8.md) | — |
| 密码/密钥/公网地址 | **禁止写入 harness 文档**，使用占位符代替 | `CHANGE-ME` / `your-server-ip` 等 |

## 安全机制

| 机制 | 位置 | 说明 |
|------|------|------|
| 隧道数据加密 | `common/crypto.go` | AES-256-GCM，`auth.key` 非空时自动启用 |
| CheckOrigin | `server/server.go` | `security.allowed_origins` 白名单，空=放行 |
| 安全响应头 | `server/security.go` | X-Content-Type-Options、X-Frame-Options 等 |
| Body 大小限制 | `server/security.go` | `security.max_body_size_mb`，默认 10MB |
| 登录速率限制 | `server/security.go` | `security.login_rate_limit`，默认 5/min/IP |
| TLS 传输加密 | `server/server.go` / `agent/connector.go` | `server.tls.enabled: true` 启用 |

## 配置（新增 security 段）

```yaml
security:
  allowed_origins: []       # WebSocket Origin 白名单
  login_rate_limit: 5       # 登录速率限制（次/分/IP）
  max_body_size_mb: 10      # 请求体最大 MB
```

## 构建部署

1. `swag init -g cmd/server/main.go -o docs` — 生成 Swagger 文档
2. 交叉编译对应平台二进制
3. 检查服务器磁盘空间（`df -h`）
4. 停旧进程（`fuser -k 8080/tcp`）
5. **上传二进制和配置（无需 static/ 目录，Web 界面已通过 go:embed 编译进二进制）**
6. 启动服务端，验证 `"tunnel data encryption enabled (AES-256-GCM)"`
7. 启动 Agent，确认加密日志
8. 通过 API 创建隧道，验证加密数据转发

详见: `harness/workflow/encrypted-tunnel-deploy-verify.md`

## API 端点

| Method | Path | 说明 |
|--------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/login.html` | Web 登录页（go:embed 嵌入） |
| POST | `/api/login` | 管理员登录（速率限制保护） |
| POST | `/api/logout` | 登出 |
| GET | `/api/check-auth` | 认证状态检查 |
| GET | `/api/clients` | 客户端列表（需认证） |
| GET | `/api/clients/:id` | 客户端详情 |
| GET | `/api/client-tunnels/:client_id` | 指定客户端的所有隧道 |
| POST | `/api/tunnels` | 创建隧道 |
| GET | `/api/tunnels` | 隧道列表 |
| GET | `/api/tunnels/:id` | 隧道详情 |
| PUT | `/api/tunnels/:id` | 更新隧道 |
| DELETE | `/api/tunnels/:id` | 删除隧道 |
| GET | `/api/port-status` | 端口范围使用状况（含被占端口列表） |
| GET | `/static/*` | 静态资源（go:embed 嵌入） |
| GET | `/` | Web 管理首页（go:embed 嵌入） |

## 常见问题

| 问题 | 解决 |
|------|------|
| TLS 证书无效 | Go 1.15+ 需要 SAN，用 `-addext "subjectAltName=IP:xxx"` |
| pscp 上传 Network error | 磁盘满，`df -h` 检查并清理旧日志 |
| `swag init` 后编译失败 | 确认 `-o docs` 路径与 import 一致 |
| 隧道数据无法传输 | 确认服务端和 Agent 的 `auth.key` 完全一致 |
| 加密未启用 | 检查日志是否包含 `encryption enabled` |
| curl JSON 请求乱码 | 用 `@file.json` 方式，`Out-File -Encoding ascii` |
| Start-Process 找不到配置 | 加 `-WorkingDirectory` 参数 |
| plink 主机密钥警告 | 同一服务器不同端口有独立的主机密钥缓存，用 `-hostkey` 参数指定 |
| Gitee Release 中文乱码 | PowerShell 编码损坏中文，需用 Go 程序 `json.Marshal` 发送 API 请求 |

## 测试注意

- 加密功能测试覆盖：`go test -v ./internal/common/`（9 个用例）
- 测试中 `NewConnector` 需 5 个参数（含 `insecureSkipVerify`）
- `go vet` 应在每次提交前通过
