# GoRemote 项目开发指南

## 技术栈

- **语言**: Go 1.26.2
- **模块名**: `goremote` (不是 `go-remote`)
- **Web框架**: Gin
- **WebSocket**: gorilla/websocket
- **架构**: SSH 隧道内网穿透（简化版，移除了 exec/file/openclaw/tasks）

## 目录结构

```
go-remote/
├── cmd/
│   ├── server/main.go    # 服务端入口
│   └── agent/main.go     # 客户端入口
├── internal/
│   ├── common/message.go # WebSocket 消息类型（共享）
│   ├── server/           # Gin + websocket 服务端
│   └── agent/            # Agent + 重连逻辑
├── config/
│   ├── server.yaml       # 服务端配置
│   └── agent.yaml        # 客户端配置
├── bin/                  # 编译输出目录
├── opencode/
│   ├── docs/             # 设计文档、经验、流程
│   ├── scripts/          # 自动化脚本
│   ├── references/       # 配置参考、TLS指南
│   └── assets/           # 模板、二进制
└── skills/               # Skill 目录（不要与 opencode 重复）
```

## 常用命令

```bash
# 编译（Windows）
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent

# 交叉编译（Linux）
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent

# 测试
go test -v ./internal/server/...
go test -v ./internal/agent/...

# 运行
./bin/server.exe --config config/server.yaml
./bin/agent.exe --config config/agent.yaml
```

## 关键文件

- `internal/common/message.go` - WebSocket 消息类型定义
- `internal/server/` - 服务端实现（隧道管理、API）
- `internal/agent/` - 客户端实现（重连、心跳）
- `config/server.yaml` / `config/agent.yaml` - 配置文件

## 构建部署

1. 编译对应平台二进制到 `bin/`
2. 准备配置文件（参考 `opencode/assets/*.template`）
3. 部署服务端到公网服务器
4. 部署客户端到内网服务器
5. 通过 API 创建隧道映射端口

详见: `opencode/docs/workflow/ssh-tunnel-direct-access.md`

## 常见问题

| 问题 | 解决 |
|------|------|
| TLS 证书无效 | Go 1.15+ 需要 SAN，用 `-addext "subjectAltName=IP:xxx"` 生成 |
| 客户端连不上 | 检查 `server.address` 是否指向正确公网地址，验证 TLS 配置匹配 |
| 隧道创建成功但无响应 | 确认内网 agent 进程正常运行 |
| 配置文件不生效 | 重启服务，检查 YAML 语法 |
| binary 无法覆盖 | 先 `mv` 重命名，再上传，杀进程后重启 |

## API 端点

- `GET /health` - 健康检查
- `POST /api/login` - 管理员登录
- `GET /api/clients` - 查看客户端列表（需认证）
- `POST /api/tunnels` - 创建隧道
- `GET /api/tunnels` - 查看隧道列表
- `PUT /api/tunnels/:id` - 更新隧道
- `DELETE /api/tunnels/:id` - 删除隧道

Swagger UI: `http://localhost:8080/swagger/index.html`

## 测试注意

- Windows 上 `sleep` → `timeout /t`，`ls` → `dir`
- 使用 `runtime.GOOS` 做平台判断