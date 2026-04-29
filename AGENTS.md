# AGENTS.md

## Build

```bash
# Windows
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent

# Linux (cross-compile from Windows)
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent
```

No Makefile. Binaries go to `bin/`.

## Test

```bash
go test -v ./internal/server/...
go test -v ./internal/agent/...
go test -coverprofile=coverage.out ./internal/server/...
```

## Run

```bash
./bin/server.exe --config config/server.yaml
./bin/agent.exe --config config/agent.yaml
```

## Key Files

- `cmd/server/main.go` / `cmd/agent/main.go` - Entrypoints
- `internal/common/message.go` - WebSocket message types (shared)
- `internal/server/` - Gin + gorilla/websocket (server implementation)
- `internal/agent/` - Agent implementation with reconnect logic
- `config/server.yaml`, `config/agent.yaml` - Config

## Swagger

Server starts: `http://localhost:8080/swagger/index.html`

## Cross-Platform

Tests use `runtime.GOOS` checks. Windows: `sleep` → `timeout /t`, `ls` → `dir`.

## Architecture

- Module: `goremote` (not `go-remote`)
- Go 1.26.2
- Simplified to SSH tunnel functionality only (removed exec, file, openclaw, tasks)
- Stale `.exe` files exist in repo root (not `bin/`) - ignore

## Documentation Index

- **[服务端设计文档]** - docs/server-design.md：服务端架构、消息协议、接口设计
- **[客户端设计文档]** - docs/agent-design.md：客户端架构、重连机制
- **[服务端测试方案]** - docs/server-test.md：服务端单元/集成/端到端测试
- **[客户端测试方案]** - docs/agent-test.md：客户端单元/集成/端到端测试
- **[项目结构]** - docs/project-structure.md：项目目录结构、架构设计、消息协议格式
- **[隧道设计文档]** - docs/tunnel-design.md：隧道架构、数据传输、安全机制
- **[SSH 隧道直通测试用例]** - docs/test/ssh-tunnel-test-cases.md：SSH 隧道直通流程测试用例，覆盖正常流程、边界条件、异常情况
- **[GoRemote 调试开发经验]** - docs/experience/go-remote-debugging.md：常见坑点、排查思路、最佳实践、环境差异处理技巧等经验总结，包括 Web 服务部署、SSH 隧道连接、API 调用、进程管理、Windows 特殊处理等
- **[SSH 隧道直通内网服务流程]** - docs/workflow/ssh-tunnel-direct-access.md：SSH 隧道从公网访问内网服务的完整流程，包括隧道创建、SSH 直连内网、部署服务、问题排查等实操步骤