# GoRemote

基于 WebSocket 的隧道内网穿透系统，支持 AES-256-GCM 加密传输。

## 功能特性

- **加密隧道**: 所有数据经 AES-256-GCM 加密，密钥由 `auth.key` 派生
- **Web 管理界面**: 浅色主题，支持隧道 CRUD、客户端管理、SSH 命令复制
- **安全机制**: 安全响应头、请求体限制、登录速率限制、Origin 白名单
- **公网端口编辑**: 运行中可修改隧道公网端口，无需删除重建
- **心跳保活**: Agent 定期心跳，服务端超时自动清理
- **自动重连**: 指数退避重连，网络恢复后自动上线
- **TLS 加密传输**: WebSocket 支持 TLS，服务端可配置 CA 验证
- **跨平台**: Linux / Windows / macOS / Android (ARM64)

## 快速开始

### 从 Release 下载

[Gitee Release](https://gitee.com/cxy20219/go-remote/releases) 提供各平台预编译包，每个 zip 含 `server` + `agent` + `static/` 界面文件 + 配置模板。

### 服务端部署

```bash
# 1. 解压 release 包
unzip go-remote-v1.0.0-linux-amd64.zip
cd go-remote-v1.0.0-linux-amd64

# 2. 修改配置（务必改 auth.key 和 admin.password）
cp server.example.yaml server.yaml
vim server.yaml

# 3. 启动
chmod +x server
./server --config server.yaml
```

访问 `https://your-ip:8080/` 打开管理界面。

### 各平台 Agent 使用

### Agent 部署（所有平台）

从 [Release](https://gitee.com/cxy20219/go-remote/releases) 下载对应平台的 zip，解压后修改 `agent.yaml` 中的 `server.address` 和 `auth.key`。

#### Linux (x86_64 / arm64)

```bash
tar xf go-remote-v1.0.0-linux-amd64.zip
cd go-remote-v1.0.0-linux-amd64
vim agent.yaml            # 修改 server.address + auth.key
chmod +x agent
nohup ./agent --config agent.yaml > agent.log 2>&1 &
```

#### macOS (Intel / Apple Silicon)

```bash
unzip go-remote-v1.0.0-darwin-arm64.zip
cd go-remote-v1.0.0-darwin-arm64
vim agent.yaml
chmod +x agent
nohup ./agent --config agent.yaml > agent.log 2>&1 &
```

#### Windows (x86_64)

```powershell
Expand-Archive go-remote-v1.0.0-windows-amd64.zip
cd go-remote-v1.0.0-windows-amd64
notepad agent.yaml         # 修改 server.address + auth.key
Start-Process -FilePath ".\agent.exe" -ArgumentList "--config agent.yaml" -WindowStyle Hidden
```

#### Android (arm64, ADB 直推)

无需安装任何 App。从 Release 下载 `go-remote-v1.0.0-linux-arm64.zip`，取出其中的 `agent` 二进制即可（ARM64 Linux 二进制兼容 Android 内核）：

```bash
# 解压，只需 agent 文件
unzip go-remote-v1.0.0-linux-arm64.zip
# 推送 + 启动（带 watchdog 自动重启）
adb push agent /data/local/tmp/go-remote-agent
adb push agent.yaml /data/local/tmp/agent.yaml
adb shell "pkill go-remote-agent; cd /data/local/tmp && sh -c 'while true; do ./go-remote-agent --config agent.yaml; sleep 5; done > agent.log 2>&1 &'"
```

#### 远程 ADB 调试场景

```bash
# 1. 手机开启 adb TCP 模式
adb tcpip 5555

# 2. 创建隧道（映射手机 5555 到公网 10000）
curl -k -X POST https://server:8080/api/tunnels \
  -H "Content-Type: application/json" \
  -d '{"client_id":"xxx","local_addr":"127.0.0.1","local_port":5555,"protocol":"tcp"}'

# 3. 远程连接
adb connect your-server:10000
adb shell getprop ro.product.model   # 验证
```

## API

| 接口 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/login` | POST | 管理员登录 |
| `/api/clients` | GET | 在线客户端列表 |
| `/api/tunnels` | GET | 隧道列表 |
| `/api/tunnels` | POST | 创建隧道（支持 client_id/local_addr/local_port/protocol） |
| `/api/tunnels/:id` | PUT | 更新隧道（支持 public_port/local_port/local_addr/protocol） |
| `/api/tunnels/:id` | DELETE | 删除隧道 |

## 配置

完整配置示例见 `config/server.example.yaml` 和 `config/agent.example.yaml`。

```yaml
# security 段（新增）
security:
  allowed_origins: []       # WebSocket Origin 白名单
  login_rate_limit: 5       # 登录速率限制（次/分）
  max_body_size_mb: 10      # 请求体最大 MB
```

## 编译

```bash
# 生成 API 文档（首次）
swag init -g cmd/server/main.go -o docs

# 编译全平台 Release
go install github.com/swaggo/swag/cmd/swag@latest

# 各平台
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux-amd64   ./cmd/server
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o agent-linux-arm64    ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o server-windows-amd64.exe ./cmd/server
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o server-darwin-amd64  ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin-arm64  ./cmd/server
```

## 文档

- [Harness 开发指南](harness/Harness.md) — 技术栈、目录结构、常用命令、资源路由
- [加密隧道部署验证](harness/workflow/encrypted-tunnel-deploy-verify.md) — 完整部署流程
- [SSH 隧道直通内网](harness/workflow/ssh-tunnel-direct-access.md) — SSH 穿透实操
- [调试开发经验](harness/experience/go-remote-debugging.md) — 综合排查手册
- [加密隧道踩坑记录](harness/experience/encrypted-tunnel-lessons.md) — 开发实战经验
- [远程部署坑点](harness/experience/remote-deployment-pitfalls.md) — 五大运维坑

## 架构

```
外部用户 ──→ [服务端:公网端口] ──WebSocket(TLS+AES-256-GCM)──→ [Agent:内网端口]
              (端口映射+加密)          (加密数据透传)             (内网服务/ADB)
```

## License

MIT
