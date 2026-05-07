# 加密隧道部署与验证直通流程

## 概述

本文档记录 GoRemote 加密隧道的完整部署和验证流程：从零开始，在公网服务器部署含 AES-256-GCM 加密的服务端，在本地 Windows 启动 Agent，创建隧道并通过加密通道验证数据转发。

## 前置条件

| 条件 | 说明 |
|------|------|
| 公网服务器 | Linux x86_64，已配置 SSH 访问（密码或密钥） |
| 本地开发机 | Windows x86_64，已安装 Go 1.26+ 和 PuTTY 工具链（plink.exe、pscp.exe） |
| 域名/IP | 公网服务器 IP 已知，端口 22（SSH）和 8080（GoRemote）可访问 |
| 磁盘空间 | 服务器 `/root` 至少 100MB 可用空间（注意清理旧日志和二进制） |

## 步骤一：交叉编译

在本地 Windows 编译 Linux 服务端和 Windows Agent：

```powershell
# 进入项目根目录
cd E:\AI-work\go-remote

# 生成 Swagger docs（首次或 API 变更后）
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/server/main.go -o docs

# 编译 Linux 服务端
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o opencode/assets/bin/server-linux-amd64 ./cmd/server/

# 编译 Windows Agent
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o opencode/assets/bin/agent-windows-amd64.exe ./cmd/agent/
```

> `-ldflags "-s -w"` 去除调试信息，减小二进制体积。

## 步骤二：检查服务器磁盘空间

部署前必须确认磁盘有可用空间，否则 pscp 上传会静默失败（只写入 0 字节）。

```powershell
plink -batch -pw "PASSWORD" root@YOUR_SERVER_IP "df -h /root"
```

**常见问题**：磁盘满导致上传失败。
- 旧日志文件（如 1.6GB 的 `server.log`）是主要空间占用源
- 清理命令：`rm -f /root/goremote/server.log`
- 旧二进制备份也需清理：`rm -f /root/goremote/server_old*`

## 步骤三：停止旧服务

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "kill -9 $(pgrep -f 'server --config') $(pgrep agent) 2>/dev/null; fuser -k 8080/tcp 2>/dev/null; echo done"
```

## 步骤四：上传并启动新服务端

### 4.1 上传二进制和配置

```powershell
# 上传服务端二进制
pscp -P 22 -pw "PASSWORD" "E:\AI-work\go-remote\opencode\assets\bin\server-linux-amd64" "root@SERVER_IP:/root/goremote/server_new"

# 上传配置文件
pscp -P 22 -pw "PASSWORD" "E:\AI-work\go-remote\config\server-deploy.yaml" "root@SERVER_IP:/root/goremote/config.yaml"
```

### 4.2 替换并启动

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "mv /root/goremote/server_new /root/goremote/server; chmod +x /root/goremote/server; rm -f /root/goremote/server.log; cd /root/goremote && nohup ./server --config config.yaml > server.log 2>&1 & sleep 2; curl -k -s https://localhost:8080/health"
```

预期输出：`{"status":"ok"}`

### 4.3 验证加密已启用

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "grep 'encryption enabled' /root/goremote/server.log"
```

预期输出：`"tunnel data encryption enabled (AES-256-GCM)"`

### 4.4 验证安全响应头

```powershell
curl.exe -k -v https://SERVER_IP:8080/health 2>&1 | findstr -i "X-Content-Type-Options X-Frame-Options Referrer-Policy Permissions-Policy"
```

预期看到：`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 等安全头。

## 步骤五：准备并启动本地 Agent

### 5.1 Agent 配置文件 (agent-local.yaml)

```yaml
server:
  address: SERVER_IP:8080
  tls:
    enabled: true
    insecure_skip_verify: true   # 测试用，生产应配置 CA

auth:
  key: test-secret-key            # 必须与服务端一致

agent:
  hostname: win-local
  os: windows

heartbeat:
  interval: 30

reconnect:
  interval: 5
  max_interval: 60

log:
  level: debug

tunnel:
  enabled: true
```

### 5.2 启动 Agent

```powershell
Start-Process -FilePath "E:\AI-work\go-remote\opencode\assets\bin\agent-windows-amd64.exe" `
  -ArgumentList "--config E:\AI-work\go-remote\config\agent-local.yaml" `
  -WorkingDirectory "E:\AI-work\go-remote" `
  -WindowStyle Hidden
```

> **重要**：必须指定 `-WorkingDirectory`，否则默认工作目录为 `C:\Windows\System32`，导致相对路径配置找不到。

### 5.3 验证 Agent 注册

```powershell
# 登录获取 token
curl.exe -k -c cookies.txt -X POST https://SERVER_IP:8080/api/login `
  -H "Content-Type: application/json" -d '{"password":"admin123"}'

# 查看在线客户端
curl.exe -k -b cookies.txt -s https://SERVER_IP:8080/api/clients
```

预期看到 `hostname":"win-local","os":"windows","status":"online"`。

## 步骤六：创建隧道并验证

### 6.1 创建测试隧道

使用 JSON 文件避免 PowerShell 转义问题：

```powershell
# 准备隧道请求体
@'
{"client_id":"CLIENT_ID","local_addr":"TARGET_IP","local_port":22,"protocol":"tcp"}
'@ | Out-File tunnel.json -Encoding ascii

# 创建隧道
curl.exe -k -b cookies.txt -X POST https://SERVER_IP:8080/api/tunnels `
  -H "Content-Type: application/json" -d "@tunnel.json"
```

返回包含 `public_port` 和 `tunnel_id` 的 JSON。

### 6.2 验证隧道连通性

**TCP 连通性**（从服务器到自身 tunnel 端口）：

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "timeout 3 nc -w 2 127.0.0.1 PUBLIC_PORT 2>&1"
```

应收到目标服务的协议 banner（如 SSH 的 `SSH-2.0-OpenSSH_...`）。

**HTTP 隧道**：

```powershell
curl.exe -k -s https://SERVER_IP:PUBLIC_PORT/health
```

预期返回 `{"status":"ok"}`（如果目标服务是 GoRemote 自身）。

### 6.3 验证服务端加密日志

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "tail -30 /root/goremote/server.log | grep -E 'tunnel|external conn'"
```

应看到：
- `tunnel created` — 隧道创建
- `tunnel listener started` — 端口监听
- `external connection accepted` — 外部连接通过加密隧道到达

## 步骤七：验证断线清理

```powershell
# 杀掉本地 Agent
taskkill /F /IM agent-windows-amd64.exe

# 等待心跳超时后检查
Start-Sleep -Seconds 5
curl.exe -k -b cookies.txt -s https://SERVER_IP:8080/api/tunnels
# 预期：{"total":0,"tunnels":[]}
curl.exe -k -b cookies.txt -s https://SERVER_IP:8080/api/clients
# 预期：{"clients":[],"total":0}
```

验证端口已释放：

```powershell
plink -batch -pw "PASSWORD" root@SERVER_IP "ss -tlnp | grep -E '10000|10001' || echo 'ports released'"
```

## 验证清单

部署完成后逐项确认：

```
□ 服务端运行中，日志显示 "tunnel data encryption enabled (AES-256-GCM)"
□ 安全响应头已启用（X-Content-Type-Options、X-Frame-Options 等）
□ 健康检查通过: curl -k https://SERVER_IP:8080/health → {"status":"ok"}
□ Agent 已注册且在线: GET /api/clients → status=online
□ 隧道可创建: POST /api/tunnels → 返回 tunnel_id + public_port
□ 加密隧道数据转发正常: curl 通过 tunnel 端口收到目标服务响应
□ 端口释放正常: 杀 Agent 后隧道和端口全部清理
```

## 注意事项

1. **加密密钥一致性**：服务端和 Agent 的 `auth.key` 必须完全一致，否则加解密失败，隧道数据无法传输
2. **TLS 自签证书**：测试环境 Agent 可设置 `insecure_skip_verify: true`，生产环境必须配置正确的 CA 证书
3. **磁盘空间**：部署前务必检查服务器磁盘空间，旧日志文件是常见空间杀手
4. **PowerShell JSON 传递**：始终使用 `@file.json` 方式传递 JSON，避免引号转义问题
5. **plink 主机密钥**：同一服务器不同端口有独立的主机密钥缓存，连接新 tunnel 端口可能触发密钥验证
6. **日志级别**：调试部署问题时可设 `log.level: debug`，确认功能正常后改回 `info`

## 相关文档

- [加密隧道开发经验教训](../experience/encrypted-tunnel-lessons.md) — 本轮开发中踩过的坑
- [SSH 隧道直通内网服务流程](./ssh-tunnel-direct-access.md) — 更早的无加密隧道流程
- [GoRemote 调试开发经验](../experience/go-remote-debugging.md) — 综合调试排查手册
