---
name: goremote-deploy
description: GoRemote 部署与调试技能。编译服务端/客户端二进制、部署到服务器、配置TLS、排查问题时使用。
compatibility: opencode
metadata:
  scope: project
---

# GoRemote 部署与调试

## 职责

指导 GoRemote 服务端和客户端的编译、部署、配置和常见问题排查。

## 触发场景

- 用户要求编译服务端/客户端
- 部署 GoRemote 到服务器
- 隧道创建后无法连接
- TLS 握手失败
- Agent 断线后隧道未清理
- 配置文件不生效

## 编译

### Windows

```powershell
go build -o bin/server.exe ./cmd/server
go build -o bin/agent.exe ./cmd/agent
```

### Linux (交叉编译)

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent
# 验证: file bin/server
```

## 部署服务端

### 启动

```bash
# 直接运行
./server --config config/server.yaml

# 后台运行 (Linux)
nohup ./server > server.log 2>&1 &

# 验证
curl http://localhost:8080/health
```

### 杀进程

```bash
# 按端口杀（最可靠）
fuser -k 8080/tcp

# 或 killall
killall -9 server
```

## 部署客户端 Agent

### 启动 (Linux)

```bash
nohup ./agent --config config/agent.yaml > agent.log 2>&1 &
```

### 启动 (Windows PowerShell)

```powershell
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml" -WorkingDirectory "E:\path\to\project"
```

### 验证在线

```bash
curl http://server:8080/api/clients
# 确认 status: online
```

## 隧道创建

```bash
# 1. 确认 Agent 在线
curl http://server:8080/api/clients

# 2. 创建隧道
curl -X POST http://server:8080/api/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<client_id>","local_port":22,"protocol":"tcp"}'

# 3. 验证端口监听
ss -tlnp | grep <public_port>

# 4. SSH 连接测试
ssh -p <public_port> user@server
```

## TLS 配置

### 生成证书 (必须带 SAN)

```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server" \
  -addext "subjectAltName=IP:your-ip,DNS:your-server"
```

### 服务端配置

```yaml
server:
  tls:
    enabled: true
    cert: "server.crt"
    key: "server.key"
```

### 客户端配置

```yaml
server:
  tls:
    enabled: true
    ca: "server.crt"  # 服务端证书作为 CA
```

## 常见问题排查

### 隧道创建成功但无法连接

1. 检查 Agent 在线：`curl /api/clients`
2. 检查公网端口监听：`ss -tlnp | grep <port>`
3. 检查内网服务运行：`curl localhost:<local_port>/`
4. 检查 Agent 进程：`ps aux | grep agent`

### TLS 握手失败

```
x509: certificate relies on legacy Common Name field, use SANs instead
```
→ 重新生成带 SAN 的证书

### Binary in use 无法覆盖

```bash
# 先重命名
mv server server_old
# 再上传新 binary
# 最后杀旧进程
fuser -k 8080/tcp
```

### Permission denied

```bash
chmod +x server
```

### nohup 启动后卡住

```bash
nohup ./server > server.log 2>&1 &
# 或
nohup ./server </dev/null > server.log 2>&1 &
```

### PowerShell curl JSON

```powershell
# ✅ 正确方式
@'{"key":"value"}'@ | Out-File body.json -Encoding ascii
curl.exe -d "@body.json" -H "Content-Type: application/json"
Remove-Item "body.json"
```

## 健康检查清单

```
□ 服务端进程运行中: ps aux | grep server
□ 健康检查通过: curl /health → {"status":"ok"}
□ Agent 已注册: /api/clients → client 在线
□ 隧道可创建: POST /api/tunnels → 返回 tunnel_id
□ 隧道数据转发: curl public:port → 返回内网响应
□ TLS 握手成功: agent 日志显示 "connected to server"
□ 端口清理正常: taskkill agent 后 /api/tunnels → total:0
```

## 文件索引

- [调试经验](references/go-remote-debugging.md)：TLS、PowerShell、配置等
- [部署经验](references/go-remote-deploy-debug.md)：实战经验汇总
- [远程部署坑点](references/remote-deployment-pitfalls.md)：binary in use、权限等
- [Gin/路由技巧](references/gin-auth-route-tips.md)：路由规划、Cookie、Middleware
- [跨平台技巧](references/cross-platform-ps-tips.md)：交叉编译、curl、plink
- [SSH隧道直通流程](references/ssh-tunnel-direct-access.md)：完整操作流程
- [SSH隧道测试用例](references/ssh-tunnel-test-cases.md)：测试用例表