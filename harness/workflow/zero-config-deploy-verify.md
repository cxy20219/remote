# 零配置部署与验证直通流程

> 最后验证：2026-05-14 | 适用场景：首次部署零配置版、版本升级、功能验证 | 对应二进制：`./server`（无 config 文件）+ `./agent --server <ip>:<port>`

## 适用场景

- 全新部署 GoRemote（不兼容旧版共享 auth.key 模式）
- 从旧版迁移：需先清理旧 `server-state.json` 和 `auth.key` 配置
- 不适用：需要保留旧版 auth.key 认证的混合场景

## 前置条件

| 条件 | 说明 |
|------|------|
| 公网服务器 | Linux x86_64，已配置 SSH 访问 |
| 本地开发机 | Windows x86_64，安装 Go 1.26+ 和 plink.exe/pscp.exe |
| 端口 | 服务端 8080（默认）+ 隧道段 10000+（可配）可访问 |
| 磁盘 | `/root` 至少 50MB 可用空间 |

## 关联资源

- [设计文档](../references/zero-config-design.md)：架构设计与实现差异
- [部署脚本](../scripts/deploy-server.ps1)：自动化部署（Windows→Linux）
- [Agent 部署脚本](../scripts/deploy-agent.sh)：自动化 Agent 部署
- [测试经验](../experience/zero-config-testing-lessons.md)：调试踩坑记录
- [远程部署坑点](../experience/remote-deployment-pitfalls.md)：binary in use、fuser、nohup 卡住

## 执行步骤

### 1. 交叉编译

```powershell
# 进入项目根目录
cd E:\AI-work\go-remote

# 生成 Swagger 文档（首次或 API 变更后）
swag init -g cmd/server/main.go -o docs

# 编译 Linux 服务端
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o harness/assets/bin/server-linux-amd64 ./cmd/server/

# 编译 Windows Agent
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o harness/assets/bin/agent-windows-amd64.exe ./cmd/agent/
```

### 2. 检查服务器状态

```powershell
# 检查磁盘
plink -batch -pw "PASSWORD" root@YOUR_SERVER "df -h /root"

# 停止旧进程（需正确处理 PowerShell 转义）
plink -batch -pw "PASSWORD" root@YOUR_SERVER 'kill -9 $(pgrep -f server) 2>/dev/null; mkdir -p /root/goremote/data; echo ready'
```

> **坑点**：PowerShell 双引号中 `$(...)` 会被展开为子表达式。必须用**单引号**包裹远程命令，或把命令存入变量再传给 plink。

### 3. 上传并启动服务端

```powershell
# 上传二进制
pscp -P 22 -pw "PASSWORD" "E:\AI-work\go-remote\harness\assets\bin\server-linux-amd64" root@YOUR_SERVER:/root/goremote/server

# 启动（零配置，无需任何 yaml）
plink -batch -pw "PASSWORD" root@YOUR_SERVER 'chmod +x /root/goremote/server; cd /root/goremote && nohup ./server --data /root/goremote/data > server.log 2>&1 & sleep 2; curl -s http://localhost:8080/health'
```

预期输出：`{"status":"ok"}`

### 4. 获取 admin 密码

```powershell
plink -batch -pw "PASSWORD" root@YOUR_SERVER 'grep "Admin password" /root/goremote/server.log'
```

预期输出：
```
{"level":"INFO","msg":"Admin password","password":"9d99e3b9-2b8"}
```

> 密码仅在**首次运行**时生成打印，且明文仅在启动日志中出现一次（后续登录用 bcrypt 哈希校验）。

### 5. 启动 Agent（本机 Windows）

```powershell
# 清理旧 identity（如要全新注册）
Remove-Item "$env:USERPROFILE\.goremote\identity" -ErrorAction SilentlyContinue

# 启动 Agent
Start-Process -FilePath ".\agent-windows-amd64.exe" -ArgumentList "--server YOUR_SERVER:8080" -WindowStyle Hidden
```

预期日志输出：
```
"msg":"registering with new identity"
"msg":"waiting for admin approval","client_id":"client-ff155a09"
```

### 6. 审批设备

```powershell
# 1. 登录获取 session
$body = @{password="9d99e3b9-2b8"} | ConvertTo-Json
$login = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/login" -Method POST -Body $body -ContentType "application/json" -SessionVariable "session" -UseBasicParsing

# 2. 查看待审批设备
$pending = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/devices/pending" -WebSession $session -UseBasicParsing
$pending.Content

# 3. 批准设备
$approve = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/devices/pending/client-ff155a09/approve" -Method POST -WebSession $session -UseBasicParsing
$approve.Content
```

预期输出：`{"device_id":"client-ff155a09","status":"approved"}`

Agent 自动收到 `register_ok` 和加密密钥，日志出现：
```
"msg":"tunnel data encryption enabled (AES-256-GCM)"
"msg":"registered successfully","client_id":"client-ff155a09"
```

### 7. 验证隧道

```powershell
# 1. 在本机起一个测试服务（TCP 回声或 HTTP）
# 例如用 PowerShell TCP listener
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 22222)
$listener.Start()

# 2. 创建隧道
$tunnel = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/tunnels" -Method POST `
  -Body '{"client_id":"client-ff155a09","local_addr":"127.0.0.1","local_port":22222,"protocol":"tcp"}' `
  -ContentType "application/json" -WebSession $session -UseBasicParsing
$tunnel.Content

# 3. 在服务端验证数据贯通
plink -batch -pw "PASSWORD" root@YOUR_SERVER 'echo test | timeout 3 nc -w 2 127.0.0.1 10000 2>&1'
```

预期输出：测试服务响应的数据（如 `HELLO FROM WINDOWS TEST SERVER`）。

### 8. 验证 key 轮换

```powershell
$regen = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/devices/client-ff155a09/regen-key" -Method PUT -WebSession $session -UseBasicParsing
$regen.Content
```

预期输出：`{"device_id":"client-ff155a09","status":"key_regenerated"}`

验证隧道在 key 轮换后仍正常工作（步骤 7.3）。

## 验证清单

| 验证项 | 验证方式 | 预期 |
|--------|---------|------|
| 服务端健康 | `curl /health` | `{"status":"ok"}` |
| admin 登录 | `POST /api/login` | 返回 token |
| Agent 注册 | server.log | `waiting for admin approval` |
| 设备审批 | `POST /api/devices/pending/:id/approve` | `status: approved` |
| 加密激活 | agent.log | `tunnel data encryption enabled` |
| 隧道连通 | `nc <server> <port>` | 收到本地服务响应 |
| key 轮换 | `PUT /api/devices/:id/regen-key` | `status: key_regenerated` |
| 断线重连 | kill agent → 重启 | `client reconnected` |
| 状态持久化 | 检查 server-state.json | 设备、设置完整 |

## 失败回退

| 失败表现 | 可能原因 | 排查/恢复 |
|----------|---------|----------|
| Agent 报 `unauthorized` | 设备被管理员删除 | 清空 `~/.goremote/identity` 重新注册 |
| 隧道不通 | 本地端口未监听 | 确认本地服务运行，`ss -tlnp \| grep <port>` |
| 审批后 Agent 无反应 | enc_key 传输失败 | 重新启动 Agent（携带已有 identity 自动重连获取密钥） |
| 服务端启动报端口占用 | 旧进程未清理 | `fuser -k 8080/tcp` 再启动 |
| `server-state.json` 损坏 | 磁盘写异常 | 手工修复 JSON 或删除后重启（密钥和设备信息丢失） |

## 注意事项

- **首次启动前必须清理旧状态**：旧版 `server-state.json` 的格式与新版不兼容，必须删除重新生成
- **Agent 身份文件**：`~/.goremote/identity` 包含设备私钥，丢失后需管理员删除旧设备后重新注册
- **端口扫描器**：公网服务器会持续收到扫端口的连接请求，会触发 `registration failed` 日志——这是正常行为，不影响稳定运行
- **密码安全性**：admin 密码首次启动后不再明文存储。如遗忘密码，删除 `server-state.json` 重新启动
