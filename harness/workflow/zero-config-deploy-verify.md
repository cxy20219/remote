# 零配置部署与验证直通流程

> 最后验证：2026-05-15 | 适用场景：首次部署零配置版、版本升级、功能验证 | 对应二进制：`./server`（无 config 文件）+ `./agent --server <ip>:<port>`

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
- [稳定性、性能、完整性综合验证](stability-performance-completeness-verify.md)：隧道核心改动后的压测和回归验收
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
go build -ldflags "-s -w" -o build/server-linux-amd64 ./cmd/server/

# 编译 Windows Agent
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o build/agent-windows-amd64.exe ./cmd/agent/
```

> 生成产物放 `build/`，验证后可清理。`harness/assets/` 只保存模板和静态资源，不保存临时二进制。

### 2. 检查服务器状态（首次连接需缓存主机密钥）

```powershell
# 首次连接：plink -batch 会因未缓存主机密钥而失败，需用 -hostkey 参数
# 指纹来自首次连接失败的提示信息
$hostkey = "ssh-ed25519 255 SHA256:服务器指纹"

# 检查磁盘
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER "df -h /root"

# 停止旧进程（需正确处理 PowerShell 转义）
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER 'kill -9 $(pgrep -f server) 2>/dev/null; mkdir -p /root/goremote/data; echo ready'
```

> **坑点**：PowerShell 双引号中 `$(...)` 会被展开为子表达式。必须用**单引号**包裹远程命令，或把命令存入变量再传给 plink。
> 
> **坑点**：`echo y \| plink ...` 管道方式不可用——plink 直接从控制台读取，不从 stdin。必须用 `-hostkey` 参数。
>
> **坑点**：如果旧数据目录曾启用状态加密，未提供原 `--state-key` 会报 `state encryption key is required`。生产升级必须带原 key；临时验证可使用独立 `--data /root/goremote/data-test`，避免误动旧状态。

### 3. 上传并启动服务端

```powershell
# 上传二进制
pscp -P 22 -pw "PASSWORD" "E:\AI-work\go-remote\harness\assets\bin\server-linux-amd64" root@YOUR_SERVER:/root/goremote/server

# 启动（零配置，无需任何 yaml）
plink -batch -pw "PASSWORD" root@YOUR_SERVER 'chmod +x /root/goremote/server; cd /root/goremote && nohup ./server --data /root/goremote/data --log-file /root/goremote/server.log --log-max-size-mb 50 --log-max-backups 5 > /dev/null 2>&1 < /dev/null & sleep 2; curl -s http://localhost:8080/health'
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

### 5a. 启动 Agent（Android 手机 via adb）

```powershell
# 0. 确认手机架构（当前仅 arm64 被测试验证）
adb shell getprop ro.product.cpu.abi

# 1. 交叉编译 arm64 Agent
$env:GOOS="android"; $env:GOARCH="arm64"
go build -ldflags "-s -w" -o build/agent-android-arm64 ./cmd/agent

# 2. 推送到手机
adb push build/agent-android-arm64 /data/local/tmp/agent
adb shell chmod +x /data/local/tmp/agent

# 3. 启动（--identity-dir 参数必须指定可写路径，因为 Android 的 HOME=/ 只读）
adb shell "nohup /data/local/tmp/agent --server YOUR_SERVER:8080 --identity-dir /data/local/tmp > /data/local/tmp/agent.log 2>&1 &"
```

预期日志输出：
```
"msg":"registering with new identity"
"msg":"waiting for admin approval","client_id":"client-ff155a09"
```

注意：adb shell 断开后 nohup 进程继续运行。再次连接后可查看日志。

### 5b. 启动 Agent（内网 Linux 服务器）

```bash
# 交叉编译 Linux amd64 后上传，启动
chmod +x ~/agent
rm -rf ~/.goremote  # 可选：清理旧身份进行全新注册
nohup ./agent --server YOUR_SERVER:8080 --log-file /opt/goremote/agent.log --log-max-size-mb 50 --log-max-backups 5 > /dev/null 2>&1 < /dev/null &
tail -5 agent.log
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

### 7. 将 127.0.0.1 加入全局白名单

```powershell
# 防止服务端本机 nc 测试被限流；高并发压测时还需加入压测来源公网 IP
$wl = Invoke-WebRequest -Uri "http://YOUR_SERVER:8080/api/security/global-whitelist" -Method PUT `
  -Body '{"ips":["127.0.0.1","YOUR_TEST_SOURCE_IP"]}' -ContentType "application/json" -WebSession $session -UseBasicParsing
$wl.Content
# → {"global_whitelist":["127.0.0.1","YOUR_TEST_SOURCE_IP"]}
```

### 8. 验证隧道

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
$hostkey = "ssh-ed25519 255 SHA256:服务器指纹"
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER 'echo test | timeout 3 nc -w 2 127.0.0.1 10000 2>&1'
```

预期输出：测试服务响应的数据（如 `HELLO FROM WINDOWS TEST SERVER`）。

### 8a. 验证高并发和长连接稳定性

```powershell
# 并发测试：从压测机通过公网隧道端口发起 30 个 SSH 命令，建议错峰 200ms
$count=30
$jobs = foreach($i in 1..$count) {
  Start-Sleep -Milliseconds 200
  Start-Job -ScriptBlock {
    param($i,$pw,$innerHostkey)
    $remote="echo SESSION_$i; hostname; for n in 1 2 3; do sha256sum /etc/hosts >/dev/null; done; echo DONE_$i"
    $out = & plink -batch -P TUNNEL_PORT -hostkey $innerHostkey -pw $pw user@YOUR_SERVER $remote 2>&1
    [pscustomobject]@{Id=$i; Code=$LASTEXITCODE; Text=($out -join ' | ')}
  } -ArgumentList $i,"PASSWORD",$innerHostkey
}
Wait-Job $jobs | Out-Null
$results=Receive-Job $jobs
Remove-Job $jobs
($results | Where-Object { $_.Code -eq 0 -and $_.Text -match 'DONE_' }).Count

# 数据传输测试（建议 50MB + SHA256；若耗时偏高，做公网直连/内网直连对照）
Get-FileHash -Algorithm SHA256 build/upload-50mb.bin
pscp -batch -P TUNNEL_PORT -hostkey $innerHostkey -pw "PASSWORD" build/upload-50mb.bin user@YOUR_SERVER:/tmp/upload-50mb.bin
plink -batch -P TUNNEL_PORT -hostkey $innerHostkey -pw "PASSWORD" user@YOUR_SERVER 'sha256sum /tmp/upload-50mb.bin'

# 长时间连接测试：检查 Agent 日志确认心跳正常
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER "grep -c 'client reconnected' /root/goremote/server.log"
# 预期：2-4 次以内（仅重启/断线场景），非持续增长
```

预期结果：
- 压测来源加入白名单后，30 并发 SSH 错峰 200ms 可达到 30/30
- 50MB 数据传输 SHA256 一致
- 服务端日志无持续连接断开重连记录

### 8b. 验证服务端重启后的设备恢复

```powershell
# 模拟服务端重启
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER 'fuser -k 8080/tcp 2>/dev/null; cd /root/goremote && nohup ./server --data /root/goremote/data --log-file /root/goremote/server.log --log-max-size-mb 50 --log-max-backups 5 > /dev/null 2>&1 < /dev/null & sleep 2'

# 检查 Agent 是否自动重连成功（已有 identity 应触发 reauth）
plink -batch -hostkey $hostkey -pw "PASSWORD" root@YOUR_SERVER 'grep -E "reconnect|register_ok" /root/goremote/server.log | tail -3'

# 注意：如果 server-state.json 丢失（如误删），所有设备消失，Agent 需重新审批
```

### 8c. 验证 key 轮换

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
| admin 登录 | `POST /api/login` | 返回 `status: ok` 并设置 HttpOnly `go_remote_token` Cookie |
| Agent 注册 | server.log | `waiting for admin approval` |
| 设备审批 | `POST /api/devices/pending/:id/approve` | `status: approved` |
| 加密激活 | agent.log | `tunnel data encryption enabled` |
| 隧道连通 | `nc <server> <port>` | 收到本地服务响应 |
| key 轮换 | `PUT /api/devices/:id/regen-key` | `status: key_regenerated` |
| 断线重连 | kill agent → 重启 | `client reconnected` |
| 状态持久化 | 检查 server-state.json | 设备、设置完整 |
| 高并发 SSH | 30 并发错峰 SSH 会话 | 压测源白名单后 30/30 成功 |
| 大数据传输 | 50MB 数据通过隧道加密传输 | SHA256 一致 |
| pending 长等待 | 临时 Agent pending 75s+ 后再查设备 | 同一 pending ID 不漂移 |
| 服务端重启恢复 | fuser 重启 server | Agent 自动 reauth 重连 |
| Android Agent | adb push + nohup 启动 | 注册审批后加密激活 |

## 失败回退

| 失败表现 | 可能原因 | 排查/恢复 |
|----------|---------|----------|
| Agent 报 `unauthorized` | 设备被管理员删除 | 清空 `~/.goremote/identity` 重新注册 |
| 隧道不通 | 本地端口未监听 | 确认本地服务运行，`ss -tlnp \| grep <port>` |
| 审批后 Agent 无反应 | enc_key 传输失败 | 重新启动 Agent（携带已有 identity 自动重连获取密钥） |
| Agent 不断注册新 pending ID | 未部署 pending 心跳修复；或未知旧 Agent 持续重连；或服务端状态被重置 | 部署新版 Agent/Server；清理或拉黑未知 pending 来源；必要时清空 Agent identity 后重新注册 |
| 高并发 SSH 大量关闭 | 压测来源触发 `max_conn_per_min=10` 防扫描限流 | 将压测来源 IP 加入全局白名单后复测 |
| agent.log 出现 `registration failed` | 服务端重启后旧设备消失 | 清空 `~/.goremote/identity` 重新注册，或在服务端重新审批 |
| agent.log 出现 `non-fatal message error, continuing` | 二进制隧道帧处理失败或外部连接已关闭 | 正常行为（端口扫描器的短连接），不影响 Agent 连接 |
| server-state.json 损坏 | 磁盘写异常 | 手工修复 JSON 或删除后重启（密钥和设备信息丢失） |
| 服务端启动报端口占用 | 旧进程未清理 | `fuser -k 8080/tcp` 再启动 |

## 注意事项

- **首次启动前必须清理旧状态**：旧版 `server-state.json` 的格式与新版不兼容，必须删除重新生成
- **Agent 身份文件**：`~/.goremote/identity` 包含设备私钥，丢失后需管理员删除旧设备后重新注册
- **端口扫描器**：公网服务器会持续收到扫端口的连接请求，会触发 `registration failed` 或限流日志——这是正常行为，不影响稳定运行；压测前应白名单压测源
- **密码安全性**：admin 密码首次启动后不再明文存储。如遗忘密码，删除 `server-state.json` 重新启动
