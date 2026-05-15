# 稳定性、性能、完整性综合验证流程

> 最近验证：2026-05-15 | 适用场景：隧道核心改动后回归、生产部署前压测、SSH/Android 映射稳定性验收

## 适用场景

- 修改 `internal/server/tunnel.go`、`internal/agent/tunnel.go`、WebSocket 连接、设备注册、pending 审批、密钥轮换后，需要做端到端回归。
- 业务会通过公网映射端口执行大量 SSH 命令、文件传输、Android adb/nohup 场景，需要确认服务稳定、安全、可恢复。
- 不适用：只改 UI 文案或纯静态资源；这类变更优先跑 `go test ./...` 和相关前端检查。

## 前置条件

| 条件 | 要求 |
|------|------|
| 公网服务端 | Linux amd64，服务端 8080 和隧道端口段可访问 |
| 内网 Linux Agent | 可访问本机 SSH 22 端口，已启动 GoRemote Agent |
| Android Agent | adb 可连接，`/data/local/tmp` 可写，已部署 Agent 和 echo 测试服务 |
| 本地开发机 | Windows + Go + plink/pscp + adb |
| 安全 | 文档和脚本只使用占位符，不写入真实密码、公网 IP、hostkey |

## 关联资源

- [零配置部署验证流程](zero-config-deploy-verify.md)：从零部署和审批的基础路径
- [SSH 隧道直通内网服务流程](ssh-tunnel-direct-access.md)：SSH 映射创建和基础排查
- [多平台集成测试实战经验](../experience/multi-platform-testing.md)：本流程背后的判断经验和失败归因
- [零配置测试与调试经验](../experience/zero-config-testing-lessons.md)：PowerShell、pending、认证 Cookie、日志映射
- [隧道设计文档](../references/tunnel-design.md)：隧道协议、二进制数据帧、端口防扫描

## 执行步骤

### 1. 本地质量门禁

```powershell
gofmt -w <changed-go-files>
go test ./...
go vet ./internal/...
```

`go test -race ./internal/...` 需要本机有 gcc/cgo 环境。Windows 未安装 gcc 时会报 `C compiler "gcc" not found`，此时记录为环境限制，不要误判为代码失败。

### 2. 交叉编译三端

```powershell
New-Item -ItemType Directory -Force -Path build | Out-Null
$env:CGO_ENABLED='0'

$env:GOOS='linux'; $env:GOARCH='amd64'
go build -trimpath -ldflags='-s -w' -o build/server-linux-amd64 ./cmd/server
go build -trimpath -ldflags='-s -w' -o build/agent-linux-amd64 ./cmd/agent

$env:GOOS='android'; $env:GOARCH='arm64'
go build -trimpath -ldflags='-s -w' -o build/agent-android-arm64 ./cmd/agent
```

生成物放在 `build/`，不要放入 `harness/assets/`；assets 只保存模板和静态资源。

### 3. 滚动部署并确认重连

上传时先使用 `.new` 文件名，远端停止旧进程后再 `mv -f` 替换，避免 Linux 上二进制仍被占用或半覆盖：

```powershell
pscp -batch -P 22 -hostkey $SERVER_HOSTKEY -pw "PASSWORD" build/server-linux-amd64 root@YOUR_SERVER:/root/goremote/server.new

plink -batch -hostkey $SERVER_HOSTKEY -pw "PASSWORD" root@YOUR_SERVER '
cd /root/goremote
chmod +x server.new
pidof server > /tmp/goremote_server_pids 2>/dev/null || true
if [ -s /tmp/goremote_server_pids ]; then kill $(cat /tmp/goremote_server_pids) || true; sleep 1; fi
if [ -f server ]; then cp server server.prev.$(date +%Y%m%d%H%M%S); fi
mv -f server.new server
nohup ./server --data /root/goremote/data > server.log 2>&1 < /dev/null &
sleep 2
curl -s http://127.0.0.1:8080/health
'
```

Linux Agent 和 Android Agent 同样使用 `.new` 替换。Android 必须指定可写身份目录：

```powershell
adb push build/agent-android-arm64 /data/local/tmp/goremote-agent.new
adb shell 'cd /data/local/tmp; chmod 755 goremote-agent.new; pidof goremote-agent > /data/local/tmp/goremote-agent.pids 2>/dev/null || true; if [ -s /data/local/tmp/goremote-agent.pids ]; then kill $(cat /data/local/tmp/goremote-agent.pids) || true; sleep 1; fi; mv -f goremote-agent.new goremote-agent; nohup ./goremote-agent --server YOUR_SERVER:8080 --identity-dir /data/local/tmp/goremote-android-id > /data/local/tmp/goremote-agent.log 2>&1 < /dev/null &'
```

### 4. 清理状态并重建隧道

登录 API 后检查设备和隧道：

```powershell
$body = @{password='ADMIN_PASSWORD'} | ConvertTo-Json
Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/login' -Method POST -Body $body -ContentType 'application/json' -SessionVariable session -UseBasicParsing | Out-Null

(Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/devices' -WebSession $session -UseBasicParsing).Content
(Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/tunnels' -WebSession $session -UseBasicParsing).Content
```

预期只保留目标授权设备在线。未知来源持续生成 pending 时，先确认是否属于本次测试机器；确认无关后加入黑名单并删除 pending，避免污染验收：

```powershell
$black = @{ip='UNKNOWN_IP'; reason='unknown stale pending agent during stability test'} | ConvertTo-Json
Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/security/blacklist' -Method POST -Body $black -ContentType 'application/json' -WebSession $session -UseBasicParsing
```

创建两个核心隧道：

| 隧道 | 目标 |
|------|------|
| SSH | `Linux Agent 127.0.0.1:22` |
| Android echo | `Android Agent 127.0.0.1:12345` |

### 5. 配置压测白名单

公网隧道端口有防扫描限流，默认 `max_conn_per_min=10`。压测来源必须加入全局白名单，否则 20/30 并发会被正确拒绝，不能当成隧道不稳定：

```powershell
$wl = @{ips=@('127.0.0.1','YOUR_TEST_SOURCE_IP')} | ConvertTo-Json
Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/security/global-whitelist' -Method PUT -Body $wl -ContentType 'application/json' -WebSession $session -UseBasicParsing
```

### 6. SSH 并发验证

基础命令：

```powershell
plink -batch -P SSH_TUNNEL_PORT -hostkey $INNER_HOSTKEY -pw "PASSWORD" user@YOUR_SERVER 'hostname; whoami; echo SSH_OK'
```

30 并发建议错峰 200ms，避免把 SSH 握手尖峰和隧道吞吐混在一起：

```powershell
$count=30
$jobs = foreach($i in 1..$count) {
  Start-Sleep -Milliseconds 200
  Start-Job -ScriptBlock {
    param($i,$pw,$hostkey)
    $remote="echo JOB_$i; hostname; for n in 1 2 3; do sha256sum /etc/hosts >/dev/null; done; echo DONE_$i"
    $out = & plink -batch -P SSH_TUNNEL_PORT -hostkey $hostkey -pw $pw user@YOUR_SERVER $remote 2>&1
    [pscustomobject]@{Id=$i; Code=$LASTEXITCODE; Text=($out -join ' | ')}
  } -ArgumentList $i,"PASSWORD",$INNER_HOSTKEY
}
Wait-Job $jobs | Out-Null
$results=Receive-Job $jobs
Remove-Job $jobs
($results | Where-Object { $_.Code -eq 0 -and $_.Text -match 'DONE_' }).Count
```

最近验证结果：30 并发、200ms 错峰，30/30 成功。完全同时发起时少量 `Connection timed out` 更可能是公网入口或 SSH 握手尖峰，不直接归因于隧道层。

### 7. Android echo 并发验证

```powershell
$count=50
$jobs = foreach($i in 1..$count) {
  Start-Job -ScriptBlock {
    param($i)
    $client=[System.Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout=10000
    $client.SendTimeout=10000
    $client.Connect('YOUR_SERVER',ANDROID_TUNNEL_PORT)
    $stream=$client.GetStream()
    $text="ANDROID_JOB_$i`n"
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $stream.Write($bytes,0,$bytes.Length)
    $buf=New-Object byte[] 512
    $n=$stream.Read($buf,0,$buf.Length)
    $resp=[Text.Encoding]::UTF8.GetString($buf,0,$n)
    $client.Close()
    $resp -match "ANDROID-ECHO:ANDROID_JOB_$i"
  } -ArgumentList $i
}
Wait-Job $jobs | Out-Null
($jobs | Receive-Job | Where-Object { $_ }).Count
Remove-Job $jobs
```

最近验证结果：50/50 成功。

### 8. 大文件完整性与瓶颈定位

先生成本地 50MB 随机文件并记录 SHA256：

```powershell
$path='build/upload-50mb.bin'
$rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
$buffer=New-Object byte[] (1024*1024)
$fs=[System.IO.File]::Open($path,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write)
try { for($i=0; $i -lt 50; $i++){ $rng.GetBytes($buffer); $fs.Write($buffer,0,$buffer.Length) } } finally { $fs.Close(); $rng.Dispose() }
Get-FileHash -Algorithm SHA256 $path
```

通过隧道上传/下载后，分别在两端用 SHA256 比对。若吞吐偏低，必须做两个对照：

- 本机 ↔ 公网服务端直连 pscp，判断公网出/入方向带宽。
- 本机 ↔ 内网 SSH 直连 pscp，判断内网 SSH 服务和本地网络上限。

最近验证结论：

| 测试 | 结果 |
|------|------|
| 隧道 50MB 下载 | SHA256 一致，约 129s |
| 隧道 50MB 上传 | SHA256 一致，约 133s |
| 公网服务端直连下载到本机 | 约 0.38MB/s，说明下载瓶颈主要在公网出方向链路 |
| 内网直连上传/下载 | 约 5-7s，内网 SSH 本身不是瓶颈 |

### 9. pending 长等待验证

启动临时 Agent，不审批，等待超过 60 秒：

```powershell
# 启动临时身份目录的 Agent，等待 75 秒后再次查询 /api/devices
# 预期：同一设备 ID 仍 pending，不应不断换 ID
```

最近验证结果：80 秒内本次临时 Agent 保持同一个 pending ID，无 60 秒断线换 ID。

### 10. 收尾检查

```powershell
go test ./...
go vet ./internal/...

(Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/devices' -WebSession $session -UseBasicParsing).Content
(Invoke-WebRequest -Uri 'http://YOUR_SERVER:8080/api/tunnels' -WebSession $session -UseBasicParsing).Content
```

预期：

- 只有目标授权设备在线；无无关 pending。
- SSH 和 Android echo 隧道均 active。
- 服务端日志无 panic、持续 reconnect、持续 rate limited。
- `server.log` 不应快速膨胀；磁盘空间保持充足。

## 失败回退

| 失败表现 | 优先判断 | 回退动作 |
|----------|----------|----------|
| 20/30 并发大量 `Remote side unexpectedly closed` | 测试源未加白名单或 `max_conn_per_min=10` 触发 | 加入全局白名单后复测 |
| 少量 SSH `Connection timed out` | 公网入口/SSHD 握手尖峰 | 200ms 错峰复测；必要时调整 SSHD `MaxStartups` |
| 大文件下载慢但哈希一致 | 公网服务端出方向带宽不足 | 做公网直连下载对照，不先改隧道代码 |
| pending ID 持续变化 | Agent pending 心跳失效或旧 Agent 重连 | 查 Agent 日志；确认 `handlePending` 心跳；清理未知旧 pending |
| SSH 冒烟卡死且 Agent 日志出现 `encryption key not found` | reauth 失败降级注册时缺 `DeviceDHPubkey`，审批后未拿到 enc_key | 确认 Agent reauth payload 携带 DH 公钥，服务端 reauth 刷新 DH 公钥；必要时删除坏授权设备后重新注册审批 |
| Android 注册后 OS 显示错误 | reauth 未刷新 hostname/os | 确认 Agent reauth payload 携带元信息，服务端更新设备状态 |
| 二进制替换失败 | 旧进程仍占用或命令被 PowerShell 本地展开 | 使用 `.new` + 单引号远程命令 + `pidof` 精准停进程 |

## 常见误区

- 不要把公网端口限流触发误判为隧道不稳定；压测前必须白名单压测源。
- 不要只看 pscp 的秒数判断协议瓶颈；必须做公网直连和内网直连对照。
- 不要把 generated binaries 放进 `harness/assets/`；临时产物放 `build/`，验证后清理。
- 不要在文档中保存真实公网 IP、账号、密码、hostkey；只写占位符和复用方法。
