# 稳定性、性能、完整性综合验证流程

> 最近验证：2026-05-16 | 适用场景：隧道核心改动后回归、生产部署前压测、SSH/Android 映射稳定性验收

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
nohup ./server --data /root/goremote/data --log-file /root/goremote/server.log --log-max-size-mb 50 --log-max-backups 5 > /dev/null 2>&1 < /dev/null &
sleep 2
curl -s http://127.0.0.1:8080/health
'
```

Linux Agent 和 Android Agent 同样使用 `.new` 替换。Android 必须指定可写身份目录：

```powershell
adb push build/agent-android-arm64 /data/local/tmp/goremote-agent.new
adb shell 'cd /data/local/tmp; chmod 755 goremote-agent.new; pidof goremote-agent > /data/local/tmp/goremote-agent.pids 2>/dev/null || true; if [ -s /data/local/tmp/goremote-agent.pids ]; then kill $(cat /data/local/tmp/goremote-agent.pids) || true; sleep 1; fi; mv -f goremote-agent.new goremote-agent; nohup ./goremote-agent --server YOUR_SERVER:8080 --identity-dir /data/local/tmp/goremote-android-id --log-file /data/local/tmp/goremote-agent.log --log-max-size-mb 20 --log-max-backups 3 > /dev/null 2>&1 < /dev/null &'
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
| Android ADB | `Android Agent 127.0.0.1:5555`，仅在手机已启用 adb tcpip 或本机 5555 可用时创建 |

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

如需使用 Windows OpenSSH 而不是 plink，密码认证不能直接把密码写到命令行。使用临时 `SSH_ASKPASS` helper 从环境变量读取密码，helper 文件内不保存密码：

```powershell
$askpass = Join-Path $env:TEMP ('goremote-askpass-' + [guid]::NewGuid() + '.cmd')
Set-Content -LiteralPath $askpass -Value @('@echo off','echo %SSHPASS_VALUE%') -Encoding ASCII
$env:SSH_ASKPASS=$askpass
$env:SSH_ASKPASS_REQUIRE='force'
$env:DISPLAY='1'
$env:SSHPASS_VALUE='PASSWORD'
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 `
  -o StrictHostKeyChecking=accept-new -p SSH_TUNNEL_PORT user@YOUR_SERVER `
  'hostname; whoami; echo SSH_OK'
Remove-Item -LiteralPath $askpass -Force
Remove-Item Env:\SSHPASS_VALUE,Env:\SSH_ASKPASS,Env:\SSH_ASKPASS_REQUIRE,Env:\DISPLAY -ErrorAction SilentlyContinue
```

注意：PowerShell `Start-Job` 的错误对象可能把脚本行序列化进输出，压测脚本不要把真实密码直接写在 ScriptBlock 里；应通过环境变量/临时 askpass 传入，并只汇总 exit code、耗时和首行错误。

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

最近验证结果：

- plink：30 并发、200ms 错峰，30/30 成功。
- OpenSSH：公网客户端经公网隧道端口发起 30 并发时出现少量 TCP `Connection timed out`；公网服务器本机对 `127.0.0.1:SSH_TUNNEL_PORT` 发起同等 30 并发为 30/30 成功，说明应优先把少量 timeout 归因到公网入口链路或连接尖峰，再判断隧道内部。

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

#### Android ADB 5555 长连接验证

当业务会通过公网端口远程操作手机 adb 时，必须额外创建 `Android Agent 127.0.0.1:5555` 隧道，并让测试命令明确指定公网映射 serial，避免误走 USB 设备：

```powershell
adb disconnect YOUR_SERVER:ADB_TUNNEL_PORT
adb connect YOUR_SERVER:ADB_TUNNEL_PORT
adb devices

$serial='YOUR_SERVER:ADB_TUNNEL_PORT'
$ok=0; $fail=0
for($i=1; $i -le 150; $i++) {
  $out = & adb -s $serial shell "echo ADB_LOOP_$i; getprop ro.product.model; date" 2>&1
  if ($LASTEXITCODE -eq 0 -and (($out -join "`n") -match "ADB_LOOP_$i")) { $ok++ } else { $fail++ }
  Start-Sleep -Seconds 1
}
[pscustomobject]@{Ok=$ok; Fail=$fail}
```

随后再做一轮大输出，确认不是只有短命令稳定：

```powershell
adb -s YOUR_SERVER:ADB_TUNNEL_PORT exec-out "yes ADB_STRESS_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 | head -c 5242880" > build/adb-stress.txt
adb -s YOUR_SERVER:ADB_TUNNEL_PORT shell "echo ADB_AFTER_STRESS; date"
```

验证标准：

- 循环时长必须超过服务端 `heartbeat_timeout`，默认至少 90 秒。
- `adb devices` 中公网映射 serial 保持 `device`，不是 `offline`。
- `/api/clients` 中 Android Agent 的 `last_ping` 或最近活动时间持续刷新。
- `/api/tunnels` 中 ADB 5555 隧道保持 `active`。
- 服务端日志无新的 `client heartbeat timeout`、`client disconnected`、`decrypt failed`、`encryption key not found`。
- 若需要读取 Android Agent 日志，可临时使用 USB 只做日志观察；远程 adb 操作必须始终指定公网映射 serial。

最近验证结果：远程 ADB 5555 映射在 150 次循环 shell、约 204 秒持续操作后 150/150 成功；随后 5MB 级大输出成功；Android Agent 与 ADB 隧道保持在线，服务端日志无新的 heartbeat timeout 或异常断线。

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
- 使用 OpenSSH 时用 `scp -P SSH_TUNNEL_PORT` 走同一隧道；同样必须记录上传、下载耗时和三端 SHA256。
- OpenSSH `scp` 大文件传输时不要默认叠加过短的 `ServerAliveInterval/ServerAliveCountMax`。高吞吐低带宽链路上 keepalive 可能被数据流拥塞误伤，表现为 `server not responding` 和 `Broken pipe`；去掉 keepalive 后再复测，若仍失败再归因到隧道层。

最近验证结论：

| 测试 | 结果 |
|------|------|
| 隧道 50MB 下载 | SHA256 一致，约 129s |
| 隧道 50MB 上传 | SHA256 一致，约 133s |
| OpenSSH scp 50MB 上传/下载 | SHA256 一致，上传约 132s，下载约 131s |
| 最新破兼容硬化代码三端部署后 OpenSSH scp 50MB | SHA256 一致，上传约 130s，下载约 129s；带过短 keepalive 的首次上传在约 42MB 处误断，去掉 keepalive 后通过 |
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
- SSH、Android echo 以及本轮需要的 Android ADB 5555 隧道均 active。
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
| 远程 ADB 一段时间后 `offline` 且隧道全没 | 服务端只按 ping 刷新活动时间，ADB 二进制隧道流量未计入存活，触发心跳误判 | 确认服务端 `readLoop` 对所有合法消息刷新活动时间；重建 ADB 5555 隧道后跑超过 `heartbeat_timeout` 的远程 adb 循环 |
| 二进制替换失败 | 旧进程仍占用或命令被 PowerShell 本地展开 | 使用 `.new` + 单引号远程命令 + `pidof` 精准停进程 |

## 常见误区

- 不要把公网端口限流触发误判为隧道不稳定；压测前必须白名单压测源。
- 不要只看 pscp 的秒数判断协议瓶颈；必须做公网直连和内网直连对照。
- 不要把 generated binaries 放进 `harness/assets/`；临时产物放 `build/`，验证后清理。
- 不要在文档中保存真实公网 IP、账号、密码、hostkey；只写占位符和复用方法。
