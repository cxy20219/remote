# 多平台集成测试实战经验

> 最后更新：2026-05-14 | 关联流程：[零配置部署验证](../workflow/zero-config-deploy-verify.md) | 关联参考：[隧道设计](../references/tunnel-design.md)

## 适用场景

在本轮四端（公网 Linux 服务端、内网 Linux Agent、Windows 本机 Agent、Android 手机 Agent）全流程测试中，以下经验可复用于 SSH 隧道场景的质量保障。

## 1. Agent pendingApproval 标志缺失

### 问题

`internal/agent/agent.go` 中 `connect()` 收到 `register_pending` 后未调用 `a.setPendingApproval(true)`。导致：

- Agent 进入主消息循环而非 `handlePending()` 循环
- 管理员的 `register_ok` 到达时被主 handler 处理，**不调用 `processRegisterOK`**，加密密钥未设置
- 隧道数据被 agent 加密后，服务端无法解密（日志：`encryption key not found for client`）

### 修复

`agent.go:185` 的 `register_pending` case 中添加 `a.setPendingApproval(true)`

`handler.go:53` 的 `handleRegisterOK` 中添加 `h.agent.processRegisterOK(&payload)`（兜底保护）

### 适用边界

- **仅影响新 Agent 首次注册场景**。已有 identity 的 Agent 在重连时直接从 identity 文件加载 enc_key（`NewAgent` 构造函数中），不触发此路径
- Windows / Android 新 Agent 首次注册必然触发，**必须修复**

## 2. EOF 包解密崩溃导致隧道中断

### 问题

服务端发送 EOF 时 `tunnel_data` 的 `Data` 字段为空字符串（`""`）。Agent 的 `handleTunnelData` 调用 `cryptoMgr.Decrypt(clientID, "")`：

```go
base64.StdEncoding.DecodeString("")  // → []byte{}（空切片）
len([]byte{}) < nonceSize(12)        // → "ciphertext too short"
```

解密失败 → handler 返回 error → `handleConnection` 关闭连接 → Agent 断线重连 → 正在进行的 SSH 会话中断。

### 修复

`agent/handler.go` 和 `server/handler.go` 的 `handleTunnelData`：当 `IsEOF==true && Data==""` 时跳过解密，直接关闭连接。

### 触发条件

每次隧道外部连接正常关闭都会触发。**不是罕见边界，而是每次连接的必经路径**。

## 3. Agent pending 状态无心跳导致超时断开

### 问题

Agent 收到 `register_pending` 后进入等待审批状态。`handlePending()` 只从 WebSocket 读取消息，**不主动发送 ping**。服务端的 `pendingLoop` 设置 60 秒读超时，超时后关闭连接。

Agent 重连后获得新的 `client_id`，再次 pending，循环往复。如果管理员审批不及时（超过 60 秒），Agent 永远无法进入工作状态。

### 表现

```
Agent 日志: "waiting for admin approval" → 60秒后 "connection error: websocket: close 1006" → 重连 → 再次 pending
```

### 缓解

- 审批需在 Agent 首次 pending 连接存活期内完成（60 秒内）
- 审批后若 Agent 已断开，需手动重启 Agent（使用已有 identity 重连会直接 reauth，跳过 pending）

## 4. 127.0.0.1 被黑名单误伤

### 问题

公网服务器的扫描器持续连接 WebSocket 端口，触发 `connLimiter` 限流。`portLimiter` 对 127.0.0.1 也生效，导致从服务端自身通过 `nc 127.0.0.1 TUNNEL_PORT` 测试隧道时被拒绝。

### 修复

`tunnel.go:acceptLoop` 中 localhost（`127.0.0.1`、`::1`）直接跳过所有黑名单/限流检查。

### 排查方法

服务端日志出现大量 `ws connection from blacklisted IP rejected ip=127.0.0.1` 时，确认是此问题。

## 5. IP 白名单空桩（`getDeviceStateForClient` 始终返回 nil）

### 问题

`internal/server/client.go:85-87` 的 `getDeviceStateForClient` 是空桩，永远返回 nil。导致：
- `IsIPWhitelisted()` 永远返回 false
- `GetIPWhitelist()` 永远返回空切片
- 设备级 IP 白名单完全失效

### 修复

添加 `DeviceQuerier` 接口 + `SetStore()` 方法，从 `stateStore.GetDeviceByID` 查询真正的设备状态。

## 6. plink 主机密钥缓存（PuTTY 工具链）

### 问题

Windows 的 plink/pscp 在 `-batch` 模式下遇到未缓存的 SSH 主机密钥会直接失败。`echo y | plink ...` 管道方式因 plink 直接从控制台读取而非 stdin 而无效。

### 正确做法

```powershell
# 首次连接：指定 -hostkey 参数（指纹来自服务器提示）
$key = "ssh-ed25519 255 SHA256:服务器指纹"
plink -batch -hostkey $key -pw "PASSWORD" user@host 'command'

# 后续所有命令都携带此参数
# 注意：pscp 也支持同样的 -hostkey 语法
pscp -P 22 -hostkey $key -pw "PASSWORD" local.file user@host:/remote/path
```

### 将 127.0.0.1 加入全局白名单（API）

防止本地 `nc` 隧道测试被限流：

```powershell
$login = Invoke-WebRequest -Uri "http://SERVER:8080/api/login" -Method POST `
  -Body '{"password":"PASSWORD"}' -ContentType "application/json" -SessionVariable s -UseBasicParsing

Invoke-WebRequest -Uri "http://SERVER:8080/api/security/global-whitelist" -Method PUT `
  -Body '{"ips":["127.0.0.1"]}' -ContentType "application/json" -WebSession $s -UseBasicParsing
```

## 7. Android Agent 部署要点

```powershell
# 0. 确认架构
adb shell getprop ro.product.cpu.abi  # → arm64-v8a

# 1. 推送二进制
adb push agent-linux-arm64 /data/local/tmp/goremote-agent

# 2. 设置 HOME（默认 / 只读，必须指定可写路径）
adb shell "HOME=/data/local/tmp nohup /data/local/tmp/goremote-agent --server IP:8080 > /data/local/tmp/agent.log 2>&1 &"

# 3. 支持 --identity-dir 参数（v2+）
adb shell "nohup /data/local/tmp/goremote-agent --server IP:8080 --identity-dir /data/local/tmp > /data/local/tmp/agent.log 2>&1 &"
```

### 注意

- Android shell 中 `os.UserHomeDir()` 返回 `/`（只读），必须 `HOME=/data/local/tmp` 或 `--identity-dir`
- adb shell 断开后 nohup 进程继续运行
- Android 默认无 `nc`/`busybox`，测试隧道需自行编译 echo server

## 8. 隧道验证脚本（跨平台 SSH 场景）

### 简明验证流程

```powershell
# 1. 启动本地 echo 服务
# Windows:
$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 22223); $l.Start()
# Linux:
#    python3 -c "import socket;s=socket.socket();s.setsockopt(1,2,1);s.bind(('127.0.0.1',22223));s.listen(5)"

# 2. 创建隧道
Invoke-WebRequest -Uri "http://SERVER:8080/api/tunnels" -Method POST `
  -Body '{"client_id":"CLIENT_ID","local_addr":"127.0.0.1","local_port":22223,"protocol":"tcp"}' `
  -ContentType "application/json" -WebSession $session -UseBasicParsing

# 3. 从服务端测试
echo "test-data" | timeout 5 nc -w 3 127.0.0.1 TUNNEL_PORT
# 预期输出: ECHO:test-data （echo server 的响应）
```

## 9. 已修正的代码问题列表

| 文件 | 行号 | 问题 | 说明 |
|------|------|------|------|
| `agent/agent.go` | 185 | 缺少 `setPendingApproval(true)` | 新 Agent 加密密钥不生效 |
| `agent/handler.go` | 182 | EOF 解密崩溃 | 每次连接关闭触发 |
| `server/handler.go` | 270 | EOF 解密崩溃 | 同上 |
| `server/client.go` | 85-87 | IP 白名单空桩 | 设备级白名单完全失效 |
| `server/tunnel.go` | 393-424 | localhost 被黑名单误杀 | 添加 `127.0.0.1/::1` 跳过检查 |
| `server/tunnel.go` | 448 | 外部连接无 ReadDeadline | 慢连接可耗尽 goroutine |
