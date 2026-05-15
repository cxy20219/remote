# 多平台集成测试实战经验

> 最后更新：2026-05-15 | 关联流程：[零配置部署验证](../workflow/zero-config-deploy-verify.md)、[稳定性性能完整性综合验证](../workflow/stability-performance-completeness-verify.md) | 关联参考：[隧道设计](../references/tunnel-design.md)

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

### 修复

- Agent `handlePending()` 中启动与工作态一致的 heartbeat goroutine，pending 阶段每 30 秒发送 ping。
- 服务端 `pendingLoop` 使用运行时 `heartbeat_timeout`，默认 90 秒，收到 ping 后回复 pong。
- Agent 收到 `register_ok` 后立即发送一次 ping，唤醒服务端从 pending 状态切换到工作读循环。
- 同一设备公钥已有 pending 时复用原 pending 设备 ID，刷新 hostname/os/DH 公钥，避免超时或重连制造大量 pending 记录。

### 验证

2026-05-15 启动临时 Agent 后不审批，等待 80 秒，设备仍保持同一个 pending ID；日志只出现一次 `waiting for admin approval`，无 60 秒断线换 ID。

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

| 文件 | 行号 | 问题 | 发现/修复时间 | 说明 |
|------|------|------|------|------|
| `agent/agent.go` | 185 | 缺少 `setPendingApproval(true)` | v1 | 新 Agent 加密密钥不生效 |
| `agent/handler.go` | 182 | EOF 解密崩溃 | v1 | 每次连接关闭触发 |
| `server/handler.go` | 270 | EOF 解密崩溃 | v1 | 同上 |
| `server/client.go` | 85-87 | IP 白名单空桩 | v1 | 设备级白名单完全失效 |
| `server/tunnel.go` | 393-424 | localhost 被黑名单误杀 | v1 | 添加 `127.0.0.1/::1` 跳过检查 |
| `server/tunnel.go` | 448 | 外部连接无 ReadDeadline | v1 | 慢连接可耗尽 goroutine |
| `agent/agent.go` | 260-263 | handler 非致命错误断开整个连接 | 2026-05-14 | 单个 tunnel_data 解密失败丢失所有隧道 |
| `server/tunnel.go` | 454 | 外部连接 ReadDeadline 未刷新 | 2026-05-14 | SSH 长连接 15 分钟后被误断 |
| `server/tunnel.go` | 71-93 | AllocatePort TOCTOU 竞态 | 2026-05-14 | 端口测试后释放再绑定期间可被抢占 |
| `server/tunnel.go` | 598-608 | HandleAgentData 写操作无超时 | 2026-05-14 | 慢消费者导致无限阻塞 |
| `agent/tunnel.go` | 307 | readFromLocal 每次分配 32KB | 2026-05-14 | 高并发 GC 压力 |
| `server/tunnel.go` | 435 | connID 用 timestamp 碰撞风险 | 2026-05-14 | 改用 UUID |
| `agent/agent.go` | pending 循环 | pending 状态无心跳 | 2026-05-15 | 80 秒 pending 长等待不再换 ID |
| `server/device_mgr.go` | pendingConns | pending 连接替换清理竞态 | 2026-05-15 | 旧连接 cleanup 不会误删新连接 |
| `agent/agent.go` / `cmd/agent/main.go` | identity 保存 | `--identity-dir` 未贯穿审批/更新路径 | 2026-05-15 | Android/临时身份目录稳定 |
| `common/message.go` / `tunnel.go` | 隧道数据帧 | JSON+base64 数据帧开销高 | 2026-05-15 | 改 WebSocket Binary frame，保留 JSON 控制消息 |
| `server/handler.go` / `agent/connector.go` | reauth 元信息 | 重连不刷新 hostname/os | 2026-05-15 | Android 设备 OS 正确显示为 android |
| `agent/connector.go` / `server/handler.go` / `server/device_mgr.go` | reauth 降级注册 | reauth 失败转 pending 时未携带/刷新 `DeviceDHPubkey`，审批后无加密密钥 | 2026-05-15 | SSH 隧道不再因 `encryption key not found` 卡死 |

## 10. Agent 非致命 handler 错误不应断开整个连接

### 问题

`agent/agent.go` 的 `handleConnection` 中，任何 `handler.Handle` 返回的错误都会导致 Agent 关闭 WebSocket 连接并重新连接。这意味着：

- 一个 `tunnel_data` 解密失败（可能是传输中的短暂数据损坏）会导致所有隧道同时丢失
- Agent 重连 → 重建所有隧道 → 正在进行的 SSH 会话中断
- **服务端 `readLoop` 同样遇到 handler 错误只记录日志，不中断连接** — 行为不一致

### 修复

```go
// agent/agent.go handleConnection — 区分非致命错误
if err := a.handler.Handle(msg); err != nil {
    switch msg.Type {
    case "register_ok", "register_fail", "register_update", "device_deleted":
        // 注册/身份类错误 → 必须重新连接
        close(hbDone)
        return err
    default:
        // tunnel_data/tunnel_open 等运行时错误 → 只记录，不断开
        slog.Warn("non-fatal message error, continuing", ...)
    }
}
```

### 验证

Agent 日志出现 `"non-fatal message error, continuing"` 但 Agent 保持在线，其他隧道不受影响。

### 适用边界

- 注册/身份相关错误（`register_ok`/`register_fail` 等）仍然导致断开，这是正确的
- `tunnel_data` 的 `"external connection not found"` 错误是端口扫描器短连接的正常行为

## 11. handleExternalConn 读超时必须每次刷新

### 问题

`server/tunnel.go` 的 `handleExternalConn` 中，`extConn.SetReadDeadline(time.Now().Add(15 * time.Minute))` 仅在连接开始时设置一次。

SSH 连接空闲一段时间后重新发送数据时，总连接时间已超过 15 分钟 → **ReadDeadline 触发 → 连接断**。

### 修复

每次成功读取数据后刷新 deadline：

```go
for {
    n, err := extConn.Read(buf)
    if n > 0 {
        extConn.SetReadDeadline(time.Now().Add(15 * time.Minute))
    }
    // ...
}
```

### 触发条件

任何通过隧道建立的、单次空闲超过 15 分钟的 TCP 连接（SSH 会话、数据库连接池等）。

## 12. AllocatePort TOCTOU 竞态

### 问题

`AllocatePort` 先 bind 测试端口可用，`ln.Close()` 释放，然后 `startListener` 再绑定。在 `Close()` 和 `startListener` 之间的窗口内，另一个进程或线程可能占用该端口。

### 修复

`AllocatePort` 返回已绑定的 `net.Listener`，不再需要二次绑定。新增 `AcceptOnListener` 方法直接注册 listener 到 TunnelManager。

### 影响函数

- `AllocatePort` — 签名从 `(int, error)` 改为 `(int, net.Listener, error)`
- `handleTunnelOpen`（handler.go） — 调用方同步变更
- `handleAPICreateTunnel`（api.go） — 同上
- `UpdateTunnel` — 端口变更时直接创建 listener 而不是调用 startListener

## 13. Agent pending 状态 60 秒超时困境（已修复）

### 问题

Agent 进入 pending 状态后 `handlePending()` **不主动发送心跳**。服务端 `pendingLoop` 设置 60 秒读超时，超时后关闭连接。

Agent 重连 → 生成新的 `client_id` → 再次 pending → 等待审批。如果管理员审批超过 60 秒，Agent 永远无法进入工作状态。

### 表现

```
Agent 日志不断交替：
  "waiting for admin approval" (client_id=A)
  → 60秒后 "connection error: websocket: close 1006"
  → "reconnecting with existing identity"
  → "waiting for admin approval" (client_id=B ← 新ID)
  → 重复
```

### 修复措施

- Agent pending 阶段主动发送心跳，服务端 pendingLoop 响应 pong。
- pendingLoop 不再硬编码 60 秒，使用服务端 `heartbeat_timeout`，默认 90 秒。
- 审批后 Agent 主动发送一次 ping，服务端在 pendingLoop 中检测授权状态后切换到 `readLoop`。
- `RegisterNewClient` 发现同一设备公钥已有 pending 时复用原设备 ID，避免重复 pending。
- `RemovePendingConnIfMatch` 和 `DetachPendingConnIfMatch` 区分“关闭旧连接”和“仅从 pending 表摘除”，防止旧连接 defer 误删新连接。

### 验证

2026-05-15 通过临时身份目录启动 Agent，等待 80 秒后仍保持同一个 pending ID，无 60 秒断线换 ID。停止临时 Agent 后删除 pending，设备列表恢复为两个授权在线设备。

## 14. 服务器重启导致 Agent 身份漂移

### 问题

服务端 `server-state.json` 被删除或损坏重启后，所有设备记录消失。Agent 以旧 identity 重连：

1. Agent 发送 reauth（含 ed25519 签名、timestamp）
2. 服务端收到 `client_id` 不存在 → `register_fail`
3. Agent 清除 identity 的 `ClientID` 和 `EncKey`
4. Agent 以新身份注册 → 获得新 `client_id` → pending
5. 需要管理员再次审批

若审批速度慢（通常在手动模式下），Agent 不断进入 §13 的 60 秒超时循环。

### 表现

```
Agent 日志:
  "reconnecting with existing identity" (client_id=OLD)
  "registration failed" → 清除身份
  "registering with new identity"
  "waiting for admin approval" (client_id=NEW)
  60秒后... 循环
```

### 应对

- 清空 `/root/goremote/data/server-state.json` 重启服务端后，必须在 Agent 端同时清除 identity 文件
- 生产环境应使用 `--data` 持久化目录，避免误删

## 15. 高并发 SSH 吞吐测试结果

### 测试环境

| 参数 | 值 |
|------|-----|
| 公网服务器 | `YOUR_SERVER`（本轮为 2核4G Linux） |
| 内网服务器 | `YOUR_INTERNAL_HOST`（本轮为 2核2G Linux） |
| 隧道协议 | TCP 端口映射 |
| 目标服务 | SSH (端口 22) |

### 并发会话测试

| 并发数 | 成功 | 失败原因 |
|--------|------|----------|
| 10 并发 SSH | 10/10 | — |
| 20 并发 SSH（未白名单压测源） | 8/20 | 触发 `max_conn_per_min=10` 防扫描限流 |
| 20 并发 SSH（白名单压测源） | 19/20 | 1 个 SSH 握手/公网入口瞬时关闭 |
| 30 并发 SSH（白名单压测源，200ms 错峰） | 30/30 | — |

SSH 认证方式：密码认证。Windows 压测机使用 `plink -batch -P <tunnel_port>`，每个作业执行 `hostname` 和多次 `sha256sum /etc/hosts`。

### 数据传输测试

```
# 50MB 上传/下载 → SHA256 验证
Get-FileHash -Algorithm SHA256 build/upload-50mb.bin
pscp -batch -P TUNNEL_PORT -hostkey $innerHostkey -pw "PASSWORD" build/upload-50mb.bin user@YOUR_SERVER:/tmp/upload-50mb.bin
plink -batch -P TUNNEL_PORT -hostkey $innerHostkey -pw "PASSWORD" user@YOUR_SERVER 'sha256sum /tmp/upload-50mb.bin'
```

### 结论

- 默认端口防扫描限流会影响高并发压测，压测源白名单后再判断隧道稳定性。
- 30 并发错峰 200ms 可 30/30 成功，隧道层在 SSH 命令并发下稳定。
- 50MB 上传/下载 SHA256 一致，无数据损坏。
- 吞吐慢时必须做公网直连和内网直连对照；本轮下载瓶颈主要在公网服务端出方向链路。

## 16. 2026-05-15 稳定性、性能、完整性优化复盘

### 背景

目标是验证 GoRemote 在公网端口映射 SSH、Android adb/nohup 部署、短连接高并发和大文件传输下是否稳定。测试覆盖公网 Linux 服务端、内网 Linux Agent、Android arm64 Agent、本地 Windows 压测机。

### 稳定性结论

- pending 审批链路已从“60 秒内必须审批”演进为“pending 阶段心跳保活 + 同公钥 pending 复用 + 审批后不断线进入工作态”。
- WebSocket 写入、外部 TCP 写入、本地服务写入均增加 deadline，避免慢消费者长期卡住 goroutine。
- pending 连接替换时主动关闭旧连接，但旧连接的 cleanup 不会删除新连接。
- 隧道连接正常 EOF、broken pipe、已关闭连接等场景降为 Debug 或非致命处理，避免端口扫描器噪音诱发重连。

### 性能结论

- 隧道数据从 JSON+base64 改为 WebSocket Binary frame，控制消息仍走 JSON；AES-GCM 直接传 nonce+ciphertext 字节。
- buffer 和 WebSocket 读写缓冲统一为 128KB，减少帧数和分配压力。
- 50MB 上传从 JSON 版约 176 秒降到二进制帧版约 133 秒，SHA256 一致。
- 50MB 下载约 129 秒；公网服务端直连下载到本地约 0.38MB/s，说明主要瓶颈是公网服务端出方向链路，不应继续盲目归因到隧道协议。
- 内网直连 50MB 上传/下载约 5-7 秒，说明内网 SSH 服务和本地网络不是瓶颈。

### 完整性结论

| 验证项 | 结果 | 判断 |
|--------|------|------|
| `go test ./...` | 通过 | 单元和集成测试基本面正常 |
| `go vet ./internal/...` | 通过 | 静态检查正常 |
| `go test -race ./internal/...` | 未执行成功 | Windows 本机缺 gcc/cgo，属于环境限制 |
| SSH 基础连通 | 成功 | 公网端口到内网 22 贯通 |
| SSH 30 并发 200ms 错峰 | 30/30 | 隧道层稳定 |
| Android echo 50 并发 | 50/50 | Android Agent 和短连接稳定 |
| pending 80 秒长等待 | 同 ID 保持 pending | pending 心跳修复有效 |
| 50MB 上传/下载 | SHA256 一致 | 大数据完整性通过 |

### 可复用判断

- 压测前必须把压测来源 IP 加入全局白名单。否则默认 `max_conn_per_min=10` 的防扫描限流会正确拒绝连接，表现为 SSH 大量 `Remote side unexpectedly closed network connection`。
- 完全同时发起 20/30 SSH 连接时，少量失败可能来自 SSHD `MaxStartups`、公网入口瞬时超时或压测机网络，不应仅凭单轮失败判定隧道不稳定。错峰 100-200ms 更适合衡量隧道承载能力。
- 大文件吞吐必须做三组对照：隧道传输、公网服务端直连、内网服务直连。只有三者对比后，才能判断瓶颈在隧道协议、公网链路还是 SSH 服务。
- Android 场景必须使用 `--identity-dir /data/local/tmp/...`，并确认 reauth 后设备 OS/hostname 被服务端刷新。
- reauth 失败被服务端降级为新 pending 时，Agent 必须在 reauth payload 中携带 `DeviceDHPubkey`；服务端 reauth 成功时也要刷新保存的 DH 公钥，否则审批后可能出现设备在线但隧道数据 `decrypt failed: encryption key not found`。

### 应升级为固定流程

已沉淀为 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md)。以后涉及隧道协议、pending、WebSocket、设备身份、Android Agent、端口限流的改动，均应执行该流程的核心检查。
