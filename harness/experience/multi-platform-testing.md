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
- 隧道读写 chunk 提升到 256KB，WebSocket 缓冲保持 128KB，减少大文件传输帧数和加密调用次数。
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

## 17. 2026-05-15 第二轮极限稳定性与安全优化

### 背景

在二进制隧道和三端压测通过后，继续从“默认安全边界、运行时设置生效、坏链路隔离、协议完整性”复查代码。目标不是兼容旧行为，而是降低公网复杂 SSH/短连接场景下的尾部风险。

### 可复用判断

- Gin 默认代理信任会让 `ClientIP()` 受 `X-Forwarded-For` 影响；公网直连部署必须默认 `SetTrustedProxies(nil)`，否则登录限流、WS 限流、黑名单可能被伪造请求头绕过。若未来需要反代，应显式增加可信代理配置，而不是恢复“信任所有代理”。
- `max_conn_per_min`、`login_rate_limit` 等运行时设置修改后必须同步刷新内存限流器；只写入 `server-state.json` 会造成 UI 显示已保存但实际仍按旧阈值执行。
- Agent 连接本地服务时不要持有 `TunnelManager` 写锁做 `DialTimeout`。本地端口异常或防火墙阻断时，10 秒拨号会拖住其他连接、关闭和 cleanup。
- EOF 控制帧不需要再做 AES-GCM 空明文加密。发送空 data + `is_eof=true` 可减少关闭路径的一次随机数读取、加密和解密，同时服务端/Agent 已有兼容处理。
- 隧道二进制帧的 flags 应拒绝未知 bit。协议扩展必须显式升级版本或定义新 flag，不能静默接受未来/畸形帧。
- HTTP 请求体默认应有限制。当前默认 `max_body_size_mb=10`；运行时可改，`0` 表示禁用限制，但生产不建议长期关闭。

### 验证

- 新增/补充测试覆盖：限流器 `0=禁用`、限流器运行时更新、动态请求体限制、隧道目标参数校验、二进制帧未知 flags 拒绝。
- 已通过 `go test ./...`、`go vet ./internal/...`、`go build ./...`。

### 关联流程

- 代码改动后仍按 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md) 做三端回归。
- 配置和安全边界说明见 [配置参考](../references/config-reference.md) 与 [Harness 开发指南](../Harness.md)。

## 18. 2026-05-16 第三轮管理面与密钥完整性优化

### 背景

继续追求极致安全和稳定时，除了隧道吞吐，还要检查管理面写接口、会话生命周期、后台 goroutine 和密钥材料边界。公网部署中，管理 Cookie、Origin/Referer、黑名单阈值持久化和 DH 公钥格式都属于容易被忽略但长期风险较高的区域。

### 可复用判断

- 管理 API 使用 Cookie 认证后，`SameSite=Strict` 不是唯一防线。已认证的 POST/PUT/DELETE 需要额外校验浏览器 `Origin`/`Referer`；CLI/PowerShell/curl 通常不带这些头，应继续放行，避免破坏运维脚本。
- 管理员 session 不能无限增长。token 保持 256-bit 随机值，同时应设置 TTL 和最大会话数；当前为 24 小时过期、最多 64 个会话，新登录会清理过期会话并淘汰最旧会话。
- `blacklist_threshold` 单独 API 更新必须同时写入 `server-state.json`，否则 UI 显示和运行时生效但重启后回退。
- RateLimiter、BlacklistManager、HeartbeatChecker 这类后台 ticker 应在 `Server.Stop()` 时退出；否则测试或嵌入式反复创建服务时会积累后台 goroutine。
- 设备 `DeviceDHPubkey` 必须严格校验为 32 字节 hex。只解 hex 不校验长度会导致短值被拷贝进 `[32]byte` 并隐式补零，破坏 ECDH 安全边界。
- reauth 准备 `register_ok` 前应先确认服务端保存的 `enc_key` 和 DH 公钥都有效；如果密钥材料损坏，不应先把连接加入在线表。

### 验证

- 新增/补充测试覆盖：管理员 session 清理和上限、浏览器跨站写请求拒绝、黑名单阈值持久化、RateLimiter/BlacklistManager Stop 幂等、无效 DH 公钥拒绝、损坏 DH 公钥下 reauth 不进入在线表。
- 已通过 `go test ./...`、`go vet ./internal/...`、`go build ./...`、`git diff --check`。

### 关联流程

- 管理 API、安全中间件、设备身份、密钥轮换相关改动，代码验证后仍需按 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md) 做三端真实部署回归。

## 19. 2026-05-16 第四轮破兼容安全与性能收紧

### 背景

继续按“可以不兼容旧行为”的标准审查管理面和请求路径。重点是清除对可伪造代理头的隐式信任、收紧 JSON API 契约，并减少热路径对持久状态锁的依赖。

### 可复用判断

- 在默认 `SetTrustedProxies(nil)` 的公网直连模型下，不应再用 `X-Forwarded-Proto` 判断请求是否 HTTPS。Cookie `Secure` 和管理写请求同源判断只信任真实 TLS；如果未来要支持反向代理，应增加显式可信代理配置，而不是默认信任头。
- 管理写接口应使用严格 JSON 解码：要求 `Content-Type: application/json`，拒绝未知字段和尾随多个 JSON 文档。这样能尽早暴露错误调用方，降低配置漂移和“字段写了但服务端忽略”的隐患。
- `io.ReadAll` + `json.Unmarshal` 会一次性读完整 body，也默认接受未知字段。写接口改用 streaming decoder 后，继续由动态 body limit 控制上限，但减少不必要的大对象分配。
- `max_body_size_mb` 是热路径配置；每个请求都读 `StateStore` 会产生锁和拷贝。当前改为原子字节数缓存，运行时设置更新时刷新，普通请求只读 atomic。

### 验证

- 新增/补充测试覆盖：严格 JSON Content-Type、未知字段、多 JSON 文档拒绝，以及伪造 `X-Forwarded-Proto` 不影响同源判断。
- 已通过 `go test ./...`、`go vet ./internal/...`、`go build ./...`。

## 20. 2026-05-16 第五轮传输层与协议面破兼容硬化

### 背景

继续按“极致安全、极致稳定”的标准审查公网暴露面。重点从管理 API 下沉到传输层和协议入口：HTTP Server 超时、TLS 协议版本、WebSocket 控制消息、二进制帧长度解析。

### 可复用判断

- HTTP Server 不能依赖 Go 默认零值超时。公网入口应显式设置 `ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout`、`IdleTimeout` 和较小的 `MaxHeaderBytes`，降低慢请求、超大请求头和异常客户端拖住连接的风险。
- 如果目标是破兼容安全基线，TLS 应明确要求 TLS 1.3。Agent 的 `insecure_skip_verify` 只表示跳过证书身份验证，不应降低 TLS 版本下限。
- WebSocket TextMessage 属于控制面，不应继续使用宽松 `json.Unmarshal`。先严格解码 `common.Message`，再按具体 payload 严格解码，可拒绝未知字段和尾随多个 JSON 文档，避免协议漂移。
- 二进制隧道帧解析长度时应分段扣减剩余字节，而不是只做一次总长度相加判断。这样对畸形长度更稳，也避免不同架构上的整数边界隐患。

### 验证

- 新增/补充测试覆盖：HTTP Server 硬化默认值、TLS 1.3 下限、严格 JSON helper、二进制帧畸形长度拒绝。
- 已通过定向测试：`go test ./internal/common`、`go test ./internal/agent -run "TestBuildTLSConfig|TestConnectorConnectTLS"`、`go test ./internal/server -run "TestNewHTTPServerHardeningDefaults|TestServerTLS|TestBuildOriginChecker"`。

### 关联流程

- 传输层、WebSocket 协议、隧道二进制帧相关改动，仍需按 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md) 做真实三端回归。

## 21. 2026-05-16 OpenSSH 多端实测经验

### 背景

在已有 GoRemote Server、Linux Agent 和 Android Agent 在线的环境中，按用户要求改用系统 OpenSSH 客户端做多端验证。目标是确认公网直连 SSH、经公网隧道访问内网 SSH、OpenSSH scp 大文件完整性、Android echo 隧道，以及测试完成后的服务健康状态。

### 可复用判断

- Windows OpenSSH 没有 `sshpass` 参数。非交互密码认证可用临时 `SSH_ASKPASS` helper，从环境变量读取密码；helper 文件只包含 `echo %SSHPASS_VALUE%`，测试后立即删除。`Set-Content` 必须写成多行数组，不能用单引号字符串里的反引号伪造换行，否则 askpass 会输出空密码。
- PowerShell `Start-Job` 捕获 native command 错误时，错误对象可能带出完整脚本行。压测脚本不要把真实密码写死在 ScriptBlock 里；输出应只汇总 `Id/Code/Ms/Done/FirstLine` 等脱敏字段。
- 公网客户端经映射端口发起 30 路 OpenSSH 并发时，少量 `connect timed out` 可能发生在 TCP 连接阶段，服务端日志没有 rate limit、decrypt、panic 等对应错误时，应先按公网入口链路或连接尖峰归因。
- 为拆分公网入口和隧道内部能力，可在公网服务器本机用 OpenSSH 连接 `127.0.0.1:SSH_TUNNEL_PORT`。本轮同等 30 并发在该路径 30/30 成功，说明 Server→Agent→内网 SSH 链路稳定。
- Android 端通常不是 SSH 服务，不能强行归入 OpenSSH 测试；应使用 TCP echo 隧道和 adb 只读检查进程/日志，作为多端链路验证的一部分。

### 本轮结果摘要

| 项目 | 结果 |
|------|------|
| 公网服务器 OpenSSH 直连 | 成功 |
| 本机 → 公网隧道端口 → 内网 SSH，30 并发 200ms 错峰 | 29/30 成功，1 个 TCP connect timeout |
| 本机 → 公网隧道端口 → 内网 SSH，30 并发 500ms 错峰 | 28/30 成功，2 个 TCP connect timeout |
| 公网服务器本机 → `127.0.0.1:SSH_TUNNEL_PORT` → 内网 SSH，30 并发 200ms 错峰 | 30/30 成功，平均约 597ms |
| OpenSSH scp 50MB 上传 | 成功，约 132s，SHA256 一致 |
| OpenSSH scp 50MB 下载 | 成功，约 131s，SHA256 一致 |
| Android echo 隧道 50 并发 | 50/50 成功 |
| 收尾健康检查 | `/health` 正常；SSH/Android 隧道监听仍在；最近日志未见 panic、rate limited、decrypt failed、encryption key not found |

### 适用边界

- 本轮测试使用的是已部署远端二进制，并未重新滚动部署当前工作区未提交的破兼容硬化代码。
- 对公网客户端高并发 SSH 的结论要和白名单状态、云厂商安全组、入口链路质量一起看。若必须证明公网入口 30/30，需要在同一压测源稳定白名单生效后，多轮错峰复测并采集服务端 `ss`、日志和云监控。

### 关联流程

- 固化到 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md) 的 SSH 并发与大文件完整性章节。

## 22. 2026-05-16 最新破兼容硬化代码三端部署回归

### 背景

将本地最新破兼容硬化代码重新交叉编译并部署到公网 Server、内网 Linux Agent、Android Agent。部署后重新创建 SSH 和 Android echo 隧道，并按稳定性、性能、完整性流程做完整回归。

### 可复用做法

- 内网 Linux Agent 依赖当前 GoRemote SSH 隧道访问时，应先上传 `agent.new`，再在远端调度一个 `nohup` 自替换脚本。脚本先备份旧二进制、`mv -f agent.new agent`，再杀旧进程并启动新进程；不要在同一个前台 SSH 会话里杀 Agent 后再继续执行后续命令，否则隧道断开会中断部署。
- Android `adb shell` 启动后台 Agent 时，若命令超时，不要立即重复替换；先用 `pidof goremote-agent`、`ls -l` 和日志确认。常见情况是进程已启动，只是 shell 没完全脱离。
- 公网 Server 重启后运行时隧道会消失，应等待两个授权 Agent 重新在线，再用管理 API 重建 SSH/Android 隧道。不要误以为设备在线就代表旧隧道仍可用。
- 部署后用本地构建产物 SHA256 对比三端线上二进制。公网 Server 和 Linux Agent 可用 `sha256sum`，Android 可用 `adb shell sha256sum`。
- 生产安全基线应确认 `max_body_size_mb` 不是历史测试遗留的 `0`。本轮部署后恢复为 `10`，压测源白名单只临时添加，测试结束后撤回。
- OpenSSH `scp` 大文件传输不要叠加过短 keepalive。本轮首次上传带 `ServerAliveInterval=5`、`ServerAliveCountMax=2`，约 42MB 后被 OpenSSH 判定 `server not responding` 并断开；去掉 keepalive 后同一文件上传/下载均通过且 SHA256 一致。

### 本轮结果摘要

| 项目 | 结果 |
|------|------|
| 本地门禁 | `go test ./...`、`go vet ./internal/...`、`go build ./...` 通过 |
| 三端部署 | Server、Linux Agent、Android Agent 线上 SHA256 均与本地构建产物一致 |
| Agent 在线 | Linux 与 Android 两台授权设备均 online |
| 隧道重建 | SSH 隧道映射内网 `127.0.0.1:22`，Android echo 隧道映射 `127.0.0.1:12345`，均 active |
| OpenSSH 基础连通 | 公网 SSH、隧道 SSH、Android echo 均成功 |
| OpenSSH 30 并发（本机经公网入口） | 30/30 成功，平均约 996ms |
| OpenSSH 30 并发（公网服务器本机到 `127.0.0.1:SSH_TUNNEL_PORT`） | 30/30 成功，平均约 562ms |
| OpenSSH scp 50MB 上传/下载 | 去掉过短 keepalive 后成功，SHA256 一致；上传约 130s，下载约 129s |
| Android echo 50 并发 | 50/50 成功 |
| pending 长等待 | 临时 Agent 80 秒后仍保持同一个 pending ID，清理后 pending 为 0 |
| 收尾健康 | `/health` 正常；两个隧道 active；最近日志未见 panic、rate limited、decrypt failed、encryption key not found |

### 适用边界

- 这些结果说明最新硬化代码在本轮三端环境下通过完整回归；公网大文件吞吐仍受链路带宽影响，不应仅凭 50MB 耗时判断隧道协议瓶颈。
- 若下一轮调整 HTTP Server 超时、WebSocket 读写、隧道 chunk 或 SSH keepalive 策略，必须重复 OpenSSH scp 大文件与 30 并发组合测试。

### 关联流程

- 主流程见 [稳定性、性能、完整性综合验证流程](../workflow/stability-performance-completeness-verify.md)。
