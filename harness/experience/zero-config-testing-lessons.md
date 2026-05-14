# 零配置架构测试与调试经验

> 最后更新：2026-05-14 | 关联流程：[零配置部署验证](../workflow/zero-config-deploy-verify.md) | 关联参考：[零配置设计](../references/zero-config-design.md)

## 1. PowerShell 远程命令转义

### 问题

PowerShell 5.1 双引号字符串中 `$(...)` 会被作为子表达式展开，导致 plink 传递到远程服务器的命令被破坏。

### 表现形式

```powershell
# ❌ 错误：PowerShell 先执行 $(pgrep -f server) 再传结果给 plink
plink -batch -pw "PWD" root@IP "kill -9 $(pgrep -f server)"
# → 实际发送: kill -9   (空，因为本地没有 pgrep)
```

### 正确做法

```powershell
# ✅ 方案A：单引号（推荐）
plink -batch -pw "PWD" root@IP 'kill -9 $(pgrep -f server) 2>/dev/null; echo ready'

# ✅ 方案B：存入变量再传
$cmd = 'kill -9 $(pgrep -f server) 2>/dev/null; echo ready'
plink -batch -pw "PWD" root@IP $cmd

# ✅ 方案C：反引号转义 $（双引号场景）
plink -batch -pw "PWD" root@IP "kill -9 `$(pgrep -f server) 2>/dev/null; echo ready"
```

### 不适用场景

- 不需要传递特殊字符的简单命令（如 `hostname`、`df -h /root`）可直接用双引号
- `Invoke-WebRequest` 不存在此问题（body 字符串不走 plink）

## 2. Agent 后台启动（Windows）

### 问题

`Start-Process` 不能同时指定 `-NoNewWindow` 和 `-RedirectStandardOutput`/`-RedirectStandardError`，违反 PowerShell 设计限制。

### 正确做法

```powershell
# ✅ 简单场景：隐藏窗口启动（适合生产）
Start-Process -FilePath ".\agent.exe" -ArgumentList "--server YOUR_SERVER:8080" -WindowStyle Hidden

# ✅ 调试场景：使用 PowerShell Job（输出可捕获）
Start-Job -Name "agent" -ScriptBlock { & 'C:\path\to\agent.exe' --server YOUR_SERVER:8080 }
Receive-Job -Name "agent"          # 查看输出
Stop-Job -Name "agent"; Remove-Job -Name "agent"
```

## 3. `fuser -k` 会杀死 SSH 会话本身

### 问题

`fuser -k 8080/tcp` 会杀死占用 8080 端口的所有进程。如果 SSH 会话本身是通过某个端口连接的（与 8080 无关则安全），但更常见的问题是与 `$(pgrep ...)` 配合时的整体命令超时。

### 经验

- 如果 `fuser -k 8080/tcp` 后 plink 立即返回 exit code 128 或无输出，说明 fuser 杀死了关键进程（极罕见，通常不影响 SSH）
- 更靠谱的方式：先 `kill -9 $(pgrep -f server)` 再启动，不要依赖 `fuser`
- `fuser` 本身是排查端口占用的好工具，但用于停服不如 `kill` 精准

## 4. test 服务选择

### 问题

测试隧道时需要一个本地监听的服务来验证数据贯通。Windows 默认不开启 SSH Server，Python 可能不可用。

### 做法

```powershell
# PowerShell TCP listener（无需安装任何东西）
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 22222)
$listener.Start()
# 每次连接返回一行文本
# 注意：此监听器仅用于验证贯通，不支持 HTTP
```

隧道创建后，在服务端用 `nc` 验证：
```bash
echo test | timeout 3 nc -w 2 127.0.0.1 10000
```

## 5. Web UI 认证 Cookie

### 问题

测试 API 时需要登录获取 cookie。`Invoke-WebRequest` 默认不保存 cookie，需要 `-SessionVariable`。

### 做法

```powershell
$login = Invoke-WebRequest -Uri "http://server:8080/api/login" -Method POST `
  -Body '{"password":"xxx"}' -ContentType "application/json" -SessionVariable "session" -UseBasicParsing

# 后续请求携带 session
$resp = Invoke-WebRequest -Uri "http://server:8080/api/devices" -WebSession $session -UseBasicParsing
```

## 6. Pending 连接的生命周期

### 行为

Agent 注册后进入 pending 状态，连接保持存活等待审批。如果审批前 Agent 断开（如进程被杀），需要重新连接并重新进入 pending。

### 代码逻辑

- `handleConn` → 新注册 → `send register_pending` → 进入 `pendingLoop`（只响应 ping + 轮询设备状态）
- 管理员审批 → API handler 通过 `pendingConns[deviceID].Conn` 直接发送 `register_ok`
- Agent 收到 `register_ok` → 解密 enc_key → 保存 identity → 进入工作状态
- `pendingLoop` 的 read goroutine 检测到 `device.Status == "authorized"` → 停止 pending goroutine → 启动 `readLoop`

### 注意

pending 连接的服务端读超时为 60 秒。Agent 在 pending 状态下**不主动发送心跳**（`handlePending` 只读取消息），因此若审批未在 60 秒内完成，服务端读超时断开连接，Agent 重连后获得新的 `client_id`，需重新审批。

**影响**：审批操作必须在 Agent 首次连接后 60 秒内完成。超时后即使管理员审批，原连接已断开，`register_ok` 发送到已关闭的 WebSocket。Agent 每次重连都生成新的 pending 记录。

## 7. ECDH 密钥交换的完整链路追踪

当审批或 key 轮换时，enc_key 经过以下链路：

```
服务端:
  1. 生成 32 字节随机 enc_key
  2. 生成临时 x25519 密钥对（server_eph_priv, server_eph_pub）
  3. 用 Agent 的 x25519 公钥 + server_eph_priv 计算共享密钥
  4. HKDF-SHA256(salt="goremote-enc-key-exchange-v1") 派生 AES 密钥
  5. AES-256-GCM 加密 enc_key
  6. 发送: enc_key_encrypted + server_eph_pub

Agent:
  1. 收到 server_eph_pub + enc_key_encrypted
  2. 用本地 x25519 私钥 + server_eph_pub 计算共享密钥（与服务器相同）
  3. HKDF-SHA256 派生相同 AES 密钥
  4. AES-256-GCM 解密 enc_key
  5. 存入 identity 文件 + 注入 CryptoManager
```

## 8. 日志字段映射

| 日志 | 含义 | 关联操作 |
|------|------|----------|
| `new device pending approval` | 新设备注册，等待审批 | Agent 执行 `RegisterNew` |
| `client reconnected` | Agent 用 ed25519 签名重连成功 | Agent 执行 `RegisterReauth` |
| `tunnel data encryption enabled` | Agent 收到并解密了 enc_key | 审批或 key 轮换后 |
| `external connection accepted` | 公网用户连接到隧道端口 | 隧道创建后外部访问 |
| `tunnel error from agent: failed to connect to local service` | Agent 无法连接本地内网端口 | 本地服务未启动 |
| `registration failed` | 连接尝试注册但失败 | 扫描器/旧 Agent/无关连接 |
