# 零配置部署设计方案（纯新架构）

> **状态：已实现** (2026-05-14) | 对应代码分支/提交见 git log | 实现过程中对原始方案有若干优化，详见 §13

## 1. 设计目标

| 目标 | 说明 |
|------|------|
| Agent 零配置 | `./agent <server_url>` 唯一命令行，无配置文件、无密钥、无环境变量 |
| 服务端零配置启动 | `./server` 即可启动，管理员密码由首次初始化向导设置（不再自动生成/打印） |
| 全量管理 Web 化 | 注册审批、加密开关、端口范围、限流参数全部在 Web UI 操作 |
| 纯新架构 | 不兼容旧 `auth.key` 模式，不携带历史包袱 |

## 2. 一句话用户体验

```
服务端:   ./server                           → 打印一次性初始化令牌 + 管理 URL
管理员:   打开 setup.html（loopback 或令牌） → 设置密码，可选扫码启用 TOTP
Agent:    ./agent YOUR_SERVER:8080          → 等待管理员批准
管理员:   浏览器打开管理 URL → 看到待处理列表 → 点击"批准"
Agent:    自动进入工作状态 → 可在 Web UI 创建隧道、管理配置
```

## 3. 整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                        Server                                      │
│                                                                      │
│  ┌──────────────────┐         ┌──────────────────────────┐          │
│  │  待处理(pending)  │         │  已授权(authorized)       │          │
│  │  ┌────────────┐  │ approve │  ┌────────────────────┐  │          │
│  │  │ 10.0.0.1   │──┼─────────┼─→│ my-server          │  │          │
│  │  │ 192.168.1.5│  │         │  │  ├ 🔒 加密已启用     │  │          │
│  │  └────────────┘  │         │  │  ├ 白名单:10.0.0/8  │  │          │
│  │  [批准][拒绝]     │  delete  │  │  ├ 隧道: t1, t2    │  │          │
│  └──────────────────┘  ────────│  └────────────────────┘  │          │
│                                │  [重命名] [加密开关] [🗑]  │          │
│                                └──────────────────────────┘          │
│                                                                      │
│  持久化层 (server-state.json)                                        │
│  ├─ server ed25519 密钥对                                            │
│  ├─ admin bcrypt 密码哈希                                            │
│  ├─ 全局设置 (端口范围/限流/...)...                                    │
│  └─ devices: [{id, pubkey, hostname, enc_key, enc_enabled, ...}]     │
└──────────────────────────────────────────────────────────────────┘
         ▲ WebSocket                              │
         │ register(device_pubkey)                │ register(challenge_signature)
         │                                        │
┌────────┴──────────────────┐  ┌──────────────────┘
│  首次运行 Agent             │  │  重连 Agent
│  ./agent <server_url>      │  │  (自动读取本地 identity)
│                            │  │
│  1. 生成 ed25519 密钥对     │  │  1. 读取 ~/.goremote/identity
│  2. 存入 ~/.goremote/      │  │  2. 用私钥签名 challenge
│  3. 发送 pubkey → 等待审批  │  │  3. 发送 → 服务端验证通过
│  4. 收到 enc_key + config  │  │  4. 进入工作状态
│  5. 进入工作状态            │  │
└────────────────────────────┘  └────────────────────────────────────┘
```

## 4. 数据结构

### 4.1 服务端持久化 `server-state.json`

```json
{
  "server_privkey": "ed25519_privkey_hex",
  "server_pubkey": "ed25519_pubkey_hex",
  "admin_password_hash": "bcrypt_hash",
  "settings": {
    "port_range_start": 10000,
    "port_range_end": 20000,
    "max_conn_per_min": 10,
    "login_rate_limit": 5,
    "blacklist_threshold": 100,
    "global_whitelist": ["10.0.0.0/8"]
  },
  "devices": [
    {
      "id": "client-uuid",
      "name": "my-server",              // 管理员可重命名的别名
      "device_pubkey": "agent_ed25519_pubkey",
      "device_dh_pubkey": "agent_x25519_pubkey_hex",
      "hostname": "my-server",
      "os": "linux",
      "status": "authorized",            // pending | authorized
      "enc_key": "AES-256-GCM_key_hex",  // 32 字节 hex，空=加密未启用
      "first_seen": "2026-05-14T10:00:00Z",
      "approved_at": "2026-05-14T10:05:00Z"
    }
  ],
  "pending_challenge": {
    "client_id": "challenge_str",
    "expires_at": "..."   
  }
}
```

### 4.2 Agent 本地身份 `~/.goremote/identity`

```json
{
  "server_url": "YOUR_SERVER:8080",
  "device_privkey": "ed25519_privkey_hex",
  "device_pubkey": "ed25519_pubkey_hex",
  "client_id": "client-uuid",
  "enc_key": "AES-256-GCM_key_hex"
}
```

这个文件是 Agent 的唯一"身份"，丢失后设备失去授权，需重新注册。

## 5. Agent 生命周期

### 5.1 首次运行

```
用户: ./agent YOUR_SERVER:8080

Agent 内部:
  1. 检查 ~/.goremote/identity
     → 不存在: 生成 ed25519 密钥对，创建目录，写入 identity（不含 client_id 和 enc_key）
     → 存在:   跳转到 5.2（重连）

  2. 连接 ws://YOUR_SERVER:8080/ws
  3. 发送:
     {
       "type": "register",
       "device_pubkey": "<hex>",
       "hostname": "my-server",
       "os": "linux"
     }
  4. 服务端回复:
     {
       "type": "register_pending",
       "message": "等待管理员批准",
       "client_id": "client-123"     // 预分配，后续 approve 使用同一 ID
     }
  5. Agent 将 client_id 写入 identity，保持 WebSocket 心跳

  6. 管理员在 Web UI 点击"批准":
     {
       "type": "register_ok",
       "enc_key": "<AES-256-GCM key>",     // 空表示加密未启用
       "enc_enabled": true
     }

  7. Agent 收到后:
     - 将 enc_key 写入 identity
     - 进入正常隧道/心跳/数据转发工作状态
```

### 5.2 重连（已有身份）

```
  1. 读取 identity → 拿到 client_id + device_privkey
  2. 连接服务端 → 发送:
     {
       "type": "register",
       "reauth": true,
       "client_id": "client-123",
       "device_pubkey": "<pubkey_hex>",
       "signature": "<用 device_privkey 签名的 challenge>"
     }
  3. 服务端:
     - 查找 client_id
     - 用存储的 device_pubkey 验证 signature
     - 通过 → 直接进入工作状态
     - 失败 → register_pending（需重新审批）
```

### 5.3 被删除后重连

```
管理员删除已授权客户端 → 服务端从 authorized 移除记录

Agent 下次重连:
  → 发送 reauth 签名
  → 服务端找不到 client_id（或标记为 deleted）
  → 回复 register_pending（进入待处理列表）
  → Agent 更新本地 identity（清空 enc_key）
  → 等待重新审批
```

## 6. 服务端 WebSocket 消息协议

### 6.1 消息类型

| Type | 方向 | 说明 |
|------|------|------|
| `register` | C→S | 首次注册或重连认证（携带 device_pubkey 或 signature） |
| `register_pending` | S→C | 已进入待处理列表，等待管理员批准 |
| `register_ok` | S→C | 审批通过，下发加密密钥 |
| `register_denied` | S→C | 管理员拒绝注册 |
| `register_update` | S→C | 管理员修改配置（加密开关变更等），通知 Agent 更新本地配置 |
| `ping` / `pong` | C↔S | 心跳 |
| `tunnel_open` | S→C | 服务端下发隧道目标 |
| `tunnel_close` | S→C | 服务端关闭/重建隧道 |
| `tunnel_data_bin` | C↔S | 隧道数据（WebSocket Binary frame） |
| `tunnel_error` | C→S | Agent 报告本地拨号/写失败 |

### 6.2 register 消息详

```json
// 首次注册
{
  "type": "register",
  "device_pubkey": "ed25519_pubkey_hex",
  "hostname": "my-server",
  "os": "linux"
}

// 重连认证
{
  "type": "register",
  "reauth": true,
  "client_id": "client-123",
  "device_pubkey": "ed25519_pubkey_hex",
  "signature": "hex_signed_challenge"
}
```

## 7. 审批与配置 API

全部在 Web UI 操作，API 需 admin 认证。

| Method | Path | 说明 |
|--------|------|------|
| GET | `/api/devices/pending` | 待处理客户端列表 |
| POST | `/api/devices/pending/:id/approve` | 批准注册 |
| POST | `/api/devices/pending/:id/deny` | 拒绝注册 |
| GET | `/api/devices` | 已授权客户端列表 |
| DELETE | `/api/devices/:id` | 删除客户端（回到 pending 池） |
| PUT | `/api/devices/:id/config` | 更新客户端配置（加密、白名单、别名等） |
| PUT | `/api/devices/:id/regen-key` | 重新生成加密密钥 |

## 8. Web UI 布局

```
┌─────────────────────────────────────────────────────────┐
│  GoRemote v2                                    admin │ 退出 │
├─────────────────────────────────────────────────────────┤
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                    │
│  │ 正常  │ │ 在线 5│ │ 隧道 3│ │端口9990│               │
│  └──────┘ └──────┘ └──────┘ └──────┘                    │
├─────────────────────────────────────────────────────────┤
│  ⚙ 服务端设置                                           │
│  ├─ 监听: 0.0.0.0:8080                                  │
│  ├─ 端口范围: 10000 - 20000                             │
│  ├─ 限流: 登录 5/min | 连接 10/min                      │
│  ├─ 全局白名单: 10.0.0.0/8, 192.168.1.0/24             │
│  └─ 黑名单阈值: 100                                     │
│  [编辑设置]                                              │
├─────────────────────────────────────────────────────────┤
│  ⚠ 待处理客户端 (2)                     [全部刷新]       │
│  ┌──────────────────────────────────────────────────┐   │
│  │ IP          │ 主机名    │ 系统  │ 连接时间 │ 操作   │   │
│  │─────────────│───────────│───────│─────────│───────│   │
│  │ 10.0.0.1    │ my-server │ linux │ 10:00:15│ [批准]│   │
│  │ 192.168.1.5 │ nas       │ linux │ 10:01:20│ [批准]│   │
│  └──────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  ✅ 已授权客户端 (3)                                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 别名      │ 主机名   │ 系统 │🔒│ 白名单  │ 操作   │   │
│  │──────────│──────────│──────│──│────────│───────│   │
│  │ my-server│ my-server│ linux│🔒│10.0/8  │ [⚙] [🗑]│   │
│  │ nas      │ nas      │ linux│🔓│ —      │ [⚙] [🗑]│   │
│  │ win-pc   │ DESKTOP  │ win  │🔒│ —      │ [⚙] [🗑]│   │
│  └──────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  🔗 隧道列表 (5)                                        │
│  ... (同现有隧道管理卡片)                                 │
├─────────────────────────────────────────────────────────┤
│  安全设置 (同现有安全管理卡片)                             │
└─────────────────────────────────────────────────────────┘
```

## 9. 关键机制设计

### 9.1 每设备独立加密密钥

```go
// crypto.go 改造：从全局派生密钥改为按 client_id 查表
type CryptoManager struct {
    mu   sync.RWMutex
    keys map[string][]byte  // client_id → 32-byte AES key
}

// 服务端加密隧道数据时
key := cm.GetKey(clientID)
if key == nil {
    // 该客户端加密未启用，不加密（向后兼容不支持？不需要！
    // 这里意味着：不加密 = 明文传输隧道数据
    // 但新的系统应该强制加密或者让配置明确
}

// 实际上更优：加密默认为开启，管理员可手动关闭
// 这样新系统默认就是安全状态
```

**密钥生命周期**：
- 批准时服务端生成 32 字节随机 AES-256 密钥
- 随 register_ok 消息下发
- Agent 存入 identity 文件
- 服务端存入 state.json
- 管理员在 Web UI 可「重新生成密钥」→ 发生成 + 下发新密钥

### 9.2 服务端 ed25519 身份

- 服务端首次运行生成 ed25519 密钥对
- Agent 首次连接时记录 server_pubkey
- 后续连接验证 server 签名，防止中间人攻击
- 等同于 SSH `known_hosts` 机制

### 9.3 Challenge-Response 认证（防重放）

```
服务端 → Agent: {type:"auth_challenge", challenge:"random_hex"}
Agent → 服务端: {type:"register", reauth:true,
                  client_id:"...", device_pubkey:"...",
                  signature:"ed25519_sign(challenge)"}
服务端: 验证签名 ✅ → 通过
```

challenge 有效期 60 秒，过期需重新获取。

### 9.4 持久化安全

`server-state.json` 包含加密密钥，必须保护：
- 默认保存到 `--data` 目录（默认 `./data`），权限建议 `700`
- 生产环境建议放到加密文件系统或仅 root 可读
- 定期备份

## 10. 拒绝和删除语义

| 操作 | 对服务端 | 对 Agent |
|------|---------|---------|
| 拒绝注册 | 删除 pending 记录 | 断开 WebSocket |
| 批准注册 | 标记 authorized，生成密钥 | 收到 register_ok → 进入工作状态 |
| 删除已授权 | 从 authorized 移除（保留到 deleted 历史） | 断开连接 |
| 重新注册 | Agent 再次连接 → 进入 pending | 清理本地 enc_key |

## 11. 文件变更清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/server/persist.go` | **新增** | state.json 读写，RWMutex 保护 |
| `internal/server/identity.go` | **新增** | ed25519 key 生成/签名/验证 |
| `internal/server/crypto_mgr.go` | **新增** | 每设备加密密钥管理 |
| `internal/server/handler.go` | 重写 | register 处理改为审批制 |
| `internal/server/client.go` | 重写 | ClientManager 支持 pending/authorized 状态 |
| `internal/server/server.go` | 修改 | 集成持久化、identity |
| `internal/server/api.go` | 修改 | 新增 devices API |
| `internal/server/config.go` | 重写 | 去掉 Config 结构体，仅保留 CLI flag 解析 |
| `internal/agent/identity.go` | **新增** | Agent 本地 identity 管理 |
| `internal/agent/agent.go` | 重写 | CLI 改为 `./agent <server_url>` |
| `cmd/server/main.go` | 重写 | 零配置启动 |
| `cmd/agent/main.go` | 重写 | 零配置启动 |
| `web/static/index.html` | 重写 | 新增待处理卡片、客户端管理面板 |
| `internal/common/message.go` | 修改 | 更新 register 消息结构 |
| `internal/common/crypto.go` | 修改 | 支持按 client_id 获取密钥 |
| `config/server.yaml` | **移除** | 不再需要 |
| `config/agent.yaml` | **移除** | 不再需要 |

估算净增代码：约 **500-600 行**，重写约 400 行，新增约 200 行。

## 12. 风险与边界

| 风险 | 缓解 |
|------|------|
| Agent 身份文件丢失 | 管理员在 Web UI 删除旧设备，Agent 重新注册 |
| 服务端 state.json 损坏 | JSON 格式可手工修复；定时自动备份 `state.json.bak` |
| 恶意连接填满 pending 列表 | 复用 IP 限流 + 黑名单，单 IP 最多 N 个 pending |
| 审批后 Agent 未收到消息 | Agent 每隔 10s 轮询状态，超时后重新连接 |
| 加密密钥被窃 | Web UI 可重新生成密钥，Agent 重启后自动接收新密钥 |

## 13. 实现差异与优化（v1 实现 vs 原始设计）

本节记录实现过程中对原始设计方案的调整，供后续维护参考。

### 13.1 Challenge-Response → 自签名时间戳

**原始设计（§9.3）**：服务端发送 `auth_challenge`，Agent 签名后返回，需两轮交互 + 服务端维护 pending_challenge 状态。

**实际实现**：Agent 直接签名 `client_id:timestamp`，服务端用存储的 ed25519 公钥验证签名，同时校验时间戳在 ±5 分钟内。一轮完成，无需 pending_challenge 状态。

**涉及文件**：`internal/common/identity.go` (`SignTimestamp`, `VerifyTimestamp`, `IsTimestampValid`)

### 13.2 ECDH 密钥交换保护 enc_key 传输

**原始设计（§9.1）**：enc_key 直接通过 WebSocket 在 `register_ok` 消息中下发。

**实际实现**：Agent 生成 x25519 DH 密钥对，随注册消息发送公钥。服务端审批时生成临时 x25519 密钥对，与 Agent 公钥计算共享密钥，通过 HKDF-SHA256 派生加密密钥，再用 AES-256-GCM 加密 enc_key。Agent 收到后用本地 DH 私钥解密。

**涉及文件**：`internal/common/identity.go` (`GenerateDHKeypair`, `DHSharedSecret`, `EncryptKeyWithSharedSecret`)

### 13.3 pending_challenge 改为纯内存

**原始设计（§4.1）**：`pending_challenge` 持久化到 `server-state.json`。

**实际实现**：`pendingConns` map 纯内存，不持久化。挑战只有 60 秒有效期，不存在持久化价值。

### 13.4 ClientManager → DeviceManager

**原始设计**：ClientManager 扩展支持 pending/authorized 状态。

**实际实现**：新增 `DeviceManager`（`internal/server/device_mgr.go`），持有 `StateStore` 引用，管理 pending/authorized 设备状态。`ClientManager` 简化为纯运行时的在线 WebSocket 连接管理。`DeviceManager.pendingConns` 存储待审批设备的 WebSocket 连接，approve 后直接通过该连接发送 `register_ok`。

### 13.5 StateStore 异步原子写入

**原始设计**：未指定写入策略。

**实际实现**：`StateStore` 采用 dirty 标记 + 3 秒定时刷盘 + 原子 rename 机制。写操作仅修改内存，`MarkDirty()` 通知后台 goroutine 写入。文件先写入 `.tmp` 后缀临时文件，再 `os.Rename` 完成原子替换，防止写入崩溃导致文件损坏。

### 13.6 文件权限

**原始设计（§9.4）**：仅提及 `--data` 目录权限建议 `700`。

**实际实现**：identity 文件写入时指定 `0600`（仅属主读写），state.json 写入时指定 `0600`，目录创建时指定 `0700`。

### 13.7 服务端 CLI 参数体系

**原始设计（§11）**：移除 `config/server.yaml`，未明确替代方案。

**实际实现**：`--host/--port/--data/--tls-cert/--tls-key/--tunnel/--swagger/--allowed-origins` 以及日志、`--state-key` 参数。运行时可变配置（端口范围、限流、心跳、白名单等）走 Web UI → API → `StateStore`，不在 CLI 中重复。

### 13.8 加密方式

**原始设计（§9.1）**：原始 `CryptoContext` 用全局共享密钥派生 AES-256-GCM 密钥。

**实际实现**：保留 `CryptoContext` 作为底层加密原语，新增 `CryptoManager` 按 `client_id` 管理独立的 `CryptoContext`。隧道数据热路径使用 `EncryptTo` 直接写入 Binary 帧预留区，服务端/Agent 各用 `DecryptBytes` 还原，每设备独立密钥且避免 chunk 二次拷贝。

### 13.9 代码量

**原始设计**：估算净增 500-600 行。

**实际**：净增约 **800 行**（新增 5 个文件约 400 行，重写 10 个文件约 400 行），差异主要在 ECDH 密钥交换 + DeviceManager 状态机 + 异步持久化。
