# rust-remote 设计要点

> 适用：理解 Rust 重构的 wire 协议、加密链路、生命周期与 Go 实现的差异。
> 主参考：`rust-remote/README.md` + `rust-remote/crates/{common,server,agent}/src/lib.rs`。

## 1. Wire 协议（与 Go 字节级兼容）

### 消息包络

```json
{ "type": "register", "payload": { ... } }
```

- `type` 字段严格匹配 Go 的 `common.Message.Type`。
- `payload` 是任意 JSON，调用方解码到强类型 struct。
- 严格 JSON 解析：`#[serde(deny_unknown_fields)]` + `decode_strict_json`（拒绝多值/尾随空白）。

### 控制消息类型

| type | 方向 | payload 强类型 |
|------|------|----------------|
| `register` | agent→server | `RegisterPayload`（reauth, client_id?, device_pubkey, device_dh_pubkey?, hostname, os, timestamp?, signature?） |
| `register_pending` | server→agent | `{ client_id, message }` |
| `register_ok` | server→agent | `{ client_id, enc_key_encrypted?, server_dh_pubkey?, enc_enabled }` |
| `register_fail` | server→agent | `{ reason }` |
| `tunnel_open` | agent→server | `{ tunnel_id, local_addr, local_port, protocol }` |
| `tunnel_open_ack` | server→agent | `{ tunnel_id, public_port, success, error? }` |
| `tunnel_close` | agent→server | `{ tunnel_id, conn_id? }` |
| `tunnel_data_bin` | 双向 | 二进制帧（tunnel_id + conn_id + 数据） |
| `ping`/`pong` | 双向 | 空 |
| `device_deleted` | server→agent | `{ reason }` |

### 二进制隧道帧（`tunnel_data_bin`）

```
┌──────────┬──────────┬──────────────┬──────────────┬──────────────┬────────────┬────────────┬─────────┐
│ 1 byte   │ 1 byte   │  2 bytes     │  2 bytes     │  4 bytes     │ tunnel_id  │  conn_id   │  data   │
│ version  │ flags    │ tid_len      │ cid_len      │ data_len     │ (UTF-8)    │ (UTF-8)    │ (bytes) │
│ (u8)     │ (u8)     │ (BE u16)     │ (BE u16)     │ (BE u32)     │            │            │         │
└──────────┴──────────┴──────────────┴──────────────┴──────────────┴────────────┴────────────┴─────────┘
```

**关键不变式**（与 Go 完全字节级一致，见 `go-remote/internal/common/message.go:102-170`）：
- `version` 固定为 `0x01`。其它版本会被 `decode` 拒收。
- `flags` 当前仅 `bit0` = `is_eof`。其它位会被拒收，保证未来扩展时不静默接受错帧。
- `tunnel_id` / `conn_id` 是 **UTF-8 string**，各自有 2 字节 BE 长度前缀；**不是** 16 字节 binary UUID / 8 字节 BE u64。早期的设计文档曾把它们画成定长 binary，与 Go 实现不符，已修订。
- `data` 段是变长明文 payload，agent 侧的 AES-GCM 加密由 `tunnel-rs-agent` 在自己那一层完成，`frame.rs` 不感知。
- `FRAME_HEADER_SIZE = 10`；总长 = `10 + tid_len + cid_len + data_len`。
- `tunnel_id` / `conn_id` 单段上限 `0xFFFF` 字节（编码端会拒绝更长）。
- Rust 实现：`crates/common/src/frame.rs`；Go 实现：`go-remote/internal/common/message.go::Encode/DecodeBinaryTunnelDataFrame`。两者 byte-for-byte 互通（已在跨语言 e2e 脚本中验证 register/approve/enc_key/tunnel_create 阶段）。

## 2. 加密链路（与 Go 完全对齐）

```
[server]                              [agent]
  ECDH x25519 keypair                  ECDH x25519 keypair
  server_dh_priv                       agent_dh_priv
        │                                    │
        ├──── register ───────────────────────►
        │  payload.device_dh_pubkey = agent's ECDH pub
        │                                    │
        │◄── register (with reauth) ─────────┤
        │  client_id, signature              │
        │                                    │
        ├──── register_ok ───────────────────►
        │  enc_key_encrypted = AES-GCM(enc_key)
        │  server_dh_pubkey                  │
        │                                    │
   shared = ECDH(server_priv, agent_pub) ◄──── shared = ECDH(agent_priv, server_pub)
        │                                    │
   aes_key = HKDF-SHA256(                aes_key = HKDF-SHA256(
     secret=shared,                         secret=shared,
     salt="goremote-enc-key-exchange-v1",   salt="goremote-enc-key-exchange-v1",
     info=nil)                              info=nil)
        │                                    │
   decrypt enc_key with aes_key        decrypt enc_key with aes_key
```

### 关键 HKDF 参数（容易写错）

```rust
// Go 端
hkdf.New(sha256.New, shared, "goremote-enc-key-exchange-v1", nil)
//                                  ^salt                     ^info
// Rust 端
Hkdf::<Sha256>::new(Some(b"goremote-enc-key-exchange-v1"), shared)
   .and_then(|hk| hk.expand(&[], aes_key_len))   // info = empty
```

`salt` 和 `secret` 参数位置在两个实现中**完全相反**，写反了 ECDH 出来的 aes_key 不一样 → AES-GCM 解密失败 `aead::Error`。

## 3. 持久化文件 schema

`server-state.json` 与 Go server 字节级兼容：
```json
{
  "settings": { ... },
  "admin_password_hash": "bcrypt...",
  "devices": [
    {
      "id": "client-xxxxxxxx",
      "device_sign_pubkey": "abcd...",
      "device_dh_pubkey": "ef01...",
      "hostname": "...",
      "os": "linux",
      "status": "pending|authorized",
      "enc_key": "aabb...",
      "enc_enabled": true,
      "ip_whitelist": ["..."],
      "first_seen": "2026-06-07T12:00:00Z",
      "approved_at": "2026-06-07T12:00:00Z"
    }
  ],
  "tunnels": [ ... ]
}
```

`agent-id/identity.json`：
```json
{
  "client_id": "client-xxxxxxxx",
  "device_pubkey": "abcd...",
  "device_dh_pubkey": "ef01...",
  "sign_priv_enc": "...",   // 加密存储（默认无密码）
  "dh_priv_enc": "...",
  "server_pubkey": "...",   // 可选：用于验证 server 注册签名
  "enc_key": "..."          // 64 hex chars（AES-256 key 16 字节 → 32 hex；项目实际是 32 hex）
}
```

> **注意**：README 中说 `enc_key` 是 64 hex 字符（32 字节 = AES-256），但实际代码生成的 `enc_key` 长度需要看 `tunnel-rs-common::generate_enc_key`。脚本断言用的是 `[0-9a-fA-F]{64}`。

## 4. Cookie 与 session

- Cookie 名：`go_remote_token`（固定，匹配 Go）。
- Session lifetime：24h，session 池上限 64 个（LRU 淘汰最旧）。
- Token：32 字节 random，hex 编码后写入 cookie。

## 5. 限流

| 端点 | 限流 | 默认 | 触发 |
|------|------|------|------|
| `POST /api/login` | `login_limiter` | 5 次/分/IP | 密码错也计数 |
| `GET /ws` | `ws_limiter` | 10 次/分/IP | 升级前检查 |
| 隧道外部连接 | `tunnel anti-scan` | 内置 | Go server 端有，Rust 端待对齐 |

## 6. 状态机

### Agent 生命周期

```
[no identity] → AgentIdentity::load_or_create() → [identity created]
                                                            ↓
                                                      [WS connected]
                                                            ↓
                                              register → register_pending
                                                            ↓
                                              （admin approve in web UI）
                                                            ↓
                                              register_ok → enc_key 持久化
                                                            ↓
                                                  [authorized 状态]
                                                            ↓
              reconnect loop ←── ws close ──→ [backoff retry]
```

### Server WebSocket 连接状态

```
[connected] → read register
                    ↓
              reauth?  ──yes──→ DeviceManager::reauth → register_ok
                    ↓ no
              register_new → add_pending_conn
                    ↓
              [pending] 等待 admin approve（device_mgr.take_pending_conn）
                    ↓ approve
              [authorized] → register_authorized_sender
                    ↓
              处理 tunnel_open / tunnel_close / tunnel_data_bin
```

## 7. 已知差异 / TODO（与 Go 对齐）

| 差异 | 状态 | 备注 |
|------|------|------|
| Session pool 大小 64 | ✅ 对齐 | `SESSION_MAX` |
| 审批时 ECDH 加密 enc_key | ✅ 对齐 | HKDF 参数注意 |
| Cookie 名 `go_remote_token` | ✅ 对齐 | |
| 端口防扫描限流 | ❌ Rust 缺 | `tunnel.rs` 仅有 `accept_through_listener` 测试 |
| 登录限流挂载 | ✅ 2026-06-07 新增 | `api::login` |
| WS 限流挂载 | ✅ 2026-06-07 新增 | `ws::ws_handler` |
| 静态文件 | ✅ 2026-06-07 新增 | `include_str!` 嵌入 |
| Swagger UI | ❌ 故意省略 | 见 README |
| 跨语言 e2e 脚本 | ✅ 2026-06-07 新增 | `bin/test-rust-agent-against-go-server.ps1` |

## 关联资源

- [rust-remote 总览](../Harness.md)
- [Rust 端口编译踩坑](../experience/rust-remote-build-pitfalls.md)
- [跨语言 e2e 流程](../workflow/rust-remote-verify.md)
- [Go server 设计](../../../go-remote/harness/references/server-design.md)
- [Go agent 设计](../../../go-remote/harness/references/agent-design.md)
- [隧道设计](../../../go-remote/harness/references/tunnel-design.md)
- [零配置设计](../../../go-remote/harness/references/zero-config-design.md)
