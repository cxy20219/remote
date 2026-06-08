# rust-remote 跨语言 e2e 验证流程

> 适用：每次 rust-remote 核心改动后验证 Go server ↔ Rust agent 互通。
> 关联脚本：`rust-remote/bin/test-rust-agent-against-go-server.ps1`。
> 最近验证：2026-06-07（register / approve / enc_key 全 PASS；tunnel round-trip 受 Go server `pendingLoop` 时序限制，见 §4）。

## 适用场景

- rustls / tokio-tungstenite / axum 版本升级
- WebSocket 消息协议（`message.rs` / `frame.rs`）改动
- 加密链路（ECDH / HKDF / AES-GCM）改动
- `device_mgr` / `ws.rs` / `tunnel.rs` 行为改动
- `Cargo.toml` 依赖变更

## 前置条件

1. **Rust 工具链** 1.85+（`rustc --version`）。
2. **Go 工具链** 1.22+（`go version`，需在 PATH 中）。
3. **编译**：`cd rust-remote && cargo build --release`（产物在 `target/release/`）。
4. **空闲端口**：18080（可改 `-Port`）。
5. **curl.exe** 在 PATH（Win10+ 自带）。

## 关键步骤

### 1. 跑单元 + 集成测试

```powershell
cd E:\AI-work\go-remote\rust-remote
cargo test --workspace --no-fail-fast
```

预期：**95 unit + 11 integration 全部通过**。新增的 `admin_api::static_pages_served_with_html_content_type` 和 `admin_api::login_rate_limit_blocks_after_threshold` 必须绿。

### 2. 跑 clippy 严格检查

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

预期：**完全干净**（CI 强约束）。如果出现 `result_large_err` / `dead_code` / 未使用 import，立即修。

### 3. 跑跨语言 e2e

```powershell
powershell -ExecutionPolicy Bypass -File rust-remote\bin\test-rust-agent-against-go-server.ps1
```

预期输出（节选）：
```
[interop] admin password: xxxxxxxx-xxx
[interop] login ok
[interop] pending device: client-xxxxxxxx
[interop] approved
[interop] enc_key persisted (len=64)
[interop] PASS (register / approve / enc_key)
```

### 4. （可选）验证 tunnel round-trip

e2e 脚本的 `[interop] tunnel create response:` 步骤当前是 best-effort — 详见 §4 限制。
如需完整验证，需要：
1. 启动一个 echo server：`ncat -l 0.0.0.0 12345 --exec '/bin/cat'`（Linux）或 `ncat -l 0.0.0.0 12345 -k -c "cmd /c type"`（Windows）。
2. 等待 3-5 个心跳（agent 默认 30s/次，共需 90-150s）。
3. 手动 `curl http://127.0.0.1:30000/ -d 'interop-hello'` 期望返回 `interop-hello`。

## 验证方式

| 步骤 | 验证 | 失败信号 |
|------|------|----------|
| 1. cargo test | `test result: ok. ... passed` | 任何 `FAILED` / `error[E...]` |
| 2. cargo clippy | `Finished` 无 warning/error | `error:` / `warning:` |
| 3.1 启动 Go server | slog 输出 `"Admin password (first run only)"` | 端口占用 / 编译失败 |
| 3.2 admin login | 200 OK + `go_remote_token` cookie | 401/500 |
| 3.3 register pending | `/api/devices/pending` 含 device | 空列表 / 脚本 15s 超时 |
| 3.4 approve | 200 OK + device.enc_key 不为空 | 401/500 |
| 3.5 enc_key 持久化 | `$IdDir/identity.json` 含 64 字符 hex `enc_key` 字段 | 15s 内未出现 |

## 失败回退

| 现象 | 排查方向 |
|------|----------|
| `rustls_pki_types` 未解析 | workspace Cargo.toml 缺依赖；agent Cargo.toml 缺依赖 |
| `clippy::result_large_err` | `ConnectorError::Ws` 改 `Ws(String)` 而非 `Box<WsError>` |
| `decrypt failed: aead::Error` | HKDF 参数顺序：Rust `Hkdf::new(salt, secret)` + `expand(info, ...)`，对应 Go `hkdf.New(hash, secret, info=...)` |
| 脚本 `PositionalParameterNotFound` | 脚本含 em-dash/en-dash；改用 ASCII `--`/`-` |
| `agent did not persist enc_key` | agent 收到 register_ok 但 ECDH 解密失败；检查 `tunnel-rs-common::dh_shared_secret` 与 Go `ecdh` 实现 |
| Go server `Only one usage of socket` | 端口 18080 残留僵尸；脚本入口 `Get-NetTCPConnection` 清理 |
| Tunnel `client not found or offline` | 正常！Go server `pendingLoop` 需要 ≥1 个 ping 后才把 authorized device 迁入 in-memory clients map；README 已知 |

## §4 Go server `pendingLoop` 时序限制

Go server 的 pending→authorized 迁移在 `pendingLoop` 中实现，触发条件是**收到下一个 `ping` 帧**。Rust agent 默认 `--heartbeat-interval=30`，所以：
- t=0 审批通过
- t=0..30 agent 等下次心跳
- t=30 第一次心跳触发 Go `pendingLoop` 迁入 clients map
- t=30 之后 `POST /api/tunnels` 才会成功

**e2e 脚本默认 2 次心跳（60s）+ 2s 缓冲** = 62s，但 `tunnel_create` 在 t≈65s 调用，对 Go server 而言仍在 30s 窗口内（取决于审批→心跳间隔），偶尔成功偶失败。完整验证需手动等待 3-5 个心跳。

## 关联资源

- [Rust 端口编译与 clippy 踩坑](../experience/rust-remote-build-pitfalls.md)
- [PowerShell 5.1 跨语言脚本踩坑](../experience/powershell-cross-lang-ps5.1.md)
- [rust-remote 设计要点](../references/rust-remote-design.md)
- [Go server 设计](../../../go-remote/harness/references/server-design.md)
- [Go agent 设计](../../../go-remote/harness/references/agent-design.md)
- [零配置部署设计](../../../go-remote/harness/references/zero-config-design.md)
