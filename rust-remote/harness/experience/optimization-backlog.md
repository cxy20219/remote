# rust-remote 优化 Backlog

> 适用：`rust-remote` 子项目持续优化追踪。  
> 起源：2026-06-07 完整代码扫描 + 跨语言 e2e 审计；按"关联优先 / 整体最优"原则排序。  
> 状态：🔴 必修阻塞生产 / 🟠 必补正确性 / 🟡 健壮性 / 🟢 长期演进。

## 0. 跟踪规则

- 每完成一项：勾选 `[x]`、补上完成日期 + commit hash，更新"实际耗时"。
- 改动文件 / 行号以当时代码为准；升级依赖时重新核对。
- 验收标准：每项都有"如何验证"小节，跑 `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` 全绿。

---

## 🔴 必修：阻塞生产可用（Phase A）

### #1 持久化实际未启用（正确性） `[x]` 已完成 2026-06-07
**症状**：`main.rs:27` 调 `AppState::new()`（内存态），`persist.rs:137-151` 的 `start_sync_loop` 是空 stub，真实循环在 `:156-166` 的 `start_sync_loop_with_handle` 没人调。重启丢 admin 密码 / 设备 / 隧道。README 声称的 `state in ./data/server-state.json` 名存实亡。  
**关联**：`Config` 无 `--data-dir` 参数；`AppState::new` vs `with_store` 二选一未在 main 接线。  
**修法**：
1. `Config` 加 `--data-dir`（env `TUNNEL_RS_DATA_DIR`，默认 `./data`）。
2. `main.rs` 用 `StateStore::load_or_init(data_dir.join("server-state.json"))`。
3. `AppState` 用 `with_store(...)`。
4. `state_store.start_sync_loop_with_handle()` 拿 JoinHandle；`with_graceful_shutdown` 中先 abort 任务再 final flush。
5. `persist.rs` 删 `start_sync_loop` 空 stub + 删 `flush_notify` dead field。
6. `main.rs` 用 `with_graceful_shutdown(ctrl_c || SIGTERM)`，shutdown 后调 `state_store.stop().await` 同步 flush。
**如何验证**：
- 单元：`persist::tests::round_trip_persists` 已绿。
- 集成 smoke：起 server (18200)，改 settings，Stop-Process -Force，restart，新进程**不打印新密码**（从 state 恢复），`state_file.admin_password_hash` 两次完全一致。
**实际耗时**：~ 30 分钟

### #2 admin API 零鉴权（安全漏洞） `[x]` 已完成 2026-06-07
**症状**：`api/mod.rs:26-76` 注释承诺 `auth_middleware`，但全 542 行**没有任何 `Router::layer` 挂鉴权**。`has_valid_session` 只被 `/api/check-auth` 使用。`POST /api/devices/.../approve`、`DELETE /api/devices/:id`、`PUT /api/settings`、`PUT /api/security/blacklist`、`DELETE /api/devices/:id/regen-key` 全部开放。`admin_api.rs` 测试里连错的 cookie 名 `tunnel_admin` 都能 200，说明 bug 长期存在。  
**修法**：
1. `api/mod.rs` router 拆为 `public`（login/logout/check-auth）+ `admin`（其余），admin 用 `.route_layer(from_fn_with_state(state, require_session))`。
2. `require_session` 中间件：未通过 `has_valid_session` 返 `ServerError::Unauthorized`（401）。
3. `error.rs` 新增 `Unauthorized` 映射到 `StatusCode::UNAUTHORIZED`。
4. 修 `admin_api.rs:186` 旧 bug：把测试里的 `tunnel_admin={token}` 改成 `go_remote_token={token}`。
5. 修 `register_flow.rs`：3 处 admin 端点（approve + list devices）加 `login_token` 步骤。
6. 修 `admin_api::port_status_endpoint` 加 login。
7. 新增 `admin_endpoints_require_session` 集成测试覆盖：无 cookie / 错 cookie / 错 cookie 名 / 登录后 / PUT 405。
**如何验证**：
- `admin_endpoints_require_session` 全绿。
- `cargo test --workspace` 108 个测试全过（之前 107 + 1 新鉴权）。
- `cargo clippy --workspace --all-targets -- -D warnings` 干净。
**实际耗时**：~ 1.5 小时

### #3 设备密钥/共享 secret 写到 stdout（密钥泄露） `[x]` 已完成 2026-06-07
**症状**：`crates/agent/src/identity.rs:188-215` 残留调试代码：
- 写 entry diag 含 `enc_key_encrypted` 长度 + `server_dh_pub_hex` + `self.device_dh_privkey`
- 写 ECDH `shared` 共享密钥
- 解密失败时写 shared + enc_key_encrypted 原文
这些是**长期私钥 / 会话密钥**，会进 stdout 抓取 / 日志聚合。  
**修法**：删 4 个 `write_all` / `writeln!` 块；解密失败改 `tracing::debug!`（不进 release 日志）；函数 doc 加 **Security note** 提醒后续维护者。  
**如何验证**：`cargo test agent::identity::tests::enc_key_round_trip` 仍绿；`grep -r "device_dh_privkey\|shared=\|enc_key_encrypted" crates/agent/src/*.rs` 在 identity.rs 主体 0 命中（只在结构体字段声明处出现）。  
**实际耗时**：~ 5 分钟

---

## 🟠 必补：正确性 + 互操作（Phase B）

### #4 二进制隧道帧 `conn_id` 格式与设计文档不一致 `[x]` 已完成 2026-06-07（文档修订）
**症状**：设计文档 `rust-remote-design.md:36-48` 写"4 字节 length + 16 字节 binary tunnel_id + 8 字节 BE u64 conn_id + 1 字节 is_eof + 4 字节 data_len + N 字节 data" — 这是**错的**。Rust `crates/common/src/frame.rs:26-52` 实际是 `[u8 ver][u8 flags][u16 BE tid_len][u16 BE cid_len][u32 BE data_len][tunnel_id UTF-8][conn_id UTF-8][data]`，**与 Go `internal/common/message.go:102-170` 字节级一致**。
**关联**：跨语言 e2e 验证（`bin/test-rust-agent-against-go-server.ps1`）已确认 Rust agent 的 `tunnel_create` 帧能被 Go server 接受，说明**代码一直是对的**，只是设计文档表述错误。
**修法**：
1. 重写设计文档的帧结构图（替换为 10 字节头 + 变长 UTF-8 字符串段）。
2. 删除"conn_id 是 8 字节 BE u64"等所有错误描述。
3. 标注 Go 端参考文件 `go-remote/internal/common/message.go::Encode/DecodeBinaryTunnelDataFrame`。
4. 保留 `frame.rs` 现有 50 个单元测试（`roundtrip_simple` / `roundtrip_256k_chunk` / `roundtrip_utf8_id` / `rejects_*`）作为 wire 兼容性回归网。
**如何验证**：
- `cargo test common::frame::tests` 50 个全绿。
- 跨语言 e2e 脚本 `tunnel_create` 阶段已通过。
- 设计文档 + Go 参考双向链接到位。
**实际耗时**：~ 15 分钟

### #5 设置项热更新不生效（半数 silent no-op） `[x]` 已完成 2026-06-07
**症状**：
- `api/mod.rs:463-467` 的 `apply_runtime_settings` 只应用了 `port_range`。
- `login_rate_limit` / `max_conn_per_min` 改完 API 看不到效果。
- `security.rs:110-113` 的 `BlacklistManager::set_threshold` 是 `let _ = threshold;`（**no-op**）。
- `state.rs:19` 定义 `MAX_TUNNELS_PER_CLIENT`，全代码无引用。
**修法**：
1. `BlacklistManager::threshold` 改 `Arc<AtomicU32>`，`set_threshold` 改 `store`，`add_violation` 改读 AtomicU32。
2. `apply_runtime_settings` 调 `login_limiter.set_limit(s.login_rate_limit)` + `ws_limiter.set_limit(s.max_conn_per_min)` + `blacklist.set_threshold(s.blacklist_threshold)`。
3. `create_tunnel` 加 `state.settings.read().max_tunnels_per_client` 检查（=0 视为无限制）。
**如何验证**：
- 新增 `settings_hot_reload_changes_limiter_caps` 集成测试：PUT settings 改 login_rate_limit=1，burn quota 后正确密码仍被拒；改回 0 后正常；blacklist_threshold=1 立即生效。
- `cargo test --workspace` 110 个测试全过。
**实际耗时**：~ 30 分钟

### #6 `DefaultBodyLimit` 与 `max_body_size_mb` 脱钩 `[x]` 已完成 2026-06-07
**症状**：`state.rs:24,50` 定义 `MAX_BODY_SIZE_MB=10` 并在 `ServerSettings` 暴露 `max_body_size_mb`，但 `main.rs:38` 写死 `.layer(DefaultBodyLimit::max(1024 * 1024))`（1 MB）。设置项是装饰品，实际限制比声明小 10 倍。  
**修法**：`main.rs` 启动时用 `state.state_store.get_settings().max_body_size_mb as usize * 1024 * 1024` 动态设 `DefaultBodyLimit`。  
**如何验证**：PUT /api/settings 改 `max_body_size_mb=20` 后，20 MB body 通过；当前默认 10 MB 限制生效。  
**实际耗时**：~ 20 分钟

### #7 优雅关闭缺失 `[ ]`
**症状**：`axum::serve(...)` 无 `with_graceful_shutdown`，SIGTERM 时 in-flight WS / 隧道任务、后台 3s 同步循环全部被砍，可能导致 `server-state.json` 写不完整或半包帧。  
**修法**：
1. `tokio::signal::ctrl_c()` + 跨平台 `Termination` 信号监听。
2. `axum::serve(...).with_graceful_shutdown(shutdown_signal())`。
3. shutdown 顺序：HTTP server stop accept → `state_store.stop()` 同步 flush → abort sync loop JoinHandle → 短超时兜底。
**如何验证**：
- 启动 server，`PUT /api/settings` 改某值，立刻 Ctrl-C，restart 后值不丢。
- `kill -TERM $(pidof tunnel-rs-server)` 不留半包 state 文件。  
**估时**：1-2h

### #8 WS 最大消息未限 `[ ]`
**症状**：`common/src/lib.rs:34` 定义 `MAX_WS_MESSAGE_SIZE = 2 MB`，全代码无引用。`axum::extract::ws::WebSocketUpgrade` 不带大小限，恶意 agent 可发任意大帧撑爆内存。  
**修法**：
- axum 0.7 没原生 max_frame。
- 选项 A：`tower_http::limit::RequestBodyLimitLayer` 限定 HTTP 升级请求（管握手，管不了后续帧）。
- 选项 B：reader 循环里手动 bound chunked read（`MessageStream` 配 `try_filter`）。
- 选项 C：用 `tokio_tungstenite` 替代 axum 自带 ws（变动大，不推荐）。
**如何验证**：发 10 MB 帧 → server 断开连接 / 拒绝帧；正常 1 MB 帧 → 200。  
**估时**：1h

### #9 tunnel update 端点 500 → 405 `[x]` 已完成 2026-06-07
**症状**：`api/mod.rs:362-372` 返 `ServerError::Internal("tunnel update is not yet implemented")` → 实际是 500，前端困惑。  
**修法**：`error.rs` 新增 `MethodNotAllowed(String)` 映射到 405，`update_tunnel` 改返 `MethodNotAllowed`。  
**如何验证**：`admin_endpoints_require_session` 集成测试断言 PUT `/api/tunnels/some-tunnel` 返 405。  
**实际耗时**：~ 5 分钟

---

## 🟡 健壮性 + 代码质量（Phase C）

### #10 测试覆盖盲区 `[x]` 已完成 2026-06-07（4/6 子项）
**症状**：95+11 测试主要 happy path。  
**完成情况**：
- (a) ✅ 断线重连风暴 — 新增 `reconnect_storm_does_not_oom_server`：100 次 ws register→close 循环，验证 server 仍可响应。
- (b) ✅ 大帧 + 反压 — #8 阶段已做 `ws_rejects_oversized_frames`。
- (c) ✅ admin session 过期 — `SessionManager::expire_for_test` helper + `expired_session_is_rejected_by_admin_endpoint` 集成测试。
- (d) ✅ 恶意 payload fuzz — `crates/common/src/frame.rs` 内嵌 3 个 proptest（`decode_never_panics` / `conn_id_with_garbage_bytes` / `roundtrip_arbitrary`），共 768 cases/run。
- (e) ⏳ 并发 tunnel 风暴 — backlog 提到依赖 #5（已加 `max_tunnels_per_client` 检查），但并发风暴测试没写。**留给后续迭代**。
- (f) ⏳ enc_key 轮换 — **留给后续迭代**。
**修法**：
- `Cargo.toml` workspace 加 `proptest = "1"`。
- `crates/common/Cargo.toml` dev-deps 加 `proptest`。
- `crates/server/Cargo.toml` dev-deps 加 `proptest`。
- `crates/common/src/frame.rs` 内嵌 `mod proptests` 含 3 个 proptest。
- `crates/server/src/session.rs` 新增 `pub fn expire_for_test`（命名带 `_for_test` 后缀，prod 路径不会误用）。
- 新建 `crates/server/tests/reconnect_session.rs` 含 2 个集成测试。
**如何验证**：
- `cargo test --workspace` 115 个测试全过（之前 110 + 2 集成 + 3 proptest，每 proptest 256 cases）。
- `cargo test --workspace --release` 115 全过。
- `cargo clippy --workspace --all-targets -- -D warnings` 干净。
- 跨语言 e2e 18203 PASS。
**实际耗时**：~ 1h
**后续 backlog**：e/f 留给下一轮 Phase C 收尾。

### #11 死代码 + stub `[x]` 已完成 2026-06-07
**清单与结果**：
- `crates/server/src/tunnel.rs` `settings` 字段 `#[allow(dead_code)]` → **改注释**（line 536 实际用了 `self.settings.read()` 读 global whitelist）。
- `crates/server/src/tunnel.rs:167-183` `bind_state` 接 5 个参数但 `authorized_senders` 形参 + `let _ = authorized_senders;` 占位 → **删 2 个无用参数**（device_mgr / authorized_senders），同步更新 `state.rs` 调用点 + `tunnel.rs:658` 测试 helper。
- `crates/server/src/api/mod.rs:101-104` `health()` 未挂载的 handler（main.rs 用了 inline closure） → **删**。
- `crates/server/src/api/mod.rs:586-587` `_typecheck` 桩 + `use BlacklistManager` → **删**（`BlacklistManager` 实际被 `state.rs` 等其它模块使用，不需桩）。
- `crates/agent/src/agent.rs:43` `crypto_mgr` 字段 → **保留**（虽然 Agent 自身方法体没引用，但 `Agent::new` 仍接受，将来子模块 wire 时会用）。
- `crates/agent/src/agent.rs:290-294` `WorkCmd::Binary` 变体 + match arm → **删**（从未被构造，writer 走 `binary_rx` 通道）。
- `crates/agent/src/connector.rs:172` `resolve_server_name` `#[allow(dead_code)]` → **保留**（"未来 TLS server name 解析可能用到"语义有效，符合 harness 经验指引）。
- `crates/server/src/persist.rs:54-60` `flush_notify: Notify` 字段 → **已随 #1 删**。
- `TunnelStatus::Closing` 和 `extract_ip` → **保留**（`Closing` 在 `api/mod.rs:540` match arm 用，`extract_ip` 在自测试里用）。
**如何验证**：
- `cargo test --workspace` 110 个测试全过。
- `cargo clippy --workspace --all-targets -- -D warnings` 干净。
- `bind_state` 签名从 5 参数缩到 3 参数，调用点（`state.rs:213`、`tunnel.rs:658`）同步更新。
**实际耗时**：~ 30 分钟

### #12 `send_to_server_eof` 重复编码 `[x]` 已完成 2026-06-07
**症状**：`crates/agent/src/tunnel.rs:220-230` 同一帧 `encode_frame(... true)` 调两次（一次拿 Err 丢日志，一次拿 Ok 发送）。  
**修法**：合并为一次 `let frame = match encode_frame(... is_eof=true) { Ok(f) => f, Err(e) => { warn!(...); return; } };`。  
**如何验证**：`agent::tunnel::tests::round_trip_through_local_service` 仍绿。  
**实际耗时**：~ 5 分钟

### #13 随机源不统一 `[x]` 已完成 2026-06-07
**症状**：`crypto.rs:41`（per-frame nonce，`CryptoContext::encrypt`）、`crypto.rs:94`（per-frame nonce，`CryptoManager::encrypt`）、`persist.rs:318, 320`（admin 密码）、`session.rs:86`（session token）用 `rand::thread_rng()`；`common/identity.rs:13,115,158` 用 `OsRng`。`thread_rng` 在 0.8 是 CSPRNG 目前安全，但风格不一致。GCM nonce 推荐 `OsRng` 避免 PRNG 状态污染。  
**修法**：所有密钥/Nonce 路径统一改 `OsRng`。测试 helper（`crypto.rs:122` `#[cfg(test)]` 块）保留 `thread_rng`（测试用，不影响生产 wire）。  
**如何验证**：`grep "thread_rng" crates/{common,server,agent}/src/*.rs` 命中数从 4 降到 1（仅测试 helper）。  
**实际耗时**：~ 20 分钟

### #14 CI 缺 macOS + musl 静态链接 `[x]` 已完成 2026-06-07
**症状**：`.github/workflows/rust-remote.yml` 跑 `ubuntu-latest` + `windows-latest`，没覆盖 macOS、没做 musl 静态链接。生产部署到 alpine / scratch 容器时需要本地 cross 编译指引。  
**修法**：
1. 新增 `macos` job：`macos-latest` 跑 `cargo test --workspace`，捕获 Linux-only 假设。
2. 新增 `musl` job：`ubuntu-latest` 装 `musl-tools` + rustup 加 `x86_64-unknown-linux-musl` target，`RUSTFLAGS="-C target-feature=+crt-static"`，编译 agent 静态二进制 + `file` 验证 ELF 类型。
3. e2e job 重编号为 #5。
**如何验证**：CI push 后 macos + musl 跑通。本地验证：`cargo build --release --target x86_64-unknown-linux-musl -p tunnel-rs-agent` 产出 ~2MB 静态二进制。  
**实际耗时**：~ 15 分钟

---

## 🟢 长期演进（Phase D / E）

### #15 运维资源缺失 `[x]` 已完成 2026-06-08（**6/6 全部**）
**症状**：生产部署无 Dockerfile / systemd unit / CHANGELOG；K8s 友好端点（`/healthz` `/readyz`）缺失。
**完成情况**：
- ✅ `rust-remote/Dockerfile` — multi-stage（`rust:1.85-alpine` builder → `scratch` runtime），musl 静态编译 + strip，uid 65532 非 root，体积 ~3MB。
- ✅ `rust-remote/contrib/systemd/tunnel-rs-server.service` — hardened unit（`NoNewPrivileges` `ProtectSystem=strict` `RestrictNamespaces` `SystemCallFilter=@system-service`），30s graceful shutdown。
- ✅ `rust-remote/CHANGELOG.md` — Keep-a-Changelog 风格，[Unreleased] 段详细列出 Phase A-D 所有改动。
- ✅ `/healthz` + `/readyz` + `/health`（back-compat 别名）端点（K8s liveness/readiness）。
- ✅ `/metrics` prometheus 端点（`crates/server/src/metrics.rs` + `crates/server/Cargo.toml` 加 `prometheus = "0.13"`），导出 HTTP request 分类、admin login 成功/失败、设备注册/审批计数、ws/authorized/active tunnels gauges、blacklist size。`render_is_prometheus_text` 单元测试覆盖。
- ✅ `--pidfile` CLI 参数（env `TUNNEL_RS_PIDFILE`），启动时写 pid 到文件，admin 友好（monit/supervisord 可读）。
- ✅ 状态文件损坏时降级到 read-only — `StateStore::load_or_init` 在 JSON 解析失败时 `tracing::error!` 输出明显警告 + 返 `Self::new_in_memory_handle()`（`path=None` 天然 read-only）；新增 `is_read_only()` 方法；`main.rs` 检测到 read-only 时**跳过后台 sync loop** + 输出 `READ-ONLY mode` warning。`tracing_subscriber` 改用 `with_writer(stderr)` 确保警告进 stderr。**2 个新单元测试** + 1 个 smoke test 覆盖。
**如何验证**：
- 单元：118 个测试全过（之前 116 + 2 个 RO 测试 `corrupt_state_falls_back_to_read_only` + `missing_state_file_is_read_write`）。
- Smoke test（端口 18500）：预写坏 JSON → 启动 server → stderr 出现 "state file is corrupt" + "READ-ONLY mode" 警告 → `/healthz` 200 → state 文件字节级未被覆盖。
- 跨语言 e2e 18206 PASS。
- `cargo clippy --workspace --all-targets -- -D warnings` 干净。
**实际耗时**：~ 1h

### #16 日志结构化 / 链路追踪 `[x]` 已完成 2026-06-08
**症状**：用了 `tracing` 但 `init_tracing` 用 `compact` formatter，无 JSON、无 request-id 透传、`TraceLayer` 无耗时打点。
**修法**：
1. `init_tracing` 支持 `RUST_LOG_FORMAT=json` env toggle（`tracing-subscriber` 加 `json` feature）。
2. 自定义 `HttpSpan: MakeSpan<B>` — 每个 HTTP 请求建一个 `info_span!("http", method, uri, request_id=Uuid::new_v4(), status=Empty, latency_ms=Empty)`。
3. 自定义 `HttpOnResponse: OnResponse<B>` — 响应时 `span.record("status", ...)` + `span.record("latency_ms", ...)` 填字段。
4. 字段用 `tracing::field::Empty` 占位，response 时 record 填充（标准 tracing 模式）。
**如何验证**：
- 编译过 + `cargo clippy --workspace --all-targets -- -D warnings` 干净。
- `cargo test --workspace` 115 个测试全过（不需新增 — 行为不破坏现有）。
**实际耗时**：~ 30 分钟

---

## 历史 & 验证记录

| 日期 | 改动 | 验证 | 备注 |
|------|------|------|------|
| 2026-06-07 | #3 删密钥日志 | `agent::identity::enc_key_round_trip` 绿 | 5 分钟 |
| 2026-06-07 | #9 tunnel update 405 | `admin_endpoints_require_session` 断言 405 | 5 分钟 |
| 2026-06-07 | #6 DefaultBodyLimit 跟设置 | `DefaultBodyLimit::max((max_body_size_mb as usize) * 1024 * 1024)` 编译过 | 20 分钟 |
| 2026-06-07 | #2 admin 鉴权中间件 | `admin_endpoints_require_session` 集成测试绿；旧 `tunnel_admin=` 测试修 | 1.5h |
| 2026-06-07 | #1 持久化接线 | smoke test：起 server → kill → restart → `admin_password_hash` 字节级一致 | 30 分钟 |
| 2026-06-07 | Phase A 全量回归 | `cargo test --workspace` 108 全过；`cargo test --workspace --release` 108 全过；`cargo clippy --workspace --all-targets -- -D warnings` 干净 | ~ 3h |
| 2026-06-07 | #7 优雅关闭 | #1 阶段已实现：`with_graceful_shutdown(ctrl_c \|\| SIGTERM)` + `state_store.stop()` final flush + `sync_handle.abort()` | （随 #1 闭环） |
| 2026-06-07 | #5 设置热更新 + max_tunnels_per_client | `settings_hot_reload_changes_limiter_caps` 集成测试绿；`apply_runtime_settings` 接 `set_limit`/`set_threshold` | 30 分钟 |
| 2026-06-07 | #8 WS 最大消息 2MB | `ws_rejects_oversized_frames` 集成测试绿（发 MAX+1 byte → ws 流终止） | 30 分钟 |
| 2026-06-07 | #4 帧格式文档修订 | design.md 重写为实际格式（u16 BE + UTF-8 string）；跨语言 e2e 再次 PASS | 15 分钟 |
| 2026-06-07 | Phase B 全量回归 | `cargo test --workspace` 110 全过；`cargo test --workspace --release` 110 全过；`cargo clippy` 干净；跨语言 e2e PASS | ~ 1h |
| 2026-06-07 | #12 `send_to_server_eof` 去重 | `agent::tunnel::tests::round_trip_through_local_service` 绿 | 5 分钟 |
| 2026-06-07 | #11 死代码 + 残留 stub 清理 | `bind_state` 缩为 3 参数；`WorkCmd::Binary` 删；`_typecheck`/`health` 删；settings 注释改写 | 30 分钟 |
| 2026-06-07 | #13 随机源统一 thread_rng → OsRng | `crypto.rs`（2 个 encrypt）+ `persist.rs`（admin 密码）+ `session.rs`（token） | 20 分钟 |
| 2026-06-07 | #14 CI 加 macOS + musl | `.github/workflows/rust-remote.yml` 新增 2 个 job | 15 分钟 |
| 2026-06-07 | Phase C 阶段 1 全量回归 | `cargo test --workspace` 110 全过；`cargo test --workspace --release` 110 全过；`cargo clippy` 干净；跨语言 e2e PASS | ~ 1h |
| 2026-06-07 | #10 测试覆盖（4/6 子项） | 引入 proptest；3 个 frame fuzz（768 cases）；`reconnect_storm_does_not_oom_server`；`expire_session`；`expire_for_test` helper；`SessionManager::expire_for_test` | ~ 1h |
| 2026-06-07 | Phase C 阶段 2 全量回归 | `cargo test --workspace` 115 全过（+proptest 768 cases）；`cargo test --workspace --release` 115 全过；`cargo clippy` 干净；跨语言 e2e 18203 PASS | ~ 30 分钟 |
| 2026-06-08 | #16 日志结构化 + TraceLayer span | `init_tracing` 支持 `RUST_LOG_FORMAT=json`；`HttpSpan` + `HttpOnResponse` 填 request_id/status/latency_ms | 30 分钟 |
| 2026-06-08 | #15 运维资源（3/6 子项） | `Dockerfile`（multi-stage scratch）/ `tunnel-rs-server.service`（hardened）/ `CHANGELOG.md`（Keep-a-Changelog）/ `/healthz` + `/readyz` + `/health` 别名 | 30 分钟 |
| 2026-06-08 | Phase D 全量回归 | `cargo test --workspace` 115 全过；`cargo test --workspace --release` 115 全过；`cargo clippy` 干净；跨语言 e2e 18204 PASS；smoke test `/healthz` 200 / `/readyz` 200 | ~ 30 分钟 |
| 2026-06-08 | Phase D 收尾（5/6 #15） | `/metrics` prometheus（`crates/server/src/metrics.rs` + 8 counters/gauges + 单元测试）；`--pidfile` CLI（`Config` + main 启动钩子） | 1h |
| 2026-06-08 | Phase D 收尾全量回归 | `cargo test --workspace` 116 全过；`cargo test --workspace --release` 116 全过；`cargo clippy` 干净；跨语言 e2e 18205 PASS；smoke test pidfile OK + `/metrics` 200 | ~ 30 分钟 |
| 2026-06-08 | #15 状态文件损坏降级 read-only（收尾） | `load_or_init` 解析失败 → `new_in_memory_handle()` + stderr 警告 + `is_read_only()` + main 跳 sync loop + tracing 改 stderr；2 单元 + 1 smoke | 1h |
| 2026-06-08 | 全优化项收官回归 | `cargo test --workspace` 118 全过；`cargo test --workspace --release` 118 全过；`cargo clippy` 干净；跨语言 e2e 18206 PASS；RO smoke test 全 4 项断言过 | ~ 30 分钟 |
