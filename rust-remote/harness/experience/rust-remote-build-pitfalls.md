# Rust 端口编译与 clippy 踩坑

> 适用：`rust-remote` 子项目（rustls 0.23 + tokio-tungstenite 0.24 + axum 0.7 + thiserror）。
> 最近验证：2026-06-07（cargo test 95+11 通过 / clippy 干净）。

## 1. rustls 0.23 依赖缺失与 API 错配

**现象**：`cargo build` 报
- `unresolved import rustls_pki_types`
- `cannot find ring in crypto`
- `cannot find module or crate webpki_roots`
- `no method named add_certs found for struct RootCertStore`

**根因**：rustls 0.23 把证书类型（`CertificateDer`、`ServerName`、`TrustAnchor`）拆到独立 crate `rustls-pki-types`；webpki-roots 也不是 rustls 内置。`add_certs` 是 rustls 0.22 API，0.23 改名 `add_parsable_certificates`（返回 `(added, ignored)` tuple）。

**修法**：
1. `Cargo.toml` workspace 加：
   ```toml
   rustls-pki-types = "1"
   webpki-roots = "0.26"
   ```
2. agent `Cargo.toml` 加这两个依赖。
3. `connector.rs`：
   ```rust
   // 之前
   roots.add_certs(certs)
   // 之后
   let (added, ignored) = roots.add_parsable_certificates(certs);
   ```

**根因 2**：`rustls::crypto::ring::default_provider()` 在当前依赖下未启用（rustls 0.23 默认 `aws_lc_rs`）。要么 `features=["ring"]`（重编），要么直接用 `rustls::crypto::aws_lc_rs::default_provider()`。本项目用后者（已下载 `aws-lc-sys` 0.41，零额外编译）。

## 2. clippy::result_large_err（`tungstenite::Error` 过大）

**现象**：`cargo clippy --workspace --all-targets -- -D warnings` 报
```
error: the `Err`-variant returned from this function is very large
  --> crates/agent/src/connector.rs:36:5
   = help: try reducing the size of `connector::ConnectorError`
```

**根因**：`tungstenite::Error` 是大 enum（TLS / IO / capacity / protocol 四类变体），`#[from] WsError` 让 `Result<T, ConnectorError>` 的 Err 体积大到 256+ 字节，clippy 在每个返回 `Result` 的 `pub fn` 上都报。

**修法**：把变体从 `Ws(#[from] WsError)` 改为 `Ws(String)`，调用点手动 `.map_err(|e| ConnectorError::Ws(e.to_string()))?`。`#[allow(clippy::result_large_err)]` 加在 type alias 上**无效**（lint 评估是基于具体函数返回的 Result 大小）。

**反例**：用 `Ws(Box<WsError>)` 会让 `map_err(ConnectorError::Ws)` 函数指针签名断（Box<WsError> 不能再 From 转换），得手动 `.map_err(|e| ConnectorError::Ws(Box::new(e)))`，得不偿失。

## 3. 死代码与不破坏 API 风格

**现象**：`pub(crate) fn resolve_server_name` 编译通过但从未被调用，clippy 报 `dead_code`。

**修法**：保留 API（agent 后续 TLS server name 解析可能用到）但加 `#[allow(dead_code)]`。**不要**直接删 — 这会失去后续 helper。

## 4. axum 0.7 静态文件服务

**现象**：Go server 用 `embed.FS` 把 `index.html` / `login.html` 编进二进制。Rust 端没有 ServeDir 集成（README 已知 TODO）。

**修法**：`include_str!("../static/index.html")` 嵌入二进制，配合 axum 路由：
```rust
const INDEX_HTML: &str = include_str!("../static/index.html");
const LOGIN_HTML: &str = include_str!("../static/login.html");

.route("/", get(index_page))
.route("/index.html", get(index_page))
.route("/login.html", get(login_page))

async fn index_page() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML)
}
```

**优势**：与 Go `embed.FS` 字节级自包含等价；不依赖运行时工作目录；编译期静态校验文件存在。

## 5. RateLimiter 集成

**现象**：`security::RateLimiter` 单元测试通过但未挂载到 `POST /api/login` 和 `GET /ws`（README 已知 TODO）。

**修法**：
1. `AppState` 加 `login_limiter: Arc<RateLimiter>` 和 `ws_limiter: Arc<RateLimiter>` 字段。
2. 加 `AppState::with_store_and_limits(state_store, login_limit, ws_limit)` 构造函数 — 测试可注入 limit=1 触发限流。
3. `api::login` 加 `ConnectInfo<SocketAddr>` 提取器，限流检查前置。
4. `ws::ws_handler` 限流不通过直接返回 `(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")`。

**测试覆盖**：`admin_api::login_rate_limit_blocks_after_threshold` 用 `start_test_server_with_login_limit(1)` 验证第二次登录返回 500 + "rate limit" 错误。

## 关联资源

- [Rust 端口编译 / 跨语言 e2e 流程](workflow/rust-remote-verify.md)
- [PowerShell 5.1 跨语言脚本踩坑](powershell-cross-lang-ps5.1.md)
- [rust-remote 设计要点](references/rust-remote-design.md)

---

## 6. RateLimiter 真正支持 hot-reload（对齐 Go SetLimit）

**现象**：`RateLimiter::set_limit` 之前是 no-op（`let _ = limit;`），admin 改 `max_conn_per_min` 后 `login_limiter` / `ws_limiter` / port anti-scan 限流都不会跟着变。

**根因**：`RateLimiter` 把 `limit: u32` 存为不可变字段；初始 cap 在构造时定，运行时不热改。

**修法**：用 `Arc<AtomicU32>` 替换：
```rust
pub struct RateLimiter {
    inner: Arc<RwLock<Inner>>,
    limit: Arc<AtomicU32>,
    window: Duration,
}

pub fn set_limit(&self, limit: u32) {
    self.limit.store(limit, Ordering::Relaxed);
}

pub fn allow(&self, key: IpAddr) -> bool {
    let limit = self.limit.load(Ordering::Relaxed);
    if limit == 0 { return true; }
    // ... use `limit` (not self.limit)
}
```

**Go parity**：`s.portLimiter.SetLimit(settings.MaxConnPerMin)` 在 `apply_runtime_settings` 中调用；Rust 端 `AppState` 持有 `Arc<RateLimiter>`，`PUT /api/settings` → `apply_runtime_settings` → `login_limiter.set_limit(s.login_rate_limit)` + `ws_limiter.set_limit(s.max_conn_per_min)` 自动跟随。

**测试覆盖**：
- `rate_limiter_set_limit_takes_effect_immediately` — cap 从 0 改到 2，下两次通过第三次拒绝
- `rate_limiter_set_limit_keeps_inflight_burst` — 抬高 cap 时不会让在飞事件重置（避免"反悔"接受已拒绝的请求）

## 7. TunnelManager::bind_state 从 no-op 升级

**现象**：原本 `bind_state(&self, ...)` 是空壳（`let _ = ...`），`TunnelManager` 拿不到 cross-component 引用做 anti-scan。

**修法**：改 `&mut self` + 接收 `Arc<RateLimiter>` / `Arc<BlacklistManager>` / `Arc<StateStore>`：

```rust
pub fn bind_state(
    &mut self,
    _device_mgr: Arc<DeviceManager>,
    _authorized_senders: Arc<DashMap<...>>,
    port_limiter: Arc<RateLimiter>,
    blacklist: Arc<BlacklistManager>,
    state_store: Arc<StateStore>,
) { ... }
```

调用方（`AppState::with_store_and_limits`）在 `Arc<TunnelManager>` 刚构造、strong count=1 时用 `Arc::get_mut` 拿 `&mut`：
```rust
let mut tunnel_mgr = Arc::new(TunnelManager::new(crypto.clone(), settings.clone()));
// ... build login_limiter, ws_limiter, blacklist
Arc::get_mut(&mut tunnel_mgr)
    .expect("tunnel_mgr just constructed; no other Arc references")
    .bind_state(device_mgr.clone(), authorized_senders.clone(),
                ws_limiter.clone(), blacklist.clone(), state_store.clone());
```

**反例**：直接 `tunnel_mgr.bind_state(...)`（`tunnel_mgr` 是 `Arc`）会编不过 — Arc 拿不到 `&mut self`。

## 8. ext conn 死锁：select! biased 不打破 read 阻塞

**现象**：测试 `dispatch_from_agent_writes_to_ext_conn` 偶发 read timeout 2s 后 panic（不是稳定的 n=14/15 错位）。

**根因**：`ext conn task` 用 `tokio::select! { biased; msg = rx.recv() => ..., read = stream.read(...) => ... }`。`biased` 只在**两者都 ready**时选 mpsc 优先；**当只有 stream.read 阻塞时**，select 不能切到 mpsc 分支。
- client 端 read 等 server 写
- server 端 ext conn task 阻塞在 stream.read 等 client 写
- dispatch 写 mpsc，但 ext conn task 卡在 stream.read 上，永远轮不到 select mpsc
- 死锁

**修法**：让 client 先发 1 字节"k" 触发 stream.read 返回 Ok(1)，ext conn task 跳出该分支、回到 select 顶部、命中 mpsc：
```rust
s.write_all(b"k").await.unwrap();   // 打破死锁
let mut buf = vec![0u8; 32];
let n = s.read(&mut buf).await;
```

**测试断言技巧**：dispatch 测试读 15 字节 = `b"ping-from-agent"`（15 字符，不是 14！），加 `&buf[..15] == b"ping-from-agent"`。手数字符串容易错，建议断言后注释字符数。

## 9. StateStore 在 helper 中跨实例 settings 不共享

**现象**：`mgr_with_acl(1, 0, vec!["10.0.0.0/24"])` 测试，IP 在白名单但仍被限流。

**根因**：`TunnelManager::settings` 是构造时传入的独立 `Arc<RwLock<ServerSettings>>`；`state_store.update_settings` 只改 `state_store` 内部的 settings，不影响 manager 持有的。

**修法**：构造 manager 时创建 `shared_settings` 变量，先改它再传入；`state_store` 用于 device whitelist lookup 不需要管 global：
```rust
let shared_settings = settings();
shared_settings.write().global_whitelist = global_whitelist;
let mut m = TunnelManager::new(crypto, shared_settings.clone());
```

## 10. 端口防扫描限流复用 `max_conn_per_min`（Go parity）

**对齐点**：Go server 的 `s.portLimiter` 和 `s.connLimiter` 都用 `settings.MaxConnPerMin` 初始化，**同一个**值同时控制 WS 连接和外部 tunnel 连接。

**Rust 实现**：`AppState` 中 `ws_limiter` 兼任 anti-scan limiter，注入到 `TunnelManager::bind_state(port_limiter = ws_limiter.clone())`。`PUT /api/settings` 改 `max_conn_per_min` 时 `ws_limiter.set_limit` 立即生效，anti-scan 自动跟随。

**逻辑链（与 Go `tunnel.go:557` 完全对齐）**：
```
loopback (127.0.0.1, ::1) → bypass
  ↓
blacklist.contains(ip) → reject + close
  ↓
global_whitelist.contains(ip) → bypass
  ↓
device_whitelist.contains(ip) → bypass
  ↓
port_limiter.allow(ip) → reject + close + add_violation
```

`add_violation` 在 threshold 到达时自动晋升 IP 到全局 blacklist。

## 11. CI 集成要点（`.github/workflows/rust-remote.yml`）

- **矩阵单线程但双 profile**：`cargo test --workspace`（debug）+ `cargo test --workspace --release`（捕获 release-only 行为差异）
- **缓存**：`Swatinem/rust-cache@v2` + `workspaces: rust-remote -> target` 把 target 目录跨 job 复用，节省 5+ 分钟
- **RUSTFLAGS=-D warnings**：让 CI 把 warning 当 error，跟 `clippy -D warnings` 一致
- **e2e 走 Windows runner**：PS5.1 脚本只能在 Windows 跑（pwsh linux 6+ 不支持 `Get-NetTCPConnection` / `Test-NetConnection`）
- **path filter 避免无谓触发**：`paths:` 限定 `rust-remote/**` `cmd/**` `internal/**` `go.mod/sum` `rust-remote.yml` — 修改 docs 不跑 CI
- **heartbeat 参数**：CI 至少给 3 次心跳 × 30s + 余量，避免 Go server `pendingLoop` 时序失败

## 12. cargo build 跨 workspace 路径

CI 在根 `E:\AI-work\go-remote` checkout，cargo build/test 需要 `working-directory: rust-remote`。Swatinem cache 的 `workspaces: rust-remote -> target` 显式声明子项目 target 路径，跨 step 复用 hash。
