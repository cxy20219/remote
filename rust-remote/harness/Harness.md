# rust-remote (Rust 重构) 项目总览

> 子项目：`go-remote` 的 Rust 重构，wire 协议与 Go 实现字节级兼容（可互通）。
> 状态：Phase 1–7 完成 + 跨语言 e2e 互通（register / approve / ECDH enc_key 持久化）+ 端口防扫描限流 + CI 自动化。

## 关键约束

- **跨语言兼容优先**：所有 wire 消息、API 路由、cookie 名、状态文件 shape 都必须与 Go server 字节级一致。改动时优先回看 `harness/references/zero-config-design.md` 和 `harness/references/tunnel-design.md`。
- **零配置架构**：Agent 无需预配置 — 启动时发 `register` 消息，由 admin 通过 Web UI 审批。
- **加密链路**：ECDH (X25519) 派生 shared secret → HKDF-SHA256 → AES-256-GCM；ECDH 参数命名 `goremote-enc-key-exchange-v1`（必须用 HKDF 的 `salt=info`、`secret=shared`，与 Go 端 `hkdf.New(hash, secret, info=string)` 对齐）。
- **Cookie 名**：`go_remote_token`（不是 `tunnel_admin`）。
- **端口防扫描限流**：与 Go `s.portLimiter` 一致，复用 `max_conn_per_min`；逻辑链 `loopback → blacklist → global whitelist → device whitelist → limiter`；超限 `add_violation` 累积到阈值自动入全局黑名单。
- **Rust 工具链**：rust 1.85+，依赖 `aws_lc_rs`（rustls 默认 crypto provider），不是 `ring`。

## 常用入口

- **编译**：`cargo build --workspace --release` → `target/release/tunnel-rs-server.exe` / `tunnel-rs-agent.exe`。
- **测试**：`cargo test --workspace`（95 unit + 11 integration，含 anti-scan / 大帧 / EOF / agent→ext / RateLimiter hot-reload）。
- **Lint**：`cargo clippy --workspace --all-targets -- -D warnings`（必须干净，CI 强约束）。
- **跨语言 e2e**：`powershell -File rust-remote/bin/test-rust-agent-against-go-server.ps1`。
- **CI**：`.github/workflows/rust-remote.yml`（cargo test debug+release + clippy + 跨语言 e2e Windows runner）。
- **配置文件**：`harness/assets/server.yaml.template` / `agent.yaml.template`（已废弃作参考）。
- **架构参考**：`rust-remote/README.md` + `rust-remote/crates/{common,server,agent}/src/lib.rs`。

## 目录结构

```
rust-remote/
├── Cargo.toml                  # workspace
├── crates/
│   ├── common/                 # 协议编解码 / ed25519 / x25519 / AES-256-GCM
│   ├── server/                 # axum 0.7 + tokio / StateStore / tunnel manager
│   └── agent/                  # tokio-tungstenite / identity / reconnect
├── bin/
│   └── test-rust-agent-against-go-server.ps1   # Go server + Rust agent e2e
└── target/release/             # 编译产物（4MB agent / 2.8MB server）
```

## 子项目资源

- [跨语言 e2e 互通流程](workflow/rust-remote-verify.md)
- [Rust 端口编译与 clippy 踩坑](experience/rust-remote-build-pitfalls.md)
- [PowerShell 5.1 跨语言脚本踩坑](experience/powershell-cross-lang-ps5.1.md)
- [rust-remote 设计要点](references/rust-remote-design.md)

## 与主项目的边界

`go-remote/` 根目录的 `harness/` 是 Go 实现的主资源系统。
`rust-remote/harness/` 是 Rust 重构的子项目资源。
两个系统的以下内容**不应重复**：协议设计、消息格式、配置 schema — 这些在主项目 `harness/references/` 已沉淀。Rust 端只写实现差异和坑点。
