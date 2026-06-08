# Changelog

All notable changes to `tunnel-rs-server` and `tunnel-rs-agent` are
documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- **Admin API now requires a session cookie.** Every `/api/*` endpoint
  except `/login`, `/logout`, and `/check-auth` is wrapped by
  `require_session` middleware; an unauthenticated request returns
  `401 Unauthorized` (was: 200 to anyone).
- **Agent private key material no longer leaks to stdout.** The
  `install_enc_key` debug path was removed; decryption failures use
  `tracing::debug!` (release builds: no log).
- **WS frames are bounded at 2 MB.** The reader loop in `ws.rs` closes
  the connection on any text or binary frame larger than
  `MAX_WS_MESSAGE_SIZE`.

### Fixed
- **State is now actually persisted.** `main.rs` calls
  `StateStore::load_or_init` and starts the 3-second background sync
  loop. Settings, devices, and tunnels survive a restart.
- **Settings hot-reload works end-to-end.** `PUT /api/settings` updates
  the `RateLimiter` caps and the `BlacklistManager` threshold via
  `AtomicU32` stores — no restart required.
- **`tunnel update` returns 405, not 500.** The previously-unimplemented
  endpoint now signals "method not allowed" so front-ends can branch
  cleanly.

### Added
- `--data-dir` CLI flag (env `TUNNEL_RS_DATA_DIR`, default `./data`)
  for explicit state-file location.
- `CreateTunnel` now enforces `max_tunnels_per_client` (configurable
  via `ServerSettings`).
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- 115 unit + 11 integration tests (debug + release profiles).
- Cross-language e2e script: `bin/test-rust-agent-against-go-server.ps1`.
- Graceful shutdown on `SIGTERM` and `Ctrl-C` (final state flush + sync
  loop abort, ≤ 30 s).
- `proptest` fuzzing on the binary frame codec (768 cases / run).
- `reconnect_storm_does_not_oom_server` and
  `expired_session_is_rejected_by_admin_endpoint` integration tests.
- `/healthz` (liveness) and `/readyz` (readiness) endpoints.
- `RUST_LOG_FORMAT=json` toggles structured JSON logs for container
  aggregators.
- `TraceLayer` emits per-request spans with `request_id` (UUID v4),
  `status`, and `latency_ms` fields.
- CI: macOS (`macos-latest`) and musl static-build jobs.

### Changed
- Wire format docs (`harness/references/rust-remote-design.md`) now
  accurately describe the `tunnel_data_bin` frame: 10-byte header
  (`[u8 ver][u8 flags][u16 BE tid_len][u16 BE cid_len][u32 BE data_len]`)
  plus UTF-8 strings and the data segment. The previous diagram
  (fixed-length binary fields) was wrong and contradicted both the Go
  reference and the implementation.
- `TunnelManager::bind_state` lost its unused `device_mgr` and
  `authorized_senders` parameters; the redundant `let _ = placeholder`
  gotchas are gone.
- All cryptographic random sources (`CryptoManager::encrypt`,
  `CryptoContext::encrypt`, admin password, session token) now use
  `OsRng` rather than `thread_rng` for consistency and PRNG-state
  independence.

### Removed
- `send_to_server_eof` double-encoded the EOF frame; the second encode
  was deleted.
- `WorkCmd::Binary` variant + its match arm in `agent.rs` (the writer
  loop uses `binary_rx` directly).
- `_typecheck` import-stub in `api/mod.rs` (and the now-unused
  `BlacklistManager` import).
- `health()` handler in `api/mod.rs` (the inline closure in `main.rs`
  already serves `/healthz`).
- `start_sync_loop` empty stub and `flush_notify: Notify` field in
  `persist.rs` (the real loop lives in `start_sync_loop_with_handle`).

## [0.1.0] - 2026-01-15

### Added
- Initial Rust port of `go-remote`. Wire protocol byte-compatible with
  the Go server, so a Go server can interop with a Rust agent and
  vice versa.
- Zero-config device registration with admin approval workflow.
- ECDH (X25519) + HKDF-SHA256 + AES-256-GCM per-device encryption.
- Rate limiting on `POST /api/login` and `GET /ws`.
- Port anti-scanning limiter (Go parity: `s.portLimiter`).
- In-memory session pool (24 h TTL, LRU 64).
- Bcrypt admin password hashing.
- 95 unit + 9 integration tests across `common`, `server`, and
  `agent` crates.
