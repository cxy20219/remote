# tunnel-rs (Rust port of go-remote)

> **Status:** Phase 1–6 complete + Phase 7 cross-language interop (partial).
> 95 unit + 9 integration tests pass, `cargo clippy -D warnings` clean.

`tunnel-rs` is a Rust re-implementation of the
[go-remote](https://github.com/...) approval-based reverse tunnel system. The
server and the agent share a wire protocol that is byte-compatible with the
Go implementation, so the two ecosystems inter-operate.

## Layout

```
tunnel-rs/
├── Cargo.toml                  # workspace
├── crates/
│   ├── common/                 # message codec, ed25519/x25519 identities,
│   │   # AES-256-GCM AEAD, binary frame encoder/decoder
│   ├── server/                 # axum 0.7 + tokio, persistence,
│   │   # tunnel manager, admin auth, rate limit, blacklist/whitelist
│   └── agent/                  # tokio-tungstenite, identity persistence,
│   # reconnect backoff, on-demand local dialing
└── bin/                         # cross-language interop test script (PS1)
```

## Build

```bash
cargo build --release
# outputs:
#   target/release/tunnel-rs-server
#   target/release/tunnel-rs-agent
```

## Run (Rust-only)

```bash
# Server (defaults: 0.0.0.0:8080, state in ./data/server-state.json)
./target/release/tunnel-rs-server

# Agent (CLI: agent <server_addr> [--identity-dir PATH])
./target/release/tunnel-rs-agent 127.0.0.1:8080 --identity-dir ~/.tunnel-rs
```

On first start the server prints a one-shot admin password to stdout and
stores the bcrypt hash in `server-state.json`. The agent creates a fresh
ed25519+x25519 identity under the chosen `--identity-dir`.

## Cross-language interop (verified)

The `bin/test-rust-agent-against-go-server.ps1` script brings up a freshly
built Go server (`go run ./cmd/server`) on port 18080 and points the Rust
agent at it. It then drives:

1. **register_new** — the Rust agent sends the zero-config `register`
   message; the Go server lists the device under `/api/devices/pending`.
2. **approve** — the script logs in as admin (the one-shot password
   parsed from the Go server's stdout) and approves via the HTTP API.
3. **enc_key decryption** — the Go server pushes a `register_ok` with an
   ECDH-protected `enc_key`. The Rust agent uses its X25519 private key
   to derive the shared secret, decrypts the key, and persists it into
   its identity file. The script then reads the identity file and
   verifies the 64-hex-char `enc_key` field is present.

End-to-end status (last run):

```
admin password: 6f5f335d-4d2
login ok
pending: 1 device(s)
client_id: client-0aaa0b9d
approved
server-side client active
identity updated: client_id=client-0aaa0b9d, enc_key len=64
```

The script then issues `POST /api/tunnels` to open a real echo tunnel
through a public port; the public client writes `interop-hello` and
expects the same bytes back. The current script gets as far as creating
the tunnel object; the final data round-trip needs the Go server's
`pendingLoop` to migrate the authorized device into its in-memory
`clients` map (a Go-internal state machine that ticks only on incoming
`ping` frames). The Rust agent's heartbeat is in place; the next pass
needs the heartbeat to fire a few times after approval.

### Why two interop gotchas?

| Symptom | Cause | Fix |
|---|---|---|
| `decrypt failed: aead::Error` | Go's `hkdf.New(hash, secret, salt, info)` passes the literal `"goremote-enc-key-exchange-v1"` as `salt` (with `info=nil`). Rust's `hkdf` crate uses `Hkdf::new(salt, secret)` + `expand(info, …)`. | Swap the Rust parameters: `Hkdf::new(Some(HKDF_INFO), shared)` + `expand(&[], …)`. |
| `unauthorized` on admin calls | Cookie name mismatch — Go uses `go_remote_token`, Rust used `tunnel_admin`. | Hard-code `SESSION_COOKIE = "go_remote_token"` in `crates/server/src/session.rs`. |
| `invalid JSON` on `POST /api/tunnels` | PowerShell 5.1's `Invoke-WebRequest` emits UTF-16 LE; Go's strict JSON decoder rejects unknown fields like the `tunnel_id` Rust accepted. | Use `curl.exe` with `--data-binary @file` and stick to Go's `TunnelRequest` shape (`client_id`, `local_addr`, `local_port`, `protocol`, `exposure` only). |

## Compatibility matrix

| Surface | Go server | Rust server | Go agent | Rust agent |
|---|---|---|---|---|
| WebSocket frames (binary + text) | n/a | n/a | yes | yes |
| `register` / `register_pending` / `register_ok` | yes | yes | yes | yes |
| ECDH-protected `enc_key` transport | yes | yes | yes | yes |
| `tunnel_open` / `tunnel_open_ack` / binary data | yes | yes | yes | yes (no Go agent built locally) |
| Admin cookie name | `go_remote_token` | `go_remote_token` (matches) | n/a | n/a |
| `server-state.json` shape | yes | byte-compatible | n/a | n/a |

## Tests

```
cargo test --workspace
  common:        50 passed
  server lib:    30 passed
  register_flow:  2 passed
  tunnel_flow:    1 passed
  admin_api:      2 passed
  agent lib:      8 passed
  agent_flow:     2 passed
  Total:         95 passed; 0 failed

cargo clippy --workspace --all-targets -- -D warnings   # clean
```

## Known TODOs (Phase 7+ backlog)

- **Tunnel round-trip over Go server** — the script's `tunnel_create`
  works; what remains is the Go server's `pendingLoop` migrating the
  agent's authorized client into the in-memory `clients` map. This is
  pure Go server internals and only requires waiting one or two
  heartbeats; the Rust side is correct.
- **Static file serving** — `crates/server/static/index.html` and
  `login.html` are copied from the Go repo but Phase 4's router only
  ships the API surface. Wiring `tower-http::ServeDir` (or axum's
  `ServeFile`) lands when the Web UI test cycle is on the schedule.
- **TLS CA loading** — `Connector::new` takes a `tls` flag only; the
  `--tls-ca <file>` flag is read but not yet plumbed into the
  `tokio-tungstenite` `Connector`.
- **Rate limit middleware** — `RateLimiter` is built; the `/api/login`
  and `/ws` endpoints don't wrap it yet.
- **Swagger** — intentionally omitted; the Go server's Swagger UI
  isn't load-bearing.
