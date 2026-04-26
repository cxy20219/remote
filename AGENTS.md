# AGENTS.md

## Build

```bash
# Server
go build -o bin/server.exe ./cmd/server

# Agent
go build -o bin/agent.exe ./cmd/agent
```

No Makefile. Binaries are placed in `bin/`.

## Test

```bash
# All server tests
go test -v ./internal/server/...

# All agent tests
go test -v ./internal/agent/...

# Coverage
go test -coverprofile=coverage.out ./internal/server/...
```

## Run

```bash
./bin/server.exe --config config/server.yaml
./bin/agent.exe --config config/agent.yaml
```

## Key Files

- `cmd/server/main.go` - Server entrypoint
- `cmd/agent/main.go` - Agent entrypoint
- `internal/common/message.go` - WebSocket message types (shared)
- `internal/server/` - Server: Gin HTTP + gorilla/websocket
- `internal/agent/` - Agent: command executor, reconnect logic
- `config/server.yaml`, `config/agent.yaml` - Config files

## Swagger

After server starts: `http://localhost:8080/swagger/index.html`

## Cross-Platform Notes

Agent tests use `runtime.GOOS` checks. Windows commands differ: `sleep` → `timeout /t`, `ls` → `dir`, etc.

## Important Context

- Module name is `goremote` (not `go-remote`)
- Go 1.26.2
- Design docs in `docs/` directory (server-design.md, agent-design.md, tunnel-design.md, etc.)
- Pre-compiled `.exe` files exist in root (not in bin/) - these are likely stale
