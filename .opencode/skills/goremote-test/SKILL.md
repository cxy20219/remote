---
name: goremote-test
description: GoRemote 测试技能。编写服务端/客户端单元测试、集成测试和端到端测试时使用。
compatibility: opencode
metadata:
  scope: project
---

# GoRemote 测试

## 职责

指导 GoRemote 服务端和客户端的测试编写，覆盖单元测试、集成测试和端到端测试。

## 触发场景

- 用户要求为服务端/客户端编写测试
- 运行 `go test` 遇到失败
- 需要 mock WebSocket 连接
- 需要 httptest + websocket 测试服务端

## 测试框架

- Go 标准库 `testing`
- `golang.org/x/net/websocket` - WebSocket 测试
- `net/http/httptest` - HTTP 测试

## 服务端测试

### 单元测试

**ClientManager** (`internal/server/client_test.go`)：

```go
func TestClientManager_Add(t *testing.T) {
    m := NewClientManager()
    m.Add(&Client{ClientID: "test-001"})
    got := m.Get("test-001")
    if got == nil || got.ClientID != "test-001" {
        t.Errorf("expected client test-001")
    }
}
```

**Handler** (`internal/server/handler_test.go`)：
```go
func TestHandler_HandleRegister(t *testing.T) {
    server, client := setupTestServerAndClient(t)
    defer teardownTestServer(server)
    // 发送 register，检查返回 register_ok
}
```

### 集成测试

```go
func TestIntegration_ClientRegistration(t *testing.T) {
    server := startTestServer(t, "test-key")
    defer server.Stop()
    conn, _ := websocket.Dial(server.URL, "", "http://localhost/")
    // 发送 register，验证 register_ok
}
```

## 客户端测试

### Reconnect 测试

```go
func TestReconnect_ShouldRetry(t *testing.T) {
    tests := []struct{ maxAttempts, attempts int; want bool }{
        {0, 100, true},   // 无限重试
        {5, 3, true},     // 限制内
        {5, 5, false},    // 达限
    }
    for _, tt := range tests {
        r := &Reconnect{maxAttempts: tt.maxAttempts, attempts: tt.attempts}
        if got := r.shouldRetry(); got != tt.want {
            t.Errorf("shouldRetry() = %v, want %v", got, tt.want)
        }
    }
}
```

### Mock Server

```go
type MockServer struct {
    Server           *httptest.Server
    receivedMessages []*Message
}
func NewMockServer(authKey string) *MockServer { ... }
```

## 运行测试

```bash
# 所有测试
go test -v ./internal/server/...
go test -v ./internal/agent/...

# 按类型运行
go test -v ./internal/server/... -run "Unit"
go test -v ./internal/server/... -run "Integration"

# 覆盖率
go test -coverprofile=coverage.out ./internal/server/...
```

## 覆盖目标

| 组件 | 目标 |
|------|------|
| ClientManager | 90%+ |
| Handler | 85%+ |
| TunnelManager | 85%+ |
| Reconnect | 85%+ |
| 整体 | 80%+ |

## 文件索引

- [服务端测试方案](references/server-test.md)：详细测试代码示例
- [客户端测试方案](references/agent-test.md)：Agent 测试详解
- [SSH隧道测试用例](references/ssh-tunnel-test-cases.md)：完整测试用例表