# 服务端测试方案

## 1. 测试策略

| 层级 | 范围 | 测试方式 |
|------|------|----------|
| 单元测试 | 各个组件独立功能 | 直接调用函数，mock 依赖 |
| 集成测试 | 多组件协作 | 启动真实服务，模拟客户端 |
| 端到端测试 | 完整流程 | 启动真实服务端和客户端 |

## 2. 单元测试

### ClientManager 测试

```go
func TestClientManager_Add(t *testing.T) {
    m := NewClientManager()
    client := &Client{ClientID: "test-001"}
    m.Add(client)
    got := m.Get("test-001")
    if got == nil || got.ClientID != "test-001" {
        t.Errorf("expected client test-001, got %v", got)
    }
}

func TestClientManager_Remove(t *testing.T) {
    m := NewClientManager()
    m.Add(&Client{ClientID: "test-001"})
    m.Remove("test-001")
    if m.Get("test-001") != nil {
        t.Errorf("expected nil after remove")
    }
}

func TestClientManager_List(t *testing.T) {
    m := NewClientManager()
    m.Add(&Client{ClientID: "c1"})
    m.Add(&Client{ClientID: "c2"})
    if len(m.List()) != 2 {
        t.Errorf("expected 2 clients")
    }
}
```

### Handler 测试

```go
func TestHandler_HandleRegister(t *testing.T) {
    server, client := setupTestServerAndClient(t)
    defer teardownTestServer(server)

    err := client.WriteJSON(Message{
        Type: "register",
        Payload: RegisterPayload{Key: "valid-key", Hostname: "test", OS: "linux"},
    })
    // 验证返回 register_ok
}
```

## 3. 集成测试

```go
func TestIntegration_ClientRegistration(t *testing.T) {
    server := startTestServer(t, "test-key")
    defer server.Stop()

    conn, _ := websocket.Dial(server.URL, "", "http://localhost/")
    defer conn.Close()

    websocket.JSON.Send(conn, Message{
        Type: "register",
        Payload: RegisterPayload{Key: "test-key", Hostname: "test", OS: "linux"},
    })

    var resp Message
    websocket.JSON.Receive(conn, &resp)
    if resp.Type != "register_ok" {
        t.Errorf("expected register_ok, got %s", resp.Type)
    }
}
```

## 4. 端到端测试

```go
func TestE2E_ClientLifecycle(t *testing.T) {
    server := startTestServer(t, "e2e-key")
    defer server.Stop()

    clients := make([]*websocket.Conn, 3)
    for i := 0; i < 3; i++ {
        conn := connectAndRegister(t, server, "e2e-key", fmt.Sprintf("client-%d", i), "linux")
        clients[i] = conn
        defer conn.Close()
    }

    onlineClients := server.GetClients()
    if len(onlineClients) != 3 {
        t.Errorf("expected 3 online clients, got %d", len(onlineClients))
    }
}
```

## 5. Mock 连接

```go
type mockConn struct {
    writeCalled *bool
    writeData   []byte
    mu          sync.Mutex
}

func (m *mockConn) Write(p []byte) (n int, err error) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.writeData = append(m.writeData, p...)
    if m.writeCalled != nil {
        *m.writeCalled = true
    }
    return len(p), nil
}
```

## 6. 运行测试

```bash
go test -v ./internal/server/...
go test -v ./internal/server/... -run "Unit"
go test -v ./internal/server/... -run "Integration"
go test -coverprofile=coverage.out ./internal/server/...
```

## 7. 覆盖目标

| 组件 | 覆盖率目标 |
|------|-----------|
| ClientManager | 90%+ |
| Handler | 85%+ |
| TunnelManager | 85%+ |
| Config | 90%+ |
| API | 85%+ |