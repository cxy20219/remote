# 客户端 (Agent) 测试方案

## 1. 测试策略

| 层级 | 范围 | 测试方式 |
|------|------|----------|
| 单元测试 | Reconnect 等独立组件 | 直接调用函数，mock 外部依赖 |
| 集成测试 | Agent 与 Mock 服务端交互 | httptest + websocket |
| 端到端测试 | Agent 与真实服务端连接 | 启动真实服务，完整流程 |

## 2. 单元测试

### Reconnect 重连机制

```go
func TestReconnect_ShouldRetry(t *testing.T) {
    tests := []struct {
        maxAttempts, attempts int
        want                 bool
    }{
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

func TestReconnect_Backoff(t *testing.T) {
    r := &Reconnect{interval: 5 * time.Second, maxInterval: 60 * time.Second}
    r.beforeRetry()
    // 验证指数退避计算
}
```

### Handler 消息处理

```go
func TestHandler_HandleRegisterOK(t *testing.T) {
    handler := &Handler{}
    msg := &Message{
        Type:    "register_ok",
        Payload: json.RawMessage(`{"client_id":"abc-123"}`),
    }
    clientID, _ := handler.HandleRegisterOK(msg)
    if clientID != "abc-123" {
        t.Errorf("got %s", clientID)
    }
}

func TestHandler_HandleTunnelOpenAck(t *testing.T) {
    handler := &Handler{agent: &Agent{tunnels: make(map[string]*Tunnel)}}
    msg := &Message{
        Type:    "tunnel_open_ack",
        Payload: json.RawMessage(`{"tunnel_id":"t1","public_port":15001,"success":true}`),
    }
    ack := handler.HandleTunnelOpenAck(msg)
    if !ack.Success || ack.PublicPort != 15001 {
        t.Error("expected success with port 15001")
    }
}
```

## 3. 集成测试

### Mock WebSocket 服务端

```go
type MockServer struct {
    Server           *httptest.Server
    WSURL            string
    receivedMessages []*Message
    mu               sync.Mutex
}

func NewMockServer(authKey string) *MockServer {
    ms := &MockServer{receivedMessages: make([]*Message, 0)}
    mux := http.NewServeMux()
    mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
        websocket.Handler(ms.handleConnection).ServeHTTP(w, r)
    })
    ms.Server = httptest.NewServer(mux)
    ms.WSURL = "ws" + ms.Server.URL[4:] + "/ws"
    return ms
}
```

### Agent 连接测试

```go
func TestIntegration_ConnectAndRegister(t *testing.T) {
    mockServer := NewMockServer("test-key")
    defer mockServer.Close()

    agent := NewAgent(&Config{
        Server: ServerConfig{Address: mockServer.WSURL},
        Auth:   AuthConfig{Key: "test-key"},
    })
    if err := agent.Connect(); err != nil {
        t.Fatalf("failed to connect: %v", err)
    }
    defer agent.Close()
}
```

## 4. 端到端测试

```go
func TestE2E_Reconnect(t *testing.T) {
    server := startRealServer(t, "test-key", 0)
    serverPort := server.Port

    agent := NewAgent(&Config{
        Server: ServerConfig{Address: fmt.Sprintf("127.0.0.1:%d", serverPort)},
        Auth:   AuthConfig{Key: "test-key"},
        Reconnect: ReconnectConfig{Interval: 1, MaxAttempts: 10},
    })

    go agent.Run()
    time.Sleep(500 * time.Millisecond)

    server.Stop()
    time.Sleep(500 * time.Millisecond)

    newServer := startRealServer(t, "test-key", serverPort)
    defer newServer.Stop()

    time.Sleep(2 * time.Second)
    if len(newServer.GetClients()) != 1 {
        t.Error("agent should have reconnected")
    }
    agent.Stop()
}
```

## 5. 运行测试

```bash
go test -v ./internal/agent/...
go test -v ./internal/agent/... -run "Unit"
go test -v ./internal/agent/... -run "Integration"
go test -coverprofile=coverage.out ./internal/agent/...
```

## 6. 覆盖目标

| 组件 | 覆盖率目标 |
|------|-----------|
| Reconnect | 85%+ |
| Handler | 85%+ |
| TunnelManager | 85%+ |
| Config | 90%+ |