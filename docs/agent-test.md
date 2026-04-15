# 客户端 (Agent) 测试方案

## 1. 测试策略

### 1.1 测试分层

| 层级 | 范围 | 测试方式 |
|------|------|----------|
| 单元测试 | Executor/Reconnect等独立组件 | 直接调用函数，mock外部依赖 |
| 集成测试 | Agent与Mock服务端交互 | httptest + websocket |
| 端到端测试 | Agent与真实服务端连接 | 启动真实服务，完整流程 |

### 1.2 测试框架

- **测试框架**: Go 标准库 `testing`
- **WebSocket测试**: `golang.org/x/net/websocket`
- **HTTP测试**: `net/http/httptest`

## 2. 单元测试

### 2.1 Executor 命令执行

```go
// internal/agent/executor_test.go

func TestExecutor_Execute(t *testing.T) {
    e := NewExecutor()

    tests := []struct {
        cmd     string
        wantOut string
        wantErr bool
    }{
        {"echo hello", "hello", false},
        {"exit 0", "", false},
    }

    for _, tt := range tests {
        t.Run(tt.cmd, func(t *testing.T) {
            result, err := e.Execute(tt.cmd, 10)
            if (err != nil) != tt.wantErr {
                t.Errorf("Execute() error = %v", err)
            }
            if !strings.Contains(result.Stdout, tt.wantOut) {
                t.Errorf("expected %q in stdout, got %q", tt.wantOut, result.Stdout)
            }
        })
    }
}

func TestExecutor_Execute_Timeout(t *testing.T) {
    e := NewExecutor()
    cmd := "sleep 10"
    if runtime.GOOS == "windows" {
        cmd = "timeout /t 10"
    }

    result, err := e.Execute(cmd, 1)
    if err == nil && result.ExitCode == 0 {
        t.Error("expected timeout error")
    }
}

func TestExecutor_Execute_CommandNotFound(t *testing.T) {
    e := NewExecutor()
    _, err := e.Execute("nonexistent-command-xyz", 10)
    if err == nil {
        t.Error("expected error for nonexistent command")
    }
}
```

### 2.2 Reconnect 重连机制

```go
// internal/agent/reconnect_test.go

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

    expected := r.interval
    if expected > r.maxInterval {
        expected = r.maxInterval
    }
    // 验证指数退避计算
}
```

### 2.3 Config 配置加载

```go
// internal/agent/config_test.go

func TestLoadConfig(t *testing.T) {
    tmpFile, _ := os.CreateTemp("", "agent-config-*.yaml")
    defer os.Remove(tmpFile.Name())

    tmpFile.WriteString(`
server:
  address: "192.168.1.100:8080"
auth:
  key: "my-secret-key"
`)
    tmpFile.Close()

    config, err := LoadConfig(tmpFile.Name())
    if err != nil {
        t.Fatalf("failed to load config: %v", err)
    }

    if config.Server.Address != "192.168.1.100:8080" {
        t.Errorf("got %s", config.Server.Address)
    }
    if config.Auth.Key != "my-secret-key" {
        t.Errorf("got %s", config.Auth.Key)
    }
}

func TestLoadConfig_FileNotFound(t *testing.T) {
    _, err := LoadConfig("/nonexistent/agent.yaml")
    if err == nil {
        t.Error("expected error")
    }
}
```

### 2.4 Handler 消息处理

```go
// internal/agent/handler_test.go

func TestHandler_HandleExec(t *testing.T) {
    handler := &Handler{executor: NewExecutor()}
    msg := &Message{
        Type:    "exec",
        Payload: json.RawMessage(`{"task_id":"t1","command":"echo test","timeout":10}`),
    }

    result, err := handler.HandleExec(msg)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.TaskID != "t1" || result.ExitCode != 0 {
        t.Errorf("unexpected result: %+v", result)
    }
}

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
```

## 3. 集成测试

### 3.1 Mock WebSocket 服务端

```go
// internal/agent/integration_test.go

type MockServer struct {
    Server  *httptest.Server
    WSURL   string
    receivedMessages []*Message
    mu      sync.Mutex
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

func (ms *MockServer) handleConnection(conn *websocket.Conn) {
    defer conn.Close()
    for {
        var msg Message
        if err := websocket.JSON.Receive(conn, &msg); err != nil {
            return
        }
        ms.mu.Lock()
        ms.receivedMessages = append(ms.receivedMessages, &msg)
        ms.mu.Unlock()

        switch msg.Type {
        case "register":
            var payload RegisterPayload
            json.Unmarshal(msg.Payload, &payload)
            clientID := "mock-client-" + uuid.New().String()
            websocket.JSON.Send(conn, Message{
                Type:    "register_ok",
                Payload: RegisterOKPayload{ClientID: clientID},
            })
        case "ping":
            websocket.JSON.Send(conn, Message{Type: "pong"})
        }
    }
}
```

### 3.2 Agent 连接测试

```go
func TestIntegration_ConnectAndRegister(t *testing.T) {
    mockServer := NewMockServer("test-key")
    defer mockServer.Close()

    agent := NewAgent(&Config{
        Server: ServerConfig{Address: mockServer.WSURL},
        Auth:   AuthConfig{Key: "test-key"},
        Agent:  AgentConfig{Hostname: "test-host", OS: "linux"},
    })

    if err := agent.Connect(); err != nil {
        t.Fatalf("failed to connect: %v", err)
    }
    defer agent.Close()

    // 验证注册消息
    msgs := mockServer.receivedMessages
    var registerMsg *Message
    for _, msg := range msgs {
        if msg.Type == "register" {
            registerMsg = msg
            break
        }
    }
    if registerMsg == nil {
        t.Fatal("register message not found")
    }
}

func TestIntegration_Heartbeat(t *testing.T) {
    mockServer := NewMockServer("test-key")
    defer mockServer.Close()

    agent := NewAgent(&Config{
        Server:  ServerConfig{Address: mockServer.WSURL},
        Auth:    AuthConfig{Key: "test-key"},
        Heartbeat: HeartbeatConfig{Interval: 1},
    })

    agent.Connect()
    defer agent.Close()

    time.Sleep(2500 * time.Millisecond)

    pingCount := 0
    for _, msg := range mockServer.receivedMessages {
        if msg.Type == "ping" {
            pingCount++
        }
    }
    if pingCount < 2 {
        t.Errorf("expected at least 2 pings, got %d", pingCount)
    }
}
```

## 4. 端到端测试

### 4.1 命令执行与重连

```go
// internal/agent/e2e_test.go

func TestE2E_CommandExecution(t *testing.T) {
    server := startRealServer(t, "test-key", 0)
    defer server.Stop()

    agent := NewAgent(&Config{
        Server: ServerConfig{Address: fmt.Sprintf("127.0.0.1:%d", server.Port)},
        Auth:   AuthConfig{Key: "test-key"},
        Agent:  AgentConfig{Hostname: "e2e-agent", OS: runtime.GOOS},
    })

    errCh := make(chan error, 1)
    go func() { errCh <- agent.Run() }()
    time.Sleep(500 * time.Millisecond)

    if len(server.GetClients()) != 1 {
        t.Fatal("agent not connected")
    }

    agent.Stop()
}

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
    if len(server.GetClients()) != 1 {
        t.Fatal("agent not connected")
    }

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

## 5. 测试辅助工具

```go
// internal/agent/testutil.go

func NewTestConfig() *Config {
    return &Config{
        Server: ServerConfig{Address: "localhost:9999", TLS: TLSConfig{Enabled: false}},
        Auth:   AuthConfig{Key: "test-key"},
        Agent:  AgentConfig{Hostname: "test-agent", OS: runtime.GOOS},
        Heartbeat: HeartbeatConfig{Interval: 30},
        Reconnect: ReconnectConfig{Interval: 5, MaxAttempts: 0, MaxInterval: 60},
    }
}

type CapturingExecutor struct {
    *Executor
    Results []*Result
    mu      sync.Mutex
}

func (ce *CapturingExecutor) Execute(cmd string, timeout int) (*Result, error) {
    result, err := ce.Executor.Execute(cmd, timeout)
    ce.mu.Lock()
    ce.Results = append(ce.Results, result)
    ce.mu.Unlock()
    return result, err
}
```

## 6. 测试覆盖率目标

| 组件 | 覆盖率目标 |
|------|-----------|
| Executor | 90%+ |
| Reconnect | 85%+ |
| Handler | 85%+ |
| Config | 90%+ |
| 整体客户端 | 80%+ |

## 7. 运行测试

```bash
# 运行所有测试
go test -v ./internal/agent/...

# 按类型运行
go test -v ./internal/agent/... -run "Unit"
go test -v ./internal/agent/... -run "Integration"

# 跳过耗时测试
go test -v -short ./internal/agent/...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./internal/agent/...
go tool cover -html=coverage.out -o coverage.html
```

## 8. 跨平台测试注意事项

```go
// Windows 命令映射
var windowsCommands = map[string]string{
    "pwd":      "cd",
    "sleep":    "timeout /t",
    "ls":       "dir",
    "cat":      "type",
    "ps":       "tasklist",
    "ifconfig": "ipconfig",
}

func TestExecutor_WindowsCommands(t *testing.T) {
    if runtime.GOOS != "windows" {
        t.Skip("windows-specific test")
    }
    e := NewExecutor()
    for _, winCmd := range windowsCommands {
        result, _ := e.Execute(winCmd+" /?", 5)
        if result.ExitCode != 0 {
            t.Errorf("%s failed", winCmd)
        }
    }
}
```
