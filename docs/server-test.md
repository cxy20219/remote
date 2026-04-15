# 服务端测试方案

## 1. 测试策略

### 1.1 测试分层

| 层级 | 范围 | 测试方式 |
|------|------|----------|
| 单元测试 | 各个组件独立功能 | 直接调用函数，mock依赖 |
| 集成测试 | 多组件协作 | 启动真实服务，模拟客户端 |
| 端到端测试 | 完整流程 | 启动真实服务端和客户端 |

### 1.2 测试框架

- **测试框架**: Go 标准库 `testing`
- **WebSocket测试**: `golang.org/x/net/websocket`
- **HTTP测试**: `net/http/httptest`
- **Mock**: 使用接口和 mock 对象

## 2. 单元测试

### 2.1 ClientManager 客户端管理

```go
// internal/server/client_test.go

func TestClientManager_Add(t *testing.T) {
    m := NewClientManager()
    client := &Client{
        ClientID: "test-001",
        Hostname: "test-host",
        OS:       "linux",
    }

    m.Add(client)

    got := m.Get("test-001")
    if got == nil || got.ClientID != "test-001" {
        t.Errorf("expected client test-001, got %v", got)
    }
}

func TestClientManager_Remove(t *testing.T) {
    m := NewClientManager()
    client := &Client{ClientID: "test-001"}

    m.Add(client)
    m.Remove("test-001")

    got := m.Get("test-001")
    if got != nil {
        t.Errorf("expected nil after remove, got %v", got)
    }
}

func TestClientManager_List(t *testing.T) {
    m := NewClientManager()
    m.Add(&Client{ClientID: "c1"})
    m.Add(&Client{ClientID: "c2"})
    m.Add(&Client{ClientID: "c3"})

    list := m.List()
    if len(list) != 3 {
        t.Errorf("expected 3 clients, got %d", len(list))
    }
}

func TestClientManager_Broadcast(t *testing.T) {
    m := NewClientManager()

    // 创建两个 mock 连接
    var conn1Called, conn2Called bool
    m.Add(&Client{
        ClientID: "c1",
        Conn:     &mockConn{writeCalled: &conn1Called},
    })
    m.Add(&Client{
        ClientID: "c2",
        Conn:     &mockConn{writeCalled: &conn2Called},
    })

    m.Broadcast([]byte("hello"))

    if !conn1Called || !conn2Called {
        t.Errorf("broadcast not called for all clients")
    }
}
```

### 2.2 TaskStore 任务管理

```go
// internal/server/task_test.go

func TestTaskStore_Create(t *testing.T) {
    store := NewTaskStore()
    task := &Task{
        TaskID:   "task-001",
        ClientID: "client-001",
        Command:  "ls -la",
        Timeout:  30,
        Status:   StatusPending,
    }

    store.Create(task)

    got := store.Get("task-001")
    if got == nil || got.Command != "ls -la" {
        t.Errorf("expected task with command 'ls -la', got %v", got)
    }
}

func TestTaskStore_Update(t *testing.T) {
    store := NewTaskStore()
    store.Create(&Task{TaskID: "task-001", Status: StatusPending})

    store.Update("task-001", StatusRunning)

    task := store.Get("task-001")
    if task.Status != StatusRunning {
        t.Errorf("expected status running, got %s", task.Status)
    }
}

func TestTaskStore_GetByClient(t *testing.T) {
    store := NewTaskStore()
    store.Create(&Task{TaskID: "t1", ClientID: "c1"})
    store.Create(&Task{TaskID: "t2", ClientID: "c1"})
    store.Create(&Task{TaskID: "t3", ClientID: "c2"})

    tasks := store.GetByClient("c1")
    if len(tasks) != 2 {
        t.Errorf("expected 2 tasks for client c1, got %d", len(tasks))
    }
}

func TestTaskStore_List(t *testing.T) {
    store := NewTaskStore()
    store.Create(&Task{TaskID: "t1"})
    store.Create(&Task{TaskID: "t2"})
    store.Create(&Task{TaskID: "t3"})

    tasks := store.List()
    if len(tasks) != 3 {
        t.Errorf("expected 3 tasks, got %d", len(tasks))
    }
}
```

### 2.3 Handler 消息处理

```go
// internal/server/handler_test.go

func TestHandler_HandleRegister(t *testing.T) {
    // 准备测试服务器和客户端
    server, client := setupTestServerAndClient(t)
    defer teardownTestServer(server)

    // 发送注册消息
    err := client.WriteJSON(Message{
        Type: "register",
        Payload: RegisterPayload{
            Key:     "valid-key",
            Hostname: "test-host",
            OS:      "linux",
        },
    })
    if err != nil {
        t.Fatalf("failed to send register: %v", err)
    }

    // 接收响应
    var resp Message
    err = client.ReadJSON(&resp)
    if err != nil {
        t.Fatalf("failed to read response: %v", err)
    }

    if resp.Type != "register_ok" {
        t.Errorf("expected register_ok, got %s", resp.Type)
    }
}

func TestHandler_HandleRegister_InvalidKey(t *testing.T) {
    server, client := setupTestServerAndClient(t)
    defer teardownTestServer(server)

    err := client.WriteJSON(Message{
        Type: "register",
        Payload: RegisterPayload{
            Key:     "invalid-key",
            Hostname: "test-host",
            OS:      "linux",
        },
    })
    if err != nil {
        t.Fatalf("failed to send register: %v", err)
    }

    var resp Message
    client.ReadJSON(&resp)

    if resp.Type != "register_fail" {
        t.Errorf("expected register_fail, got %s", resp.Type)
    }
}

func TestHandler_HandlePing(t *testing.T) {
    server, client := setupTestServerAndClient(t)
    defer teardownTestServer(server)

    // 先注册
    registerAndVerify(t, client, "valid-key")

    // 发送 ping
    err := client.WriteJSON(Message{Type: "ping"})
    if err != nil {
        t.Fatalf("failed to send ping: %v", err)
    }

    // 接收 pong
    var resp Message
    err = client.ReadJSON(&resp)
    if err != nil {
        t.Fatalf("failed to read pong: %v", err)
    }

    if resp.Type != "pong" {
        t.Errorf("expected pong, got %s", resp.Type)
    }
}
```

### 2.4 配置加载

```go
// internal/server/config_test.go

func TestLoadConfig(t *testing.T) {
    // 创建临时配置文件
    tmpFile, err := os.CreateTemp("", "config-*.yaml")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    defer os.Remove(tmpFile.Name())

    configContent := `
server:
  host: "127.0.0.1"
  port: 9999
auth:
  key: "test-key"
heartbeat:
  interval: 15
  timeout: 45
`
    tmpFile.WriteString(configContent)
    tmpFile.Close()

    config, err := LoadConfig(tmpFile.Name())
    if err != nil {
        t.Fatalf("failed to load config: %v", err)
    }

    if config.Server.Host != "127.0.0.1" {
        t.Errorf("expected host 127.0.0.1, got %s", config.Server.Host)
    }
    if config.Server.Port != 9999 {
        t.Errorf("expected port 9999, got %d", config.Server.Port)
    }
    if config.Auth.Key != "test-key" {
        t.Errorf("expected key test-key, got %s", config.Auth.Key)
    }
    if config.Heartbeat.Interval != 15 {
        t.Errorf("expected interval 15, got %d", config.Heartbeat.Interval)
    }
}

func TestLoadConfig_FileNotFound(t *testing.T) {
    _, err := LoadConfig("/nonexistent/config.yaml")
    if err == nil {
        t.Error("expected error for nonexistent file")
    }
}
```

## 3. 集成测试

### 3.1 WebSocket 连接和注册流程

```go
// internal/server/integration_test.go

func TestIntegration_ClientRegistration(t *testing.T) {
    // 启动测试服务器
    server := startTestServer(t, "test-key")
    defer server.Stop()

    // 连接到服务器
    conn, err := websocket.Dial(server.URL, "", "http://localhost/")
    if err != nil {
        t.Fatalf("failed to connect: %v", err)
    }
    defer conn.Close()

    // 发送注册
    err = websocket.JSON.Send(conn, Message{
        Type: "register",
        Payload: RegisterPayload{
            Key:     "test-key",
            Hostname: "integration-test",
            OS:      "linux",
        },
    })
    if err != nil {
        t.Fatalf("failed to send register: %v", err)
    }

    // 验证注册成功
    var resp Message
    err = websocket.JSON.Receive(conn, &resp)
    if err != nil {
        t.Fatalf("failed to receive response: %v", err)
    }

    if resp.Type != "register_ok" {
        t.Errorf("expected register_ok, got %s", resp.Type)
    }

    // 验证客户端出现在列表中
    clients := server.GetClients()
    if len(clients) != 1 {
        t.Errorf("expected 1 client, got %d", len(clients))
    }
}

func TestIntegration_InvalidKeyRegistration(t *testing.T) {
    server := startTestServer(t, "correct-key")
    defer server.Stop()

    conn, err := websocket.Dial(server.URL, "", "http://localhost/")
    if err != nil {
        t.Fatalf("failed to connect: %v", err)
    }
    defer conn.Close()

    // 使用错误密钥注册
    err = websocket.JSON.Send(conn, Message{
        Type: "register",
        Payload: RegisterPayload{
            Key:     "wrong-key",
            Hostname: "test",
            OS:      "linux",
        },
    })

    var resp Message
    websocket.JSON.Receive(conn, &resp)

    if resp.Type != "register_fail" {
        t.Errorf("expected register_fail, got %s", resp.Type)
    }
}
```

### 3.2 命令执行流程

```go
// internal/server/integration_test.go

func TestIntegration_CommandExecution(t *testing.T) {
    server := startTestServer(t, "test-key")
    defer server.Stop()

    // 连接并注册客户端
    clientConn := connectAndRegister(t, server, "test-key", "test-host", "linux")
    defer clientConn.Close()

    // 从服务端发送命令
    taskID := "task-integration-001"
    err := websocket.JSON.Send(clientConn, Message{
        Type: "exec",
        Payload: ExecPayload{
            TaskID:  taskID,
            Command: "echo hello",
            Timeout: 10,
        },
    })
    if err != nil {
        t.Fatalf("failed to send exec: %v", err)
    }

    // 客户端接收并处理命令（模拟）
    // 这里简化处理，实际测试时需要客户端也运行

    // 验证任务被创建
    task := server.GetTask(taskID)
    if task == nil {
        t.Errorf("task %s not found", taskID)
    }
}
```

### 3.3 心跳保活

```go
// internal/server/integration_test.go

func TestIntegration_Heartbeat(t *testing.T) {
    server := startTestServer(t, "test-key")
    defer server.Stop()

    conn := connectAndRegister(t, server, "test-key", "test-host", "linux")
    defer conn.Close()

    // 发送心跳
    for i := 0; i < 3; i++ {
        err := websocket.JSON.Send(conn, Message{Type: "ping"})
        if err != nil {
            t.Fatalf("failed to send ping: %v", err)
        }

        var resp Message
        err = websocket.JSON.Receive(conn, &resp)
        if err != nil {
            t.Fatalf("failed to receive pong: %v", err)
        }

        if resp.Type != "pong" {
            t.Errorf("expected pong, got %s", resp.Type)
        }

        time.Sleep(time.Second)
    }
}

func TestIntegration_HeartbeatTimeout(t *testing.T) {
    // 使用短超时配置启动服务器
    server := startTestServerWithTimeout(t, "test-key", 2*time.Second)
    defer server.Stop()

    conn := connectAndRegister(t, server, "test-key", "test-host", "linux")
    defer conn.Close()

    // 不发送心跳，等待超时
    time.Sleep(3 * time.Second)

    // 连接应该被关闭
    _, err := conn.Read([]byte{})
    if err == nil {
        t.Error("expected connection to be closed due to heartbeat timeout")
    }
}
```

## 4. 端到端测试

### 4.1 完整流程测试

```go
// internal/server/e2e_test.go

func TestE2E_FullWorkflow(t *testing.T) {
    // 启动服务端
    server := startTestServer(t, "e2e-key")
    defer server.Stop()

    // 启动多个客户端
    clients := make([]*websocket.Conn, 3)
    clientIDs := []string{"client-1", "client-2", "client-3"}

    for i := 0; i < 3; i++ {
        conn := connectAndRegister(t, server, "e2e-key", clientIDs[i], "linux")
        clients[i] = conn
        defer conn.Close()
    }

    // 验证所有客户端在线
    onlineClients := server.GetClients()
    if len(onlineClients) != 3 {
        t.Errorf("expected 3 online clients, got %d", len(onlineClients))
    }

    // 向每个客户端发送命令
    for i, clientID := range clientIDs {
        taskID := fmt.Sprintf("task-%d", i)
        err := server.SendCommand(clientID, taskID, "echo hello", 10)
        if err != nil {
            t.Errorf("failed to send command to %s: %v", clientID, err)
        }
    }

    // 等待命令执行
    time.Sleep(2 * time.Second)

    // 验证任务状态
    for i := range clientIDs {
        taskID := fmt.Sprintf("task-%d", i)
        task := server.GetTask(taskID)
        if task.Status != StatusCompleted {
            t.Errorf("task %s expected status completed, got %s", taskID, task.Status)
        }
    }
}
```

## 5. 测试工具

### 5.1 测试辅助函数

```go
// internal/server/testutil.go

func startTestServer(t *testing.T, authKey string) *TestServer {
    // 创建监听在随机端口的服务器
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("failed to listen: %v", err)
    }

    port := listener.Addr().(*net.TCPAddr).Port

    server := &TestServer{
        Listener: listener,
        Port:     port,
        URL:     fmt.Sprintf("ws://127.0.0.1:%d/ws", port),
    }

    // 在 goroutine 中启动服务器
    go func() {
        // 实际启动服务器的代码
    }()

    // 等待服务器启动
    time.Sleep(100 * time.Millisecond)

    return server
}

func connectAndRegister(t *testing.T, server *TestServer, key, hostname, os string) *websocket.Conn {
    conn, err := websocket.Dial(server.URL, "", "http://localhost/")
    if err != nil {
        t.Fatalf("failed to connect: %v", err)
    }

    err = websocket.JSON.Send(conn, Message{
        Type: "register",
        Payload: RegisterPayload{
            Key:     key,
            Hostname: hostname,
            OS:      os,
        },
    })
    if err != nil {
        conn.Close()
        t.Fatalf("failed to register: %v", err)
    }

    var resp Message
    err = websocket.JSON.Receive(conn, &resp)
    if err != nil || resp.Type != "register_ok" {
        conn.Close()
        t.Fatalf("failed to get register_ok: %v, resp: %v", err, resp)
    }

    return conn
}
```

### 5.2 Mock 连接

```go
// internal/server/mockconn.go

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

func (m *mockConn) Read(p []byte) (n int, err error) {
    return 0, io.EOF
}

func (m *mockConn) Close() error {
    return nil
}

func (m *mockConn) LocalAddr() net.Addr {
    return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (m *mockConn) RemoteAddr() net.Addr {
    return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}
```

## 6. 测试覆盖率目标

| 组件 | 覆盖率目标 |
|------|-----------|
| ClientManager | 90%+ |
| TaskStore | 90%+ |
| Handler | 85%+ |
| Config | 90%+ |
| 整体服务端 | 80%+ |

## 7. 运行测试

```bash
# 运行所有测试
go test -v ./internal/server/...

# 运行单元测试
go test -v ./internal/server/... -run "Unit"

# 运行集成测试
go test -v ./internal/server/... -run "Integration"

# 运行端到端测试
go test -v ./internal/server/... -run "E2E"

# 生成覆盖率报告
go test -coverprofile=coverage.out ./internal/server/...
go tool cover -html=coverage.out -o coverage.html
```
