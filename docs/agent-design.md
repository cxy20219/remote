# 客户端 (Agent) 设计文档

## 1. 功能概述

客户端是一个后台常驻程序（Agent），部署在需要被管理的机器上，负责：
- 与服务端建立WebSocket长连接
- 认证注册
- 接收并执行服务端下发的命令
- 返回命令执行结果
- 维持心跳保活

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                       Agent                                  │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Connector  │──│    Agent    │──│     Executor        │ │
│  │ (WebSocket) │  │  (主控)     │  │    (命令执行)       │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                │                    │              │
│         ▼                ▼                    ▼              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Reconnect  │  │   Handler   │  │      Logger        │ │
│  │  (重连)     │  │  (消息处理) │  │                    │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

| 组件 | 职责 |
|------|------|
| Connector | WebSocket连接管理，断线重连 |
| Agent | 主控逻辑，协调各组件 |
| Handler | 消息解析和路由 |
| Executor | 命令执行，跨平台兼容 |
| Logger | 日志记录 |

## 3. 消息协议

### 3.1 消息类型

| Type | 方向 | 描述 |
|------|------|------|
| register | C→S | 客户端注册 |
| register_ok | S→C | 注册成功 |
| register_fail | S→C | 注册失败 |
| exec | S→C | 服务端下发命令 |
| result | C→S | 客户端返回结果 |
| ping | C→S | 心跳请求 |
| pong | S→C | 心跳响应 |
| upload | S→C | 上传文件请求（服务端→客户端） |
| upload_data | S→C | 上传文件数据 |
| upload_complete | C→S | 上传完成确认 |
| download | C→S | 下载文件请求（客户端→服务端） |
| download_data | S→C | 下载文件数据 |
| download_complete | S→C | 下载完成确认 |

### 3.2 消息格式

**Payload 数据结构**：

```go
type RegisterPayload struct {
    Key      string `json:"key"`
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
}

type ExecPayload struct {
    TaskID  string `json:"task_id"`
    Command string `json:"command"`
    Timeout int    `json:"timeout"`
}

type UploadPayload struct {
    TaskID   string `json:"task_id"`
    FileID   string `json:"file_id"`
    Filename string `json:"filename"`
    Size     int64  `json:"size"`
    Offset   int64  `json:"offset"`
}

type UploadDataPayload struct {
    FileID string `json:"file_id"`
    Offset int64  `json:"offset"`
    Data   string `json:"data"`  // base64 encoded
    EOF    bool   `json:"eof"`
}

type UploadCompletePayload struct {
    FileID  string `json:"file_id"`
    Success bool   `json:"success"`
    Error   string `json:"error,omitempty"`
}

type DownloadPayload struct {
    TaskID   string `json:"task_id"`
    FileID   string `json:"file_id"`
    Filename string `json:"filename"`
    Offset   int64  `json:"offset"`
}

type DownloadDataPayload struct {
    FileID string `json:"file_id"`
    Offset int64  `json:"offset"`
    Data   string `json:"data"`  // base64 encoded
    EOF    bool   `json:"eof"`
}

type DownloadCompletePayload struct {
    FileID  string `json:"file_id"`
    Success bool   `json:"success"`
    Error   string `json:"error,omitempty"`
}
```

**发送的消息**：

```go
// 注册消息
{
  "type": "register",
  "key": "your-secret-key",
  "hostname": "server-01",
  "os": "linux"
}

// 心跳
{"type": "ping"}

// 执行结果
{
  "type": "result",
  "task_id": "uuid",
  "exit_code": 0,
  "stdout": "...",
  "stderr": ""
}
```

**接收的消息**：

```go
// 注册成功
{
  "type": "register_ok",
  "client_id": "uuid"
}

// 注册失败
{
  "type": "register_fail",
  "reason": "invalid key"
}

// 执行命令
{
  "type": "exec",
  "task_id": "uuid",
  "command": "ls -la /tmp",
  "timeout": 30
}

// 心跳响应
{"type": "pong"}
```

## 4. 详细设计

### 4.1 Connector 连接器

```go
type Connector struct {
    serverAddr string
    tlsEnabled bool
    authKey    string

    conn    *websocket.Conn
    mu      sync.Mutex
    done    chan struct{}
}

func (c *Connector) Connect() error
func (c *Connector) Close() error
func (c *Connector) Send(msg *Message) error
func (c *Connector) Receive() (*Message, error)
```

**主要职责**：
- 建立WebSocket连接
- 发送/接收消息
- TLS加密（可选）
- 连接关闭处理

### 4.2 Agent 主控

```go
type Agent struct {
    config     *Config
    connector  *Connector
    handler    *Handler
    executor   *Executor
    reconnect  *Reconnect
    hostname   string
    os         string
}

func (a *Agent) Run() error {
    for {
        if err := a.connect(); err != nil {
            log.Printf("connection failed: %v", err)
            if !a.reconnect.shouldRetry() {
                return err
            }
            a.reconnect.wait()
            continue
        }

        if err := a.handleConnection(); err != nil {
            log.Printf("connection error: %v", err)
        }

        a.connector.Close()
        a.reconnect.beforeRetry()
    }
}
```

### 4.3 Handler 消息处理

```go
type Handler struct {
    agent *Agent
}

func (h *Handler) Handle(msg *Message) error {
    switch msg.Type {
    case "register_ok":
        return h.handleRegisterOK(msg)
    case "register_fail":
        return h.handleRegisterFail(msg)
    case "exec":
        return h.handleExec(msg)
    case "pong":
        return nil  // 心跳响应，无需处理
    case "upload":
        return h.handleUpload(msg)
    case "upload_data":
        return h.handleUploadData(msg)
    case "upload_complete":
        return h.handleUploadComplete(msg)
    case "download_data":
        return h.handleDownloadData(msg)
    case "download_complete":
        return h.handleDownloadComplete(msg)
    default:
        return fmt.Errorf("unknown message type: %s", msg.Type)
    }
}

func (h *Handler) handleExec(msg *Message) error {
    var payload ExecPayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    result, err := h.agent.executor.Execute(payload.Command, payload.Timeout)
    if err != nil {
        result = &Result{
            ExitCode: -1,
            Stderr:  err.Error(),
        }
    }

    return h.agent.sendResult(payload.TaskID, result)
}

### 4.4 文件传输处理

#### 4.4.1 上传处理（接收服务端文件）

```go
// handleUpload 处理服务端的上传请求
func (h *Handler) handleUpload(msg *Message) error {
    var payload UploadPayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    // 创建本地文件准备接收
    file, err := os.Create(payload.Filename)
    if err != nil {
        return h.agent.sendUploadComplete(payload.FileID, false, err.Error())
    }

    h.agent.downloads[payload.FileID] = &DownloadTask{
        FileID:   payload.FileID,
        Filename: payload.Filename,
        File:     file,
        Offset:   payload.Offset,
    }

    return nil
}

// handleUploadData 处理分片数据
func (h *Handler) handleUploadData(msg *Message) error {
    var payload UploadDataPayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    task := h.agent.downloads[payload.FileID]
    if task == nil {
        return fmt.Errorf("unknown file_id: %s", payload.FileID)
    }

    // 解码数据
    data, err := base64.StdEncoding.DecodeString(payload.Data)
    if err != nil {
        return err
    }

    // 写入文件
    _, err = task.File.Write(data)
    if err != nil {
        task.File.Close()
        delete(h.agent.downloads, payload.FileID)
        return h.agent.sendUploadComplete(payload.FileID, false, err.Error())
    }

    task.Offset += int64(len(data))

    // 文件传输完成
    if payload.EOF {
        task.File.Close()
        delete(h.agent.downloads, payload.FileID)
        return h.agent.sendUploadComplete(payload.FileID, true, "")
    }

    return nil
}

type DownloadTask struct {
    FileID   string
    Filename string
    File     *os.File
    Offset   int64
}
```

#### 4.4.2 下载处理（向服务端发送文件）

```go
// sendDownloadRequest 请求从服务端下载文件（实际上是从本地上传）
func (a *Agent) sendDownloadRequest(taskID, fileID, filename string, offset int64) error {
    return a.connector.Send(&Message{
        Type: "download",
        Payload: DownloadPayload{
            TaskID:   taskID,
            FileID:   fileID,
            Filename: filename,
            Offset:   offset,
        },
    })
}

// uploadFile 上传本地文件到服务端
func (a *Agent) uploadFile(taskID, fileID, filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    stat, _ := file.Stat()
    chunkSize := 64 * 1024  // 64KB
    buffer := make([]byte, chunkSize)
    offset := int64(0)

    for {
        n, err := file.Read(buffer)
        if n > 0 {
            data := base64.StdEncoding.EncodeToString(buffer[:n])
            eof := int64(offset)+int64(n) >= stat.Size()

            err := a.connector.Send(&Message{
                Type: "upload_data",
                Payload: UploadDataPayload{
                    FileID: fileID,
                    Offset: offset,
                    Data:   data,
                    EOF:    eof,
                },
            })
            if err != nil {
                return err
            }
            offset += int64(n)
        }

        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
    }
    return nil
}

// handleUploadComplete 处理服务端对上传完成的响应
func (h *Handler) handleUploadComplete(msg *Message) error {
    var payload UploadCompletePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    if !payload.Success {
        slog.Warn("upload failed", "file_id", payload.FileID, "error", payload.Error)
    }
    return nil
}

// handleDownloadData 处理服务端发来的下载数据
func (h *Handler) handleDownloadData(msg *Message) error {
    var payload DownloadDataPayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    task := h.agent.downloads[payload.FileID]
    if task == nil {
        return fmt.Errorf("unknown file_id: %s", payload.FileID)
    }

    data, err := base64.StdEncoding.DecodeString(payload.Data)
    if err != nil {
        return err
    }

    _, err = task.File.Write(data)
    if err != nil {
        task.File.Close()
        delete(h.agent.downloads, payload.FileID)
        return err
    }

    task.Offset += int64(len(data))

    if payload.EOF {
        task.File.Close()
        delete(h.agent.downloads, payload.FileID)
        return h.agent.sendDownloadComplete(payload.FileID, true, "")
    }

    return nil
}

// handleDownloadComplete 处理下载完成确认
func (h *Handler) handleDownloadComplete(msg *Message) error {
    var payload DownloadCompletePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    if !payload.Success {
        slog.Warn("download failed", "file_id", payload.FileID, "error", payload.Error)
    }
    return nil
}

// sendDownloadComplete 发送下载完成确认
func (a *Agent) sendDownloadComplete(fileID string, success bool, errMsg string) error {
    return a.connector.Send(&Message{
        Type: "download_complete",
        Payload: DownloadCompletePayload{
            FileID:  fileID,
            Success: success,
            Error:   errMsg,
        },
    })
}
```

### 4.5 Executor 命令执行器

Executor已经包含在上方文件传输处理之前。后续章节编号已调整。

**跨平台兼容**：
- Linux: 使用 `/bin/sh -c "command"`
- Windows: 使用 `cmd.exe /c "command"`

### 4.6 Reconnect 重连机制

```go
type Reconnect struct {
    interval     time.Duration  // 重连间隔
    maxAttempts  int            // 最大重试次数，0=无限
    attempts     int
    nextWaitTime time.Duration
}

func (r *Reconnect) shouldRetry() bool {
    if r.maxAttempts == 0 {
        return true
    }
    return r.attempts < r.maxAttempts
}

func (r *Reconnect) wait() {
    time.Sleep(r.interval)
    r.attempts++
}
```

**重连策略**：
- 初始间隔：5秒
- 失败后指数退避：5s, 10s, 20s, 40s, 最大60s
- 达到最大重试次数后退出程序

### 4.7 心跳机制

```go
func (a *Agent) startHeartbeat() {
    ticker := time.NewTicker(a.config.Heartbeat.Interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := a.connector.Send(&Message{Type: "ping"}); err != nil {
                log.Printf("heartbeat failed: %v", err)
                return
            }
        case <-a.connector.done:
            return
        }
    }
}
```

## 5. 配置设计

### 5.1 config.yaml

```yaml
server:
  address: "server.example.com:8080"
  tls:
    enabled: false
    ca: "ca.crt"           # 可选，验证服务端证书

auth:
  key: "your-secret-key"

agent:
  hostname: ""              # 空则自动获取
  os: ""                    # 空则自动识别

heartbeat:
  interval: 30              # 心跳间隔(秒)

reconnect:
  interval: 5               # 初始重连间隔(秒)
  max_attempts: 0           # 0=无限重试
  max_interval: 60           # 最大重连间隔(秒)

log:
  level: "info"
  file: ""
```

## 6. 启动流程

```
Agent 启动
    │
    ▼
读取配置文件
    │
    ▼
获取主机名和操作系统
    │
    ▼
创建 Connector
    │
    ▼
进入连接循环
    │
    ├──► Connect() ──► WebSocket 握手
    │                      │
    │                      ▼
    │                 发送 register
    │                      │
    │                      ▼
    │                 接收 register_ok / register_fail
    │                      │
    │              ┌───────┴───────┐
    │            成功            失败
    │              │              │
    │              ▼              ▼
    │         启动心跳        记录日志
    │              │           关闭连接
    │              ▼              │
    │         启动主循环           │
    │              │               │
    │    ┌────────┴────────┐      │
    │    │                 │      │
    │    ▼                 ▼      │
    │  接收消息          连接断开  │
    │    │                 │       │
    │    ▼                 ▼       │
    │  处理消息          等待重连  │
    │    │                 │       │
    │    └────────┬────────┘       │
    │             │                │
    │             ▼                │
    └───── 继续重连 ◄──────────────┘
```

## 7. 错误处理

| 错误场景 | 处理方式 |
|----------|----------|
| 连接失败 | 等待后重连 |
| 注册失败 | 记录日志，关闭连接，等待重连 |
| 消息解析失败 | 记录日志，忽略该消息 |
| 命令执行超时 | 返回超时错误 |
| 命令执行崩溃 | 返回错误信息 |

## 8. 日志设计

```go
slog.Info("agent starting", "server", serverAddr)
slog.Info("connected to server", "server", serverAddr)
slog.Info("registered successfully", "client_id", clientID)
slog.Info("command executed", "task_id", taskID, "duration", duration)
slog.Warn("connection lost", "error", err)
slog.Error("reconnect failed", "attempt", attempt, "error", err)
```

## 9. 项目结构

```
internal/agent/
├── agent.go       # 主控逻辑
├── connector.go   # WebSocket连接管理
├── handler.go     # 消息处理
├── executor.go    # 命令执行
├── reconnect.go   # 重连机制
├── config.go      # 配置加载
└── logger.go      # 日志配置
```
