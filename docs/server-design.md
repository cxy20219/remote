# 服务端设计文档

## 1. 功能概述

服务端是整个系统的控制中心，负责：
- 接收客户端WebSocket连接
- 验证客户端身份
- 管理在线客户端
- 下发命令到指定客户端
- 收集并返回执行结果

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                      Server                                  │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  WebSocket  │  │   Client    │  │      Handler        │ │
│  │   Server    │──│   Manager   │──│   (消息分发)        │ │
│  │  ( :8080 )  │  │ (在线状态)  │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                │                    │              │
│         │                ▼                    ▼              │
│         │         ┌─────────────┐  ┌─────────────────────┐ │
│         │         │   Task      │  │   Command          │ │
│         │         │   Store     │  │   Dispatcher       │ │
│         │         │ (任务管理)  │  │                     │ │
│         │         └─────────────┘  └─────────────────────┘ │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │   Logger   │                                           │
│  │   (日志)   │                                           │
│  └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

| 组件 | 职责 |
|------|------|
| WebSocket Server | 监听端口，接收客户端连接 |
| Client Manager | 维护客户端在线状态，client_id ↔ 连接映射 |
| Handler | 消息路由，分发给对应处理函数 |
| Task Store | 存储命令任务及执行结果 |
| Logger | 日志记录 |

## 3. 数据结构

### 3.1 Client 客户端信息

```go
type Client struct {
    ClientID  string           // 唯一标识 (UUID)
    Hostname  string           // 主机名
    OS        string           // 操作系统 (linux/windows)
    Conn      *websocket.Conn  // WebSocket连接
    RegTime   time.Time        // 注册时间
    LastPing  time.Time        // 最后心跳时间
    Status    string           // online/offline
}
```

### 3.2 Task 命令任务

```go
type Task struct {
    TaskID    string    // 任务ID (UUID)
    ClientID  string    // 目标客户端ID
    Command   string    // 待执行命令
    Timeout   int       // 超时时间(秒)
    Status    string    // pending/running/completed/timeout/failed
    Result    *TaskResult
    CreateAt  time.Time
    StartAt   time.Time
    EndAt     time.Time
}

type TaskResult struct {
    ExitCode int
    Stdout  string
    Stderr  string
    Error   string  // 执行错误信息
}
```

### 3.3 Message 消息结构

```go
type Message struct {
    Type    string          `json:"type"`
    Payload json.RawMessage  `json:"payload,omitempty"`
}

type RegisterPayload struct {
    Key     string `json:"key"`
    Hostname string `json:"hostname"`
    OS      string `json:"os"`
}

type RegisterOKPayload struct {
    ClientID string `json:"client_id"`
}

type RegisterFailPayload struct {
    Reason string `json:"reason"`
}

type ExecPayload struct {
    TaskID   string `json:"task_id"`
    Command  string `json:"command"`
    Timeout  int    `json:"timeout"`
}

type ResultPayload struct {
    TaskID   string `json:"task_id"`
    ExitCode int    `json:"exit_code"`
    Stdout   string `json:"stdout"`
    Stderr   string `json:"stderr"`
}

// 文件传输消息
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

## 4. 消息协议

### 4.1 消息类型

| Type | 方向 | 描述 |
|------|------|------|
| register | C→S | 客户端注册 |
| register_ok | S→C | 注册成功 |
| register_fail | S→C | 注册失败 |
| exec | S→C | 服务端下发命令 |
| result | C→S | 客户端返回结果 |
| ping | C→S | 心跳请求 |
| pong | S→C | 心跳响应 |
| upload | S→C | 上传文件请求 |
| upload_data | S→C | 上传文件数据 |
| upload_complete | C→S | 上传完成确认 |
| download | C→S | 下载文件请求 |
| download_data | S→C | 下载文件数据 |
| download_complete | S→C | 下载完成确认 |

### 4.2 消息流程

```
客户端连接
    │
    ▼
┌─────────────────┐
│  发送 register  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 验证 key 是否正确 │
└────────┬────────┘
         │
    ┌────┴────┐
    │ 验证结果  │
    └────┬────┘
         │
    ┌────┴────┐
    │         │
  成功      失败
    │         │
    ▼         ▼
register_ok  register_fail
    │         │
    ▼         (关闭连接)
  进入主循环
    │
    ├─ 接收 exec ── 执行命令 ── 返回 result
    │
    ├─ 发送 ping ──────────── 接收 pong
    │
    └─ 断开连接 ── 标记 offline
```

## 5. 详细设计

### 5.1 WebSocket Server

```go
type Server struct {
    addr       string
    tlsEnabled bool
    tlsCert    string
    tlsKey     string

    authKey    string

    clients    *ClientManager
    tasks      *TaskStore
    handler    *Handler

    upgrader   websocket.Upgrader
    hbInterval time.Duration  // 心跳检测间隔
    hbTimeout  time.Duration   // 心跳超时时间
}
```

**主要方法**：
- `Start()` - 启动服务
- `Stop()` - 停止服务
- `handleConn()` - 处理新连接

### 5.2 Client Manager

```go
type ClientManager struct {
    mu      sync.RWMutex
    clients map[string]*Client  // clientID -> Client
}
```

**主要方法**：
- `Add(client *Client)` - 添加客户端
- `Remove(clientID string)` - 移除客户端
- `Get(clientID string) (*Client, bool)` - 获取客户端
- `List() []*Client` - 获取所有客户端
- `Broadcast(msg []byte)` - 广播消息

### 5.3 Handler 消息处理

```go
type Handler struct {
    server *Server
}

func (h *Handler) Handle(client *Client, msg *Message) error {
    switch msg.Type {
    case "register":
        return h.handleRegister(client, msg)
    case "exec":
        return h.handleExec(client, msg)
    case "result":
        return h.handleResult(client, msg)
    case "ping":
        return h.handlePing(client, msg)
    case "upload":
        return h.handleUpload(client, msg)
    case "upload_data":
        return h.handleUploadData(client, msg)
    case "upload_complete":
        return h.handleUploadComplete(client, msg)
    case "download":
        return h.handleDownload(client, msg)
    case "download_complete":
        return h.handleDownloadComplete(client, msg)
    default:
        return fmt.Errorf("unknown message type: %s", msg.Type)
    }
}
```

### 5.4 文件传输处理

#### 5.4.1 上传（服务端 → 客户端）

上传指将文件从服务端传输到客户端：

```go
// UploadManager 管理正在进行的文件上传
type UploadManager struct {
    mu      sync.Mutex
    files   map[string]*UploadFile  // fileID -> UploadFile
}

type UploadFile struct {
    FileID    string
    Filename  string
    Size      int64
    Offset    int64
    Data      []byte  // 已接收的数据
    TaskID    string
    ClientID  string
    CreatedAt time.Time
}

// handleUpload 发起上传请求
func (h *Handler) handleUpload(client *Client, payload *UploadPayload) error {
    // 创建上传记录
    upload := &UploadFile{
        FileID:   payload.FileID,
        Filename: payload.Filename,
        Size:     payload.Size,
        Offset:   payload.Offset,
        TaskID:   payload.TaskID,
        ClientID: client.ClientID,
    }
    h.server.uploadManager.Add(upload)

    // 分片发送文件数据
    return h.sendFileInChunks(client, payload.FileID, payload.Filename)
}

// sendFileInChunks 分片发送文件
func (h *Handler) sendFileInChunks(client *Client, fileID, filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    stat, _ := file.Stat()
    chunkSize := 64 * 1024  // 64KB per chunk
    buffer := make([]byte, chunkSize)
    offset := int64(0)

    for {
        n, err := file.Read(buffer)
        if n > 0 {
            data := base64.StdEncoding.EncodeToString(buffer[:n])
            eof := int64(offset)+int64(n) >= stat.Size()

            err := client.Conn.WriteJSON(Message{
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
```

#### 5.4.2 下载（客户端 ← 服务端）

下载指客户端主动请求从服务端获取文件（服务端通过 upload_data 消息发送文件内容）：

```go
// handleDownload 处理客户端的下载请求
func (h *Handler) handleDownload(client *Client, payload *DownloadPayload) error {
    // 客户端请求下载文件，服务端通过 upload_data 分片发送文件内容
    // 客户端收到后回复 upload_complete 确认
    return h.sendFileInChunks(client, payload.FileID, payload.Filename)
}

// handleDownloadComplete 处理客户端下载完成确认
func (h *Handler) handleDownloadComplete(client *Client, msg *Message) error {
    var payload DownloadCompletePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    if !payload.Success {
        slog.Warn("download failed", "file_id", payload.FileID, "error", payload.Error)
    }

    return nil
}
```

**协议说明**：download 与 upload 的数据流向相同（服务端→客户端），区别在于触发方式：
- upload：服务端主动推送文件
- download：客户端主动请求，服务端再发送
```

#### 5.4.3 文件传输状态管理

```go
// FileTransfer 正在进行的文件传输
type FileTransfer struct {
    FileID    string
    Type      string  // "upload" or "download"
    Filename  string
    Size      int64
    Transferred int64
    Status    string  // "in_progress", "completed", "failed"
    Error     string
}

// handleUploadData 处理分片数据
func (h *Handler) handleUploadData(client *Client, msg *Message) error {
    var payload UploadDataPayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }

    transfer := h.server.GetTransfer(payload.FileID)
    if transfer == nil {
        return fmt.Errorf("unknown file_id: %s", payload.FileID)
    }

    // 解码并写入文件
    data, err := base64.StdEncoding.DecodeString(payload.Data)
    if err != nil {
        return err
    }

    _, err = transfer.File.Write(data)
    if err != nil {
        return err
    }

    transfer.Transferred += int64(len(data))

    if payload.EOF {
        transfer.Status = "completed"
        transfer.File.Close()
    }

    return nil
}
```

### 5.4 心跳机制

客户端主动发送心跳，服务端检测超时：
1. 客户端定期发送 ping 消息
2. 服务端收到后更新客户端的 LastPing 时间
3. 服务端启动goroutine定期检查
4. 超过`hbTimeout`未收到ping的客户端标记为offline
5. 关闭对应连接

```go
func (s *Server) startHeartbeatChecker() {
    ticker := time.NewTicker(s.hbInterval)
    go func() {
        for range ticker.C {
            s.checkClientsTimeout()
        }
    }()
}

func (s *Server) checkClientsTimeout() {
    now := time.Now()
    s.clients.mu.Lock()
    defer s.clients.mu.Unlock()

    for _, client := range s.clients.clients {
        if now.Sub(client.LastPing) > s.hbTimeout {
            log.Printf("client %s heartbeat timeout, closing", client.ClientID)
            client.Conn.Close()
        }
    }
}
```

## 6. 配置设计

### 6.1 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert: "server.crt"
    key: "server.key"

auth:
  key: "your-secret-key"

heartbeat:
  interval: 30      # 心跳检测间隔(秒)
  timeout: 90       # 心跳超时(秒)

log:
  level: "info"    # debug/info/warn/error
  file: ""         # 空则输出到stdout
```

## 7. 接口设计 (HTTP管理API)

### 7.1 REST API

| Method | Path | 描述 |
|--------|------|------|
| GET | /api/clients | 获取在线客户端列表 |
| GET | /api/clients/:id | 获取客户端详情 |
| POST | /api/exec | 向指定客户端下发命令 |
| GET | /api/tasks | 获取任务列表 |
| GET | /api/tasks/:id | 获取任务详情 |
| POST | /api/upload | 上传文件到指定客户端 |
| GET | /api/download/:client_id/:filepath | 从客户端下载文件 |
| GET | /health | 健康检查 |

### 7.2 API 详细设计

**POST /api/exec**

请求：
```json
{
  "client_id": "uuid",
  "command": "ls -la /tmp",
  "timeout": 30
}
```

响应：
```json
{
  "task_id": "uuid",
  "status": "pending"
}
```

## 8. 错误处理

| 错误类型 | 处理方式 |
|----------|----------|
| 非法消息格式 | 记录日志，关闭连接 |
| 未知消息类型 | 记录日志，关闭连接 |
| 客户端超时 | 标记offline，关闭连接 |
| 命令执行失败 | 记录结果到Task |

## 9. 日志设计

```go
// 使用 slog 记录结构化日志
slog.Info("server started", "addr", addr)
slog.Info("client connected", "client_id", clientID, "remote", remoteAddr)
slog.Info("command executed", "task_id", taskID, "exit_code", exitCode, "duration", duration)
slog.Warn("client heartbeat timeout", "client_id", clientID)
slog.Error("connection error", "client_id", clientID, "error", err)
```

## 10. 项目结构

```
internal/server/
├── server.go      # WebSocket服务端主逻辑
├── client.go      # ClientManager 客户端管理
├── handler.go     # 消息处理
├── task.go        # TaskStore 任务管理
├── api.go         # HTTP管理接口
├── config.go      # 配置加载
└── logger.go      # 日志配置
```
