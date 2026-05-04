---
name: goremote-arch
description: GoRemote 架构设计技能。当需要解释服务端/客户端架构、消息协议、WebSocket通信、隧道机制或项目结构时使用。
compatibility: opencode
metadata:
  scope: project
---

# GoRemote 架构设计

## 职责

解释 GoRemote 的服务端、客户端（Agent）架构设计，消息协议定义，WebSocket 通信流程，以及隧道管理机制。

## 触发场景

- 用户询问服务端/客户端的架构设计
- 需要解释 WebSocket 连接、注册、心跳流程
- 需要说明隧道创建、数据转发、关闭的完整流程
- 需要说明 GoRemote 项目结构
- 涉及 internal/server/、internal/agent/、internal/common/ 代码的维护

## 架构概览

**星型架构**：Agent 在内网，主动连接公网服务端 WebSocket，防火墙友好。

```
                          ┌─────────────┐
                          │   公网      │
                          │   服务端    │
                          └──────┬──────┘
                                 │ WebSocket 长连接
             ┌───────────────────┼───────────────────┐
             │                   │                   │
      ┌──────┴──────┐   ┌──────┴──────┐   ┌──────┴──────┐
      │  内网机器A   │   │  内网机器B   │   │  内网机器C   │
      │  (Agent)   │   │  (Agent)   │   │  (Agent)   │
      └─────────────┘   └─────────────┘   └─────────────┘
```

## 服务端核心组件

| 组件 | 文件 | 职责 |
|------|------|------|
| WebSocket Server | internal/server/server.go | 监听 8080，接收 Agent 连接 |
| Client Manager | internal/server/client.go | 维护 client_id ↔ 连接映射，在线状态 |
| Handler | internal/server/handler.go | 消息路由（register/ping/tunnel_*） |
| Tunnel Manager | internal/server/tunnel.go | 端口映射管理 |
| API | internal/server/api.go | HTTP REST API（/api/clients、/api/tunnels） |

## 客户端 Agent 核心组件

| 组件 | 文件 | 职责 |
|------|------|------|
| Connector | internal/agent/connector.go | WebSocket 连接管理 |
| Agent | internal/agent/agent.go | 主控逻辑，连接循环 |
| Handler | internal/agent/handler.go | 消息处理 |
| Reconnect | internal/agent/reconnect.go | 断线重连，指数退避 |
| Tunnel Manager | internal/agent/tunnel.go | 隧道管理 |

## 消息协议

| Type | 方向 | 说明 |
|------|------|------|
| register | C→S | Agent 注册 |
| register_ok | S→C | 注册成功 |
| register_fail | S→C | 注册失败 |
| ping | C→S | 心跳 |
| pong | S→C | 心跳响应 |
| tunnel_open | C→S | 申请创建隧道 |
| tunnel_open_ack | S→C | 隧道创建确认 |
| tunnel_close | C↔S | 关闭隧道 |
| tunnel_data | C↔S | 隧道数据（base64） |
| tunnel_error | S→C | 隧道错误 |

## 隧道数据流

1. Agent 发送 `tunnel_open(local_addr, local_port)`
2. Server 分配公网端口，启动监听
3. 外部用户连接公网端口 → Server accept
4. Server 发送 `tunnel_data(conn_id, data)` 给 Agent
5. Agent 收到后**按需连接**本地服务（首次收到该 conn_id 时）
6. Agent 发送 `tunnel_data(conn_id, data=响应)` 给 Server
7. Server 写入外部 TCP 连接

## 项目结构

```
internal/
├── server/         # 服务端实现
│   ├── server.go  # 主逻辑
│   ├── client.go  # 客户端管理
│   ├── handler.go # 消息处理
│   ├── tunnel.go  # 隧道管理
│   ├── api.go     # HTTP API
│   └── config.go  # 配置加载
├── agent/         # 客户端实现
│   ├── agent.go   # 主控
│   ├── connector.go # WebSocket
│   ├── handler.go # 消息处理
│   ├── reconnect.go # 重连
│   └── tunnel.go  # 隧道管理
└── common/
    └── message.go # 消息定义
```

## HTTP API

| Method | Path | 说明 |
|--------|------|------|
| GET | /health | 健康检查 |
| GET | /api/clients | 在线客户端 |
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 所有隧道 |
| DELETE | /api/tunnels/:id | 删除隧道 |

## 文件索引

- [服务端设计文档](references/server-design.md)：详细的服务端架构
- [客户端设计文档](references/agent-design.md)：详细的客户端架构
- [隧道设计文档](references/tunnel-design.md)：隧道机制详解
- [项目结构文档](references/project-structure.md)：完整项目结构