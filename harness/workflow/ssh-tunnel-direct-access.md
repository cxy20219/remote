# GoRemote SSH 隧道直通内网服务流程

## 概述

本文档记录通过 GoRemote SSH 隧道从公网访问内网服务的完整流程，包括问题排查和注意事项。

## 整体架构

```
公网客户端  →  公网服务器 (your-server-ip:10000)  →  SSH 隧道  →  内网服务器 (internal-server)
                                                              ↓
                                                    内网服务 (如 7777 端口)
```

## 前置条件

1. 公网服务器已部署 GoRemote Server 并运行
2. 内网客户端已部署 GoRemote Agent 并成功连接公网服务器
3. 已知内网服务器的 SSH 账号密码

## 隧道创建流程

### 1. 确认内网客户端在线

通过公网服务器 API 查看已连接的客户端：

```bash
curl http://your-server-ip:8080/api/clients
```

返回示例：
```json
{"clients":[{"client_id":"client-18aa891d1553d80e-b950-4000-8000-18aa891d1553d948","hostname":"internal-server","os":"linux","status":"online"}],"total":1}
```

### 2. 创建隧道映射内网端口到公网

使用 client_id 创建隧道，将内网端口映射到公网端口：

```bash
# 创建隧道 - 内网 7777 端口映射到公网
curl -X POST http://your-server-ip:8080/api/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<client_id>","local_port":7777,"protocol":"tcp"}'
```

返回示例：
```json
{"local_addr":"127.0.0.1","public_addr":"your-server-ip:10005","public_port":10005,"status":"active","tunnel_id":"18aa8af9cb10381e-c150-4000-8000-18aa8af9cb1038be"}
```

### 3. 验证隧道端口已监听

在公网服务器上检查端口是否开始监听：

```bash
netstat -tlnp | grep 10005
```

应显示：
```
tcp6  0  0  :::10005  :::*  LISTEN  server
```

## SSH 隧道直连内网服务器

### 通过公网端口 SSH 到内网

使用内网账号密码，通过公网的隧道端口 SSH 到内网服务器：

```bash
plink.exe -batch -pw "<password>" -P 10000 your-user@your-server-ip "hostname"
```

参数说明：
- `-P 10000`: 公网隧道端口（对应内网 22 端口）
- `your-user`: 内网 SSH 用户名
- `your-server-ip`: 公网服务器 IP

### 在内网服务器部署服务

在内网服务器上启动服务（需选择可用端口）：

```python
# 方式 1: Python HTTP 服务（推荐）
python3 -m http.server 7777 --directory /tmp &

# 方式 2: 简单 TCP 服务器
python3 -c "
import socket
s = socket.socket()
s.bind(('', 7777))
s.listen(1)
while True:
    c, a = s.accept()
    c.send(b'HTTP/1.1 200 OK\n\n<h1>Works!</h1>')
    c.close()
" &
```

### 常见问题：端口权限

内网服务器常用端口（如 80、8080）可能需要 root 权限。如遇 `PermissionError`，更换为高位端口（如 7777、8888）。

### 常见问题：HTTP 服务无响应

Python 的 `http.server` 在某些环境下可能不响应 curl，但 socket 方式更可靠。推荐使用自定义 TCP 服务器。

### 验证内网服务

从内网服务器本地测试：

```bash
curl -s http://localhost:7777/
```

## 通过隧道访问内网服务

### 从公网访问内网 Web

```bash
# 直接访问
curl http://your-server-ip:10005/

# 或在浏览器打开
http://your-server-ip:10005/
```

### 通过 SSH 隧道执行远程命令

```bash
# 查看内网服务进程
plink.exe -batch -pw "<password>" -P 10000 your-user@your-server-ip "ps aux | grep python"

# 查看端口监听
plink.exe -batch -pw "<password>" -P 10000 your-user@your-server-ip "ss -tlnp | grep 7777"
```

## 隧道管理 API

### 查看所有隧道

```bash
curl http://your-server-ip:8080/api/tunnels
```

### 删除隧道

```bash
curl -X DELETE http://your-server-ip:8080/api/tunnels/<tunnel_id>
```

### 更新隧道（修改内网目标端口）

```bash
curl -X PUT http://your-server-ip:8080/api/tunnels/<tunnel_id> \
  -H 'Content-Type: application/json' \
  -d '{"local_port":8888,"protocol":"tcp"}'
```

## 问题排查

### 隧道创建成功但无法连接

1. 检查公网服务器端口是否监听：`netstat -tlnp | grep <port>`
2. 检查内网服务器是否有服务监听：`ss -tlnp | grep <port>`
3. 检查服务是否正常响应：`curl -v http://localhost:<port>/`

### SSH 隧道连接被拒绝

1. 确认内网服务已启动：`ps aux | grep python`
2. 检查内网服务端口：`ss -tlnp | grep <port>`
3. 测试本地连接：`curl http://localhost:<port>/`

### 通过 SSH 执 行命令无响应

1. 使用 `-batch` 参数避免交互式密码提示
2. 确认密码正确（SSH 认证失败会返回 "Access denied"）
3. 检查公网服务器防火墙是否允许该端口入站

## 完整示例

### 场景：部署内网 Web 服务并通过公网访问

**步骤 1**: 获取客户端 ID
```bash
curl -s http://your-server-ip:8080/api/clients
```

**步骤 2**: 创建隧道（内网 7777 → 公网 10005）
```bash
curl -X POST http://your-server-ip:8080/api/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"client-18aa891d1553d80e-b950-4000-8000-18aa891d1553d948","local_port":7777,"protocol":"tcp"}'
```

**步骤 3**: SSH 到内网服务器（通过隧道）
```bash
plink.exe -batch -pw "your-password" -P 10000 your-user@your-server-ip "echo connected"
```

**步骤 4**: 在内网服务器启动 Web 服务
```bash
# 在内网服务器执行
killall python3 2>/dev/null
cat > /tmp/srv.py << 'ENDPY'
import socket
s = socket.socket()
s.bind(('', 7777))
s.listen(1)
while True:
    c, a = s.accept()
    c.send(b'HTTP/1.1 200 OK\n\n<h1>GoRemote Works!</h1>')
    c.close()
ENDPY
python3 /tmp/srv.py &
```

**步骤 5**: 验证服务
```bash
# 内网服务器本地
curl http://localhost:7777/

# 公网访问内网服务
curl http://your-server-ip:10005/
```

## 注意事项

1. **端口选择**：内网常用端口（80、8080）可能需要 root 权限，建议使用高位端口（7777、8888等）
2. **防火墙**：确保公网服务器防火墙允许相应端口入站
3. **服务可靠性**：Python socket 比 http.server 更可靠，建议使用 socket 方式
4. **隧道保活**：GoRemote Agent 会自动保持连接，如连接断开需检查 Agent 状态
5. **多隧道**：同一客户端可创建多个隧道映射不同端口

## 相关文档

- [服务端设计文档](../references/server-design.md) - GoRemote 服务端架构
- [客户端设计文档](../references/agent-design.md) - GoRemote Agent 架构
- [项目结构文档](../references/project-structure.md) - 项目目录结构说明