# GoRemote SSH 隧道直通内网服务完整流程

## 概述

本文档记录通过 GoRemote SSH 隧道从公网访问内网服务的完整流程，包括前置条件、关键步骤、验证方式和注意事项。

## 整体架构

```
外部用户 → [公网服务器:公网端口] → [WebSocket隧道] → [内网Agent:内网端口]
                                                              ↓
                                                    [内网服务 (如 7777)]
```

## 前置条件

1. 公网服务器已部署 GoRemote Server 并运行
2. 内网服务器已部署 GoRemote Agent 并成功连接公网服务器
3. 已知内网服务器的 SSH 账号密码
4. 公网服务端配置 `tunnel.public_host` 为实际公网 IP

## 关键步骤

### 步骤 1：确认 Agent 在线

通过公网服务器 API 查看已连接的客户端：

```bash
curl.exe -s -k -b cookies.txt https://YOUR_SERVER:8080/api/clients
```

返回示例：
```json
{"clients":[{"client_id":"client-18aa891d...","hostname":"internal-server","os":"linux","status":"online"}],"total":1}
```

**验证方式**：确认返回的 clients 列表中存在目标 client 且 status 为 "online"

### 步骤 2：创建隧道

使用 client_id 创建隧道，将内网端口映射到公网端口：

```bash
# 准备 JSON 文件
@'
{"client_id":"<client_id>","local_port":7777,"protocol":"tcp"}
'@ | Out-File tunnel.json -Encoding ascii

# 创建隧道
curl.exe -s -k -b cookies.txt -X POST https://YOUR_SERVER:8080/api/tunnels -H "Content-Type: application/json" -d "@tunnel.json"
```

返回示例：
```json
{"local_addr":"127.0.0.1","public_addr":"YOUR_SERVER:10005","public_port":10005,"status":"active","tunnel_id":"18aa8af9..."}
```

**验证方式**：返回的 status 为 "active"，public_port 为分配的公网端口

### 步骤 3：验证隧道监听

在公网服务器上检查端口是否开始监听：

```bash
# Linux
ss -tlnp | grep 10005

# Windows (公网服务器)
netstat -ano | Select-String ":10005"
```

应显示对应端口处于 LISTEN 状态。

### 步骤 4：验证内网服务

从内网服务器本地测试：

```bash
# SSH 到内网服务器
plink.exe -batch -pw "<内网密码>" -P 22 lvcheng@192.168.66.42 "curl -s http://localhost:7777/"
```

### 步骤 5：通过公网访问内网服务

```bash
# 直接访问
curl.exe http://YOUR_SERVER:10005/

# 或在浏览器打开
http://YOUR_SERVER:10005/
```

## 完整操作示例

### 场景：部署内网 Web 服务并通过公网访问

**步骤 1**: 获取 Agent Client ID
```bash
curl.exe -s -k -b cookies.txt https://YOUR_SERVER:8080/api/clients
```

**步骤 2**: 创建隧道（内网 7777 → 公网 10005）
```bash
@'
{"client_id":"client-18aa891d...","local_port":7777,"protocol":"tcp"}
'@ | Out-File tunnel.json -Encoding ascii
curl.exe -s -k -b cookies.txt -X POST https://YOUR_SERVER:8080/api/tunnels -H "Content-Type: application/json" -d "@tunnel.json"
```

**步骤 3**: SSH 到内网服务器验证
```bash
plink.exe -batch -pw "Ss123456!" -P 10000 lvcheng@YOUR_SERVER "echo connected"
```

**步骤 4**: 在内网服务器启动 Web 服务
```bash
# 通过隧道 SSH 到内网服务器
plink.exe -batch -pw "Ss123456!" -P 10000 lvcheng@YOUR_SERVER "python3 -c \"
import socket
s = socket.socket()
s.bind(('', 7777))
s.listen(1)
while True:
    c, a = s.accept()
    c.send(b'HTTP/1.1 200 OK\n\n<h1>Works!</h1>')
    c.close()
\" &"
```

**步骤 5**: 验证服务
```bash
# 内网服务器本地
curl http://localhost:7777/

# 公网访问内网服务
curl.exe http://YOUR_SERVER:10005/
```

## 隧道管理 API

### 查看所有隧道

```bash
curl.exe -s -k -b cookies.txt https://YOUR_SERVER:8080/api/tunnels
```

### 删除隧道

```bash
curl.exe -s -k -b cookies.txt -X DELETE https://YOUR_SERVER:8080/api/tunnels/<tunnel_id>
```

### 更新隧道

```bash
@'
{"local_port":8888,"protocol":"tcp"}
'@ | Out-File update.json -Encoding ascii
curl.exe -s -k -b cookies.txt -X PUT https://YOUR_SERVER:8080/api/tunnels/<tunnel_id> -H "Content-Type: application/json" -d "@update.json"
```

## 注意事项

1. **端口选择**：内网常用端口（80、8080）需要 root 权限，建议使用高位端口（7777、8888等）
2. **防火墙**：确保公网服务器防火墙允许相应端口入站
3. **服务可靠性**：Python socket 比 http.server 更可靠
4. **隧道保活**：GoRemote Agent 会自动保持连接
5. **多隧道**：同一客户端可创建多个隧道映射不同端口

## 问题排查

### 隧道创建成功但无法连接

1. 检查公网服务器端口是否监听：`ss -tlnp | grep <port>`
2. 检查内网服务器是否有服务监听：`ss -tlnp | grep <port>`
3. 检查服务是否正常响应：`curl -v http://localhost:<port>/`

### SSH 隧道连接被拒绝

1. 确认内网服务已启动：`ps aux | grep python`
2. 检查内网服务端口：`ss -tlnp | grep <port>`
3. 测试本地连接：`curl http://localhost:<port>/`

### 通过 SSH 执行命令无响应

1. 使用 `-batch` 参数避免交互式密码提示
2. 确认密码正确
3. 检查公网服务器防火墙是否允许该端口入站