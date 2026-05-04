# SSH 隧道直通内网服务流程

## 整体架构

```
公网客户端  →  公网服务器 (YOUR_SERVER:10000)  →  SSH 隧道  →  内网服务器 (192.168.66.42)
                                                              ↓
                                                    内网服务 (如 7777 端口)
```

## 隧道创建流程

### 1. 确认内网客户端在线

```bash
curl http://YOUR_SERVER:8080/api/clients
```

### 2. 创建隧道映射内网端口到公网

```bash
curl -X POST http://YOUR_SERVER:8080/api/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<client_id>","local_port":7777,"protocol":"tcp"}'
```

### 3. 验证隧道端口已监听

```bash
netstat -tlnp | grep 10005
# 应显示：tcp  0  0  :::10005  :::*  LISTEN  server
```

## SSH 隧道直连内网服务器

```bash
plink.exe -batch -pw "<password>" -P 10000 lvcheng@YOUR_SERVER "hostname"
```

## 在内网服务器部署服务

```python
# Python HTTP 服务（推荐）
python3 -m http.server 7777 --directory /tmp &

# 或简单 TCP 服务器
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

## 隧道管理 API

```bash
# 查看所有隧道
curl http://YOUR_SERVER:8080/api/tunnels

# 删除隧道
curl -X DELETE http://YOUR_SERVER:8080/api/tunnels/<tunnel_id>
```

## 问题排查

### 隧道创建成功但无法连接

1. 检查公网服务器端口是否监听：`netstat -tlnp | grep <port>`
2. 检查内网服务器是否有服务监听：`ss -tlnp | grep <port>`
3. 检查服务是否正常响应：`curl -v http://localhost:<port>/`

### SSH 隧道连接被拒绝

1. 确认内网服务已启动：`ps aux | grep python`
2. 检查内网服务端口：`ss -tlnp | grep <port>`

## 注意事项

1. **端口选择**：内网常用端口（80、8080）可能需要 root 权限，建议使用高位端口
2. **防火墙**：确保公网服务器防火墙允许相应端口入站
3. **服务可靠性**：Python socket 比 http.server 更可靠
4. **隧道保活**：GoRemote Agent 会自动保持连接