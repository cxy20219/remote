# GoRemote

基于 WebSocket 的零配置内网穿透系统。每设备独立 AES-256-GCM 加密，审批制注册，一键部署。

## 功能特性

- **零配置启动** — `./server` 一键启动，admin 密码自动生成；Agent 仅需服务器地址
- **审批制注册** — Agent 基于 ed25519 身份认证，管理员 Web 端一键批准/拒绝
- **每设备独立加密** — 审批时通过 X25519 ECDH 协商 AES-256-GCM 密钥，且支持 Web UI 随时轮换
- **Web 管理面板** — 设备管理、隧道 CRUD、安全策略配置、系统设置全套界面
- **安全机制** — 登录/连接/端口扫描三层限流、自动黑名单、全局/设备级 IP 白名单
- **心跳保活 + 指数退避重连** — 网络中断后 ed25519 签名快速重认证，自动恢复

## 一句话部署

### 服务端

```bash
wget -qO server https://github.com/xxx/goremote/releases/latest/download/server-linux-amd64 && chmod +x server && ./server
```

首次启动自动打印 admin 密码，浏览器打开 `http://your-ip:8080/` 登录即可。

### 客户端

```bash
wget -qO agent https://github.com/xxx/goremote/releases/latest/download/agent-linux-amd64 && chmod +x agent && ./agent --server <server-ip>:8080
```

Agent 自动创建 `~/.goremote/identity`（ed25519 身份密钥），连接服务器后进入待审批状态，管理员批准后自动进入工作状态。

## 手动部署

### 服务端

```bash
# 1. 下载二进制
wget https://github.com/xxx/goremote/releases/latest/download/server-linux-amd64
chmod +x server-linux-amd64

# 2. 启动（可选参数：--port 8080 --data ./data --tls-cert cert.pem --tls-key key.pem）
./server-linux-amd64

# 3. 查看 admin 密码
tail -n 20 server.log  # 或直接查看控制台输出
```

### 客户端

```bash
# 1. 下载对应平台二进制
wget https://github.com/xxx/goremote/releases/latest/download/agent-linux-amd64
chmod +x agent-linux-amd64

# 2. 启动（可选参数：--tls 启用 WSS，--tls-ca 指定 CA）
./agent-linux-amd64 --server YOUR_SERVER:8080

# 如需后台运行
nohup ./agent-linux-amd64 --server YOUR_SERVER:8080 --log-file agent.log --log-max-size-mb 50 --log-max-backups 5 > /dev/null 2>&1 < /dev/null &
```

## 编译

```bash
swag init -g cmd/server/main.go -o docs
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux-amd64 ./cmd/server
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o agent-linux-arm64  ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agent-windows-amd64.exe ./cmd/agent
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o agent-darwin-amd64 ./cmd/agent
```

## License

MIT
