# GoRemote

基于 WebSocket 的零配置内网穿透系统。每设备独立 AES-256-GCM 加密，审批制注册，一键部署。

## 试用效果图

零配置内网穿透：服务端一键启动，Agent 只填写服务器地址，管理员审批后即可创建 SSH/HTTP 等内网服务映射。

## 功能特性

- **零配置启动** — `./server` 一键启动；首次启动进入初始化向导（本机 loopback 或一次性令牌），自行设置管理员密码并可选启用 TOTP（见 [docs/FIRST-RUN-SETUP.md](docs/FIRST-RUN-SETUP.md)）
- **审批制注册** — Agent 基于 ed25519 身份认证，管理员 Web 端一键批准/拒绝
- **每设备独立加密** — 审批时通过 X25519 ECDH 协商 AES-256-GCM 密钥，且支持 Web UI 随时轮换
- **Web 管理面板** — 设备管理、隧道 CRUD、安全策略配置、系统设置全套界面
- **两步验证 (TOTP)** — 管理员可扫码启用动态码登录，10 个一次性恢复码，支持防重放与 IP 绑定挑战（见 [docs/TOTP-2FA.md](docs/TOTP-2FA.md)；被锁定时见 [docs/RUNBOOK-admin-lockout.md](docs/RUNBOOK-admin-lockout.md)）
- **安全机制** — 管理员改密与按 IP 登录锁定、连接/端口扫描限流、自动黑名单（24h 过期）、全局/设备级 IP 白名单
- **稳定传输** — 每连接独立有序读写队列 + 有界背压，慢客户端不会截断其他隧道或拖死 WebSocket 收包线程
- **心跳保活 + 指数退避重连** — 网络中断后 ed25519 签名快速重认证，自动恢复

## 安全特性

- **审批制接入**：新 Agent 首次连接只会进入 pending 状态，必须由管理员在 Web 面板批准后才能创建隧道。
- **设备身份认证**：每个 Agent 本地生成 ed25519 身份密钥，重连时使用签名认证，避免仅凭 client ID 冒充设备。
- **每设备独立密钥**：每台设备单独协商 AES-256-GCM 隧道数据密钥，支持按设备关闭加密或重新生成密钥。
- **密钥交换保护**：服务端下发的密钥更新带签名，Agent 首次信任后会校验后续 `register_ok` / `register_update`，防止密钥更新被篡改。
- **防重放**：设备重连签名带时间戳，服务端限制时间窗口并记录已使用签名，减少重放风险。
- **管理面加固**：支持管理员改密、按来源 IP 的登录失败临时锁定、HttpOnly Cookie，会话修改密码后自动吊销；首次启动不生成任何密码：通过本机 loopback 或一次性令牌完成初始化向导后，密码只以 bcrypt hash 写入 state，日志不含凭据。
- **两步验证 (TOTP)**：可扫码启用（RFC 6238，SHA-1/6 位/30 秒，±1 时间窗），登录需要密码 + 动态码；10 个一次性恢复码、防重放、挑战绑定来源 IP；密码失败按 IP 计数，动态码失败另有跨 IP 账户级退避（5 分钟封顶、恢复码豁免）。**启用前必须配置 `GOREMOTE_STATE_KEY`**（否则 setup 直接 409），密钥与恢复码哈希只进加密区。注意：没配 TLS 时二次验证保护有限；反代部署必须配 `--trusted-proxies`。详见 [docs/TOTP-2FA.md](docs/TOTP-2FA.md)。
- **管理面板输出转义**：设备上报的主机名、隧道地址、黑名单原因等动态内容统一转义，避免管理端存储型 XSS。
- **敏感状态加密**：可通过 `GOREMOTE_STATE_KEY` 或 `--state-key` 加密 `server-state.json` 中的服务端私钥、管理员密码 hash 和设备隧道密钥。
- **访问控制**：支持全局/设备级 IP 白名单、黑名单和自动拉黑。
- **端口防扫描**：隧道公网端口带连接频率限制，异常扫描会被拒绝并可触发自动黑名单。

## 一句话部署

### 服务端

```bash
wget -qO server https://github.com/xxx/goremote/releases/latest/download/server-linux-amd64 && chmod +x server && ./server
```

首次启动不会生成密码：无反代直连时打开 `http://127.0.0.1:8080/setup.html`（服务器本机 / SSH 转发）完成向导，其余情况使用日志里的一次性初始化令牌，详见 [docs/FIRST-RUN-SETUP.md](docs/FIRST-RUN-SETUP.md)。

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

# 2. 启动（可选参数：--port 8080 --data ./data --tls-cert cert.pem --tls-key key.pem --allowed-origins https://admin.example.com）
./server-linux-amd64

# 可选：启用状态文件敏感字段加密，生产环境建议使用随机 32 字节以上密钥
GOREMOTE_STATE_KEY='CHANGE-ME-long-random-state-key' ./server-linux-amd64

# 3. 完成首次初始化（二选一）
#    a) 无反代直连：本机/SSH 转发打开 http://127.0.0.1:8080/setup.html（免令牌）
#    b) 有反代或远程：从日志取一次性初始化令牌，打开 https://your-server:8080/setup.html 填入
journalctl -u goremote | grep 初始化   # 或 tail -n 20 server.log
```

> **任何反向代理（同机或异机）都必须用一次性令牌完成初始化**；loopback 免令牌只适用于没有反代、直连后端的场景。反代部署仍需按实际地址配置 `--trusted-proxies`（例如 `127.0.0.1`），它负责按 IP 的限流和 TOTP challenge 绑定。配置了它之后 loopback 免令牌会关闭，所以别为了省令牌把它删掉。

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

### 发布构建（可复现）

```bash
VERSION=v2.6.0 ./scripts/release.sh
```

一条命令产出七平台 × 两端（server/agent）的发布物，输出到 `dist/`：

- `goremote-v2.6.0-linux-amd64.tar.gz`、`linux-arm64`、`linux-armv7`
- `darwin-amd64`、`darwin-arm64`（`.tar.gz`）
- `windows-amd64`、`windows-arm64`（`.zip`）
- `SHA256SUMS.txt`

每个包内包含 `goremote-server`（windows 为 `.exe`）、`goremote-agent`（同上）、`README.md`、`LICENSE`。

**可复现性**：构建参数固定为 `CGO_ENABLED=0` + `-trimpath` + `-ldflags="-s -w"`，且脚本从 HEAD 的干净 git worktree 构建（工作区有未提交/未跟踪文件时，Go 会嵌入 `vcs.modified=true`，同一 commit 也会产出不同哈希）。同一 Go 版本 + 同一 commit + 本脚本会得到相同二进制；发布记录请写明 `go version`。脚本只依赖 `tar`，打包 windows 时还需要 `zip`。

### 手动编译单个平台

```bash
swag init -g cmd/server/main.go -o docs
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o server-linux-amd64 ./cmd/server
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o agent-linux-arm64  ./cmd/agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-windows-amd64.exe ./cmd/agent
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-darwin-amd64 ./cmd/agent
```
