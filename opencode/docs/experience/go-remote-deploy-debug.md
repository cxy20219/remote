# GoRemote 部署与调试经验总结

## 概述

本文档记录 GoRemote 部署、调试过程中积累的实战经验，涵盖环境差异、配置管理、问题排查和最佳实践。

## 1. PowerShell 与 curl 技巧

### 1.1 curl JSON POST 的多种转义方案

PowerShell 中发送 JSON 请求时，引号和变量展开会导致各种解析错误。

**错误示例**：
```powershell
# ❌ 直接写 JSON 字符串会因引号冲突失败
curl.exe -X POST url -d "{\"key\":\"value\"}"
```

**正确做法**：
```powershell
# ✅ 方式 1：使用文件（最可靠）
@'
{"key":"value"}
'@ | Out-File data.json -Encoding ascii
curl.exe -X POST url -d @data.json

# ✅ 方式 2：单引号 + 双引号混合（PowerShell 中单引号不展开）
curl.exe -X POST url -d '{"key":"value"}'
```

### 1.2 curl Cookie 管理

GoRemote 的 API 需要 admin 认证，通过 cookie 传递 token。

```powershell
# 登录，保存 cookie
curl.exe -k -c cookies.txt -X POST https://server/api/login --data-binary '{"password":"admin123"}'

# 请求，使用 cookie
curl.exe -k -b cookies.txt https://server/api/tunnels
```

### 1.3 PowerShell 中 curl 的坑

PowerShell 有内置的 `curl` 别名（实际是 Invoke-WebRequest），应始终使用 `curl.exe`。

### 1.4 plink 命令引用问题

PowerShell 执行 plink 时会对特殊字符做二次解析：

```powershell
# ❌ $2 被 PowerShell 视为变量
plink root@host "ps aux | awk '{print $2}'"

# ✅ 推荐：写脚本文件上传执行，避免复杂命令拼接
```

## 2. Agent 部署与运行

### 2.1 Start-Process 工作目录

使用 `Start-Process` 启动 agent 时，默认工作目录可能是 `C:\Windows\System32`：

```powershell
# ❌ 错误 - agent 找不到 config/agent.yaml
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml"

# ✅ 正确 - 指定工作目录
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml" -WorkingDirectory "E:/AI-work/go-remote"
```

### 2.2 Linux 上 nohup 启动后 plink 卡住

```bash
# ❌ 卡住
plink root@host "nohup ./agent --config config.yaml > agent.log 2>&1 &"

# ✅ 使用 echo 空输入
echo "" | plink -batch -pw "password" root@host "cd ~/goremote && nohup ./agent --config config.yaml > /dev/null 2>&1 &"
```

### 2.3 进程杀不掉用 fuser

```bash
# 按端口杀（最可靠）
fuser -k 8080/tcp

# 或用 killall
killall -9 agent

# 或用 pkill
pkill -9 -f 'agent --config'
```

### 2.4 二进制覆盖问题 (binary in use)

Linux 上正在运行的程序文件无法被覆写，必须先重命名：

```bash
# 先重命名旧 binary
mv /path/to/agent /path/to/agent_old

# 再上传新 binary
pscp -P 22 -pw "password" local/agent user@host:/path/to/agent

# 杀旧进程
pkill -9 -f 'agent --config'
```

## 3. TLS 证书配置

### 3.1 Go 1.15+ 要求 SAN

自签名证书必须包含 Subject Alternative Names：

```bash
# 生成密钥 + 带 SAN 的证书
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server" \
  -addext "subjectAltName=IP:your-ip,DNS:your-ip"
```

### 3.2 常见 TLS 错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `x509: certificate relies on legacy Common Name field` | 证书无 SAN | 重新生成带 SAN 的证书 |
| `tls: failed to verify certificate` | 客户端 CA 路径不正确 | 检查 `tls.ca` 配置 |
| `tls: bad certificate` | 证书与私钥不匹配 | 验证证书和私钥的 md5sum |

### 3.3 客户端配置

**验证模式（推荐）**：
```yaml
server:
  address: "YOUR_SERVER:8080"
  tls:
    enabled: true
    ca: "server.crt"
```

**跳过验证模式（仅测试）**：
```yaml
server:
  address: "YOUR_SERVER:8080"
  tls:
    enabled: true
    insecure_skip_verify: true
```

## 4. 交叉编译

### 从 Windows 编译 Linux 二进制

```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/agent ./cmd/agent

# 验证
file bin/agent
# 输出：ELF 64-bit LSB executable, x86-64
```

上传后需在 Linux 上执行 `chmod +x agent`。

## 5. 常见问题排查

### Agent 启动后找不到配置文件

检查工作目录，使用绝对路径：
```bash
cd /path/to/goremote && ./agent --config /path/to/goremote/config.yaml
```

### Agent 一直显示 "connecting to server"

1. 检查 `config.yaml` 中的 `server.address` 是否正确
2. 检查服务端是否启动：`curl -k https://server:8080/health`
3. 检查 TLS 配置是否匹配（服务端启用 TLS 时客户端也需启用）

### 隧道创建后客户端下线

1. 检查是否有多个 agent 进程同时运行：`ps aux | grep agent`
2. 杀掉所有旧进程后重新启动
3. 检查服务端日志确认消息处理是否正常

### 配置文件管理规范

- 文档内可保留实际 IP（便于追溯）
- 配置文件中必须脱敏，使用 `your-server` 等占位符
- 有代码默认值的字段可省略

## 6. 健康检查清单

部署完成后逐项确认：

```
□ 服务端进程运行中: ps aux | grep server
□ 健康检查通过: curl -k https://server:8080/health → {"status":"ok"}
□ Agent 已注册: curl -k -b cookies.txt https://server:8080/api/clients → client 在线
□ 隧道可创建: POST /api/tunnels → 返回 tunnel_id
□ 隧道数据转发: curl https://server:10000/ → 返回内网响应
□ TLS 握手成功: agent 日志显示 "connected to server"
□ 端口清理正常: 杀 agent 后 GET /api/tunnels → {"total":0}
```