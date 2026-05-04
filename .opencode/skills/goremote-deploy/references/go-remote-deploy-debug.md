# GoRemote 部署与调试实战经验

## 1. PowerShell 与 curl 的坑

### curl JSON POST

```powershell
# ✅ 方式 1：使用文件（最可靠）
echo '{"key":"value"}' > data.json
curl.exe -X POST url -d @data.json

# ✅ 方式 2：单引号 + 双引号混合
curl.exe -X POST url -d '{"key":"value"}'
```

### curl Cookie 管理

```powershell
# 登录，保存 cookie
curl.exe -k -c cookies.txt -X POST https://server/api/login -d '{"password":"admin123"}'
# 请求，使用 cookie
curl.exe -k -b cookies.txt https://server/api/tunnels
```

## 2. Agent 启动与运行

### Start-Process 工作目录

```powershell
# ✅ 正确 - 指定工作目录
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml" -WorkingDirectory "E:/AI-work/go-remote"
```

## 3. 配置文件管理规范

### 原则：文档内可提及 IP，配置文件中不可

| 文件类型 | IP 处理 |
|---------|---------|
| `docs/*.md` | 可以保留实际 IP |
| `config/*.yaml` | 必须脱敏，使用 `your-server` 等占位符 |
| `skills/*` | 必须脱敏 |

## 4. Agent 断线资源清理验证

```powershell
# 1. 创建隧道
curl.exe -k -b cookies.txt -X POST https://server/api/tunnels -d @tunnel.json
# 2. 确认隧道存在
curl.exe -k -b cookies.txt https://server/api/tunnels
# → {"total":1,...}
# 3. 杀 Agent
taskkill /F /IM agent.exe
# 4. 确认隧道已清理
sleep 3
curl.exe -k -b cookies.txt https://server/api/tunnels
# → {"total":0,"tunnels":[]} ✅ 修复生效
```

## 5. TLS 证书部署流程

### 快速生成命令

```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server" \
  -addext "subjectAltName=IP:your-ip,DNS:your-ip"
```

### 分发步骤

1. 服务端存放 `server.crt` + `server.key`
2. 客户端只需要 `server.crt` 作为 CA
3. 服务端配置 `tls.enabled: true`
4. 客户端配置 `tls.enabled: true` + `ca: "server.crt"`

## 6. 常见错误速查

| 现象 | 原因 | 解决 |
|------|------|------|
| Agent 启动后找不到配置文件 | 工作目录错误 | 使用绝对路径或 `-WorkingDirectory` |
| Python 命令无输出 | Microsoft Store stub | 安装完整 Python 或使用 WSL |
| curl JSON 请求乱码 | PowerShell 引号转义 | 使用 `-d @file.json` |
| `unauthorized` 错误 | 未登录获取 token | 先 `POST /api/login` 获取 cookie |
| TLS 握手被拒 | 证书无 SAN | 重新生成带 SAN 的证书 |