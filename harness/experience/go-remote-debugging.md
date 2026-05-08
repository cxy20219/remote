# GoRemote 调试开发经验

## 概述

本文档汇总 GoRemote SSH 隧道系统的开发、调试、部署和运维过程中积累的实战经验，涵盖环境差异、配置管理、问题排查和最佳实践。

> 专题文档：
> - [远程部署常见坑点](./remote-deployment-pitfalls.md) — 五大部署坑点
> - [Gin 路由与管理员认证实现经验](./gin-auth-route-tips.md) — 路由、Middleware、Cookie
> - [加密隧道开发实战经验](./encrypted-tunnel-lessons.md) — 加密功能开发踩坑记录

## 1. TLS 证书配置

### Go 1.15+ 要求 SAN 而不是 Common Name

**现象**：
```
x509: certificate relies on legacy Common Name field, use SANs instead
```

**解决**：生成证书时必须包含 SAN：
```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server.com" \
  -addext "subjectAltName=DNS:your-server.com,IP:1.2.3.4"
```

### 证书分发规则

| 文件 | 位置 | 用途 |
|------|------|------|
| `server.crt` | 服务端 + 客户端 | 服务端 TLS 证书 / 客户端 CA 验证 |
| `server.key` | 仅服务端（权限 600） | RSA 私钥，**绝不能离开服务端** |

```powershell
# 从服务器下载证书到本地
pscp -P 22 root@YOUR-SERVER:/path/to/server.crt .\config\
```

### TLS 排查清单

- [ ] 证书是否包含 SAN：`openssl x509 -in server.crt -text | grep -A1 "Subject Alternative Name"`
- [ ] 客户端 CA 路径是否正确
- [ ] 服务端证书和私钥是否匹配：`openssl x509 -in server.crt -noout -modulus` vs `openssl rsa -in server.key -noout -modulus`
- [ ] 证书是否过期：`openssl x509 -in server.crt -text -noout | grep "Not After"`

## 2. PowerShell 跨平台坑点

### 2.1 curl 别名陷阱

PowerShell 内置 `curl` 别名指向 `Invoke-WebRequest`，不是真正的 curl：

```powershell
# ❌ 这是 Invoke-WebRequest
curl http://example.com

# ✅ 始终使用 .exe 后缀
curl.exe http://example.com
```

### 2.2 JSON 传递可靠方案

```powershell
# ❌ 双引号嵌套 — 变量展开破坏 JSON
curl.exe -d "{\"key\":\"value\"}" url

# ✅ 方案 1：写文件再引用（最可靠）
@'
{"key":"value"}
'@ | Out-File body.json -Encoding ascii
curl.exe -d "@body.json" -H "Content-Type: application/json" url

# ✅ 方案 2：单引号（PowerShell 中不展开变量）
curl.exe -d '{"key":"value"}' -H "Content-Type: application/json" url
```

`Out-File -Encoding ascii` 确保 JSON 文件不含 BOM。

### 2.3 Cookie 管理

```powershell
curl.exe -k -c cookies.txt -X POST https://server/api/login -d '{"password":"admin123"}'
curl.exe -k -b cookies.txt https://server/api/tunnels
```

### 2.4 plink 特殊字符转义

PowerShell 执行 plink 时会对 `$` 等特殊字符做二次解析：

```powershell
# ❌ $2 被 PowerShell 视为变量
plink root@host "ps aux | awk '{print $2}'"

# ✅ 可靠方案：用 fuser 代替 ps|awk
plink root@host "fuser -k 8080/tcp 2>/dev/null; sleep 2; echo OK"
```

### 2.5 `&` 后台运行不可用

```powershell
# ❌ PowerShell 不支持 & 后台运行
# ✅ 使用 Start-Process
Start-Process -FilePath "./agent.exe" -WindowStyle Hidden -WorkingDirectory "E:/work"
```

### 2.6 Windows `netstat` vs Linux `ss`

```powershell
# Windows — 查看端口占用
netstat -ano | Select-String ":7777"

# Linux — 查看监听端口
ss -tlnp | grep 8080
```

## 3. Agent 启动与运行

### 3.1 Start-Process 工作目录

默认工作目录可能是 `C:\Windows\System32`，导致相对路径配置文件找不到：

```powershell
# ❌ agent 找不到 config/agent.yaml
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml"

# ✅ 指定工作目录
Start-Process -FilePath "bin/agent.exe" `
  -ArgumentList "--config config/agent.yaml" `
  -WorkingDirectory "E:/AI-work/go-remote"
```

### 3.2 Python Microsoft Store Stub

Windows 10/11 的 `python.exe` 可能是 Store 重定向 stub，非交互环境不工作：

```powershell
where.exe python
# C:\Users\xxx\AppData\Local\Microsoft\WindowsApps\python.exe  ← stub

# 解决：安装完整 Python，或隧道测试用已有服务代替
```

### 3.3 Start-Process Redirect 冲突

```powershell
# ❌ -NoNewWindow 与 -RedirectStandardOutput/Error 互斥
Start-Process ... -NoNewWindow -RedirectStandardOutput "log.txt"

# ✅ 选其一：WindowStyle Hidden 或 cmd /c 重定向
Start-Process -FilePath "agent.exe" -WindowStyle Hidden
```

### 3.4 Agent 断线资源清理验证

```powershell
# 1. 创建隧道 → 确认存在
curl.exe -k -b cookies.txt https://server/api/tunnels

# 2. 杀 Agent
taskkill /F /IM agent-windows-amd64.exe

# 3. 等待心跳超时
Start-Sleep 5

# 4. 验证隧道已清理
curl.exe -k -b cookies.txt https://server/api/tunnels
# → {"total":0,"tunnels":[]}
```

## 4. 配置文件管理

### 4.1 配置脱敏规范

| 文件类型 | IP/密码处理 |
|---------|------------|
| `docs/*.md` | 可保留实际 IP（便于追溯） |
| `config/*.yaml` | 必须脱敏，使用 `your-server` 等占位符 |
| `README.md` / `AGENTS.md` | 不包含 IP |

### 4.2 精简原则

1. 有代码默认值的字段可省略（减少配置噪声）
2. TLS 禁用时不填 cert/key
3. 部署配置与开发配置分开（`-deploy.yaml`）
4. 生产环境关闭 Swagger（`swagger.enabled: false`）

### 4.3 未使用字段清理

定期审查并删除无效字段：

| 未使用字段 | 位置 | 原因 |
|-----------|------|------|
| `file_transfer.*` | server.yaml | 文件传输功能已移除 |
| `reconnect.enabled` | agent.yaml | 配置结构中无此字段 |

### 4.4 配置修改不生效

1. 确认加载的是正确的配置文件路径
2. 重启服务使配置生效
3. 检查配置是否有语法错误（YAML 缩进、引号等）

## 5. 隧道开发与调试

### 5.1 隧道列表排序

Go map 遍历顺序不确定，需显式按 `CreatedAt` 排序：

```go
sort.Slice(tunnels, func(i, j int) bool {
    return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
})
```

### 5.2 端口修改逻辑

修改隧道配置时，区分哪些触发监听器重启、哪些只需通知 Agent：
- `publicPort` 变化 → 需要重启监听器
- `localPort` / `protocol` 变化 → 只需通知 Agent

### 5.3 隧道不通排查清单

- [ ] 服务端是否运行：`ps aux | grep server`
- [ ] 服务端监听端口：`ss -tlnp | grep 8080`
- [ ] Agent 是否运行：`ps aux | grep agent`
- [ ] Agent 是否注册：`curl -k https://server:8080/api/clients`
- [ ] 隧道是否存在：`curl -k https://server:8080/api/tunnels`
- [ ] 内网服务是否运行：`curl http://localhost:local_port/`
- [ ] 防火墙是否放行：`iptables -L -n | grep port`
- [ ] 加密是否生效：查看服务端/Agent 日志

### 5.4 验证隧道连通性

```bash
# 从服务器自身通过 tunnel 端口测试（最可靠）
nc -w 2 127.0.0.1 TUNNEL_PORT
# → 应收到目标服务的协议 banner

# 通过 SSH 到服务器执行 nc
plink root@host "timeout 3 nc -w 2 127.0.0.1 TUNNEL_PORT 2>&1"
```

## 6. 交叉编译

```powershell
# Linux 64位
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o bin/server-linux-amd64 ./cmd/server

# Windows 64位
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags "-s -w" -o bin/agent-windows-amd64.exe ./cmd/agent
```

- `$env:GOOS` 设置后只对当前进程有效
- `-ldflags "-s -w"` 去除调试信息，减小体积
- 编译后需 `chmod +x` 赋予执行权限
- 跨平台编译后本地无法直接运行，需 `file bin/server` 确认格式

## 7. 磁盘空间管理

部署前务必检查磁盘空间，上传失败最常见原因：

```bash
df -h /root                # 检查磁盘使用率
du -sh /var/log/*          # 找大文件
ls -lh /path/to/server.log # 日志文件常见 1GB+
```

**预防**：
- 日志配置 `log.file: ""` 输出到 stdout，由 systemd/journald 轮转
- 部署脚本中清理旧二进制备份
- 定期检查 `/tmp` 残留

## 8. 常见错误速查

| 现象 | 原因 | 解决 |
|------|------|------|
| Agent 启动后找不到配置文件 | 工作目录错误 | 使用绝对路径或 `-WorkingDirectory` |
| Python 命令无输出 | Microsoft Store stub | 安装完整 Python 或用已有服务测试 |
| curl JSON 请求乱码 | PowerShell 引号转义 | 使用 `-d @file.json` |
| `unauthorized` 错误 | 未登录获取 token | 先 `POST /api/login` 获取 cookie |
| 隧道数据无法传输 | 加密密钥不一致 | 确认服务端和 Agent 的 `auth.key` 相同 |
| pscp 上传 Network error | 磁盘满 | `df -h` 检查，清理旧日志/备份 |
| TLS 握手被拒 | 证书无 SAN | 重新生成带 SAN 的证书 |
| plink 主机密钥警告 | 新端口首次连接 | 用 `nc` 验证连通性，不依赖 SSH 层 |
| `swag init` 后编译失败 | 包名不匹配 | 确认 `-o docs` 输出目录与代码 import 一致 |

## 相关文档

- [加密隧道部署与验证直通流程](../workflow/encrypted-tunnel-deploy-verify.md)
- [加密隧道开发实战经验](./encrypted-tunnel-lessons.md)
- [远程部署常见坑点](./remote-deployment-pitfalls.md)
- [Gin 路由与管理员认证实现经验](./gin-auth-route-tips.md)
