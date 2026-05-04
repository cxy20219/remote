# 跨平台开发与 PowerShell 使用技巧

## 1. 交叉编译

### 从 Windows 编译 Linux 二进制
```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server
```

### 注意
- `$env:GOOS` 是 PowerShell 语法，设置后只对当前进程有效
- 跨平台编译后本地无法直接运行 binary，需 `file bin/server` 确认格式

---

## 2. PowerShell 中 `curl` 的正确用法

### 坑：PowerShell 有内置的 `curl` 别名
```powershell
# 这是 Invoke-WebRequest，不是 curl！
curl http://example.com

# 这才是真正的 curl
curl.exe http://example.com
```

### 推荐
- **始终使用 `curl.exe`** 确保调用的是系统 curl
- 或在命令开头 `curl.exe`（不加 `.exe` 在 PS 中会触发别名）

### JSON 传参方式对比

```powershell
# ❌ 容易出错 — 引号嵌套复杂
curl.exe -d "{\"key\":\"value\"}"

# ✅ 推荐 — 写文件再引用
@'
{"key":"value"}
'@ | Out-File body.json -Encoding ascii
curl.exe -d "@body.json" -H "Content-Type: application/json"

# ✅ 也可以用单引号（但 JSON 内属性名必须双引号）
curl.exe -d '{"key":"value"}' -H "Content-Type: application/json"
```

`Out-File -Encoding ascii` 保证 JSON 文件不含 BOM，避免 curl 解析问题。

---

## 3. plink 命令引用问题

### 问题
PowerShell 在执行 plink 时会对特殊字符做二次解析。

```powershell
# ❌ $2 被 PowerShell 视为变量
plink root@host "ps aux | awk '{print $2}'"

# ✅ 用单引号或转义
plink root@host "ps aux | awk '{print \$2}'"
# 但 \$ 在某些 PS 版本仍有问题，更稳妥的做法：
plink root@host "ps aux | awk '{print \$2}'"   # 需要试验
```

### 推荐方案
- **复杂命令写脚本文件上传执行**，而不是拼在 plink 参数里
- 简单的 kill/restart 用 `fuser -k PORT` 替代 `ps | awk | xargs`
- 用 `fuser -k 8080/tcp` 替代 `kill $(pgrep server)`

```powershell
# ✅ 可靠方案
plink root@host "fuser -k 8080/tcp 2>/dev/null; sleep 2; echo OK"
```

---

## 4. JSON 远程传递的可靠方式

### 背景
go-remote 的 API 需要 JSON body。直接在 curl 参数里写 JSON 容易被 shell 转义破坏。

### 可靠方案
```powershell
# 1. 本地写文件
@'
{"client_id":"xxx","local_port":7777,"protocol":"tcp"}
'@ | Out-File "tunnel.json" -Encoding ascii

# 2. 用 @file 引用（避免 shell 转义）
curl.exe -sk -X POST "https://host/api/tunnels" -H "Content-Type: application/json" -d "@tunnel.json"

# 3. 用完清理
Remove-Item "tunnel.json"
```

### 在远程服务器上构造 JSON 的方案
```bash
# 方案 A: 用 python（如果已安装）
python3 -c "import json; open('/tmp/t.json','w').write(json.dumps({'key':'value'}))"

# 方案 B: 用 heredoc 写入文件
cat > /tmp/t.json << 'EOF'
{"key":"value"}
EOF

# 方案 C: 直接用 curl（简单场景）
curl -X POST -d '{"key":"value"}' -H 'Content-Type: application/json'
```

---

## 5. Windows `netstat` vs Linux `ss`

### Windows
```powershell
netstat -ano | Select-String ":7777"
# 列含义: 协议 本地地址 外部地址 状态 PID
```

### Linux
```bash
ss -tlnp | grep 8080
# -t TCP, -l listening, -n numeric, -p process
```

---

## 6. `Start-Process` 启动后台服务

### 最佳实践
```powershell
# 启动 node 服务（无需输出重定向）
Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory "E:\path" -WindowStyle Hidden

# 注意：不能在 Start-Process 同时用 -RedirectStandardOutput 和 -NoNewWindow（冲突）
```

### 验证
```powershell
netstat -ano | Select-String ":7777"
# 确认 LISTENING 状态
```

### 清理
```powershell
Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name agent -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## 7. 证书管理

### 文件用途
| 文件 | 位置 | 用途 |
|---|---|---|
| `server.crt` | 服务端 + 客户端 | 服务端 TLS 证书 / 客户端 CA 验证 |
| `server.key` | 仅服务端 | RSA 私钥，权限 600 |

### 分发规则
- `server.crt`（公钥）可分发到客户端用于 CA 验证
- `server.key`（私钥）**绝不能离开服务端**
- 客户端配 `tls.ca: config/server.crt`，服务端配 `tls.cert` + `tls.key`

### 自签证书检查
```bash
openssl x509 -in server.crt -text -noout | grep -E "Subject:|Not Before|Not After|DNS:|IP Address:"
openssl rsa -in server.key -check -noout
```
