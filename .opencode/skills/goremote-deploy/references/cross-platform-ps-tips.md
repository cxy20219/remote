# 跨平台开发与 PowerShell 使用技巧

## 1. 交叉编译

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server
```

## 2. PowerShell 中 `curl` 的正确用法

### 坑：PowerShell 有内置的 `curl` 别名

```powershell
# ❌ 这是 Invoke-WebRequest，不是 curl！
curl http://example.com
# ✅ 这才是真正的 curl
curl.exe http://example.com
```

### JSON 传参

```powershell
# ✅ 推荐 — 写文件再引用
@'{"key":"value"}'@ | Out-File body.json -Encoding ascii
curl.exe -d "@body.json" -H "Content-Type: application/json"
```

## 3. plink 命令引用问题

```powershell
# ❌ $2 被 PowerShell 视为变量
plink root@host "ps aux | awk '{print $2}'"
# ✅ 用 fuser 替代 ps | awk | xargs
plink root@host "fuser -k 8080/tcp 2>/dev/null"
```

## 4. JSON 远程传递的可靠方式

```powershell
# 1. 本地写文件
@'{"client_id":"xxx","local_port":7777,"protocol":"tcp"}'@ | Out-File "tunnel.json" -Encoding ascii
# 2. 用 @file 引用
curl.exe -sk -X POST "https://host/api/tunnels" -H "Content-Type: application/json" -d "@tunnel.json"
# 3. 用完清理
Remove-Item "tunnel.json"
```

## 5. Windows `netstat` vs Linux `ss`

```powershell
# Windows
netstat -ano | Select-String ":7777"
# Linux
ss -tlnp | grep 8080
```

## 6. `Start-Process` 启动后台服务

```powershell
Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory "E:\path" -WindowStyle Hidden
```

## 7. 证书管理

| 文件 | 位置 | 用途 |
|---|---|---|
| `server.crt` | 服务端 + 客户端 | 服务端 TLS 证书 / 客户端 CA 验证 |
| `server.key` | 仅服务端 | RSA 私钥，权限 600 |

**分发规则**：
- `server.crt`（公钥）可分发到客户端用于 CA 验证
- `server.key`（私钥）**绝不能离开服务端**