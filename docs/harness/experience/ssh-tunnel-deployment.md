# SSH 隧道部署排障经验

## 1. Windows 跨平台编译

### 交叉编译命令
```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent
```

**注意**: PowerShell 中 `&&` 操作符无效，需用 `;` 或分行的方式执行多条命令。

## 2. PuTTY 工具集使用

### 工具位置
- plink: `C:\Program Files\PuTTY\plink.exe`
- pscp: `C:\Program Files\PuTTY\pscp.exe`

### 密码处理
Windows 下无法使用 `sshpass`，密码文件方式：
```powershell
$pass = "password" | Out-File -Encoding ASCII "$env:TEMP\pass.txt"
plink -pwfile "$env:TEMP\pass.txt" -P 22 user@host cmd
```

**安全注意**: 临时文件使用后应删除。

### plink 批处理模式 hostkey 问题
使用 `-hostkey` 参数预置 hostkey 避免交互式确认：
```powershell
plink -hostkey "ssh-ed25519 255 SHA256:xxx" -pwfile "$env:TEMP\pass.txt" -P 10000 user@host cmd
```

获取 hostkey：首次连接时会显示 fingerprint，用完整的 `ssh-ed25519 255 SHA256:xxx` 格式。

## 3. API 调试技巧

### curl JSON 请求
PowerShell 中 JSON 变量直接传递会被转义，用 `Invoke-RestMethod` 更可靠：
```powershell
$body = @{"client_id"="xxx";"local_port"=22;"protocol"="tcp"} | ConvertTo-Json
Invoke-RestMethod -Uri 'http://host/api/tunnels' -Method Post -ContentType 'application/json' -Body $body
```

### Windows curl 别名冲突
PowerShell 中 `curl` 是 `Invoke-WebRequest` 的别名，使用 `curl.exe` 调用真正的 curl。

## 4. 远程服务器排查

### 检查进程
```bash
ps aux | grep server
netstat -tlnp | grep 8080
```

### 查看日志
```bash
cat ~/goremote/server.log
```

### 端口被占用处理
先 `kill` 旧进程再启动新进程，注意进程 ID 可能变化。

### 防火墙检查
```bash
# 检查端口是否监听
netstat -tlnp | grep 8080

# 检查云服务器安全组规则（控制台）

# 检查 iptables
iptables -L -n
```

## 5. 部署检查清单

- [ ] Linux 二进制有执行权限 (`chmod +x`)
- [ ] 配置文件路径正确（绝对路径）
- [ ] `auth.key` 服务端和客户端一致
- [ ] 服务端 `tunnel.enabled: true`
- [ ] 客户端能访问服务端 WebSocket 端口（不被防火墙阻）
- [ ] 云服务器安全组/防火墙开放 8080 和隧道端口范围

## 6. 网络连通性验证

```bash
# 从公网服务器测试能否访问内网
ping 192.168.66.42

# 从本地测试公网服务器
ping YOUR_SERVER

# 测试端口连通性
nc -zv YOUR_SERVER 8080
telnet YOUR_SERVER 8080
```

**注意**: 公网服务器可能无法直接访问内网 IP（需要 VPN 或其他网络方案）。

## 7. SSH 用户认证

- SSH 隧道的用户是**内网目标服务器的用户**，不是公网服务器用户
- 本次测试：`lvcheng@YOUR_SERVER:10000` → 实际认证到 `192.168.66.42` 的 lvcheng 用户

## 8. 隧道端口分配

- 端口范围在 `server.yaml` 中配置：`port_range_start: 10000`, `port_range_end: 20000`
- 每次创建隧道从起始端口递增分配
- 删除隧道后端口释放供下次使用

## 9. 常见错误排查

| 错误 | 原因 | 解决 |
|------|------|------|
| `bind: address already in use` | 端口被占用 | kill 旧进程或改端口 |
| `tunnel is not enabled` | 配置未开启 | server.yaml 设置 `tunnel.enabled: true` |
| `client not found or offline` | 客户端未连接 | 检查 agent 状态和日志 |
| `Access denied` | 用户名/密码错误 | 确认内网服务器 SSH 凭据 |
| hostkey 确认失败 | 首次连接需确认 | 使用 `-hostkey` 参数预置 |
