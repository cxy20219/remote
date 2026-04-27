# GoRemote 调试开发经验总结

本文档记录在 GoRemote 项目调试和开发过程中总结的经验教训，避免重复踩坑。

## 1. 二进制部署关键检查

### 1.1 上传后务必验证文件大小

**问题**：通过 `pscp` 上传二进制文件时，网络中断或超时可能导致文件不完整，但命令不报错。

**现象**：本地编译的 binary 和远程的 binary 大小不一致，导致运行旧版本。

**排查方法**：
```powershell
# 本地检查大小
Get-ChildItem bin/server | Select-Object Length

# 远程检查大小
plink ... "ls -la /root/goremote/server"
```

**最佳实践**：
- 上传后立即校验 MD5 或文件大小
- 建议分两步：先 kill 旧进程，再上传新 binary，最后启动

### 1.2 Swagger Docs 嵌入在编译时

**问题**：更新了 `docs/docs.go` 后，Swagger UI 仍显示旧接口定义。

**原因**：Swagger JSON 是通过 `swaggo/swag` 工具在**编译时生成**，直接修改源文件不会生效，必须重新编译。

**解决**：
```powershell
# 1. 重新编译（docs.go 会被编译进二进制）
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o bin/server ./cmd/server

# 2. 上传到服务器
pscp -pwfile ... bin/server root@host:/path/to/server_new

# 3. 重启服务（kill 旧进程，启动新进程）
```

## 2. PuTTY 工具链注意事项

### 2.1 密码文件路径问题

**问题**：PowerShell 中使用 `$env:TEMP` 构造密码文件路径时，路径可能包含特殊字符或空格导致 PuTTY 工具无法识别。

**现象**：`plink: unable to open password file`

**解决**：
```powershell
# 方法1：直接使用短路径
$pass = "Ss123456!" | Out-File -Encoding ASCII "$env:TEMP\ssh_pass.txt"
& "C:\Program Files\PuTTY\plink.exe" -pwfile "$env:TEMP\ssh_pass.txt" ...

# 方法2：使用 -pw 直接传密码（适用于简单场景）
& "C:\Program Files\PuTTY\plink.exe" -pw "Ss123456!" ...
```

### 2.2 plink 批处理模式使用 `-batch`

**问题**：交互式确认 hostkey 时，脚本会挂起等待输入。

**解决**：使用 `-batch` 参数禁用交互：
```powershell
plink -batch -pwfile "$env:TEMP\pass.txt" -P 22 user@host "command"
```

### 2.3 plink hostkey 预置格式

**问题**：首次连接需要确认 hostkey，脚本环境下会失败。

**解决**：使用 `-hostkey` 参数预置完整格式：
```powershell
plink -hostkey "ssh-ed25519 255 SHA256:6UuurwstZ8VAi7VciSrumObZP+GpNBMBGYgCuzeKQ2c" ...
```

格式必须是完整的 `ssh-ed25519 255 SHA256:xxx`，不能只传 fingerprint。

## 3. 进程管理与服务重启

### 3.1 优雅重启顺序

**推荐顺序**：
1. 上传新 binary 为 `server_new`
2. kill 旧进程
3. 替换 binary（mv server server_old; mv server_new server）
4. chmod +x
5. 启动新进程

**避免**：先启动新进程再 kill 旧进程，可能导致端口冲突。

### 3.2 kill 命令在远程执行

**问题**：通过 plink 执行 `kill PID` 时，命令可能不会立即生效。

**解决**：使用 `-9` 信号强制终止，并加延迟：
```bash
kill -9 58093 2>/dev/null
sleep 1
ps aux | grep server | grep -v grep
```

## 4. SSH 隧道与端口转发

### 4.1 plink 建立临时端口转发

**用途**：测试阶段临时建立端口转发访问内网服务。

```powershell
# 转发本地 13306 -> 内网 22
plink -hostkey "ssh-ed25519 255 SHA256:xxx" -pwfile "$env:TEMP\pass.txt" `
  -P 10001 -L 13306:localhost:22 lvcheng@YOUR_SERVER `
  "echo 'Tunnel active'; sleep 5"
```

### 4.2 SSH 隧道用户身份

**关键点**：SSH 隧道的认证用户是**内网目标服务器的用户**，不是公网服务端用户。

**示例**：
```
ssh lvcheng@YOUR_SERVER -p 10001
# 实际认证到 192.168.66.42 的 lvcheng 用户
```

### 4.3 SCP 通过隧道传输文件

**上传到内网**：
```powershell
# 通过端口转发上传
plink -hostkey ... -pwfile ... -P 10001 lvcheng@YOUR_SERVER `
  "cat > /home/lvcheng/test_remote.txt" < local_file.txt

# 或用 pscp 指定端口
pscp -P 10001 -hostkey ... -pwfile ... local_file.txt lvcheng@YOUR_SERVER:/path/
```

**从内网下载**：
```powershell
pscp -P 10001 -hostkey ... -pwfile ... lvcheng@YOUR_SERVER:/path/remote_file.txt .
```

## 5. API 调试技巧

### 5.1 PowerShell 中 JSON 处理

**问题**：直接用字符串拼接 JSON 可能转义问题。

**推荐方法**：
```powershell
$body = @{
    client_id = "client-xxx"
    local_port = 22
    protocol = "tcp"
} | ConvertTo-Json

Invoke-RestMethod -Uri 'http://YOUR_SERVER:8080/api/tunnels' `
  -Method Post -ContentType 'application/json' -Body $body
```

### 5.2 curl.exe vs curl 别名

**问题**：PowerShell 中 `curl` 是 `Invoke-WebRequest` 别名。

**解决**：使用 `curl.exe` 调用真正的 curl，或直接用 `Invoke-RestMethod`。

### 5.3 API 响应验证

**快速验证命令**：
```powershell
# 健康检查
curl.exe -s http://YOUR_SERVER:8080/health

# 获取客户端列表
curl.exe -s http://YOUR_SERVER:8080/api/clients

# 创建隧道
$body = @{"client_id"="xxx";"local_port"=22;"protocol"="tcp"} | ConvertTo-Json
curl.exe -s -X POST -H "Content-Type: application/json" `
  -d $body http://YOUR_SERVER:8080/api/tunnels
```

## 6. 环境差异处理

### 6.1 Windows/Linux 命令差异

| 场景 | Windows | Linux |
|------|---------|-------|
| 列表目录 | `dir` 或 `Get-ChildItem` | `ls` |
| 延迟 | `Start-Sleep -Seconds 1` | `sleep 1` |
| 文件权限 | N/A | `chmod +x` |
| 进程查看 | `Get-Process` | `ps aux` |
| 网络连接 | `netstat -an` | `netstat -tlnp` |

### 6.2 Go 交叉编译

**Windows → Linux**：
```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/server ./cmd/server
```

**注意**：
- PowerShell 中 `&&` 不支持，使用 `;` 分隔命令
- 编译产物无执行权限，部署后需 `chmod +x`

## 7. 常见坑点速查

| 症状 | 可能原因 | 解决 |
|------|----------|------|
| Swagger 显示旧 API | 未重新编译 | 重新 `go build` 并部署 |
| Binary 大小不匹配 | 上传不完整 | 校验 MD5/文件大小 |
| `pscp` 上传慢 | 网络波动 | 重试或分片上传 |
| `plink` 挂起 | hostkey 交互确认 | 加 `-batch` 参数 |
| 密码文件找不到 | 路径含特殊字符 | 使用短路径或 `-pw` |
| 端口已占用 | 旧进程未关闭 | `kill -9 PID` |
| 隧道创建失败 | Agent 离线 | 检查 agent 状态 |
| SSH 认证失败 | 用户名/密码错误 | 确认内网 SSH 凭据 |

## 8. 调试检查清单

当部署或连接问题时，按顺序检查：

- [ ] 本地 binary 大小 = 远程 binary 大小
- [ ] 新 binary 已设置执行权限 (`chmod +x`)
- [ ] 旧进程已 kill（`ps aux | grep server`）
- [ ] 新进程已启动（检查 PID）
- [ ] 服务端日志无 ERROR（`cat server.log`）
- [ ] `curl http://host:8080/health` 返回正常
- [ ] `GET /api/clients` 显示 agent 在线
- [ ] 隧道创建成功（`POST /api/tunnels`）
- [ ] SSH 通过公网端口能连接内网（`ssh user@host -p PORT`）