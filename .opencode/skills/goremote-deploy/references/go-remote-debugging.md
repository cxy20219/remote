# GoRemote 调试开发经验总结

## 1. TLS 证书配置

### 问题：Go 1.15+ 要求 SAN 而不是 Common Name

**现象**：
```
x509: certificate relies on legacy Common Name field, use SANs instead
```

**解决方案**：生成证书时必须包含 SAN：

```bash
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server.com" \
  -addext "subjectAltName=DNS:your-server.com,IP:1.2.3.4"
```

## 2. PowerShell 转义问题

### 问题：在 Windows PowerShell 中执行复杂命令时转义错误

**解决方案**：

1. **使用 Python 脚本代替复杂 shell 命令**
2. **避免内联 heredoc**：先写脚本，再上传执行
3. **`&` 后台运行在 PowerShell 中不支持**：
```powershell
# 错误：./agent.exe &
# 正确：Start-Process -FilePath "./agent.exe" -NoNewWindow
```

## 3. 配置文件优化

### 问题：配置修改后不生效

**解决方案**：
1. 确认加载的是正确的配置文件路径
2. 重启服务使配置生效
3. 检查配置是否有语法错误

## 4. 隧道列表排序

### 问题：隧道列表刷新一次，顺序就变了

**原因**：Go map 遍历顺序不确定

**解决方案**：按 `CreatedAt` 字段排序

## 5. 端口修改逻辑

### 问题：端口修改提交后不生效

**原因**：`UpdateTunnel()` 中错误地关闭了监听器

**解决方案**：当只修改 `localPort/protocol` 时（publicPort 不变），不应关闭服务器端的监听器

## 6. Agent 未运行排查

### 排查步骤：

1. **检查服务端客户端列表**：`curl http://localhost:8080/api/clients`
2. **检查 agent 进程**：`ps aux | grep agent`
3. **检查 agent 日志**：`cat /path/to/agent.log`
4. **重启 agent**：`cd /path/to/agent && ./agent --config config/agent.yaml &`

## 7. 交叉编译

```powershell
# Linux 64位
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/server ./cmd/server

# 验证生成的是 Linux 二进制
file bin/server
# 输出：ELF 64-bit LSB executable, x86-64 ...
```

## 8. 快速问题排查清单

### 隧道不通时检查清单

- [ ] 服务端是否运行：`ps aux | grep server`
- [ ] 服务端监听端口：`ss -tlnp | grep 8080`
- [ ] Agent 是否运行：`ps aux | grep agent`
- [ ] Agent 是否注册：`curl http://localhost:8080/api/clients`
- [ ] 隧道是否存在：`curl http://localhost:8080/api/tunnels`
- [ ] 内网服务是否运行：`curl http://localhost:local_port/`
- [ ] TLS 证书是否有效：`openssl x509 -in server.crt -text -noout`
- [ ] 防火墙是否放行：`iptables -L -n | grep port`