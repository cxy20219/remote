# GoRemote 调试开发经验总结

## 概述

本文档记录 GoRemote SSH 隧道使用和开发调试过程中遇到的常见问题、解决方案和最佳实践。

## 1. TLS 证书配置

### 问题：Go 1.15+ 要求 SAN 而不是 Common Name

**现象**：
```
x509: certificate relies on legacy Common Name field, use SANs instead
```

**原因**：
Go 1.15+ 版本不再默认使用 Common Name 进行证书验证，要求使用 Subject Alternative Names (SANs)。

**解决方案**：
生成证书时必须包含 SAN：

```bash
# 生成私钥
openssl genrsa -out server.key 2048

# 生成带 SAN 的证书（Go 1.15+ 要求）
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server.com" \
  -addext "subjectAltName=DNS:your-server.com,IP:1.2.3.4"
```

**经验**：
- 生产环境建议使用 CA 机构签发的证书
- 自签证书用于测试，但需包含正确的 SAN
- SAN 覆盖域名和/或 IP，避免 CN 相关的历史限制

### 问题：TLS 握手失败，错误为 "certificate verify failed"

**原因**：
客户端配置的 CA 路径不正确，或证书不包含正确的 SANs。

**解决方案**：
1. 确认服务端证书包含正确的 SAN
2. 确认客户端 CA 文件指向服务端证书（server.crt）
3. 检查证书是否过期：`openssl x509 -in server.crt -text -noout | grep "Not After"`

## 2. PowerShell 转义问题

### 问题：在 Windows PowerShell 中执行复杂命令时转义错误

**现象**：
```powershell
plink -batch -pw "pass" -P 22 user@host "cat > /tmp/test.py << 'ENDPY' ... ENDPY"
# 报错：ParserError、Unexpected token 等
```

**原因**：
PowerShell 对引号、&、括号、heredoc 等特殊字符的处理与 bash 不同。

**解决方案**：

1. **使用 Python 脚本代替复杂 shell 命令**：
```python
# 创建一个 Python 脚本写文件
cfg = '''yaml content here'''
with open('/tmp/config.yaml', 'w') as f:
    f.write(cfg)
```

2. **避免内联 heredoc**：
```bash
# 错误：plink ... "cat > file << 'EOF' ... EOF"
# 正确：先写脚本，再上传执行
```

3. **& 后台运行在 PowerShell 中不支持**：
```powershell
# 错误：./agent.exe &  
# 正确：Start-Process -FilePath "./agent.exe" -NoNewWindow
```

**经验**：
- PowerShell 中复杂命令建议用 Python 脚本封装
- 上传脚本到服务器执行，避免转义问题
- 使用 `Start-Process` 代替 `&` 后台运行

## 3. 配置文件优化

### 问题：配置文件包含未使用的字段

**现象**：
配置文件中有 `file_transfer`、`server.tls.ca` 等字段，但功能已移除或未实现。

**解决方案**：
定期审查配置文件，删除未使用的字段：

| 未使用字段 | 位置 | 原因 |
|-----------|------|------|
| `file_transfer.*` | server.yaml | 文件传输功能已移除 |
| `server.tls.ca` | agent.yaml | Agent 端未实现 CA 验证 |
| `reconnect.enabled` | agent-deploy.yaml | 配置结构中无此字段 |

**经验**：
- 配置字段应与代码实现保持同步
- 使用默认值代替空字符串字段（如 `tls.cert/key` 在 disabled 时无需填写）
- 部署配置应只包含与环境相关的字段，默认值可省略

### 问题：配置修改后不生效

**现象**：
修改了 `config.yaml` 但服务端/客户端未加载新配置。

**解决方案**：
1. 确认加载的是正确的配置文件路径
2. 重启服务使配置生效
3. 检查配置是否有语法错误（YAML 缩进、引号等）

## 4. 隧道列表排序

### 问题：隧道列表刷新一次，顺序就变了

**现象**：
每次调用 `GET /api/tunnels` 返回的隧道顺序不同。

**原因**：
Go map 遍历顺序不确定，`ListTunnels()` 直接返回 map 中的值。

**解决方案**：
按 `CreatedAt` 字段排序：

```go
func (tm *TunnelManager) ListTunnels() []*Tunnel {
    tm.mu.RLock()
    defer tm.mu.RUnlock()
    tunnels := make([]*Tunnel, 0, len(tm.tunnels))
    for _, t := range tm.tunnels {
        tunnels = append(tunnels, t)
    }
    sort.Slice(tunnels, func(i, j int) bool {
        return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
    })
    return tunnels
}
```

**经验**：
- Go map 遍历顺序不确定，需要显式排序
- 按时间排序是最直观的方式
- 添加 `sort` 包到 import

## 5. 端口修改逻辑

### 问题：端口修改提交后不生效

**现象**：
前端修改隧道端口后提交，但隧道仍然转发到旧端口。

**原因**：
`UpdateTunnel()` 中错误地关闭了监听器，或监听器未重新启动。

**解决方案**：
当只修改 `localPort/protocol` 时（publicPort 不变），不应关闭服务器端的监听器：

```go
func (tm *TunnelManager) UpdateTunnel(tunnelID string, localAddr string, localPort int, protocol string) (*Tunnel, error) {
    tm.mu.Lock()
    defer tm.mu.Unlock()
    
    tunnel, ok := tm.tunnels[tunnelID]
    if !ok {
        return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
    }
    
    // 只发送 tunnel_open 给 agent，不关闭监听器
    if localPort != tunnel.LocalPort || protocol != tunnel.Protocol {
        payloadJSON, _ := json.Marshal(common.TunnelOpenPayload{
            TunnelID:  tunnelID,
            LocalAddr: tunnel.LocalAddr,
            LocalPort: localPort,  // 新端口
            Protocol:  protocol,
        })
        tunnel.Client.WriteJSON(common.Message{
            Type:    "tunnel_open",
            Payload: payloadJSON,
        })
    }
    
    tunnel.LocalAddr = localAddr
    tunnel.LocalPort = localPort
    tunnel.Protocol = protocol
    
    return tunnel, nil
}
```

**经验**：
- 修改隧道配置时，区分哪些需要重启监听器，哪些不需要
- publicPort 变化才需要重启监听器，localPort 变化只需通知 agent
- 避免在 Update 中引入不必要的状态变更

## 6. Agent 未运行排查

### 问题：隧道创建成功但访问无响应

**现象**：
隧道创建成功，但 `curl http://public:port/` 无响应或超时。

**原因**：
内网服务器上没有运行 agent，或 agent 连接已断开。

**排查步骤**：

1. **检查服务端客户端列表**：
```bash
curl http://localhost:8080/api/clients
# 确认 client 状态为 "online"
```

2. **检查 agent 进程**：
```bash
# 在内部服务器上
ps aux | grep agent | grep -v grep
```

3. **检查 agent 日志**：
```bash
# agent 日志（若配置了 file）
cat /path/to/agent.log

# 或查看 agent 输出
ps aux | grep agent  # 查看命令行的 --config 参数
```

4. **重启 agent**：
```bash
cd /path/to/agent && ./agent --config config/agent.yaml &
```

**经验**：
- 隧道工作依赖 agent 正常运行
- 服务端显示 "online" 不代表 agent 一定正常工作（可能有延迟）
- 确保 agent 的 `server.address` 指向正确的公网服务器地址

## 7. 交叉编译

### 问题：在 Windows 上编译 Linux 二进制

**现象**：
Windows 上 `go build` 生成的是 Windows .exe，无法直接上传到 Linux 服务器运行。

**解决方案**：
使用 `GOOS` 和 `GOARCH` 环境变量：

```powershell
# Linux 64位
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent

# 验证生成的是 Linux 二进制
file bin/server
# 输出：ELF 64-bit LSB executable, x86-64 ...
```

**经验**：
- Windows 编译 Linux 二进制需要设置 `GOOS=linux`
- 生成后验证文件类型（`file` 命令）
- 上传到服务器后需要 `chmod +x` 赋予执行权限

## 8. 证书分发

### 问题：客户端无法验证服务器证书

**现象**：
```
tls: failed to verify certificate: x509: certificate relies on legacy Common Name field
```

**解决方案**：

1. **服务端生成证书（带 SAN）**：
```bash
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=YOUR_SERVER" \
  -addext "subjectAltName=IP:YOUR_SERVER"
```

2. **分发证书到客户端**：
```powershell
# 从服务器下载证书
pscp -P 22 root@YOUR_SERVER:/path/to/server.crt .\config\
```

3. **客户端配置 CA**：
```yaml
server:
  address: "YOUR_SERVER:8080"
  tls:
    enabled: true
    ca: "config/server.crt"  # 指向服务器证书
```

**经验**：
- 自签证书可以作为 CA 用于验证（在生产环境应使用受信任 CA）
- 证书应放在客户端可访问的路径
- `ca` 字段为空时，客户端不验证服务器证书（不推荐）

## 9. Windows 路径问题

### 问题：配置中的路径在 Windows 和 Linux 上不兼容

**现象**：
Windows 配置文件中的路径 `C:/work/go-remote/uploads` 在 Linux 上无效。

**解决方案**：
- 开发配置使用当前系统格式
- 部署配置使用目标系统格式
- 或使用相对路径

**经验**：
- Windows 路径用 `C:\path\to\file` 或 `C:/path/to/file`
- Linux 路径用 `/path/to/file`
- 配置文件中路径应针对目标系统调整

## 10. 快速问题排查清单

### 隧道不通时检查清单

- [ ] 服务端是否运行：`ps aux | grep server`
- [ ] 服务端监听端口：`ss -tlnp | grep 8080`
- [ ] Agent 是否运行：`ps aux | grep agent`（内部服务器）
- [ ] Agent 是否注册：`curl http://localhost:8080/api/clients`
- [ ] 隧道是否存在：`curl http://localhost:8080/api/tunnels`
- [ ] 内网服务是否运行：`curl http://localhost:local_port/`（内部服务器）
- [ ] TLS 证书是否有效：`openssl x509 -in server.crt -text -noout`
- [ ] 防火墙是否放行：`iptables -L -n | grep port`

### TLS 相关

- [ ] 证书是否包含 SAN：`openssl x509 -in server.crt -text | grep -A1 "Subject Alternative Name"`
- [ ] 客户端 CA 路径是否正确
- [ ] 服务端证书和私钥是否匹配：`openssl x509 -in server.crt -noout -modulus` 对比 `openssl rsa -in server.key -noout -modulus`

## 相关文档

- [SSH 隧道直通内网服务流程](../workflow/ssh-tunnel-direct-access.md) - SSH 隧道从公网访问内网服务的完整流程
- [服务端设计文档](../server-design.md) - GoRemote 服务端架构
- [客户端设计文档](../agent-design.md) - GoRemote Agent 架构
