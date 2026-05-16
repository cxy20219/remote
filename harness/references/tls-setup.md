# GoRemote TLS 设置指南

## 概述

GoRemote 支持通过 TLS 加密 Server 与 Agent 之间的 WebSocket 通信，并可选择性验证服务端证书以防止中间人攻击。

当前实现按破兼容安全基线收紧：Server 与 Agent 的 TLS 配置默认要求 TLS 1.3。老旧 TLS 1.2 客户端或代理不能再作为中间层直接接入。

## 安全等级

| 模式 | 配置 | 安全性 | 说明 |
|------|------|--------|------|
| 无 TLS | `ws://` | ❌ 不安全 | 明文传输，易被窃听 |
| TLS 无验证 | `wss://` + `insecure_skip_verify: true` | ⚠️ 仅加密 | TLS 1.3 防窃听但无法验证服务器身份，仅用于临时测试 |
| TLS 带 CA | `wss://` + `ca: "server.crt"` | ✅ 安全 | TLS 1.3 加密 + 验证服务器证书 |

## 生成自签名证书

### 生成私钥（2048 位 RSA）

```bash
openssl genrsa -out server.key 2048
```

### 生成证书（含 SAN，Go 1.15+ 要求）

```bash
# 替换 your-server-ip 为实际公网 IP
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server-ip" \
  -addext "subjectAltName=IP:your-server-ip,DNS:your-server-ip"
```

### 验证证书

```bash
# 查看证书内容
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative"

# 验证私钥匹配
openssl x509 -in server.crt -noout -modulus | md5sum
openssl rsa -in server.key -noout -modulus | md5sum
# 两个 md5 值应相同
```

## 配置服务端（server.yaml）

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert: "server.crt"
    key: "server.key"
```

## 配置客户端（agent.yaml）

### 模式 A：验证服务器证书（推荐）

```yaml
server:
  address: "your-server-ip:8080"
  tls:
    enabled: true
    ca: "server.crt"
```

### 模式 B：仅加密不验证（测试环境）

```yaml
server:
  address: "your-server-ip:8080"
  tls:
    enabled: true
    insecure_skip_verify: true
```

## 证书分发

将服务端生成的 `server.crt` 复制到每台 Agent 机器：

```bash
# 从服务端拷贝到本地
scp root@your-server:/path/to/server.crt ./config/

# 更新 agent.yaml 中 ca 路径
# ca: "config/server.crt"
```

## 常见错误

### x509: certificate relies on legacy Common Name field

**原因**：Go 1.15+ 要求证书包含 SAN（Subject Alternative Names）。

**解决**：重新生成证书时添加 `-addext "subjectAltName=IP:your-ip"`

### tls: failed to verify certificate

**原因**：客户端 CA 路径不正确或证书不包含当前访问的 IP/域名。

**解决**：
1. 确认客户端 `ca` 路径指向正确的服务端证书
2. 确认证书 SAN 包含客户端连接的地址

### remote error: tls: bad certificate

**原因**：服务端密钥与证书不匹配，或证书已过期。

**解决**：
1. 验证证书与私钥匹配
2. 检查证书有效期：`openssl x509 -in server.crt -noout -dates`
