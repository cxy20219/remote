# GoRemote 配置字段参考

## 服务端配置 (server.yaml)

### server

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `0.0.0.0` | 监听地址 |
| `port` | int | `8080` | 监听端口 |
| `tls.enabled` | bool | `false` | 是否启用 TLS |
| `tls.cert` | string | - | TLS 证书文件路径 |
| `tls.key` | string | - | TLS 私钥文件路径 |

### auth

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `key` | string | `test-secret-key` | Agent 注册认证密钥 |

### admin

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `password` | string | `admin123` | Web 管理界面登录密码 |

### security

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `allowed_origins` | []string | `[]` | WebSocket Origin 白名单（空=允许所有，生产建议配置） |
| `login_rate_limit` | int | `5` | 每分钟每 IP 最大登录尝试次数（0=禁用） |
| `max_body_size_mb` | int | `10` | HTTP 请求体最大大小（MB，0=无限制） |

### heartbeat

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `interval` | int | `30` | 心跳检测间隔（秒） |
| `timeout` | int | `90` | 心跳超时时间（秒） |

### log

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | string | `info` | 日志级别：debug/info/warn/error |
| `file` | string | - | 日志文件路径（空=stdout） |

### tunnel

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用隧道功能 |
| `public_host` | string | - | API 返回的公网地址 |
| `default_local_addr` | string | `127.0.0.1` | 默认内网目标地址 |
| `port_range_start` | int | `10000` | 公网端口范围起始 |
| `port_range_end` | int | `20000` | 公网端口范围结束 |
| `max_tunnels_per_client` | int | `10` | 每客户端最大隧道数 |

### swagger

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用 Swagger UI（生产环境建议 false） |

---

## 客户端配置 (agent.yaml)

### server

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `address` | string | `localhost:8080` | 服务端 WebSocket 地址 |
| `tls.enabled` | bool | `false` | 是否启用 TLS |
| `tls.ca` | string | - | CA 证书路径（用于验证服务端证书） |
| `tls.insecure_skip_verify` | bool | `false` | 跳过服务端证书验证（仅测试用） |

### auth

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `key` | string | - | 注册认证密钥（须与服务端一致） |

### agent

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `hostname` | string | 自动检测 | 客户端主机名 |
| `os` | string | 自动检测 | 客户端操作系统 |

### heartbeat

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `interval` | int | `30` | 心跳间隔（秒） |

### reconnect

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `interval` | int | `5` | 初始重连间隔（秒） |
| `max_attempts` | int | `0` | 最大重连次数（0=无限） |
| `max_interval` | int | `60` | 最大重连间隔（秒） |

### log

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | string | `info` | 日志级别 |
| `file` | string | - | 日志文件路径（空=stdout） |

---

## 配置模板

### 开发环境（最小配置）

**server.yaml**:
```yaml
server:
  host: "0.0.0.0"
  port: 8080

auth:
  key: "test-secret-key"

tunnel:
  public_host: "localhost"
  port_range_start: 10000
  port_range_end: 20000
```

**agent.yaml**:
```yaml
server:
  address: "localhost:8080"

auth:
  key: "test-secret-key"

reconnect:
  interval: 5
  max_interval: 60
```

### 生产环境（完整配置）

**server.yaml**:
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert: "server.crt"
    key: "server.key"

auth:
  key: "your-production-secret-key"

admin:
  password: "your-admin-password"

heartbeat:
  interval: 30
  timeout: 90

log:
  level: "info"

tunnel:
  enabled: true
  public_host: "your-public-ip"
  port_range_start: 10000
  port_range_end: 20000
  max_tunnels_per_client: 10

swagger:
  enabled: false
```

**agent.yaml**:
```yaml
server:
  address: "your-server:8080"
  tls:
    enabled: true
    ca: "server.crt"

auth:
  key: "your-production-secret-key"

agent:
  hostname: "internal-server"
  os: "linux"

heartbeat:
  interval: 30

reconnect:
  interval: 5
  max_interval: 60

log:
  level: "info"
```