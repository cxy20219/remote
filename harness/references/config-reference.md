# GoRemote 配置字段参考

## 服务端配置 (server.yaml)

### server

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `0.0.0.0` | 监听地址 |
| `port` | int | `8080` | 监听端口 |
| `tls.enabled` | bool | `false` | 是否启用 TLS；启用后默认要求 TLS 1.3 |
| `tls.cert` | string | - | TLS 证书文件路径 |
| `tls.key` | string | - | TLS 私钥文件路径 |

### auth

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `key` | string | `CHANGE-ME-auth-key` | 旧版共享密钥字段；零配置架构下不再作为 Agent 身份主路径 |

### admin

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `password` | string | `CHANGE-ME-admin-password` | 旧版配置密码字段；零配置架构下首次启动会随机生成 admin 密码并写入 bcrypt hash |

### security

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `allowed_origins` | []string | `[]` | WebSocket Origin 白名单；空配置只允许无 Origin 的 Agent 请求，拒绝浏览器 Origin；配置值需为完整 Origin（如 `https://admin.example.com:8443`） |
| `login_rate_limit` | int | `5` | 每分钟每 IP 最大登录尝试次数（0=禁用） |
| `max_body_size_mb` | int | `10` | HTTP 请求体最大大小（MB，运行时修改立即生效；0=禁用限制） |
| `max_conn_per_min` | int | `10` | WebSocket 连接和隧道端口每分钟每 IP 最大连接数（防扫描，0=禁用） |
| `global_whitelist` | []string | `[]` | 全局 IP 白名单，支持 CIDR（如 `192.168.1.0/24`）；白名单内 IP 绕过所有限流检查 |
| `blacklist_threshold` | int | `100` | 累计限流违规次数阈值；达到后 IP 自动拉黑，后续请求直接拒绝（0=禁用自动拉黑） |
| `--state-key` / `GOREMOTE_STATE_KEY` | string | 空 | 状态文件敏感字段加密密钥；支持 `hex:<32字节hex>`、`base64:<32字节base64>` 或 32 字符以上随机字符串；建议使用环境变量而不是命令行参数 |

> 启用 `state_key` 后，`server-state.json` 中的服务端签名私钥、管理员密码 hash 和设备隧道密钥会以 AES-256-GCM 加密保存。已有明文状态在带 key 启动后会自动重写为加密格式；之后启动必须提供同一个 key。

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
| `max_size_mb` | int | `50` | 单个日志文件最大大小，仅 `file` 非空时生效 |
| `max_backups` | int | `5` | 保留的历史日志文件数量，仅 `file` 非空时生效 |

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
| `tls.enabled` | bool | `false` | 是否启用 TLS；启用后默认要求 TLS 1.3 |
| `tls.ca` | string | - | CA 证书路径（用于验证服务端证书） |
| `tls.insecure_skip_verify` | bool | `false` | 跳过服务端证书验证（仅测试用；仍要求 TLS 1.3） |

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
| `max_size_mb` | int | `50` | 单个日志文件最大大小，仅 `file` 非空时生效 |
| `max_backups` | int | `5` | 保留的历史日志文件数量，仅 `file` 非空时生效 |

---

## 配置模板

### 开发环境（最小配置）

**server.yaml**:
```yaml
server:
  host: "0.0.0.0"
  port: 8080

auth:
  key: "CHANGE-ME-auth-key"

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
  key: "CHANGE-ME-auth-key"

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

security:
  login_rate_limit: 5
  max_body_size_mb: 10
  max_conn_per_min: 10
  global_whitelist:
    - "10.0.0.0/8"
  blacklist_threshold: 100

heartbeat:
  interval: 30
  timeout: 90

log:
  level: "info"
  max_size_mb: 50
  max_backups: 5

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
  max_size_mb: 50
  max_backups: 5
```
