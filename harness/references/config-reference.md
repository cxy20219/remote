# GoRemote 配置参考

服务端采用零配置文件设计：启动参数只控制监听、TLS、数据目录和日志；端口范围、限流、心跳、白名单等运行时可调项保存在 `server-state.json`，通过 Web 面板或 `/api/settings` 修改并立即生效。

---

## 服务端启动参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--host` | string | `0.0.0.0` | HTTP/HTTPS 监听地址；仅本机使用时建议 `127.0.0.1` |
| `--port` | int | `8080` | 管理面与 Agent WebSocket 监听端口 |
| `--data` | string | `./data` | `server-state.json` 所在目录（自动创建，权限 0700） |
| `--tls-cert` | string | 空 | TLS 证书路径；与 `--tls-key` 同时提供才启用 TLS 1.3 |
| `--tls-key` | string | 空 | TLS 私钥路径 |
| `--tunnel` | bool | `true` | 是否启用隧道功能 |
| `--external-idle-timeout` | duration | `10m` | 公网隧道连接的空闲读超时；超过即关闭该连接。SSH 等长静默隧道可调大，批量端口转发可调小；`<=0` 使用内置默认 10m |
| `--swagger` | bool | `false` | 是否启用 Swagger UI（仅认证后可访问）；默认关闭，发布版不暴露该调试入口，需要时显式 `--swagger` |
| `--allowed-origins` | string | 空 | 允许打开 `/ws` 的浏览器 Origin，逗号分隔，如 `https://admin.example.com`；空值只允许无 Origin 的 Agent 连接 |
| `--state-key` | string | 空 | 状态文件敏感字段加密密钥；会出现在 `ps` / `systemctl show ExecStart`，仅作过渡，优先用 `GOREMOTE_STATE_KEY` 或 `--state-key-file` |
| `--state-key-file` | string | 空 | 从文件读取状态加密密钥；要求普通文件、非 symlink、组/其他人不可读写（0600），Windows 跳过权限位检查 |
| `--state-kdf` | string | 空 | 状态信封格式：空/`v2`（默认，口令走 argon2id）、`legacy`（只写 v1，供回滚；会把已迁移的 v2 降级回 v1，需显式指定） |
| `--trusted-proxies` | string | 空 | 逗号分隔的反代 IP/CIDR；非空时信任 `X-Forwarded-For` / `X-Real-IP`（用于限流和 challenge 绑定），同时**关闭初始化的 loopback 免令牌**，初始化一律要求一次性令牌。格式非法时服务端拒绝启动 |
| `--log-level` | string | `info` | `debug` / `info` / `warn` / `error` |
| `--log-file` | string | 空 | 空=JSON 日志写 stdout；文件权限 0600 |
| `--log-max-size-mb` | int | `50` | 单个日志文件轮转阈值 |
| `--log-max-backups` | int | `5` | 保留的历史日志文件数量 |

> 三种密钥来源（`--state-key` / `GOREMOTE_STATE_KEY` / `--state-key-file`）互斥，同时配置两个及以上时服务端拒绝启动并点名冲突项。
> `--state-key` 的值会出现在进程命令行中，生产环境优先使用 `GOREMOTE_STATE_KEY` 或 `--state-key-file`。
> 明文监听在公网接口且未启用 TLS 时，服务端会输出安全告警；管理 Cookie 和 Agent 控制消息在链路上不加密。

### 状态加密密钥格式

| 形式 | 示例 | 说明 |
|------|------|------|
| 原始字符串 | 32 字符以上随机串 | 走 argon2id（64MiB / 3 轮 / 2 并行），salt 随机生成并持久化 |
| hex | `hex:<64位hex>` | 必须解码为 32 字节；全熵密钥直通，不再做 KDF |
| base64 | `base64:<32字节base64>` | 必须解码为 32 字节；全熵密钥直通，不再做 KDF |

启用后 `server-state.json` 中的服务端签名私钥、管理员密码 hash、设备隧道密钥写入 `encrypted` 字段；旧明文状态会自动重写为加密格式，之后启动必须提供同一密钥。

**信封格式**：v2 在原有 `version/algorithm/nonce/ciphertext` 上增加 `kdf`（`argon2id-v1` / `none`）、`kdf_params`、`salt`，业务 schema 不变。旧 v1 文件（单次 SHA-256 派生、无 salt）启动时解锁成功后自动原子重写为 v2：写盘失败只记 ERROR、继续以内存态启动，文件保持 v1、下次落盘再试。每次写入复用文件里的 salt/params，只换 nonce。读取时对 `kdf_params` 做上限校验（内存 ≤256MiB、轮数 ≤10、并行度 ≤16、salt ≥16 字节），超限报错而不是静默降级。

**回滚**：升级前先备份 `server-state.json`；若需要退回旧二进制，用 `--state-kdf=legacy` 启动，服务端会把 v2 降级回 v1 格式（口令仍是同一口令，旧派生为 SHA-256），之后旧二进制才能读。已经是 v1 的文件在该开关下不会被迁移。

---

## 运行时设置（`GET/PUT /api/settings`）

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `port_range_start` | `10000` | 公网隧道端口范围起始 |
| `port_range_end` | `20000` | 公网隧道端口范围结束 |
| `max_tunnels_per_client` | `10` | 每设备最大隧道数；0=不限制 |
| `default_local_addr` | `127.0.0.1` | 创建隧道时未填写 `local_addr` 的默认值 |
| `public_host` | 空 | API 返回的隧道公网地址；空=使用请求 Host |
| `max_conn_per_min` | `10` | 每 IP 每分钟 WebSocket 连接/公网隧道连接数；0=禁用限流 |
| `login_rate_limit` | `5` | 每 IP 每分钟管理员登录尝试数；0=禁用限流 |
| `blacklist_threshold` | `10` | 1 小时内累计限流违规自动拉黑阈值；0=禁用；自动拉黑 24 小时后过期 |
| `global_whitelist` | `[]` | 全局 IP/CIDR 白名单（管理员的「可信来源」）；命中后绕过登录/WS/端口限流。黑名单优先级更高：同时命中黑名单仍会被拒。设备级 IP 白名单只豁免隧道端口限流，不影响管理面爆破防护 |
| `max_body_size_mb` | `10` | HTTP 请求体上限（MB）；0=禁用限制 |
| `heartbeat_interval` | `30` | 服务端心跳检查周期（秒） |
| `heartbeat_timeout` | `90` | 客户端心跳超时（秒）；运行中修改会在下一次读循环生效 |

> 修改设置使用部分更新语义：未提交的字段保持不变。端口范围、限流、黑名单阈值、心跳和全局白名单会立即应用到运行中的服务端。
> 管理员登录失败锁定为**按来源 IP**（连续 10 次失败锁定 5 分钟），不会因其他地址的攻击而全局锁死管理员。

---

## 服务端状态文件

`<data>/server-state.json` 保存：

- 服务端 ed25519 签名密钥（用于给 `register_ok` / `register_update` 签名）
- 管理员 bcrypt 密码 hash（由首次初始化向导设置；首次启动不再生成/打印随机密码）
- 设备身份、审批状态、设备 DH 公钥、设备白名单、隧道加密密钥
- 运行时设置

一次性初始化令牌**只存在内存**，不写入状态文件；重启会换新令牌，旧令牌永久失效。

写入采用临时文件 + rename 原子替换；每 3 秒检查脏标记异步落盘，`SIGINT/SIGTERM` 时同步 flush。

---

## Agent 启动参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--server` | string | `localhost:8080` | 服务端地址 |
| `--tls` | bool | `false` | 使用 WSS；启用后要求 TLS 1.3 |
| `--tls-ca` | string | 空 | 自定义 CA 证书路径 |
| `--tls-insecure` | bool | `false` | 跳过证书校验（仅测试；启动时告警） |
| `--config` | string | 空 | YAML 配置文件路径；CLI 参数优先 |
| `--identity-dir` | string | `$HOME/.goremote` | 身份密钥与设备 ID 存储目录（0700/0600） |
| `--log-level` | string | `info` | 日志级别 |
| `--log-file` | string | 空 | 日志文件路径 |
| `--log-max-size-mb` | int | `50` | 日志轮转阈值 |
| `--log-max-backups` | int | `5` | 历史日志数量 |

服务端地址变化时，Agent 会清空 `client_id`、设备密钥缓存、加密开关和服务器签名公钥 pin，重新注册到新服务端。

---

## Agent YAML 配置

`--config` 指向的文件支持以下字段；未配置项使用默认值。

```yaml
server:
  address: server.example.com:8080
  tls:
    enabled: true
    ca: /path/to/ca.pem
    insecure_skip_verify: false

agent:
  hostname: my-host        # 空=自动检测
  os: linux                # 空=自动检测

heartbeat:
  interval: 30             # 秒

reconnect:
  interval: 5              # 初始退避（秒）
  max_attempts: 0          # 0=无限
  max_interval: 60         # 退避上限（秒）

log:
  level: info
  file: /var/log/goremote-agent.log
  max_size_mb: 50
  max_backups: 5
```

> Agent 的 ed25519/x25519 身份保存在 `identity` 文件中；删除该文件等价于重新注册一台新设备。
