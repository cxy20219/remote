# 管理员两步验证（TOTP）

GoRemote 的管理后台支持基于 TOTP（RFC 6238）的两步验证：密码通过后还要输入验证器 App 生成的 6 位动态码，才能拿到管理员会话。

## 1. 行为与口径

| 项 | 值 |
|---|---|
| 算法 | HMAC-SHA1（与 Google Authenticator / 1Password / Authy 兼容） |
| 位数 / 步长 | 6 位 / 30 秒 |
| 时间窗 | 接受当前步及前后各 1 步（±30 秒） |
| 密钥 | 20 字节 `crypto/rand` 随机，Base32（无 padding）展示 |
| 防重放 | 记录最后接受的时间步，**同一个时间步只接受一次用于登录**。启用确认时锚点只退到「确认窗口之前」，因此那个确认码还能在随后首次登录再用一次（一次启用 + 一次登录），之后即失效；启用后不必空等 |
| 恢复码 | 启用时一次性生成 10 个、每个 12 位（约 60 bit），只显示一次；存 SHA-256，用一个失效一个 |
| 比较 | 动态码、恢复码哈希都用常量时间比较 |
| 失败计数 | 两个池：按来源 IP（IPv6 聚合到 /64）的池，密码和第二因子（动态码 / 恢复码）失败都计，10 次锁 5 分钟；**账户级池（跨 IP）只统计第二因子失败（动态码 / 恢复码）**（那一步天然要求先有正确密码），每累计 10 次触发退避：5s → 30s → **5 分钟封顶** |
| 账户级锁的衰减与豁免 | 连续 1 小时没有第二因子失败降 1 级，24 小时清零；**密码步骤和恢复码路径都不受账户锁影响**（break-glass），只有动态码校验和 `disable` 会返回 429。豁免只表示「不被锁挡住」，**失败的恢复码仍会计入失败池并可能延长锁** |
| 锁的自愈 | 账户级计数只在内存里：重启进程即清零（见 [RUNBOOK-admin-lockout.md](RUNBOOK-admin-lockout.md)） |
| 清池时机 | **只有完整认证成功**（密码 + 动态码/恢复码）才清零；密码正确不清池，否则「登录一次再猜几次」就能无限试码 |
| 管理写接口限流 | 改密、TOTP 的 setup/disable/recover 位于 session 之后，另挂 **10 次/5 分钟**独立限流（登录限流之外） |
| 429 的 Retry-After | 认证类 429（IP 失败锁、账户级退避）和限流 429 都带 `Retry-After` 秒数，登录页据此提示「请 N 秒后再试」 |

## 2. 存储与加密（启用前置条件）

两步验证的密钥和恢复码哈希落在 `server-state.json` 的 `sensitiveStatePlain` 里（与管理员密码 hash、服务端签名私钥同一块）。

**启用 TOTP 要求先配置 state 加密密钥**：没有 `GOREMOTE_STATE_KEY`（或 `--state-key`）时，`setup` / `enable` 直接返回 `409 {"error":"state encryption is required to enable TOTP; ..."}`，不允许启用。

原因：TOTP 密钥是裸密钥，能读状态文件的人就能永久离线生成动态码，二次验证直接归零；管理员密码至少还有 bcrypt 兜底，TOTP 密钥没有。线上当前的 `server-state.json` 里 `server_sign_privkey` 是明文、没有 `encrypted` 字段，说明密钥从未配置——在这种状态下启用 TOTP 等于把密钥明文落盘。

正确做法：

1. 先生成密钥：`openssl rand -hex 32` → 64 位十六进制；
2. 让服务端拿到它，二选一：`GOREMOTE_STATE_KEY='<hex>'`（推荐写 systemd 的 `EnvironmentFile=`），或 `--state-key '<hex>'`；生产环境**只用 `EnvironmentFile`**，命令行参数会出现在 `ps` 输出里；
3. 重启后确认日志里没有 `admin TOTP is enabled but state encryption is disabled`（这条 WARN 表示仍在明文降级状态）；
4. 再在管理面板启用 TOTP。

配置密钥后，签名私钥、管理员密码 hash、TOTP 密钥、恢复码哈希一起进 AES-256-GCM 密文；旧明文状态在带 key 启动时会自动迁移为加密格式。状态文件权限始终 `0600`（`internal/server/persist.go` 的 `writeState`）。

**旧版本状态文件**没有 `totp_*` 字段，加载后按「未启用」处理，不影响升级；未加密的旧文件在配置密钥后启动会自动迁移为加密格式。

## 3. 接口

所有接口都要求 `Content-Type: application/json`（`decodeStrictJSON`），未知字段会被拒绝。

### 3.1 登录（两步）

**第一步**：`POST /api/login`

```json
{"password":"..."}
```

- 未启用 TOTP：`200 {"status":"ok"}` + `go_remote_token` HttpOnly Cookie。
- 已启用：`200 {"status":"totp_required","challenge":"...","expires_in":300,"recovery_only":false}`，**不下发会话**。
- `401 {"error":"invalid password"}` / `429 {"error":"admin login temporarily locked"}`（后者只来自该 IP 的失败锁，密码步骤**不**受账户级锁影响）。
- 密钥损坏时仍是 `200 totp_required`，但带 `"recovery_only":true`：第二步的动态码注定验不过，恢复码仍可登录（唯一的 break-glass 路径）。

**第二步**：`POST /api/login/totp`

```json
{"challenge":"...","code":"123456"}
```

- 成功：`200 {"status":"ok"}` + 会话 Cookie。
- `401 {"error":"invalid totp code"}`（码错、重放、恢复码已用过，对外统一）。
- `401 {"error":"invalid or expired challenge"}`（挑战不存在/过期/IP 不匹配/尝试次数用尽）。
- `500 {"error":"two-factor authentication is misconfigured; check server logs"}`：提交的是动态码且密钥损坏（配置问题，不计入失败次数）；**改成恢复码提交则照常放行**。
- `429 {"error":"admin login temporarily locked"}`：IP 池或账户级动态码退避生效，带 `Retry-After` 秒数；恢复码不受账户级锁限制（但恢复码失败仍计数）。

挑战令牌：32 字节随机，**绑定来源 IP（IPv6 按 /64 聚合）**，5 分钟过期，单次使用，最多 3 次尝试；锁内原子占用，同一挑战并发提交只有一个请求能通过；时间步推进用 CAS，同一个码并发提交只有一个能换到会话。

登录页对挑战做了兜底：显示 `expires_in` 倒计时，到期后自动退回密码步骤并提示；收到 `invalid or expired challenge` 时会清掉本地令牌（不会拿死令牌反复重放）。「重新获取验证码」等价于退回密码步骤重新登录——**不在页面里留存明文密码**，也不会额外消耗登录限流配额。429 会本地化并用 `Retry-After` 显示还需等待的秒数。

### 3.2 状态与开关（需要管理员会话）

| 方法 | 路径 | 请求 | 成功响应 |
|---|---|---|---|
| GET | `/api/admin/totp` | — | `{"enabled":bool,"setup_pending":bool,"recovery_codes_left":n}`（永不返回密钥） |
| POST | `/api/admin/totp/setup` | `{"password":"..."}` | `{"secret":"Base32","otpauth_uri":"otpauth://totp/...","qr_data_url":"data:image/png;base64,...","expires_in":600}` |
| POST | `/api/admin/totp/enable` | `{"code":"123456"}` | `{"status":"ok","recovery_codes":["..."]}`（**恢复码仅此一次**） |
| POST | `/api/admin/totp/disable` | `{"password":"...","code":"123456"}` | `{"status":"ok"}` |
| POST | `/api/admin/totp/recover` | `{"password":"...","recovery_code":"..."}` | `{"status":"ok"}`（用一次性恢复码关闭，手机丢失时的自助出口） |

- `setup` 必须重新输入当前密码：会话被劫持后不能顺带把攻击者的验证器绑上来。
- 待激活密钥只在内存里保存 10 分钟，按当前管理员会话绑定；没确认之前不落盘。
- `enable` / `disable` 成功后**吊销其它管理员会话、保留当前会话**（与改密码语义一致）。
- 关闭必须同时提供密码和当前动态码；只给其中一个会被拒绝（`401 invalid password` / `401 invalid totp code`）；密钥损坏时返回 `500 misconfigured`，此时只能走 `recover`。账户级退避生效时 `disable` 返回 `429`；`recover` 豁免，仍然是手机丢失时的出口。
- 手机丢失时走 `/api/admin/totp/recover`：密码 + 一个有效的一次性恢复码即可关闭（恢复码本身就是第二因子），日志记为 `admin totp disabled via recovery code`。该接口**不会被账户级锁挡住**，但错误的密码/恢复码仍计入失败池，可能延长锁——豁免不是免费的。
- 注意防重放：如果刚用某个码登录过，30 秒内用同一个码去关闭会被判为重放，等下一个窗口即可。
- 启用后**立即**就可以用确认时那个码登录（防重放锚点只回退一个窗口）；只有「登录后再关闭」才需要等新窗口。
- `/api/admin/totp/setup` 生成的二维码有 10 分钟 TTL，管理页显示倒计时，过期自动收起并可重新生成。

## 4. 使用

### 4.1 通过管理面板

1. 打开右上角 ⚙「安全与系统设置」→「🛡 安全设置」→「两步验证 (TOTP)」；
2. 点「启用两步验证」，输入当前密码 → 生成二维码；
3. 用验证器 App 扫码（或手抄 Base32 密钥）；
4. 输入 App 上的 6 位动态码 →「确认启用」；
5. **立刻保存屏幕上一次性显示的 10 个恢复码**；
6. 下次登录：先输密码，再输动态码（或恢复码）。

关闭：点「关闭两步验证」，输入当前密码 + 当前动态码。

### 4.2 通过 curl

```bash
BASE=http://127.0.0.1:8080
JAR=/tmp/goremote-cookies

# 1) 登录（未启用 TOTP 时直接拿到会话）
curl -s -c $JAR -H 'Content-Type: application/json' -d '{"password":"***"}' $BASE/api/login

# 2) 生成密钥与二维码（需要当前密码）
curl -s -b $JAR -H 'Content-Type: application/json' -d '{"password":"***"}' $BASE/api/admin/totp/setup

# 3) 用验证器算码后确认启用（响应里的 recovery_codes 只出现这一次）
curl -s -b $JAR -H 'Content-Type: application/json' -d '{"code":"123456"}' $BASE/api/admin/totp/enable

# 4) 之后登录：第一步拿 challenge，第二步换会话
curl -s -H 'Content-Type: application/json' -d '{"password":"***"}' $BASE/api/login
curl -s -c $JAR -H 'Content-Type: application/json' \
  -d '{"challenge":"<上一步返回>","code":"123456"}' $BASE/api/login/totp
```

## 5. 安全边界（实话）

- **没配 TLS 时，二次验证的保护是有限的**：密码、动态码、会话 Cookie 都走明文 HTTP，同网段攻击者可以抓包。二次验证解决的是「密码泄露/撞库」，不能替代 TLS。生产环境请前置 HTTPS（反向代理或 `--tls-cert/--tls-key`）。
- **反向代理部署必须配 `--trusted-proxies`**（逗号分隔的代理 IP/CIDR，默认空 = 不信任任何转发头）。不配的话所有请求的来源 IP 都会是反代地址：按 IP 的锁定、限流、黑名单会作用于反代本身，一次攻击可能把正常管理员一起锁死，IPv6 聚合也失去意义。
  - 配置解析失败会**直接终止启动**并打印解析错误，不会静默退化成「不信任任何代理」；启动成功时日志有 `trusted proxies configured` 和生效列表。
  - 例：`--trusted-proxies 127.0.0.1,10.0.0.0/8`（只填自己的反代地址段）。
- 没配 `GOREMOTE_STATE_KEY` 时**不能启用** TOTP（见 §2）；已启用但密钥后来被移除时，启动会打 WARN 提示处于明文降级状态。
- state 里的 TOTP 密钥损坏（手工改坏、迁移失败）时**不会静默降级**：启动打 WARN，登录第一步返回 `recovery_only:true`，动态码第二步 500，但**恢复码仍能登录并关闭 TOTP**——绝不能因为密钥坏了就把密码当成完整认证放行，也不能把唯一的自助出口一起堵死。
- 账户级计数是跨 IP 的，但**只统计第二因子失败（动态码 / 恢复码）**且**封顶 5 分钟**：换 IP 刷密码不会触发；锁定期内正确密码仍能走到第二步，恢复码登录和 `recover` 不受影响。恢复码路径的豁免只是「不被锁挡住」：输错恢复码仍会计入失败池、延长锁。1 小时没有第二因子失败自动降一级、24 小时清零；进程重启直接清零（计数只在内存）。详见 [RUNBOOK-admin-lockout.md](RUNBOOK-admin-lockout.md)。
- 恢复码等价于一次性密码：泄露即失去第二因子，应离线保存；剩余数量可在状态接口看到。
- 动态码 ±1 窗口是兼容时钟偏差，代价是最多 90 秒内的码有效；防重放只保证「同一时间步不被接受两次用于登录」。

## 6. 审计日志

均通过 `slog` 输出，**不记录密钥和码值**：

- `admin totp enabled`（含恢复码数量）
- `admin totp disabled`
- `admin totp setup started`
- `admin totp verification failed`（含来源 IP）
- `admin totp replay rejected`（含来源 IP）
- `admin totp recovery code used`（含来源 IP 与剩余数量）
- 启动告警：`admin TOTP is enabled but state encryption is disabled ...`；`admin TOTP configuration is corrupt ...`
- 密钥损坏：`admin totp secret is corrupt; ...`（登录/关闭路径，含来源 IP）；`admin totp configuration is corrupt; only recovery codes can complete login`（登录第一步）
- 代理配置生效：`trusted proxies configured`（含列表）；解析失败会直接退出并打印 `invalid --trusted-proxies ...`
- 账户级退避触发/衰减没有单独日志，通过 429 响应和下方排障表定位（重启可解）

## 7. 排障

| 现象 | 原因 / 处理 |
|---|---|
| 无法启用，提示 state encryption is required | 先配置 `GOREMOTE_STATE_KEY`/`--state-key` 再启用（见 §2） |
| 动态码总是不对 | 服务器时间偏差超过 ±30 秒；校准系统时间（`timedatectl`/`ntpdate`） |
| 登录提示「验证已过期」 | challenge 超过 5 分钟或尝试次数用尽；登录页现在会自动退回密码步骤，重新登录即可 |
| 登录/关闭提示 `two-factor authentication is misconfigured` | state 里的 TOTP 密钥损坏（日志 `admin totp secret is corrupt`）：登录页会直接提示「请用恢复码」；用**恢复码**登录后到「关闭两步验证」里用恢复码关闭 TOTP，再重新启用即可拿到新密钥与 10 个新恢复码 |
| 一直 429「尝试次数过多」 | 账户级动态码退避：单次封顶 5 分钟，响应带 `Retry-After` 秒数；急用恢复码登录或调 `recover`（豁免）；攻击者持续喂失败时要直接重启进程（见 [RUNBOOK-admin-lockout.md](RUNBOOK-admin-lockout.md)） |
| 启用后立刻登录不用等 | 正常行为：启用时防重放锚点只回退一个窗口 |
| 关闭时提示动态码错误 | 该码本时间窗已用过（防重放），等 30 秒用新码 |
| 丢失验证器 | 用恢复码登录后，在「关闭两步验证」里点「用恢复码关闭」（密码 + 一个恢复码），再重新启用即可拿到新密钥与 10 个新恢复码 |
| 恢复码用完 | 用动态码登录后重新启用两步验证 |
| 反代下全体被限流/403 | `--trusted-proxies` 没配或配错：现在解析失败会拒绝启动；检查日志 `trusted proxies configured` 是否包含真实反代地址 |
