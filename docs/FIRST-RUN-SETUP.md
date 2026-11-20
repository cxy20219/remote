# 首次部署与初始化

GoRemote 首次启动**不再生成、也不再打印管理员密码**。新实例启动后处于「未初始化」状态：

- 页面访问会被重定向到 `/setup.html`；
- 业务 API 返回 `409 {"error":"setup required"}`；
- 日志里只会出现一次性初始化令牌，**不会出现任何密码或密码 hash**。

首次初始化的目标是：由人自己设置管理员密码，可选当场启用 TOTP 两步验证。

## 1. 进入初始化向导的两种方式

初始化请求必须满足其一，否则一律 `403`：

### 方式一：服务器本机 loopback（仅限无反代、直连后端）

在服务器本机（或通过 SSH 端口转发）打开向导：

```bash
# 在你自己电脑上建立转发，把服务器上的 8080 映射到本地 8080
ssh -L 8080:127.0.0.1:8080 user@your-server

# 然后在本机浏览器打开
# http://127.0.0.1:8080/setup.html
```

loopback 免令牌**只适用于没有反向代理、请求直接打到后端**的场景，并且必须同时满足：

1. 没有配置 `--trusted-proxies`；
2. TCP 对端是 loopback；
3. 请求不带 `X-Forwarded-For` / `X-Real-IP`。

**只要配置了 `--trusted-proxies`，loopback 捷径整个关闭，初始化一律要求令牌**：`/api/setup/status` 会返回 `loopback:false`，启动日志也会明确提示。原因不是保守——反代可能原样转发公网客户端伪造的 `X-Real-IP: 127.0.0.1`，同机反代可能不追加任何转发头，信任列表也可能漏配反代地址；这三种情况服务端都无法与真本机直连区分，而这里赌的是管理员权限。

**任何反向代理（同机或异机）都必须用令牌完成初始化**，包括 nginx/caddy 转发到 `127.0.0.1:8080` 的部署。SSH 端口转发不算反向代理：它直连后端 loopback、不携带转发头，所以在没配 `--trusted-proxies` 时仍可免令牌。

> 不要为了免令牌而删掉 `--trusted-proxies`：反代部署下它同时负责按 IP 的限流、失败计数和 TOTP challenge 绑定，去掉之后所有客户端会塌缩成反代一个 IP。

### 方式二：一次性初始化令牌

从服务日志里取令牌（10 位，可能显示成 `XXXXX-XXXXX`）：

```bash
journalctl -u goremote | grep 初始化
# 或：grep 初始化 /path/to/server.log
```

浏览器打开 `https://your-server:8080/setup.html`，在「一次性初始化令牌」输入框填入即可。
用 curl 直接初始化时，令牌放在请求头：

```bash
curl -s -X POST http://your-server:8080/api/setup/password \
  -H 'Content-Type: application/json' \
  -H 'X-Setup-Token: XXXXX-XXXXX' \
  -d '{"password":"Your-Strong-Password1"}'
```

令牌规则：

| 项 | 值 |
|---|---|
| 长度 | 10 位（去掉了 0/O/1/I 等易混字符） |
| 有效期 | 30 分钟（从进程启动算） |
| 使用次数 | 一次；初始化成功立即作废 |
| 试错 | 10 次错误后令牌立即作废（另有 10 次/5 分钟独立限流） |
| 重启 | **重启会换新令牌，旧令牌永久失效**——部署后别急着重启，否则要重新看日志 |

> 令牌错误 10 次即烧毁，这是防爆破的必然代价。公网暴露的未初始化实例请提前准备好可用的初始化通道：无反代直连的 loopback，或从日志取到令牌。令牌被烧毁/过期后，重启进程会生成新令牌（state 不受影响，仍是未初始化状态）。

### 令牌不是凭据

令牌只换取「设置管理员密码」这个动作的**一次机会**，它本身换不到会话、换不到任何管理权限。
初始化成功后签发的会话，来自「你已经设置好密码」这件事，而不是来自令牌。

## 2. 向导三步

1. **设置管理员密码**：≥12 位、至少 3 类字符（大写/小写/数字/符号），需二次确认。
   密码只写入 state 的 `admin_password_hash`（bcrypt），日志里不会出现明文。
2. **可选启用 TOTP**：生成二维码与 Base32 密钥 → 输入验证器上的 6 位动态码 → 返回 10 个恢复码。
   - **恢复码只显示一次，刷新页面就看不到了**（前端只放内存，不写 localStorage/sessionStorage）。这是有意的：丢恢复码的代价是重置 TOTP，比在浏览器里留一份副本安全。
   - 没配置 `GOREMOTE_STATE_KEY`（state 加密密钥）时无法启用 TOTP（保护密钥不裸落盘，`409`）；可以跳过，之后在管理面板里配置好密钥再启用。
3. **完成**：自动进入管理面板（第 1 步已自动登录；启用 TOTP 时只吊销其它会话，保留当前向导会话）。

## 3. 流程与状态

```text
GET  /api/setup/status    → {"needs_setup":bool,"loopback":bool}（公开，无秘密）
POST /api/setup/password  → 设置密码；成功 200 + 会话 Cookie
POST /api/setup/totp/start   → 向导内生成 TOTP 密钥/二维码（向导会话专用）
POST /api/setup/totp/enable  → 确认动态码，返回一次性恢复码
POST /api/setup/totp/skip    → 跳过 TOTP，关闭向导窗口
```

TOTP 的三个向导端点只在「刚设置密码之后的 10 分钟向导窗口内、且持有该会话与同一来源 IP」时可用；
而且该会话必须仍然有效——登出、改密或会话过期会立即关闭向导，端点返回 `409`。
启用成功、选择跳过或窗口超时后，全部返回 `409`。初始化完成（`needs_setup=false`）后，
`POST /api/setup/password` **永久**返回 `409`，即使带上旧令牌也一样。

未初始化时 `/ws` 返回 `503`：避免匿名客户端在初始化前注册、占满 pending 设备表。初始化完成后自动恢复，Agent 有重连退避，不需要特殊处理。

## 4. 常见错误

| 现象 | 原因 / 处理 |
|---|---|
| `403 invalid or expired setup token` | 没带令牌且不是 loopback；或令牌输错/过期/已被 10 次失败烧毁。重启服务可拿新令牌 |
| `403 setup requires loopback access or a valid setup token` | 同上，按提示走 loopback 或令牌 |
| `403` 且 `/api/setup/status` 返回 `loopback:false` | 配置了 `--trusted-proxies`，或请求带了转发头；反代场景一律用令牌初始化 |
| `/ws` 返回 `503 setup required` | 还没初始化；初始化完成后自动恢复，Agent 会退避重连 |
| `409 server is already initialized` | 已经初始化过；去 `/login.html` 登录。忘了密码只能停机后修改 state（见 §5） |
| `409 setup required`（访问业务 API） | 还没初始化；先完成向导 |
| 初始化接口 `429` | 同一 IP 5 分钟内超过 10 次请求；按 `Retry-After` 等待 |
| 向导里 TOTP 返回 `409 state encryption is required...` | 先配 `GOREMOTE_STATE_KEY`（或 `--state-key`）再启用，或跳过 TOTP |
| 打开 `/setup.html` 被重定向到 `/` | 已经初始化完成，向导已永久关闭 |

## 5. 已初始化但忘记密码

项目没有内置「找回密码」：管理员密码是唯一入口。停机后删除/改名 `server-state.json` 会**丢失设备、隧道和密钥**，回到未初始化状态。
更安全的做法是保留恢复码（如果启用了 TOTP），或从备份恢复 state 后用备份密码登录。

## 6. 与旧版本兼容

- 已有 `admin_password_hash` 的 state（包括旧版本自动生成过密码的部署）加载后 `needs_setup=false`：
  行为与以前完全一致，不会出现向导，也不会生成新令牌。
- 旧 state 里的 `admin_password_plain` 迁移逻辑保持不变。
- 新 state 文件权限仍是 `0600`；初始化前后都不会把密码写入日志。

## 7. 相关文档

- [TOTP-2FA.md](TOTP-2FA.md)：两步验证口径、接口与排障
- [RUNBOOK-admin-lockout.md](RUNBOOK-admin-lockout.md)：管理员被登录锁定时怎么处理
