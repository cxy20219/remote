# Runbook：管理员被登录锁定（429）

适用症状：

- 登录页一直提示「尝试次数过多，请稍后再试」，正确密码也进不去；
- 管理接口返回 `429 {"error":"admin login temporarily locked"}`；
- 日志没有崩溃或 OOM，只是认证被拒。

## 1. 先判断锁的是哪一层

| 层 | 触发条件 | 作用范围 | 解除方式 |
|---|---|---|---|
| IP 失败池 | 同一来源 IP 连续 10 次失败（密码、动态码或恢复码） | 只锁该 IP（IPv6 按 /64） | 等 5 分钟 |
| 账户级动态码退避 | 跨 IP 累计第二因子失败（动态码 / 恢复码），每 10 次升一级：5s → 30s → 5min 封顶 | 只拦**动态码校验**和 `disable` | 等 ≤5 分钟自动解除；1 小时无失败降级，24 小时清零 |

密码步骤**不受账户级锁影响**：锁定期内正确密码仍能拿到第二步挑战；恢复码登录和 `/api/admin/totp/recover` **完全豁免**账户级锁（break-glass）。

## 2. 处置顺序

### 2.1 等待（默认，≤5 分钟）

账户级退避单次封顶 5 分钟，不续期到小时级。等一个窗口后重试动态码即可（429 响应带 `Retry-After`，可据此判断还要等多久）。

**注意**：这条只在「没有人继续攻击」时成立。如果攻击者每 5 分钟喂满 10 次动态码失败，退避会被反复触发，实际表现是持续 429——此时不要等，直接走恢复码或重启进程。

### 2.2 用恢复码登录 / 关闭 TOTP（推荐，自助）

1. 打开 `/login.html`，输入管理员密码；
2. 第二步输入**任一未使用的 12 位恢复码**（不是 6 位动态码）；
3. 登录成功后进入「安全设置 → 两步验证」，用恢复码关闭 TOTP，再重新启用即可拿到新密钥与 10 个新恢复码。

有会话但动态码不可用时，也可以直接调接口：

```bash
curl -s -b $JAR -H 'Content-Type: application/json' \
  -d '{"password":"***","recovery_code":"ABCDEFGHJKLM"}' \
  http://127.0.0.1:8080/api/admin/totp/recover
```

### 2.3 重启进程（最后手段）

账户级计数只在内存里，重启即清零。**这是唯一能保证立刻解除的方式**，但会同时清空管理员会话和未完成的登录挑战（需要重新登录），不影响设备、隧道和 state 文件。

```bash
# 线上 unit 名以实际部署为准（见 SRE 配置）
sudo systemctl status goremote
sudo systemctl restart goremote
sudo journalctl -u goremote -n 50 --no-pager
```

重启后确认日志里没有：

- `admin TOTP configuration is corrupt`（密钥损坏，需走恢复码关闭后重新启用）
- `admin TOTP is enabled but state encryption is disabled`（`GOREMOTE_STATE_KEY` 未配置）

### 2.4 反代部署的附加检查

如果所有请求看起来来自同一个 IP（限流、黑名单误伤全体），检查 `--trusted-proxies`：

- 解析失败现在会**直接拒绝启动**（日志 `invalid --trusted-proxies ...`），不会再静默降级；
- 启动成功时日志应有 `trusted proxies configured` 和真实反代地址/网段；
- 没配时不要挂反向代理，或者先把代理地址补上再重启。

## 3. 预防

- 恢复码离线保存（10 个、一次性），不要只存在手机里；
- 多管理员场景给不同人不同恢复码；
- 监控 429 比例和 `admin login temporarily locked` 的日志量；
- 反代部署必须配 `--trusted-proxies`，否则按 IP 的锁、限流、自动拉黑都会打在反代上。

## 4. 相关文档

- [TOTP-2FA.md](TOTP-2FA.md)：口径、接口与排障表
- `README.md`：部署与安全特性概览
