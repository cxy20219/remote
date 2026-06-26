# 远程部署常见坑点与排查思路

## 1. Binary in use — 无法覆盖正在运行的程序

### 现象
```powershell
pscp server root@host:/root/goremote/server
# pscp: unable to open /root/goremote/server: failure
```

### 原因
Linux 上正在运行的程序文件无法被覆写（仍被进程引用）。必须先终止进程或重命名旧文件。

### 解决
```bash
# 先重命名旧 binary，进程继续运行但文件句柄已释放
mv /root/goremote/server /root/goremote/server_old

# 再上传新 binary
pscp server root@host:/root/goremote/server

# 最后杀旧进程、重启
fuser -k 8080/tcp
```

### 最佳实践
- **永远不要直接覆盖运行中的 binary**，先 mv 再上传
- 保留 1-2 个旧版本备份（`server_old`, `server_old2`）以便回滚
- 定期清理无用的旧 backup

---

## 2. 上传后 Permission denied

### 现象
```bash
nohup: failed to run command './server': Permission denied
```

### 原因
`pscp`/`scp` 传输后文件权限丢失，默认没有 `+x`。

### 解决
```bash
chmod +x /root/goremote/server
```

### 最佳实践
- 部署脚本中总在 upload 后加 `chmod +x`
- 或者上传前在本地设置好权限（Go 编译出的 binary 在 Linux 上默认有 execute 权限，但 SCP 后可能丢失）

---

## 3. 进程杀不掉 — `pkill` 配合 `fuser` 更可靠

### 问题
PowerShell 中 `plink` 执行 `ps aux | grep server | awk '{print $2}' | xargs kill` 会遇到 `$2` 被 PowerShell 解析的问题。

### 推荐方案
```bash
# 按端口杀（最可靠）
fuser -k 8080/tcp

# 或用 killall
killall -9 server

# 或用 pkill
pkill -9 -f '/root/goremote/server'
```

### 排查命令
```bash
# 查看哪个进程占用了端口
ss -tlnp | grep 8080

# 查看进程启动时间和完整命令行
ps aux | grep server | grep -v grep
```

---

## 4. `nohup` 启动后 plink 卡住

### 现象
```powershell
plink root@host "nohup ./server > log 2>&1 &"
# plink 一直不返回
```

### 原因
`nohup` 的后台进程可能继承了 stdout，需要关闭文件描述符。

### 解决
```bash
nohup ./server > server.log 2>&1 &
# 按 Ctrl+C 或等 plink 超时，进程已在后台运行
```

或更彻底：
```bash
nohup ./server --log-file /root/goremote/server.log --log-max-size-mb 50 --log-max-backups 5 </dev/null > /dev/null 2>&1 &
```

新版服务端和 Agent 支持程序内日志轮转；生产部署不要再只依赖 `nohup > server.log 2>&1` 这种无限追加方式。

### 验证
```bash
# 从另一 session 检查
curl -sk https://localhost:8080/health
```

---

## 5. 两台服务器目录混淆

### 现象
远程服务器上同时存在 `/root/go-remote/` 和 `/root/goremote/` 两个目录。

### 排查
```bash
# 找到真正的运行目录
cat /proc/<PID>/cmdline | tr '\0' ' '
pwdx <PID>
```

### 最佳实践
- 建立统一的部署目录约定，删除废弃的旧目录
- 在 AGENTS.md 中记录当前实际的部署路径

---

## 6. 旧数据目录启用状态加密，新二进制启动失败

### 现象
```bash
tail -20 /root/goremote/server.log
# {"msg":"failed to load server state","error":"state encryption key is required"}
```

### 原因
旧 `/root/goremote/data/server-state.json` 曾使用 `GOREMOTE_STATE_KEY` 或 `--state-key` 加密落盘。新进程未带同一个 state key 启动时，无法读取已有状态。

### 处理
```bash
# 生产保留旧状态：必须带原 state key 启动，不能换空数据目录
./server --data /root/goremote/data --state-key CHANGE-ME

# 临时功能验证：使用独立数据目录，避免破坏旧状态
./server --data /root/goremote/data-test --log-file /root/goremote/server-test.log
```

### 最佳实践
- 生产升级先确认是否存在加密状态文件和 state key 来源。
- 临时验证新功能时使用独立 `data-*` 目录和独立日志文件。
- 不要把真实 state key、管理员密码或服务器凭据写入 harness 文档。

---

## 7. Clash 测速触发代理入口黑名单

### 现象
Clash 订阅节点能识别，但测速或切换后节点大量超时；服务端日志出现：

```text
proxy connection rate limited
proxy connection from blacklisted IP, rejecting
```

### 原因
Clash 会并发探测多个节点和目标 URL，测试公网来源 IP 可能超过 `max_conn_per_min`，进而触发自动黑名单。若实现顺序先查黑名单再查白名单，后续加入全局白名单也不能绕过已有黑名单。

### 处理
- 测试环境可临时提高 `max_conn_per_min`，并把 `blacklist_threshold` 设为 `0` 关闭自动黑名单。
- 如果 IP 已被拉黑，先通过服务端本机回环管理 API 删除黑名单，再加入全局白名单。
- 代码层面应保证全局/设备白名单优先于黑名单与限流判断。

### 验证
- `GET /api/settings` 不应返回 `proxy_subscribe_token`。
- Clash 重置订阅 token 或重建代理后，需要更新订阅再测速。
- 分别验证节点出口 IP；服务器 Agent 节点访问 Google 目标失败时，先在服务器本机直连同一目标，区分代理链路问题和机房网络不可达。
