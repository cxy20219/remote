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
nohup ./server </dev/null > server.log 2>&1 &
```

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
