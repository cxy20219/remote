# 远程部署常见坑点与排查思路

## 1. Binary in use — 无法覆盖正在运行的程序

### 解决

```bash
# 先重命名旧 binary，进程继续运行但文件句柄已释放
mv /root/goremote/server /root/goremote/server_old
# 再上传新 binary
# 最后杀旧进程、重启
fuser -k 8080/tcp
```

### 最佳实践

- **永远不要直接覆盖运行中的 binary**，先 mv 再上传
- 保留 1-2 个旧版本备份（`server_old`, `server_old2`）以便回滚

## 2. 上传后 Permission denied

### 解决

```bash
chmod +x /root/goremote/server
```

### 最佳实践

- 部署脚本中总在 upload 后加 `chmod +x`

## 3. 进程杀不掉 — `fuser` 更可靠

```bash
# 按端口杀（最可靠）
fuser -k 8080/tcp
# 或用 killall
killall -9 server
```

### 排查命令

```bash
ss -tlnp | grep 8080
ps aux | grep server | grep -v grep
```

## 4. `nohup` 启动后 plink 卡住

### 解决

```bash
nohup ./server > server.log 2>&1 &
# 或
nohup ./server </dev/null > server.log 2>&1 &
```

### 验证

```bash
curl -sk https://localhost:8080/health
```

## 5. 两台服务器目录混淆

### 排查

```bash
# 找到真正的运行目录
cat /proc/<PID>/cmdline | tr '\0' ' '
pwdx <PID>
```

### 最佳实践

- 建立统一的部署目录约定，删除废弃的旧目录