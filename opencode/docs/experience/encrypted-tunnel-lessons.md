# 加密隧道开发实战经验

## 概述

本文档记录在 GoRemote 隧道加密功能开发和部署验证过程中踩过的坑、排查思路和可复用的经验。

## 1. Go 标准库 `crypto/hkdf` 不可用

**现象**：
```go
import "crypto/hkdf"
// undefined: hkdf.New
```

**原因**：Go 1.26.2 中 `crypto/hkdf` 虽然文档声称可用，但实际编译时 `hkdf.New` 未定义。

**解决**：改用 `crypto/sha256` 直接派生密钥，避免依赖不稳定的标准库 API：

```go
import "crypto/sha256"

func NewCryptoContext(sharedKey string) (*CryptoContext, error) {
    hash := sha256.Sum256([]byte(sharedKey + "goremote-tunnel-v1"))
    key := hash[:]  // 32 bytes for AES-256
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    return &CryptoContext{gcm: gcm}, nil
}
```

**经验**：
- 新增标准库 API 要实际编译验证，不要依赖文档
- SHA-256 直接派生密钥在内部系统场景下足够安全
- HKDF 的优势（salt、info 分离）在预共享密钥场景中意义不大

## 2. 服务器磁盘满导致上传静默失败

**现象**：
```powershell
pscp server root@host:/root/goremote/server
# 进度条走到 0% 后报 Network error
# 服务器上文件大小为 0 字节
```

**原因**：旧 `server.log` 文件（1.6GB）和 `/root/go-remote/` 目录（34GB）占满 40GB 磁盘。

**排查方法**：
```bash
df -h /root                      # 看磁盘使用率
du -sh /root/goremote/*          # 看各目录大小
ls -lh /root/goremote/server.log # 找大文件
```

**清理命令**：
```bash
rm -f /root/goremote/server.log /root/goremote/server_old*
rm -rf /root/go-remote/   # 旧项目目录
du -sh /tmp/* | sort -rh  # 检查 /tmp 残留
```

**经验**：
- 部署前必须检查磁盘空间（`df -h`）
- 日志文件应配置轮转（logrotate）或定期清理
- pscp 上传失败不会明确提示"磁盘满"，只会报 Network error

## 3. swag 文档生成缺失导致编译失败

**现象**：
```
cmd/server/main.go:14:2: package goremote/docs is not in std
```

**原因**：`cmd/server/main.go` 中有 `_ "goremote/docs"` 导入，但 `docs/` 目录未生成。

**解决**：
```powershell
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/server/main.go -o docs
```

**经验**：
- 首次克隆项目或 API 变更后需运行 `swag init`
- 检查 `GOPATH/bin` 是否在 PATH 中，否则用绝对路径调用 `swag.exe`
- 生产环境建议关闭 Swagger（`swagger.enabled: false`）

## 4. PowerShell curl JSON 转义陷阱

**现象**：
```powershell
curl.exe -d '{"password":"admin123"}' -H "Content-Type: application/json" url
# → {"error":"invalid request"}
```

**原因**：PowerShell 中双引号 `"` 会尝试展开变量，单引号 `'` 不展开。但 `curl.exe` 内部对引号的处理与 shell 不同。

**可靠方案（三种）**：

```powershell
# 方案 1：JSON 写入文件（最可靠，推荐）
@'
{"password":"admin123"}
'@ | Out-File body.json -Encoding ascii
curl.exe -d "@body.json" -H "Content-Type: application/json" url

# 方案 2：单引号内双引号（简单场景可用）
curl.exe -d '{\"password\":\"admin123\"}' -H "Content-Type: application/json" url

# 方案 3：登录 token 管理
curl.exe -k -c cookies.txt -X POST url -d "@body.json"
curl.exe -k -b cookies.txt url                          # 后续请求携带 cookie
```

**经验**：
- `Out-File -Encoding ascii` 确保文件不含 BOM（避免 curl 解析失败）
- 使用 `-c cookies.txt` 保存 cookie，`-b cookies.txt` 使用 cookie
- Admin token 默认 24 小时有效

## 5. plink 同服务器不同端口的主机密钥冲突

**现象**：
```
WARNING - POTENTIAL SECURITY BREACH!
The host key does not match the one Plink has cached for this server:
  YOUR_SERVER (port 10000)
Connection abandoned.
```

**原因**：plink 按 `host:port` 缓存主机密钥。同一服务器的不同端口（22 vs 10000）有独立的主机密钥记录。首次连接 tunnel 端口时，密钥与缓存不匹配。

**解决**：
```powershell
# 方案 1：接受新密钥（交互式）
plink -P 10000 root@host

# 方案 2：跳过主机密钥检查（测试用）
plink -batch -hostkey ssh-ed25519 SHA256:xxxxx -P 10000 root@host "command"

# 方案 3：从服务器自身测试（避免 plink 缓存问题）
plink root@host "nc -w 2 127.0.0.1 10000"  # 通过 SSH 到服务器，再用 nc 测试 tunnel
```

**经验**：
- 验证 tunnel 连通性优先用 `nc`（netcat），不依赖 SSH 协议层
- 从服务器自身 `nc 127.0.0.1:TUNNEL_PORT` 是最可靠的验证方式

## 6. Python Microsoft Store Stub 不可用

**现象**：
```powershell
python -c "print('hello')"
# 无输出、无错误，进程立即退出
where.exe python
# C:\Users\xxx\AppData\Local\Microsoft\WindowsApps\python.exe
```

**原因**：Windows 10/11 预装的 `python.exe` 是 Microsoft Store 重定向 stub，在非交互式环境（如 `Start-Process`）中不工作。

**解决**：
- 启动简单 HTTP 测试服务时，使用 Go 或已有服务代替 Python
- 如确实需要 Python：安装完整版 Python 并确保其 PATH 优先级高于 WindowsApps
- 隧道测试可直接利用已有服务（如 YOUR_SERVER:22 SSH），无需额外启动服务

**经验**：
- `where.exe python` 可以识别 stub
- 测试方案设计时优先利用已有服务，减少临时服务依赖

## 7. Start-Process 的 Redirect 冲突

**现象**：
```powershell
Start-Process -FilePath "agent.exe" -RedirectStandardOutput "log.txt" -RedirectStandardError "log.txt" -NoNewWindow
# InvalidOperationException: 无法执行操作
```

**原因**：PowerShell 的 `Start-Process` 在启用 `-NoNewWindow` 时不能同时使用 `-RedirectStandardOutput` 和 `-RedirectStandardError`。

**解决**：
```powershell
# 方案 1：去掉 -NoNewWindow（后台隐藏窗口）
Start-Process -FilePath "agent.exe" -ArgumentList "--config config.yaml" -WindowStyle Hidden

# 方案 2：用 cmd /c 重定向
Start-Process -FilePath "cmd" -ArgumentList '/c agent.exe --config config.yaml > log.txt 2>&1'

# 方案 3：直接 nohup（Linux）或通过内置重定向
& agent.exe --config config.yaml *> log.txt  # PowerShell 7+
```

**经验**：
- `Start-Process` 各参数互斥关系需查阅文档
- `-WorkingDirectory` 参数很重要，默认工作目录是 `C:\Windows\System32`
- Agent 日志可通过配置 `log.file` 由 Go 程序自身写入文件

## 8. 磁盘清理的级联影响

本次部署中，发现磁盘满不是单一原因造成的：

| 问题 | 大小 | 清理方式 |
|------|------|----------|
| 旧日志文件 `server.log` | 1.6 GB | `rm -f` |
| 旧项目目录 `/root/go-remote/` | 34 GB | `rm -rf` |
| 旧二进制备份 `server_old*` | ~250 MB | `rm -f` |
| `/tmp/` 残留文件 | ~160 MB | `rm -f` |

**预防措施**：
- 日志启用轮转或在配置中设置 `log.file: ""` 输出到 stdout（由 systemd/journald 管理）
- 部署脚本中应包含旧二进制清理步骤
- 定期检查 `/tmp` 残留

## 9. 加密与非加密版本兼容性

**加密协议设计要点**：
- 加密密钥从 `auth.key` 通过 SHA-256 派生，服务端和 Agent 使用相同 `auth.key` 即自动启用
- `auth.key` 为空时，两端都会记录警告并降级为明文传输（仅 base64 编码）
- 加密版本的服务端与未加密版本的 Agent 通信会失败（数据无法解码）
- 因此部署时必须同时升级服务端和所有 Agent

**验证加密生效**：
```bash
# 服务端日志
grep "encryption enabled" server.log
#→ "tunnel data encryption enabled (AES-256-GCM)"

# Agent 日志
grep "encryption enabled" agent.log
#→ "tunnel data encryption enabled (AES-256-GCM)"
```

## 相关文档

- [加密隧道部署与验证直通流程](../workflow/encrypted-tunnel-deploy-verify.md) — 完整操作步骤
- [GoRemote 调试开发经验](./go-remote-debugging.md) — 综合排查手册
- [远程部署常见坑点](./remote-deployment-pitfalls.md) — 部署五大坑点
