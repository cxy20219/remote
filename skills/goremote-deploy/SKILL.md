---
name: goremote-deploy
description: GoRemote SSH 隧道服务部署技能。当用户提及部署 GoRemote、goremote、远程部署、服务端部署、客户端部署、内网穿透部署、SSH 隧道部署、TLS 配置、证书生成、交叉编译、跨平台部署等场景时，必须使用此 skill。该 skill 提供完整的部署流程指导、配置模板、自动化脚本和问题排查方案。
---

# GoRemote 部署技能

## 概述

本 skill 指导 Agent 完成 GoRemote（SSH 隧道内网穿透系统）的编译、部署、配置和验证全流程。

**核心架构**：
```
外部用户 → [Server:公网端口] → [WebSocket隧道] → [Agent:内网端口]
```

## 前置检查

部署前确认以下信息：
- 公网服务器 IP/域名、SSH 账号密码
- 内网服务器 IP/域名、SSH 账号密码
- 目标部署平台（Linux amd64 或 Windows amd64）
- 是否需要启用 TLS 加密

## 触发场景

1. 用户首次部署 GoRemote 到新服务器
2. 用户更新了代码需要重新部署
3. 用户需要配置 TLS 证书
4. 用户需要添加新的内网客户端
5. 部署后功能异常需要排查

## 资源清单

| 资源 | 路径 | 用途 |
|------|------|------|
| 服务端配置模板 | `assets/server.yaml.template` | 生成服务端配置文件 |
| 客户端配置模板 | `assets/agent.yaml.template` | 生成客户端配置文件 |
| 部署配置模板 | `assets/server-deploy.yaml.template` | 生产环境服务端配置 |
| Linux 部署脚本 | `scripts/deploy-server.sh` | Linux 服务端部署 |
| Linux Agent 脚本 | `scripts/deploy-agent.sh` | Linux 客户端部署 |
| 配置参考文档 | `references/config-reference.md` | 所有配置字段说明 |
| TLS 设置指南 | `references/tls-setup.md` | TLS 证书生成与配置 |

## 执行步骤

### 快速部署（推荐）

使用预设二进制和脚本，一条命令完成部署：

**Linux 服务端**：
```bash
cd skills/goremote-deploy
./scripts/deploy-server.sh <server_ip> <ssh_password>
```

**Linux 客户端**：
```bash
cd skills/goremote-deploy
./scripts/deploy-agent.sh <agent_ip> <ssh_user> <ssh_password> <server_address>
```

**Windows 环境部署 Linux 服务端**：
```powershell
cd skills/goremote-deploy
.\scripts\deploy-server.ps1 -ServerIp "1.2.3.4" -SshPassword "xxx"
```

### 分步部署（自定义）

当需要自定义配置或排查问题时，按以下步骤操作：

### 步骤 1：选择并部署二进制

确认 `bin/` 目录下有对应平台的二进制：

| 文件 | 平台 | 编译命令 |
|------|------|---------|
| 预设二进制 | 目标平台 | 大小 |
|------------|---------|------|
| `assets/bin/server-linux-amd64` | Linux amd64 服务端 | ~40MB |
| `assets/bin/agent-linux-amd64` | Linux amd64 客户端 | ~9MB |
| `assets/bin/server-windows-amd64.exe` | Windows amd64 服务端 | ~40MB |
| `assets/bin/agent-windows-amd64.exe` | Windows amd64 客户端 | ~9MB |

### 使用预设二进制部署

**方式 1：直接使用**

```bash
# Linux 服务端 - 复制到目标服务器后执行：
scp assets/bin/server-linux-amd64 root@server:/opt/goremote/server
ssh root@server "chmod +x /opt/goremote/server"

# Linux 客户端 - 复制到内网服务器后执行：
scp assets/bin/agent-linux-amd64 root@agent:/opt/goremote/agent
ssh root@agent "chmod +x /opt/goremote/agent"
```

**方式 2：部署脚本自动完成**

Linux 部署脚本 `<scripts/deploy-server.sh>` 和 `<scripts/deploy-agent.sh>` 会自动：
1. 检测 `assets/bin/` 中是否存在对应二进制
2. 通过 SCP 上传到目标服务器
3. 赋予执行权限 (`chmod +x`)
4. 上传配置文件
5. 后台启动服务 (`nohup`)
6. 验证健康状态

Windows 部署脚本 `<scripts/deploy-server.ps1>` 同样支持。

### 重新编译（需要更新版本时）

```powershell
# Windows 二进制
go build -o skills/goremote-deploy/assets/bin/server-windows-amd64.exe ./cmd/server
go build -o skills/goremote-deploy/assets/bin/agent-windows-amd64.exe ./cmd/agent

# Linux 二进制（交叉编译）
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o skills/goremote-deploy/assets/bin/server-linux-amd64 ./cmd/server
go build -o skills/goremote-deploy/assets/bin/agent-linux-amd64 ./cmd/agent
```

### 步骤 2：准备配置文件

使用 `assets/` 目录中的模板生成配置文件。

**服务端配置要点**（详见 `references/config-reference.md`）：
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false          # 生产环境建议 true

auth:
  key: "your-secret-key"    # agent 与服务端一致

tunnel:
  public_host: "your-public-ip"  # 公网地址
  port_range_start: 10000
  port_range_end: 20000
```

**客户端配置要点**：
```yaml
server:
  address: "server-ip:8080"    # 指向公网服务端

auth:
  key: "your-secret-key"        # 与服务器一致

reconnect:
  interval: 5
  max_interval: 60
```

### 步骤 3：部署服务端

**预设二进制直接部署**：
```bash
# 上传 Linux 二进制
scp assets/bin/server-linux-amd64 root@your-server:/opt/goremote/server
ssh root@your-server "chmod +x /opt/goremote/server"

# 上传 Windows 二进制（通过 SMB/其他方式）
copy assets\bin\server-windows-amd64.exe \\server\share\server.exe
```

**启动服务**：
```bash
# Linux
ssh root@your-server "cd /opt/goremote && nohup ./server --config config.yaml > /dev/null 2>&1 &"

# Windows
server.exe --config config.yaml
```

**验证**：
```bash
curl -k https://server-ip:8080/health
# 预期：{"status":"ok"}
```

### 步骤 4：部署客户端（Agent）

**Linux 客户端**：
```bash
scp assets/bin/agent-linux-amd64 root@agent:/opt/goremote/agent
ssh root@agent "chmod +x /opt/goremote/agent && cd /opt/goremote && nohup ./agent --config agent.yaml > agent.log 2>&1 &"
```

**Windows 客户端**：
```powershell
copy assets\bin\agent-windows-amd64.exe C:\goremote\agent.exe
C:\goremote\agent.exe --config C:\goremote\agent.yaml
```

### 步骤 5：验证部署

1. **健康检查**：
```bash
curl -k https://server-ip:8080/health
# 预期：{"status":"ok"}
```

2. **查看客户端**：
```bash
curl -k -b cookies.txt https://server-ip:8080/api/clients
# 预期：客户端列表包含 agent
```

3. **创建隧道测试**：
```bash
curl -k -b cookies.txt -X POST https://server-ip:8080/api/tunnels \
  -H "Content-Type: application/json" \
  -d '{"client_id":"xxx","local_port":22,"protocol":"tcp"}'
```

4. **访问隧道**：
```bash
ssh user@server-ip -p <public_port>
# 预期：成功 SSH 到内网服务器
```

### 步骤 6：TLS 配置（可选）

如需启用 TLS 防止中间人攻击，参考 `references/tls-setup.md`。

简要步骤：
1. 生成证书：`openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=server-ip" -addext "subjectAltName=IP:server-ip"`
2. 服务端设置 `tls.enabled: true` 并指定 `cert/key`
3. 客户端设置 `tls.enabled: true` 并指定 `ca: "server.crt"`

## 输出标准

部署完成后，Agent 应输出：

1. **部署状态摘要**：
   - 服务端地址 + 健康状态
   - 客户端列表（数量 + ID）
   - 隧道列表（如有）

2. **验证结果**：
   - 健康检查：✅/❌
   - 客户端注册：✅/❌
   - 隧道创建：✅/❌
   - 隧道数据传输：✅/❌

3. **配置信息**（脱敏）：
   - TLS 是否启用
   - 端口范围
   - 日志级别

## 常见问题

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| 客户端无法注册 | auth.key 不一致 | 检查两端 key 配置 |
| 隧道创建失败 | client_id 错误 / 客户端离线 | 检查客户端状态 |
| 隧道访问无响应 | 内网服务未启动 | 检查内网端口服务 |
| TLS 握手失败 | 证书无 SAN | 重新生成带 SAN 的证书 |
| 二进制无法运行 | 平台不匹配 / 无执行权限 | `chmod +x` 或重新编译 |
