# GoRemote 部署与调试实战经验

## 概述

本文档记录 GoRemote 项目的部署、调试和开发过程中积累的实战经验，涵盖环境差异、配置管理、问题排查等方面。

## 1. PowerShell 与 curl 的坑

### 问题：curl JSON POST 的多种转义方案

在 PowerShell 中发送 JSON 请求，引号和变量展开会导致各种解析错误。

**错误示例**：
```powershell
# ❌ 直接写 JSON 字符串会因引号冲突失败
curl.exe -X POST url -d "{\"key\":\"value\"}"
```

**正确做法**：
```powershell
# ✅ 方式 1：使用文件（最可靠）
echo '{"key":"value"}' > data.json
curl.exe -X POST url -d @data.json

# ✅ 方式 2：单引号 + 双引号混合（PowerShell 中单引号不展开）
curl.exe -X POST url -d '{"key":"value"}'
```

**经验**：
- PowerShell 中 `"` 会尝试展开变量，导致 JSON 被破坏
- 使用 `@file.json` 方式最可靠
- 多行脚本建议用 Python 封装 API 调用，避免 shell 转义

### 问题：curl Cookie 管理

GoRemote 的 API 需要 admin 认证，通过 cookie 传递 token。

**方法**：
```powershell
# 登录，保存 cookie
curl.exe -k -c cookies.txt -X POST https://server/api/login -d '{"password":"admin123"}'

# 请求，使用 cookie
curl.exe -k -b cookies.txt https://server/api/tunnels
```

**经验**：
- `-c` 保存 cookie，`-b` 使用 cookie
- 登录 token 有 24 小时有效期（可通过 Cookie 设置调整）

## 2. Agent 启动与运行

### 问题：Start-Process 工作目录

使用 `Start-Process` 启动 agent 时，默认工作目录可能是 `C:\Windows\System32`，导致相对路径配置文件找不到。

```powershell
# ❌ 错误 - agent 找不到 config/agent.yaml
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml"

# ✅ 正确 - 指定工作目录
Start-Process -FilePath "bin/agent.exe" -ArgumentList "--config config/agent.yaml" -WorkingDirectory "E:/AI-work/go-remote"
```

### 问题：Python 不可用

Windows 10/11 上 `python` 可能指向 Microsoft Store 的 stub，在非交互式环境中不工作。

**解决**：
- 使用 `where.exe python` 检查实际路径
- 如需在后台使用，安装完整 Python 或使用 WSL

## 3. 配置文件管理规范

### 原则：文档内可提及 IP，配置文件中不可

| 文件类型 | IP 处理 |
|---------|---------|
| `docs/*.md` | 可以保留实际 IP（便于追溯） |
| `config/*.yaml` | 必须脱敏，使用 `your-server` 等占位符 |
| `skills/*` | 必须脱敏 |
| `README.md` | 必须脱敏 |
| `AGENTS.md` | 不包含 IP |

### 配置文件精简原则

1. 有代码默认值的字段可省略（减少配置噪声）
2. TLS 禁用时不填 cert/key
3. 部署配置与开发配置分开（`*-deploy.yaml`）
4. 生产环境关闭 Swagger（`swagger.enabled: false`）

## 4. Agent 断线资源清理验证

### 背景

修复了 Agent 断线后隧道自动清理的逻辑（修复 #2）。

### 验证方法

```powershell
# 1. 创建隧道
curl.exe -k -b cookies.txt -X POST https://server/api/tunnels -d @tunnel.json

# 2. 确认隧道存在
curl.exe -k -b cookies.txt https://server/api/tunnels
# → {"total":1,...}

# 3. 杀 Agent
taskkill /F /IM agent.exe

# 4. 确认隧道已清理
sleep 3
curl.exe -k -b cookies.txt https://server/api/tunnels
# → {"total":0,"tunnels":[]} ✅ 修复生效
```

## 5. TLS 证书部署流程

### Go 1.15+ 要求 SAN

自签名证书必须包含 Subject Alternative Names，否则 TLS 握手失败：
```
x509: certificate relies on legacy Common Name field, use SANs instead
```

### 快速生成命令

```bash
# 生成密钥 + 带 SAN 的证书
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=your-server" \
  -addext "subjectAltName=IP:your-ip,DNS:your-ip"
```

### 分发步骤

1. 服务端存放 `server.crt` + `server.key`
2. 客户端只需要 `server.crt` 作为 CA
3. 服务端配置 `tls.enabled: true`
4. 客户端配置 `tls.enabled: true` + `ca: "server.crt"`

## 6. Skill 创建规范

### 标准 Skill 结构

```
skill-name/
├── SKILL.md          # 必选：YAML frontmatter + 执行步骤
├── scripts/          # 可选：自动化脚本
├── references/       # 可选：参考文档
└── assets/           # 可选：模板、二进制、配置
```

### SKILL.md 要求

1. **YAML frontmatter**：`name` + `description`（含触发场景）
2. **执行步骤**：明确每步做什么、用什么命令
3. **资源说明**：何时读 references、何时用 scripts、何时用 assets
4. **输出标准**：部署完成后应输出的内容

### Assets 管理

- 预设二进制：`assets/bin/platform-binary`
- 配置模板：`assets/*.yaml.template`（使用 `{{PLACEHOLDER}}` 占位）
- 编写部署脚本时引用：`"${SKILL_DIR}/assets/bin/..."`

## 7. 项目健康检查清单

部署完成后逐项确认：

```
□ 服务端进程运行中: ps aux | grep server
□ 健康检查通过: curl https://server:8080/health → {"status":"ok"}
□ Agent 已注册: curl /api/clients → client 在线
□ 隧道可创建: POST /api/tunnels → 返回 tunnel_id
□ 隧道数据转发: curl https://server:10000/ → 返回内网响应
□ TLS 握手成功: agent 日志显示 "connected to server"
□ 端口清理正常: 杀 agent 后 GET /api/tunnels → {"total":0}
```

## 8. 常见错误速查（更新版）

| 现象 | 原因 | 解决 |
|------|------|------|
| Agent 启动后找不到配置文件 | 工作目录错误 | 使用绝对路径或 `-WorkingDirectory` |
| Python 命令无输出 | Microsoft Store stub | 安装完整 Python 或使用 WSL |
| curl JSON 请求乱码 | PowerShell 引号转义 | 使用 `-d @file.json` |
| `unauthorized` 错误 | 未登录获取 token | 先 `POST /api/login` 获取 cookie |
| 隧道定时不清理 | 旧版本未修复 | 升级到包含修复 #2 的版本 |
| TLS 握手被拒 | 证书无 SAN | 重新生成带 SAN 的证书 |

## 相关文档

- [SSH 隧道直通内网服务流程](../workflow/ssh-tunnel-direct-access.md) - 隧道创建与使用
- [GoRemote 调试开发经验](../experience/go-remote-debugging.md) - 更早的调试经验
- [配置字段参考](../../skills/goremote-deploy/references/config-reference.md) - 所有配置选项
- [TLS 设置指南](../../skills/goremote-deploy/references/tls-setup.md) - TLS 详细配置
