> 在执行任何操作前，必须先根据下方的文件索引进行查阅和使用以获取足够的上下文信息，确认信息充分后再行动
# 文档索引，按需查阅

- [Harness 开发指南](harness/Harness.md)：技术栈、目录结构、常用命令、开发规范、安全机制、API 端点、构建部署、常见问题、资源路由（含新旧架构）
- [零配置部署验证流程](harness/workflow/zero-config-deploy-verify.md)：零配置架构从零部署到功能验证的全流程，含交叉编译、服务端启动、admin 密码获取、Agent 注册、设备审批、隧道贯通验证、密钥轮换验证（最后验证：2026-05-14）
- [加密隧道部署与验证流程](harness/workflow/encrypted-tunnel-deploy-verify.md)：旧版（共享 auth.key）加密隧道部署验证流程，含交叉编译、磁盘检查、部署启动、隧道创建、连通性验证（最后验证：2026-05-12）
- [SSH 隧道直通内网服务流程](harness/workflow/ssh-tunnel-direct-access.md)：SSH 隧道从公网访问内网服务的完整流程，包括隧道创建、SSH 直连内网、部署服务、问题排查等实操步骤
- [Gitee Release 发布流程](harness/workflow/gitee-release-publish.md)：交叉编译全平台二进制、创建 Gitee Release、上传附件的完整步骤，含 API 调用注意事项和失败回退
- [多平台集成测试实战经验](harness/experience/multi-platform-testing.md)：多端（Linux/Windows/Android）全流程测试经验，涵盖 pendingApproval bug、EOF 解密崩溃、pending 无心跳超时、localhost 黑名单误伤、IP 白名单空桩、plink 主机密钥缓存、Android 部署要点、已知代码问题列表
- [零配置测试与调试经验](harness/experience/zero-config-testing-lessons.md)：零配置架构测试踩坑记录，包括 PowerShell 远程命令转义、Agent 后台启动、fuser 安全、测试服务搭建、认证 Cookie、ECDH 密钥链路追踪、日志字段映射、pending 超时说明
- [GoRemote 调试开发经验](harness/experience/go-remote-debugging.md)：综合调试排查手册，涵盖 TLS、PowerShell 坑点、Agent 启动、配置管理、隧道调试、交叉编译、磁盘管理、安全功能测试、Android adb 部署和常见错误速查
- [加密隧道开发实战经验](harness/experience/encrypted-tunnel-lessons.md)：加密功能开发中的踩坑记录，包括 Go stdlib crypto/hkdf 不可用、磁盘满导致上传失败、swag 文档缺失、PowerShell curl 转义、plink 主机密钥等
- [远程部署常见坑点](harness/experience/remote-deployment-pitfalls.md)：五大部署坑点 — binary in use 无法覆盖、Permission denied、进程杀不掉用 fuser、nohup 启动卡住、服务器目录混淆
- [Gin 路由与管理员认证实现经验](harness/experience/gin-auth-route-tips.md)：路由规划 Public vs Protected、Middleware 重定向循环、Static vs StaticFile 区别、ShouldBindJSON Content-Type 要求、Cookie 设置与清除
- [Gitee Release 中文编码问题](harness/experience/gitee-release-utf8.md)：PowerShell 传中文到 Gitee API 时编码损坏的原因和 Go 程序解决方案
- [零配置部署设计方案](harness/references/zero-config-design.md)：零配置架构完整设计方案，含设计目标、架构图、数据结构、Agent 生命周期、消息协议、API 接口、Web UI 布局、关键机制（ed25519 身份、ECDH 密钥交换、审批制注册）、实现差异说明（§13）
- [服务端设计文档](harness/references/server-design.md)：服务端架构、消息协议、接口设计
- [客户端设计文档](harness/references/agent-design.md)：客户端架构、重连机制、生命周期
- [隧道设计文档](harness/references/tunnel-design.md)：隧道架构、数据传输、安全机制、端口占用检测、端口状态查询 API
- [项目结构文档](harness/references/project-structure.md)：项目目录结构、架构设计、消息协议格式
- [服务端测试方案](harness/references/server-test.md)：服务端单元/集成/端到端测试
- [客户端测试方案](harness/references/agent-test.md)：客户端单元/集成/端到端测试
- [SSH 隧道直通测试用例](harness/references/ssh-tunnel-test-cases.md)：SSH 隧道直通流程测试用例，覆盖正常流程、边界条件、异常情况
- [TLS 设置指南](harness/references/tls-setup.md)：自签名证书生成、TLS 配置、三种安全等级、常见错误排查
- [服务端部署脚本](harness/scripts/deploy-server.ps1)：零配置版 Windows PowerShell 部署 Linux 服务端，含 fuser 停进程、pscp 上传、nohup 启动、健康检查、admin 密码提取
- [Agent 部署脚本](harness/scripts/deploy-agent.sh)：零配置版 Linux Bash 部署 Agent 脚本，仅需服务器地址，无配置文件
- [服务端配置模板](harness/assets/server.yaml.template)：旧版服务端配置模板（零配置架构下不再需要，仅作参考）
- [客户端配置模板](harness/assets/agent.yaml.template)：旧版 Agent 配置模板（零配置架构下不再需要，仅作参考）
