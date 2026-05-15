> 在执行任何操作前，必须先根据下方的文件索引进行查阅和使用以获取足够的上下文信息，确认信息充分后再行动

# 文档索引，按需查阅

- [Harness 开发指南](harness/Harness.md)：技术栈、目录结构、常用命令、开发规范、环境配置、构建部署、常见问题和关键资源路由
- [零配置部署验证流程](harness/workflow/zero-config-deploy-verify.md)：零配置架构从零部署到功能验证的直通流程，含交叉编译、服务端启动、Agent 注册审批、Android 部署、隧道验证、密钥轮换和失败回退
- [稳定性性能完整性综合验证流程](harness/workflow/stability-performance-completeness-verify.md)：隧道核心改动后的稳定性、性能、完整性验收，含三端部署、高并发 SSH、Android echo、50MB 完整性、pending 长等待和瓶颈定位
- [加密隧道部署与验证流程](harness/workflow/encrypted-tunnel-deploy-verify.md)：旧版共享 auth.key 加密隧道部署验证流程，适用于兼容旧架构和历史问题复盘
- [SSH 隧道直通内网服务流程](harness/workflow/ssh-tunnel-direct-access.md)：公网端口直通内网 SSH/HTTP 服务的创建、访问、管理和排查流程
- [Gitee Release 发布流程](harness/workflow/gitee-release-publish.md)：交叉编译全平台二进制、创建 Gitee Release、上传附件和失败回退流程
- [多平台集成测试实战经验](harness/experience/multi-platform-testing.md)：Linux/Windows/Android 多端测试经验，含 pending 心跳、二进制隧道帧、高并发 SSH、Android 部署、限流归因、吞吐瓶颈和第二轮安全/稳定优化判断
- [零配置测试与调试经验](harness/experience/zero-config-testing-lessons.md)：零配置调试经验，含 PowerShell 远程命令转义、Web UI Cookie、pending 生命周期、ECDH 链路和日志字段映射
- [GoRemote 调试开发经验](harness/experience/go-remote-debugging.md)：综合调试排查手册，覆盖 TLS、Agent 启动、配置管理、隧道调试、磁盘管理、安全功能和 Android 部署
- [加密隧道开发实战经验](harness/experience/encrypted-tunnel-lessons.md)：加密功能开发中的踩坑记录，含 hkdf、磁盘满、swag、PowerShell curl、plink 主机密钥等经验
- [远程部署常见坑点](harness/experience/remote-deployment-pitfalls.md)：远程部署常见问题，含 binary in use、Permission denied、进程清理、nohup 启动和目录混淆
- [Gin 路由与管理员认证实现经验](harness/experience/gin-auth-route-tips.md)：Gin 路由规划、认证中间件、静态文件、Content-Type 和 Cookie 相关经验
- [Gitee Release 中文编码问题](harness/experience/gitee-release-utf8.md)：PowerShell 传中文到 Gitee API 的编码损坏原因和 Go 程序解决方案
- [零配置部署设计方案](harness/references/zero-config-design.md)：零配置架构完整设计，含设备身份、ECDH、审批注册、消息协议、API、Web UI 和实现差异
- [服务端设计文档](harness/references/server-design.md)：服务端架构、消息协议、接口设计、安全中间件和模块职责
- [客户端设计文档](harness/references/agent-design.md)：Agent 架构、重连机制、生命周期和本地隧道管理设计
- [隧道设计文档](harness/references/tunnel-design.md)：端口映射架构、WebSocket Binary 隧道数据帧、端口防扫描、数据转发和验证方案
- [项目结构文档](harness/references/project-structure.md)：项目目录结构、架构设计、消息协议格式和模块关系
- [服务端测试方案](harness/references/server-test.md)：服务端单元、集成和端到端测试方案
- [客户端测试方案](harness/references/agent-test.md)：Agent 单元、集成和端到端测试方案
- [SSH 隧道直通测试用例](harness/references/ssh-tunnel-test-cases.md)：SSH 隧道直通测试用例，覆盖正常流程、边界条件和异常情况
- [配置参考](harness/references/config-reference.md)：服务端、Agent、隧道、安全、运行时限流和心跳等配置项参考
- [Swagger API 规范](harness/references/swagger-api.yaml)：HTTP 管理 API 的 OpenAPI/Swagger 规范
- [TLS 设置指南](harness/references/tls-setup.md)：自签名证书生成、TLS 配置、安全等级和常见错误排查
- [服务端部署脚本](harness/scripts/deploy-server.ps1)：Windows PowerShell 部署 Linux 服务端脚本，含上传、停进程、nohup 启动、健康检查和 admin 密码提取
- [Agent 部署脚本](harness/scripts/deploy-agent.sh)：Linux Agent 部署脚本，仅需服务端地址，支撑零配置 Agent 启动流程
- [服务端配置模板](harness/assets/server.yaml.template)：旧版服务端配置模板，零配置架构下仅作历史参考和字段对照
- [客户端配置模板](harness/assets/agent.yaml.template)：旧版 Agent 配置模板，零配置架构下仅作历史参考和字段对照
