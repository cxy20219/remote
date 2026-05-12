> 在执行任何操作前，必须先根据下方的文件索引进行查阅和使用以获取足够的上下文信息，确认信息充分后再行动
# 文档索引，按需查阅

- [Harness 开发指南](harness/Harness.md)：技术栈、目录结构、常用命令、开发规范、安全机制、环境配置、构建部署、常见问题、资源路由
- [加密隧道部署与验证流程](harness/workflow/encrypted-tunnel-deploy-verify.md)：加密隧道从零部署到功能验证的全流程，含交叉编译、磁盘检查、部署启动、隧道创建、连通性验证、断线清理、端口占用检测验证（最后验证：2026-05-12）
- [SSH 隧道直通内网服务流程](harness/workflow/ssh-tunnel-direct-access.md)：SSH 隧道从公网访问内网服务的完整流程，包括隧道创建、SSH 直连内网、部署服务、问题排查等实操步骤
- [GoRemote 调试开发经验](harness/experience/go-remote-debugging.md)：综合调试排查手册（已整合跨平台技巧和部署调试），涵盖 TLS、PowerShell 坑点、Agent 启动、配置管理、隧道调试、交叉编译、磁盘管理和常见错误速查
- [加密隧道开发实战经验](harness/experience/encrypted-tunnel-lessons.md)：加密功能开发中的踩坑记录，包括 Go stdlib crypto/hkdf 不可用、磁盘满导致上传失败、swag 文档缺失、PowerShell curl 转义、plink 主机密钥、Python stub 等
- [远程部署常见坑点](harness/experience/remote-deployment-pitfalls.md)：五大部署坑点 — binary in use 无法覆盖、Permission denied、进程杀不掉用 fuser、nohup 启动卡住、服务器目录混淆
- [Gin 路由与管理员认证实现经验](harness/experience/gin-auth-route-tips.md)：路由规划 Public vs Protected、Middleware 重定向循环、Static vs StaticFile 区别、ShouldBindJSON Content-Type 要求、Cookie 设置与清除、返回格式自动适配
- [Gitee Release 中文编码问题](harness/experience/gitee-release-utf8.md)：PowerShell 传中文到 Gitee API 时编码损坏的原因和 Go 程序解决方案
- [服务端设计文档](harness/references/server-design.md)：服务端架构、消息协议、接口设计
- [客户端设计文档](harness/references/agent-design.md)：客户端架构、重连机制
- [隧道设计文档](harness/references/tunnel-design.md)：隧道架构、数据传输、安全机制、端口占用检测、端口状态查询 API
- [项目结构文档](harness/references/project-structure.md)：项目目录结构、架构设计、消息协议格式
- [服务端测试方案](harness/references/server-test.md)：服务端单元/集成/端到端测试
- [客户端测试方案](harness/references/agent-test.md)：客户端单元/集成/端到端测试
- [SSH 隧道直通测试用例](harness/references/ssh-tunnel-test-cases.md)：SSH 隧道直通流程测试用例，覆盖正常流程、边界条件、异常情况
- [服务端部署脚本](harness/scripts/deploy-server.ps1)：Windows PowerShell 部署 Linux 服务端脚本，含 fuser 停进程、pscp 上传、nohup 启动、健康检查
- [Agent 部署脚本](harness/scripts/deploy-agent.sh)：Linux Bash 部署 Agent 脚本，含模板变量替换、远程启动
- [配置字段参考](harness/references/config-reference.md)：server.yaml 和 agent.yaml 所有配置字段说明（含新增 security 段）
- [TLS 设置指南](harness/references/tls-setup.md)：自签名证书生成、TLS 配置、三种安全等级、常见错误排查
- [Swagger API 规范](harness/references/swagger-api.yaml)：REST API 完整 YAML 规范（swag init 自动生成）
- [服务端配置模板](harness/assets/server.yaml.template)：生产环境服务端配置模板，含 security 段
- [客户端配置模板](harness/assets/agent.yaml.template)：生产环境客户端配置模板
