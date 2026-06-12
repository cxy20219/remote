# GoRemote 项目入口

> 在执行任何操作前，必须先根据下方文件索引查阅获取足够上下文，确认信息充分后再行动；`harness/Harness.md` 是必须查阅的项目总览。

本仓库是 **Go 实现的 reverse tunnel 服务端**（`tunnel-rs` Rust 重构已迁到独立仓库，本分支仅维护 Go 版本）。配套 harness 资源系统（开发指南 / 经验 / 设计 / 部署脚本）在 `harness/` 目录下。

# 文档索引，按需查阅

- [Harness 开发指南](harness/Harness.md)：技术栈、目录结构、常用命令、开发规范、环境配置、构建部署、常见问题和关键资源路由
- [零配置部署验证流程](harness/workflow/zero-config-deploy-verify.md)：零配置架构从零部署到功能验证的直通流程
- [稳定性性能完整性综合验证流程](harness/workflow/stability-performance-completeness-verify.md)：隧道核心改动后的稳定性、性能、完整性验收
- [加密隧道部署与验证流程](harness/workflow/encrypted-tunnel-deploy-verify.md)：旧版共享 auth.key 加密隧道部署验证流程
- [SSH 隧道直通内网服务流程](harness/workflow/ssh-tunnel-direct-access.md)：公网端口直通内网 SSH/HTTP 服务的创建、访问、管理和排查
- [Gitee Release 发布流程](harness/workflow/gitee-release-publish.md)：交叉编译全平台二进制、创建 Gitee Release、上传附件和失败回退
- [多平台集成测试实战经验](harness/experience/multi-platform-testing.md)：Linux/Windows/Android 多端测试经验
- [零配置测试与调试经验](harness/experience/zero-config-testing-lessons.md)：零配置调试经验
- [GoRemote 调试开发经验](harness/experience/go-remote-debugging.md)：综合调试排查手册
- [加密隧道开发实战经验](harness/experience/encrypted-tunnel-lessons.md)：加密功能开发中的踩坑记录
- [远程部署常见坑点](harness/experience/remote-deployment-pitfalls.md)：远程部署常见问题
- [Gin 路由与管理员认证实现经验](harness/experience/gin-auth-route-tips.md)：Gin 路由规划、认证中间件、Cookie 相关经验
- [Gitee Release 中文编码问题](harness/experience/gitee-release-utf8.md)：PowerShell 传中文到 Gitee API 编码损坏
- [零配置部署设计方案](harness/references/zero-config-design.md)：零配置架构完整设计
- [服务端设计文档](harness/references/server-design.md)：服务端架构、消息协议、接口设计
- [客户端设计文档](harness/references/agent-design.md)：Agent 架构、重连机制、生命周期
- [隧道设计文档](harness/references/tunnel-design.md)：端口映射、二进制隧道数据帧、端口防扫描
- [项目结构文档](harness/references/project-structure.md)：项目目录结构、架构设计
- [服务端测试方案](harness/references/server-test.md)：服务端单元、集成和端到端测试方案
- [客户端测试方案](harness/references/agent-test.md)：Agent 单元、集成和端到端测试方案
- [SSH 隧道直通测试用例](harness/references/ssh-tunnel-test-cases.md)：SSH 隧道直通测试用例
- [配置参考](harness/references/config-reference.md)：服务端、Agent、隧道、安全、运行时限流和心跳
- [Swagger API 规范](harness/references/swagger-api.yaml)：HTTP 管理 API 的 OpenAPI/Swagger 规范
- [TLS 设置指南](harness/references/tls-setup.md)：自签名证书生成、TLS 配置
- [服务端部署脚本](harness/scripts/deploy-server.ps1)：Windows PowerShell 部署 Linux 服务端脚本
- [Agent 部署脚本](harness/scripts/deploy-agent.sh)：Linux Agent 部署脚本
- [服务端配置模板](harness/assets/server.yaml.template)：旧版服务端配置模板（历史参考）
- [客户端配置模板](harness/assets/agent.yaml.template)：旧版 Agent 配置模板（历史参考）

## Rust 重构

`tunnel-rs`（Rust 重构，wire 协议字节级兼容 Go）已迁到独立仓库维护。Go 分支不再包含 Rust 源码。跨语言互通通过 [test-rust-agent-against-go-server.ps1](https://gitee.com/cxy20219/tunnel-rs) 脚本验证。

## CI 集中目录

- [`.github/workflows/`](.github/workflows/)：所有 GitHub Actions 工作流
