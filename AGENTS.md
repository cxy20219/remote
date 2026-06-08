> 在执行任何操作前，必须先根据下方的文件索引进行查阅和使用以获取足够的上下文信息，确认信息充分后再行动
>
> **仓库布局**：本仓库是单仓双子项目布局：
> - `go-remote/` — Go 实现（参考实现，已稳定）
> - `rust-remote/` — Rust 重构（wire 协议字节级兼容，目标逐步替代 Go）
> - `AGENTS.md` — 根索引
> - `.github/workflows/` — 集中 CI
>
> 路径示例：根 `harness/` 已迁入 `go-remote/harness/`，根 `tunnel-rs/` 已迁入 `rust-remote/`。

# 文档索引，按需查阅

## Go 实现（`go-remote/`）

- [Harness 开发指南](go-remote/harness/Harness.md)：技术栈、目录结构、常用命令、开发规范、环境配置、构建部署、常见问题和关键资源路由
- [零配置部署验证流程](go-remote/harness/workflow/zero-config-deploy-verify.md)：零配置架构从零部署到功能验证的直通流程
- [稳定性性能完整性综合验证流程](go-remote/harness/workflow/stability-performance-completeness-verify.md)：隧道核心改动后的稳定性、性能、完整性验收
- [加密隧道部署与验证流程](go-remote/harness/workflow/encrypted-tunnel-deploy-verify.md)：旧版共享 auth.key 加密隧道部署验证流程
- [SSH 隧道直通内网服务流程](go-remote/harness/workflow/ssh-tunnel-direct-access.md)：公网端口直通内网 SSH/HTTP 服务的创建、访问、管理和排查
- [Gitee Release 发布流程](go-remote/harness/workflow/gitee-release-publish.md)：交叉编译全平台二进制、创建 Gitee Release、上传附件和失败回退
- [多平台集成测试实战经验](go-remote/harness/experience/multi-platform-testing.md)：Linux/Windows/Android 多端测试经验
- [零配置测试与调试经验](go-remote/harness/experience/zero-config-testing-lessons.md)：零配置调试经验
- [GoRemote 调试开发经验](go-remote/harness/experience/go-remote-debugging.md)：综合调试排查手册
- [加密隧道开发实战经验](go-remote/harness/experience/encrypted-tunnel-lessons.md)：加密功能开发中的踩坑记录
- [远程部署常见坑点](go-remote/harness/experience/remote-deployment-pitfalls.md)：远程部署常见问题
- [Gin 路由与管理员认证实现经验](go-remote/harness/experience/gin-auth-route-tips.md)：Gin 路由规划、认证中间件、Cookie 相关经验
- [Gitee Release 中文编码问题](go-remote/harness/experience/gitee-release-utf8.md)：PowerShell 传中文到 Gitee API 编码损坏
- [零配置部署设计方案](go-remote/harness/references/zero-config-design.md)：零配置架构完整设计
- [服务端设计文档](go-remote/harness/references/server-design.md)：服务端架构、消息协议、接口设计
- [客户端设计文档](go-remote/harness/references/agent-design.md)：Agent 架构、重连机制、生命周期
- [隧道设计文档](go-remote/harness/references/tunnel-design.md)：端口映射、二进制隧道数据帧、端口防扫描
- [项目结构文档](go-remote/harness/references/project-structure.md)：项目目录结构、架构设计
- [服务端测试方案](go-remote/harness/references/server-test.md)：服务端单元、集成和端到端测试方案
- [客户端测试方案](go-remote/harness/references/agent-test.md)：Agent 单元、集成和端到端测试方案
- [SSH 隧道直通测试用例](go-remote/harness/references/ssh-tunnel-test-cases.md)：SSH 隧道直通测试用例
- [配置参考](go-remote/harness/references/config-reference.md)：服务端、Agent、隧道、安全、运行时限流和心跳
- [Swagger API 规范](go-remote/harness/references/swagger-api.yaml)：HTTP 管理 API 的 OpenAPI/Swagger 规范
- [TLS 设置指南](go-remote/harness/references/tls-setup.md)：自签名证书生成、TLS 配置
- [服务端部署脚本](go-remote/harness/scripts/deploy-server.ps1)：Windows PowerShell 部署 Linux 服务端脚本
- [Agent 部署脚本](go-remote/harness/scripts/deploy-agent.sh)：Linux Agent 部署脚本
- [服务端配置模板](go-remote/harness/assets/server.yaml.template)：旧版服务端配置模板（历史参考）
- [客户端配置模板](go-remote/harness/assets/agent.yaml.template)：旧版 Agent 配置模板（历史参考）

## Rust 重构（`rust-remote/`）

`go-remote` 的 Rust 重构，wire 协议与 Go 实现字节级兼容（可互通）。rust-remote 自身有完整的 `harness/` 子系统。

- [rust-remote 子项目 Harness](rust-remote/harness/Harness.md)：Rust 子项目总览、关键约束、常用入口
- [跨语言 e2e 验证流程](rust-remote/harness/workflow/rust-remote-verify.md)：cargo test / clippy / Go↔Rust 互通脚本验证
- [Rust 端口编译与 clippy 踩坑](rust-remote/harness/experience/rust-remote-build-pitfalls.md)：rustls 0.23 API、result_large_err、include_str 静态服务、RateLimiter 挂载、select! 死锁
- [PowerShell 5.1 跨语言脚本踩坑](rust-remote/harness/experience/powershell-cross-lang-ps5.1.md)：em-dash 破坏参数、Start-Process 同文件重定向、共享读、多行 regex
- [rust-remote 优化 Backlog](rust-remote/harness/experience/optimization-backlog.md)：16 项优化项的优先级 / 症状 / 修法 / 验证记录，Phase A 5 项已闭环（持久化、鉴权、密钥日志、body limit、tunnel update 405）
- [rust-remote 部署资源](rust-remote/Dockerfile) / [systemd unit](rust-remote/contrib/systemd/tunnel-rs-server.service) / [CHANGELOG](rust-remote/CHANGELOG.md)：multi-stage scratch 镜像、hardened systemd unit、Keep-a-Changelog 风格 changelog（Phase D #15 产物）
- [rust-remote 设计要点](rust-remote/harness/references/rust-remote-design.md)：wire 协议消息类型、加密链路 HKDF 参数、持久化 schema、状态机
- [rust-remote README](rust-remote/README.md)：构建、运行、跨语言互通测试矩阵
- [rust-remote common](rust-remote/crates/common/src/lib.rs)：共享 message codec、ed25519/x25519 身份、AES-256-GCM
- [rust-remote server](rust-remote/crates/server/src/)：axum 0.7 + tokio、StateStore、tunnel manager、admin auth
- [rust-remote agent](rust-remote/crates/agent/src/)：identity 持久化、tokio-tungstenite、reconnect 退避
- [跨语言互通测试脚本](rust-remote/bin/test-rust-agent-against-go-server.ps1)：Go server + Rust agent e2e
- [rust-remote CI](.github/workflows/rust-remote.yml)：cargo test（debug+release）+ clippy + 跨语言 e2e（Windows runner）

## CI 集中目录

- [.github/workflows/](.github/workflows/)：所有 GitHub Actions 工作流
  - `rust-remote.yml` — rust-remote 端的 test + clippy + 跨语言 e2e（Go server + Rust agent）
