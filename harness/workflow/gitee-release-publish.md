# Gitee Release 发布流程

## 适用场景

完成功能开发并提交后，交叉编译全平台二进制并发布到 Gitee Releases。

## 前置条件

- 已提交代码到 master 分支
- Gitee 个人访问令牌（需 `repos` 和 `releases` 权限）
- Go 工具链（支持交叉编译）

## 关联资源

- API规范: https://gitee.com/api/v5/swagger
- 编码注意事项: [Gitee Release 中文编码问题](../experience/gitee-release-utf8.md)
- 服务端部署脚本: [deploy-server.ps1](../scripts/deploy-server.ps1)

## 执行步骤

### 步骤一：交叉编译全平台二进制

```powershell
# 服务端
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/server-linux-amd64 ./cmd/server/
$env:GOOS="linux"; $env:GOARCH="arm64"; go build -ldflags "-s -w" -o release/server-linux-arm64 ./cmd/server/
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/server-windows-amd64.exe ./cmd/server/
$env:GOOS="darwin"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/server-darwin-amd64 ./cmd/server/
$env:GOOS="darwin"; $env:GOARCH="arm64"; go build -ldflags "-s -w" -o release/server-darwin-arm64 ./cmd/server/

# 客户端
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/agent-linux-amd64 ./cmd/agent/
$env:GOOS="linux"; $env:GOARCH="arm64"; go build -ldflags "-s -w" -o release/agent-linux-arm64 ./cmd/agent/
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/agent-windows-amd64.exe ./cmd/agent/
$env:GOOS="darwin"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o release/agent-darwin-amd64 ./cmd/agent/
$env:GOOS="darwin"; $env:GOARCH="arm64"; go build -ldflags "-s -w" -o release/agent-darwin-arm64 ./cmd/agent/
```

共 10 个二进制文件，放入 `release/` 目录。

### 步骤二：创建 Git Tag 并推送

```powershell
git tag -a v1.x.x -m "v1.x.x - 版本说明"
git push origin v1.x.x
```

### 步骤三：通过 Gitee API 创建 Release

使用 `curl -F`（multipart form-data），**不要**用 JSON body：

```powershell
$token = "your-token"
curl.exe -s -X POST "https://gitee.com/api/v5/repos/{owner}/{repo}/releases" `
  -F "access_token=$token" `
  -F "tag_name=v1.x.x" `
  -F "target_commitish=master" `
  -F "name=v1.x.x - 版本名称" `
  -F "body=版本说明正文（支持 Markdown）" `
  -F "prerelease=false"
```

**关键**：
- **必须传 `target_commitish=master`**，否则 Gitee 返回 400
- 必须用 `-F` 而非 `-d` 或 JSON body
- Release 正文中文在 PowerShell 中可正常传递（`-F` 方式不受编码损坏影响）

响应中的 `id` 字段（如 `682464`）为 release_id，后续上传附件时需要。

### 步骤四：上传二进制附件

```powershell
$token = "your-token"
$releaseId = 682464  # 步骤三响应中的 id
$baseUrl = "https://gitee.com/api/v5/repos/{owner}/{repo}/releases/$releaseId/attach_files"

foreach ($f in @("release/server-linux-amd64", ...)) {
    curl.exe -s -X POST $baseUrl -F "access_token=$token" -F "file=@$(Resolve-Path $f)"
}
```

每个文件独立上传，响应中包含 `browser_download_url`。

## 验证方式

1. 确认 Gitee Release 页面可见：`https://gitee.com/{owner}/{repo}/releases/tag/v1.x.x`
2. 确认所有 10 个二进制文件均已出现在 Release Assets 列表中
3. 随机下载一个二进制并验证 hash：本地 `Get-FileHash` vs 下载后的 `Get-FileHash`

## 注意事项

- **Token 安全**：令牌不要写入代码或文档，使用后轮换
- **PowerShell curl**：Windows 的 `curl.exe` 是原生 curl（不是 `Invoke-WebRequest` 别名），直接使用
- **API 调用失败**：400 多因缺少 `target_commitish` 参数
- **Gitee API 限频**：连续上传多个文件时建议间隔 1-2 秒避免触发限频

## 失败回退

| 失败场景 | 操作 |
|----------|------|
| Release 创建失败（400） | 检查是否传了 `target_commitish` |
| 附件上传失败 | 确认 release_id 正确，单独重试该文件 |
| 二进制不完整 | 本地重新交叉编译后单独上传该文件 |
| Tag 推错 | `git push --delete origin v1.x.x` 删除远程 tag 后重来 |

## 最近验证

- 2026-05-13: v1.2.0 发布，10 文件全部上传成功
