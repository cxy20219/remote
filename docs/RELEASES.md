# 发布记录

每次发版在这里登记：tag 指向的 commit、构建用的 Go 版本、以及**每个平台两个二进制的 sha256**。

记的是**包内二进制**的哈希，不是压缩包哈希。`tar`/`zip` 会把文件 mtime 写进包里，同一次构建重打一次包，压缩包哈希就会变；包内二进制的哈希是稳定的。所以判断「发布物有没有被重编过」一律比对下表的二进制哈希。

## 复现某次发布

三样必须一致，缺一样哈希就变：

| 要素 | 从哪拿 |
|---|---|
| commit | 本文件登记的 commit（等于 tag 指向的 commit，也等于二进制里的 `vcs.revision`） |
| Go 版本 | 本文件登记的 `go version` |
| 构建脚本 | 仓库里的 `scripts/release.sh`：参数固定 `CGO_ENABLED=0` + `-trimpath` + `-ldflags="-s -w"`，且从干净 worktree 构建（工作区 dirty 会让 `vcs.modified=true`，哈希就变） |

脚本入库之后发布的版本，直接检出 tag 跑脚本即可：

```bash
git checkout <tag>            # 例如 v2.7.0
VERSION=<tag> ./scripts/release.sh
```

`v2.6.0` 是特例：该 tag 早于 `scripts/release.sh` 入库，检出它的树里没有脚本，得把脚本从当前分支补进去再跑（脚本只认构建树的 HEAD，所以产出的二进制仍属于 `v2.6.0`）：

```bash
git worktree add --detach /tmp/goremote-v2.6.0 v2.6.0
mkdir -p /tmp/goremote-v2.6.0/scripts
git show HEAD:scripts/release.sh > /tmp/goremote-v2.6.0/scripts/release.sh
chmod +x /tmp/goremote-v2.6.0/scripts/release.sh
cd /tmp/goremote-v2.6.0 && VERSION=v2.6.0 ./scripts/release.sh
# 产物在 /tmp/goremote-v2.6.0/dist/，包内 goremote-server / goremote-agent 的 sha256 应与下表一致
```

核对单个平台（以 Linux amd64 为例）：

```bash
tar -xzf dist/goremote-v2.6.0-linux-amd64.tar.gz -C /tmp/rel
sha256sum /tmp/rel/goremote-server /tmp/rel/goremote-agent
```

CI 侧同样走这个脚本（`.github/workflows/release.yml`，Go 钉在 `1.27.4`），所以 tag 触发的流水线应与本地发布产出相同二进制。

校验 v2.6.0 这一版要注意：tag 早于 `scripts/release.sh` 入库，不能直接对 tag 触发。在 `main` 上手动触发并指定 `source_ref`：

```bash
gh workflow run release.yml --ref main -f source_ref=v2.6.0
```

这条路径检出 `v2.6.0` 作为构建树、脚本取自 `main` 的提交，产出应与下表一致（二进制里的 `vcs.revision` 仍是 `0ae72c8`）。

## v2.6.0

- **发布日期**：2026-11-22
- **tag**：`v2.6.0`（附注 tag，说明「隧道与黑名单持久化、重启自动恢复」）
- **commit**：`0ae72c8bebf84be80f7a2cc695e283f4cd67f3f1`（`0ae72c8`）
- **Go**：`go1.27.4`
- **构建**：macOS arm64 交叉编译，`vcs.modified=false`、`-trimpath=true`
- **包名**：`goremote-v2.6.0-<platform>.tar.gz`（linux/darwin）、`goremote-v2.6.0-<platform>.zip`（windows）

### 二进制 sha256

| 平台 | `goremote-server` | `goremote-agent` |
|---|---|---|
| linux-amd64 | `aba83bf97b71ab9d22652c6351dd6fdbb22e92e72bbf45f6d61860bb24e58a50` | `b0e92cf029f49a0cf7f5dab0628a522f9dd8a1e1795a3c113a848b771be23181` |
| linux-arm64 | `2e105ec53709df0e879ca166702b2f04054bb3b1d331ee47f036ada064b37194` | `a896262a9abce72d89842bca31e80bfdc38d34bea9e0654e680704e2f0515ef8` |
| linux-armv7 | `1c0c3a48e3bf00911125458b91be67811d62fbb72027212c9873ab1d183bd38e` | `15a7a05c0d7749e3b9ef1ef36b92138be7e70299c987f69aabe8b9ab3ff82267` |
| darwin-amd64 | `12007a5c4ae9efd887e53c55669a9ca4b607408a95ad37434cc183e02fb0476a` | `f4f6315a8b4bd0424bfb804a7f2c6f61d3bb72a2bdb11d55daf61978f03d4560` |
| darwin-arm64 | `5ee8ee6847f22ad308ddc8069f3bbbefaa9507a5b5f98f86f685c33938c953f9` | `056340c74945acb00c189b10a8d0483fd9f24363cce0f5558fb5a935e459f574` |
| windows-amd64 | `33dce101ee48cd4b07c0b55c6e473d67e8b3130e3028980b928eea15e60d2bfc` | `76df6bce4fa9c42e44242e6caa95faa09160926eaefd7d0ca43c4099d57c7193` |
| windows-arm64 | `b258109ff9c30199ccfcd7791f17469c903b68dec79cbc607e6d54c5a9e1783b` | `8c7aa3e68ee6dbdacaae7d779e95b37737ee97eb4007488659f24ef4aedd513b` |

Windows 两个文件名带 `.exe`（`goremote-server.exe` / `goremote-agent.exe`），哈希对应这两个文件。
