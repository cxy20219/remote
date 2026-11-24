# 发布记录

每次发版在这里登记：tag 指向的 commit、构建用的 Go 版本、以及**每个平台两个二进制的 sha256**。

记的是**包内二进制**的哈希，不是压缩包哈希。`tar`/`zip` 会把文件 mtime 写进包里，同一次构建重打一次包，压缩包哈希就会变；包内二进制的哈希是稳定的。所以判断「发布物有没有被重编过」一律比对下表的二进制哈希。

## 复现某次发布

三样必须一致，缺一样哈希就变：

| 要素 | 从哪拿 |
|---|---|
| commit | 本文件登记的 commit（等于 tag 指向的 commit，也等于二进制里的 `vcs.revision`） |
| Go 版本 | 本文件登记的 `go version` |
| 构建脚本 | 仓库里的 `scripts/release.sh`：参数取自 `scripts/ldflags.sh`（`CGO_ENABLED=0` + `-trimpath` + `-ldflags="-s -w -X goremote/internal/buildinfo.Version=<tag>"`），且从干净 worktree 构建（工作区 dirty 会让 `vcs.modified=true`，哈希就变）。`v2.8.0` 之前的版本没有 `-X` 段 |

脚本入库之后发布的版本，直接检出 tag 跑脚本即可：

```bash
git checkout <tag>            # 例如 v2.8.0
./scripts/release.sh          # 版本号直接取 HEAD 上的 v* tag，不用手填
```

> 版本号只认 tag：脚本在没有 `v*` tag 的 commit 上会拒绝构建（手填的版本号与源码
> 之间没有任何约束，写错就会让发布物永久声称一个它并不对应的版本）。本地实验可
> 用 `ALLOW_UNTAGGED=1 VERSION=vX.Y.Z ./scripts/release.sh` 显式跳过。
> 三种构建（本地 / CI / release）的 ldflags 都来自 `scripts/ldflags.sh`，不允许各写一份。

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

## v2.8.0

- **发布日期**：2026-11-25
- **tag**：`v2.8.0`（附注 tag，说明「观察面、数据安全、协议能力位、流量历史」）
- **commit**：`78b49084d5bf6749d94191cea8a8b06352a0b6dc`（`78b4908`）
- **Go**：`go1.27.4`
- **构建**：CI（GitHub Actions ubuntu-latest）跑 `scripts/release.sh`，`vcs.modified=false`、`-trimpath=true`，ldflags 取自 `scripts/ldflags.sh`（含 `-X goremote/internal/buildinfo.Version=v2.8.0`）
- **包名**：`goremote-v2.8.0-<platform>.tar.gz`（linux/darwin）、`goremote-v2.8.0-<platform>.zip`（windows）
- **线上一致性**：`linux-amd64` 的 `goremote-server` 与生产 `/opt/goremote/server` 逐位相同（本次部署即取自该流水线同一 commit 的本地构建）

### 二进制 sha256

| 平台 | `goremote-server` | `goremote-agent` |
|---|---|---|
| linux-amd64 | `7e3f0bb4e1412ec9b14f4122026cb41b1099c0fb838f1f87d258da716a78b586` | `60ed86a6dc125c817392955cddd61ef89d8bece2a2e8ee8d3fcdd04e1111a556` |
| linux-arm64 | `23bb89dd8723081625d6460671eaec16063cdef06e804606a70d5e2cc828bea7` | `bffaca5873e360f2569e4e9cb578a5f124196c8b363a600db17caf10109916b7` |
| linux-armv7 | `286fff159f752ebb17741e3dfefd0846a67775efedb05ee891f877b256f93f98` | `dc4352e1433dc4dc20ffd5c21a6846f3e7be65de33493b3c54a07a3661f8dc64` |
| darwin-amd64 | `a52dff351144ca2f752f1234b31d7d758c86d916c483cf840620712a6f201d64` | `1750ea3d5d33e76abbbf1a5f154785550b99550c50e436bd6607d385b5ddfb7d` |
| darwin-arm64 | `506843875b1a7354631fdf487b70da51786dd99886ef32160ff4f63f0362d8c7` | `983d7e5d0ab2b7531bcbfd6ba0d30a919bae0681605ac2dfc1567e922e239ca8` |
| windows-amd64 | `b6247ad55b6ffe5a6e549118f42430a2afcef11fac45f9f8b894d5c939d60c8f` | `8bd558bcfcfd509f041dbbefca90f98a6528e68a0222dd26b4403f4a6916aeec` |
| windows-arm64 | `bcadf61d33d72d21846fdbd39c0697744a39f8a4712be462dadf215d71d2f551` | `bc5c4c5611d84d424bf41ae548dac5839116ecfb6138b683ca2b6932ae7928ae` |

Windows 两个文件名带 `.exe`，哈希对应这两个文件。以上哈希均由下载发布资产、解包后对包内二进制逐一计算得出，不是压缩包哈希。

## v2.7.0

- **发布日期**：2026-11-24
- **tag**：`v2.7.0`（附注 tag，说明「安全加固与稳定性优化：reauth DH 公钥绑定、依赖 CVE 清零、state 信封 v2、AAD 帧认证、gzip、连接上限、pending TTL、数据面拆锁、隧道实时速率」）
- **commit**：`cec848f852b212909344408c0a2c638b8d8d77c6`（`cec848f`）
- **Go**：`go1.27.4`
- **构建**：macOS arm64 交叉编译，`vcs.modified=false`、`-trimpath=true`
- **包名**：`goremote-v2.7.0-<platform>.tar.gz`（linux/darwin）、`goremote-v2.7.0-<platform>.zip`（windows）

### 二进制 sha256

| 平台 | `goremote-server` | `goremote-agent` |
|---|---|---|
| linux-amd64 | `878282cc487e74b04dc212656d034502d49fafb94143a33a985cfd6323622357` | `fd552ce6ff87f5c2a6c11919e38a239711005f4216533b7d24e0b1ed01db9fec` |
| linux-arm64 | `4bd198421eb2c7b1e7f5df06340f6bb0681cdff564c61c6e337e32ca4f2c493b` | `509abd27456c77872b471f1a43dfe46191441ec65d7e1bdfb66c29efdf384ecf` |
| linux-armv7 | `4745f5379c5adf8816934099049ce7f1c16ddeaa2f2fb2e2caaab19293732f7d` | `5a9b949acd7bc03618deb6553f03084f12109767f022504d8f897be2bad9d1b6` |
| darwin-amd64 | `17ce56cb942337e9806f81cf1e4010a89128c0d4efb65c9a0f29261b5d5b2d59` | `4fc7125fe5f60adbaf08e2ddcdf273309cdc2325a5914343b3a00e86ed8b5c03` |
| darwin-arm64 | `ff441fdb234fb02646b42f7280165f4fdcbef1d250fa91050cda923e62c78d3a` | `4c9cb174680e9ae8ecc670e0fedcd36b8c8959f638f65204531e51c256391d04` |
| windows-amd64 | `78658b8f79db48f257a3a59a0e158c40e8ea49471436c1eb298fef53e48f3475` | `2f977911d4b753316ac3ae83eb344cd4e0202eb605b1c1959094380ab234e6ad` |
| windows-arm64 | `88ba8b2f646b6656d62e2cabe76b3709270402cd27d29025c8fe93583e08f606` | `a91303cc5d8171835589bece722e7f350a9f9a4e461ce738913dff742bedb165` |

Windows 两个文件名带 `.exe`（`goremote-server.exe` / `goremote-agent.exe`），哈希对应这两个文件。

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
