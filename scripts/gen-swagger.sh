#!/usr/bin/env bash
# 从 handler 注解生成 docs/ 下的 swagger 文档（docs.go / swagger.json / swagger.yaml）。
#
# 用法：./scripts/gen-swagger.sh
#
# 说明：
#   - 文档的唯一来源是 internal/server 里 handler 上方的 swag 注解；CI 会重新生成
#     并断言工作区没有改动，所以改了路由或字段必须同步改注解并重跑本脚本。
#   - 版本钉死，且**不用 PATH 上碰巧存在的 swag**：不同版本输出格式不同，本地用
#     别的版本生成、CI 用钉死的版本校验，就会出现「本地绿、CI 红」。每次都用
#     GOBIN 里的副本，缺了/版本不对就按钉死的版本重装（有构建缓存，命中时很快）。
#   - 注意 swag 的 `--version` 打印的是 CLI 的版本常量（v1.16.4），与实际模块版本
#     不一致，不能拿它做校验；所以这里只认「从钉死版本装出来的那个二进制」。
#   - --parseInternal 必须开：handler 在 internal/server 下，swag 默认跳过 internal 包。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SWAG_VERSION="${SWAG_VERSION:-v1.16.6}"

GOBIN_DIR="${GOBIN:-$(go env GOPATH)/bin}"
SWAG="${GOBIN_DIR}/swag"

echo "gen-swagger: using swag ${SWAG_VERSION} from ${SWAG}" >&2
GOBIN="$GOBIN_DIR" go install "github.com/swaggo/swag/cmd/swag@${SWAG_VERSION}"

"$SWAG" init \
	--generalInfo cmd/server/main.go \
	--output docs \
	--outputTypes go,json,yaml \
	--parseInternal
