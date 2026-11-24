#!/usr/bin/env bash
# 从 handler 注解生成 docs/ 下的 swagger 文档（docs.go / swagger.json / swagger.yaml）。
#
# 用法：./scripts/gen-swagger.sh
#
# 说明：
#   - 文档的唯一来源是 internal/server 里 handler 上方的 swag 注解；CI 会重新生成
#     并断言工作区没有改动，所以改了路由或字段必须同步改注解并重跑本脚本。
#   - swag 版本钉死。不同小版本的输出格式有差异，版本漂移会让「生成后 diff 为空」
#     这条判据变成噪声。
#   - --parseInternal 必须开：handler 在 internal/server 下，swag 默认跳过 internal 包。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SWAG_VERSION="${SWAG_VERSION:-v1.16.6}"

if command -v swag >/dev/null 2>&1; then
	SWAG="$(command -v swag)"
else
	# 没装到 PATH 时用 GOBIN 里的副本，缺了才去装，避免每次生成都走网络。
	GOBIN_DIR="${GOBIN:-$(go env GOPATH)/bin}"
	SWAG="${GOBIN_DIR}/swag"
	if [ ! -x "$SWAG" ]; then
		echo "gen-swagger: installing swag ${SWAG_VERSION} into ${GOBIN_DIR}" >&2
		GOBIN="$GOBIN_DIR" go install "github.com/swaggo/swag/cmd/swag@${SWAG_VERSION}"
	fi
fi

"$SWAG" init \
	--generalInfo cmd/server/main.go \
	--output docs \
	--outputTypes go,json,yaml \
	--parseInternal
