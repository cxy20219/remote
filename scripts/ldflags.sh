#!/usr/bin/env bash
# 唯一的构建参数定义处：本地构建、CI、release 都从这里取。
#
# 用法：ldflags="$(bash scripts/ldflags.sh v2.8.0)"
#       go build -trimpath -ldflags="$ldflags" -o out ./cmd/server
#
# 为什么必须是唯一一处：版本号靠 -X 注入，任何一处写岔（包路径拼错、少个引号）
# 都会让那个二进制悄悄退化成 dev，而发布记录里写的还是 v2.8.0——二进制哈希
# 对不上时，没人能快速想到是这个原因。
set -euo pipefail

VERSION="${1:-}"
FLAGS="-s -w"
if [[ -n "$VERSION" ]]; then
  FLAGS+=" -X goremote/internal/buildinfo.Version=${VERSION}"
fi
printf '%s' "$FLAGS"
