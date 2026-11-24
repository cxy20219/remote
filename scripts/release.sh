#!/usr/bin/env bash
#
# goremote 发布构建脚本
#
# 用法:
#   VERSION=v2.6.0 ./scripts/release.sh
#   ./scripts/release.sh v2.6.0
#   OUT_DIR=/tmp/dist VERSION=v2.6.0 ./scripts/release.sh
#
# 可复现性（重要）:
#   1. 构建参数固定为 CGO_ENABLED=0 + -trimpath + -ldflags="-s -w"。
#      三者缺一都会改变二进制 sha256。
#   2. 从 HEAD 的临时 git worktree 构建，而不是当前工作区。
#      Go 会把 vcs.modified（工作区是否 dirty）嵌进二进制：工作区里有
#      未提交/未跟踪文件时会变成 +dirty，同一 commit 也会产出不同哈希。
#      用干净 worktree 构建才能与 tag 完全一致。
#   3. 同一 Go 版本 + 同一 commit + 本脚本 ⇒ 相同哈希。
#      发布记录里请写明 `go version` 的输出。
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 版本号必须来自 HEAD 上的 v* tag：手填的版本号与源码之间没有任何约束，
# 一旦写错，发布物会永久声称一个它并不对应的版本。本地实验可以用
# ALLOW_UNTAGGED=1 显式跳过这条（它不会出现在任何发布流程里）。
VERSION="${VERSION:-${1:-}}"
TAG=""
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  TAG="$(git -C "$ROOT" describe --tags --exact-match --match 'v*' HEAD 2>/dev/null || true)"
fi
if [[ -z "$VERSION" ]]; then
  if [[ -z "$TAG" ]]; then
    echo "error: cannot derive VERSION: HEAD is not on a v* tag." >&2
    echo "       tag the commit first (git tag -a v2.8.0 -m ...), or set ALLOW_UNTAGGED=1 for a local experiment." >&2
    exit 2
  fi
  VERSION="$TAG"
else
  [[ "$VERSION" == v* ]] || VERSION="v$VERSION"
  if [[ -n "$TAG" && "$TAG" != "$VERSION" ]]; then
    echo "error: VERSION=$VERSION does not match the tag on HEAD ($TAG)." >&2
    echo "       a release must not claim a version its source does not have." >&2
    exit 2
  fi
  if [[ -z "$TAG" && "${ALLOW_UNTAGGED:-0}" != "1" ]]; then
    echo "error: HEAD is not tagged, but VERSION=$VERSION was given." >&2
    echo "       tag the commit, or set ALLOW_UNTAGGED=1 for a local experiment." >&2
    exit 2
  fi
fi

# 构建参数只有一处定义（scripts/ldflags.sh），release 不能自带一份。
LDFLAGS="$(bash "$ROOT/scripts/ldflags.sh" "$VERSION")"
if [[ -z "$LDFLAGS" ]]; then
  echo "error: scripts/ldflags.sh returned no flags" >&2
  exit 2
fi

OUT="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT"

command -v go >/dev/null 2>&1 || { echo "error: go not found in PATH" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "error: tar not found" >&2; exit 1; }
command -v gzip >/dev/null 2>&1 || { echo "error: gzip not found" >&2; exit 1; }

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    echo "error: need sha256sum or shasum" >&2
    return 1
  fi
}

echo "==> $(go version)"
echo "==> release $VERSION -> $OUT"
echo "==> ldflags: $LDFLAGS"

# 从 HEAD 的干净 worktree 构建（见文件头说明 2）。
BUILD_ROOT="$ROOT"
WORKTREE=""
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/goremote-release.XXXXXX")"
  if git -C "$ROOT" worktree add --detach "$WORKTREE" HEAD >/dev/null 2>&1; then
    BUILD_ROOT="$WORKTREE"
    echo "==> build from HEAD $(git -C "$ROOT" rev-parse --short HEAD) (clean worktree, vcs.modified=false)"
  else
    echo "warning: git worktree failed; building from working tree (hash may include +dirty)" >&2
    rm -rf "$WORKTREE"
    WORKTREE=""
  fi
fi

cleanup() {
  if [[ -n "$WORKTREE" ]]; then
    git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || rm -rf "$WORKTREE"
  fi
}
trap cleanup EXIT

cd "$BUILD_ROOT"

# 静态页的 .gz 副本会被 go:embed 打进二进制。副本过期不会让编译失败，只会
# 让线上一直发旧页面，所以发布前按内容逐字节校验，不一致就停。
echo "==> verify precompressed static pages"
for html in web/static/*.html; do
  gz="$html.gz"
  if [[ ! -f "$gz" ]]; then
    echo "error: missing $gz; run 'make static-gz' and commit it" >&2
    exit 1
  fi
  if ! cmp -s <(gzip -dc "$gz") "$html"; then
    echo "error: $gz is stale; run 'make static-gz' and commit it" >&2
    exit 1
  fi
done

# label|GOOS|GOARCH|GOARM|ext|exe-suffix
PLATFORMS=(
  "linux-amd64|linux|amd64||tar.gz|"
  "linux-arm64|linux|arm64||tar.gz|"
  "linux-armv7|linux|arm|7|tar.gz|"
  "darwin-amd64|darwin|amd64||tar.gz|"
  "darwin-arm64|darwin|arm64||tar.gz|"
  "windows-amd64|windows|amd64||zip|.exe"
  "windows-arm64|windows|arm64||zip|.exe"
)

for row in "${PLATFORMS[@]}"; do
  IFS='|' read -r label goos goarch goarm ext exe <<<"$row"
  if [[ "$ext" == "zip" ]] && ! command -v zip >/dev/null 2>&1; then
    echo "error: 'zip' is required for windows archives; install it first" >&2
    exit 1
  fi
done

: > "$OUT/SHA256SUMS.txt"

for row in "${PLATFORMS[@]}"; do
  IFS='|' read -r label goos goarch goarm ext exe <<<"$row"
  name="goremote-${VERSION}-${label}"
  stage="$OUT/.stage-$label"
  rm -rf "$stage"
  mkdir -p "$stage"

  echo
  echo "==> $label  ($goos/$goarch${goarm:+/armv$goarm})"

  envs=(CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch")
  [[ -n "$goarm" ]] && envs+=(GOARM="$goarm")

  for cmd in server agent; do
    out="$stage/goremote-$cmd$exe"
    env "${envs[@]}" go build -trimpath -ldflags="$LDFLAGS" -o "$out" "./cmd/$cmd"
    printf '    %-24s %s  %s bytes\n' "goremote-$cmd$exe" "$(sha256_hex < "$out")" "$(wc -c < "$out" | tr -d ' ')"
  done

  cp README.md LICENSE "$stage/"

  case "$ext" in
    tar.gz) ( cd "$stage" && tar -czf "$OUT/$name.tar.gz" * ) ;;
    zip)    ( cd "$stage" && zip -q -r "$OUT/$name.zip" * ) ;;
  esac
  rm -rf "$stage"

  sum="$(sha256_hex < "$OUT/$name.$ext")"
  printf '    %-44s %s\n' "$name.$ext" "$sum"
  printf '%s  %s\n' "$sum" "$name.$ext" >> "$OUT/SHA256SUMS.txt"
done

echo
echo "==> wrote $OUT/SHA256SUMS.txt"
cat "$OUT/SHA256SUMS.txt"
