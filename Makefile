# goremote 常用目标
#
# 发布构建（可复现）：
#   make release VERSION=v2.6.0
# 等价于 VERSION=v2.6.0 ./scripts/release.sh，产物在 dist/。

VERSION ?=

.PHONY: release
release:
	@if [ -z "$(VERSION)" ]; then \
		echo "usage: make release VERSION=v2.6.0" >&2; \
		exit 1; \
	fi
	VERSION="$(VERSION)" ./scripts/release.sh

# 静态页预压缩副本。改动 web/static/*.html 后跑一次并一并提交：.gz 会被
# go:embed 打进二进制，忘了重跑不会报错，只会让线上继续发旧页面（测试和
# release.sh 会拦住）。
.PHONY: static-gz
static-gz:
	@for f in web/static/*.html; do \
		gzip -9 -n -c "$$f" > "$$f.gz" || exit 1; \
		echo "  $$f.gz"; \
	done
