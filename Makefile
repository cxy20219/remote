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
