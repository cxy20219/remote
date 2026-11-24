package common

import "goremote/internal/buildinfo"

// BuildVersion 返回可读的构建标识，供审计日志、备份 manifest 与握手使用。
//
// 唯一的真相在 internal/buildinfo：发布号由 -X 注入，commit 来自 build info 的
// vcs.revision。这里只做转发，避免出现「审计日志说 v2.8.0、握手说 vcs:abc」
// 这种两套版本并存的情况。
func BuildVersion() string {
	return buildinfo.String()
}

// BuildCommit 返回 12 位短 commit（拿不到 VCS 信息时为 "dev"）。
func BuildCommit() string {
	return buildinfo.Commit()
}
