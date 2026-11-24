package common

import "runtime/debug"

// BuildVersion 返回可读的构建标识，供 /health 与启动日志使用。
//
// 取值优先级：git commit（短哈希，脏树带 .dirty）→ 模块版本 → "dev"。
// 不注入 ldflags 是刻意的：发布脚本的构建参数固定为 -trimpath -ldflags="-s -w"，
// 加 -X 会改变发布产物的构建方式，而 build info 里的 vcs.revision 本来就能唯一定位
// 源码。构建时拿不到 VCS 信息（例如在无 .git 的目录里 go build）就退回 "dev"。
func BuildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	revision := ""
	dirty := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if len(revision) > 7 {
		revision = revision[:7]
	}
	if revision != "" {
		if dirty {
			return "vcs:" + revision + ".dirty"
		}
		return "vcs:" + revision
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
