// Package buildinfo 是二进制版本信息的唯一来源。
//
// 发布号只能通过构建参数注入（见 scripts/ldflags.sh）：
//
//	-ldflags "-s -w -X goremote/internal/buildinfo.Version=v2.8.0"
//
// ldflags 字符串只允许在 scripts/ldflags.sh 里出现一次：本地构建、CI、release
// 三处只要有一处写岔，同一份源码就会产出不同哈希的二进制，发布记录立刻失效。
package buildinfo

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Version 是注入的发布版本号（形如 v2.8.0）。未注入时为空。
var Version = ""

const (
	// Unknown 是清洗后仍不可用的版本标记。协议上它就是「不知道」，不是「很旧」。
	Unknown = "unknown"
	// MaxVersionLen 与握手协议一致：超过 32 字符的版本串不是版本号。
	MaxVersionLen = 32

	defaultVersion = "dev"
)

// String 返回本次构建的版本号；未注入时回落 "dev"。
//
// "dev" 是有意义的：任何按版本比较的逻辑（例如判断 agent 是否落后）都必须
// 把 dev/unknown 当作「无法比较」，而不是当作 0.0.0。
func String() string {
	if sanitized := Sanitize(Version); sanitized != Unknown {
		return sanitized
	}
	return defaultVersion
}

// Commit 返回 12 位短 commit；脏树追加 "+dirty"，拿不到 VCS 信息回落 "dev"。
//
// commit 不靠注入：-trimpath 与 -s -w 都保留 build info 里的 vcs.revision，
// 从那里读就不会出现「构建脚本忘了传 commit」这种断链。
func Commit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return defaultVersion
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
	if revision == "" {
		return defaultVersion
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if dirty {
		return revision + "+dirty"
	}
	return revision
}

// Sanitize 把任意字符串清洗成可传输、可展示的版本串：
// 只保留 [0-9A-Za-z.+-]，最长 32 字符；清洗后为空则返回 Unknown。
//
// 版本串来自对端，属于不可信输入。它只用于展示与比较，不参与任何门控，
// 但仍然要在入库/下发之前清洗——否则一个 200 字符带控制字符的「版本」
// 会一路流进日志、面板和 state 文件。
func Sanitize(raw string) string {
	var builder strings.Builder
	for _, char := range strings.TrimSpace(raw) {
		if builder.Len() >= MaxVersionLen {
			break
		}
		switch {
		case char >= '0' && char <= '9',
			char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char == '.', char == '+', char == '-':
			builder.WriteRune(char)
		}
	}
	if builder.Len() == 0 {
		return Unknown
	}
	return builder.String()
}

// Parse 把版本串拆成 X.Y.Z 三元组。
//
// 规则（写死在这里，避免每处各有一套）：
//   - 允许一个前导 'v'；
//   - 预发布/构建后缀（'-rc1'、'+dirty'）在第一个 '-' 或 '+' 处截断，不参与排序；
//   - 必须正好三段且非负整数，否则判为不可比较。
func Parse(raw string) ([3]int, bool) {
	var version [3]int
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "v")
	if index := strings.IndexAny(trimmed, "-+"); index >= 0 {
		trimmed = trimmed[:index]
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return version, false
	}
	for index, part := range parts {
		var value int
		if _, err := fmt.Sscanf(part, "%d", &value); err != nil {
			return version, false
		}
		// %d 会接受 "2abc" 的前缀，这里要求整段都是数字。
		if itoa(value) != part {
			return version, false
		}
		version[index] = value
	}
	return version, true
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	digits := make([]byte, 0, 6)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
