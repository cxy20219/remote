package common

import (
	"sort"
	"strings"
)

// 控制面能力位：握手时双方各自声明「我这个版本支持哪些可选特性」。
//
// 使用规则（长期有效）：
//   - JSON 消息保持封闭 schema、一律严格解码；
//   - 将来要加可选字段，必须由**接收方**在握手时声明对应 cap，发送方看到
//     对端声明后才带该字段。声明了 cap 的一定是新端，它的解码器认识这个
//     字段，严格解码就不会误伤老端；
//   - 未知 cap 一律忽略，不报错——老端不认识新 cap 本来就是常态。
const (
	// CapObservability 表示支持观察面相关可选字段。
	CapObservability = "obs"

	// MaxCaps / MaxCapLen 是握手参数的长度上限：能力位是几个短标识，
	// 不是一个可以塞东西的地方。
	MaxCaps   = 16
	MaxCapLen = 24
)

// ParseCaps 解析逗号分隔的能力位。非法项（超长、含非法字符、超量）直接丢弃，
// 不报错：握手参数来自对端，解析失败不该阻断连接。
func ParseCaps(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]struct{}, MaxCaps)
	caps := make([]string, 0, MaxCaps)
	for _, item := range strings.Split(raw, ",") {
		if len(caps) >= MaxCaps {
			break
		}
		name := strings.TrimSpace(item)
		if !validCap(name) {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		caps = append(caps, name)
	}
	if len(caps) == 0 {
		return nil
	}
	sort.Strings(caps)
	return caps
}

// FormatCaps 把能力位拼成握手参数；空列表返回空串（此时不发送该参数）。
func FormatCaps(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	unique := make([]string, 0, len(caps))
	seen := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		if !validCap(cap) {
			continue
		}
		if _, duplicate := seen[cap]; duplicate {
			continue
		}
		if len(unique) >= MaxCaps {
			break
		}
		seen[cap] = struct{}{}
		unique = append(unique, cap)
	}
	sort.Strings(unique)
	return strings.Join(unique, ",")
}

// validCap 只接受 [a-z0-9_]，长度 1..MaxCapLen。
func validCap(name string) bool {
	if len(name) == 0 || len(name) > MaxCapLen {
		return false
	}
	for index := 0; index < len(name); index++ {
		char := name[index]
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return false
	}
	return true
}
