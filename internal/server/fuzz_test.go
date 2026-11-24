package server

import (
	"crypto/sha256"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// FuzzVerifyTOTP 覆盖登录时唯一的手写协议解析：Base32 密钥、用户输入的动态码
// 归一化、时间窗口与重放判定。除「不 panic」外，用输入派生一个必然合法的密钥
// 钉住整套语义（与输入本身能否解析无关，所以每次迭代都能走到有效分支）：
//
//   - 当前时间步的码必须被接受，且返回命中的时间步；
//   - 同一个码以「已用过」的 lastStep 再校验必须判 replay；
//   - step±totpSkewSteps 必须接受，再往外一步必须拒绝。
func FuzzVerifyTOTP(f *testing.F) {
	f.Add("", "")
	f.Add("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "123456")
	f.Add("jbswy3dp ehpk3pxp", " 123 - 456 ")
	f.Add("JBSWY3DPEHPK3PXP", "000000")

	now := time.Unix(1_700_000_000, 0)

	f.Fuzz(func(t *testing.T, secret, code string) {
		// 1) 任意输入都只能是分类过的错误，绝不 panic、不泄露内部形态。
		if _, err := verifyTOTP(secret, code, now, 0); err != nil {
			switch {
			case errors.Is(err, ErrTOTPNotConfigured),
				errors.Is(err, ErrTOTPInvalidCode),
				errors.Is(err, ErrTOTPCorrupt),
				errors.Is(err, ErrTOTPReplay):
			default:
				t.Fatalf("verifyTOTP returned an unclassified error: %v", err)
			}
		}

		// 2) 派生一个必然合法的密钥，检查窗口与重放语义。
		sum := sha256.Sum256([]byte(secret + "\x00" + code))
		valid := totpBase32.EncodeToString(sum[:totpSecretBytes])

		want, step, err := TOTPCodeAt(valid, now)
		if err != nil {
			t.Fatalf("TOTPCodeAt rejected a well-formed secret: %v", err)
		}
		key, err := decodeTOTPSecret(valid)
		if err != nil {
			t.Fatalf("decodeTOTPSecret rejected a well-formed secret: %v", err)
		}
		// 6 位码只有 1e-6 的碰撞概率，但 verifyTOTP 从 step-1 开始扫：窗口内
		// 相邻步的码撞上当前码时，返回的命中步是前者（不是 step）。fuzz 每秒
		// 几万次迭代，按「必须命中 step」断言迟早会假红。所以先算出窗口内的
		// 三个码，再断言可证明的性质：命中落在窗口内、且命中步的码就是提交的码。
		inWindow := make(map[string]int64, 2*totpSkewSteps+1)
		for offset := -int64(totpSkewSteps); offset <= int64(totpSkewSteps); offset++ {
			if step+offset < 0 {
				continue
			}
			inWindow[hotp(key, uint64(step+offset), totpDigits)] = step + offset
		}

		got, err := verifyTOTP(valid, want, now, -1)
		if err != nil {
			t.Fatalf("verifyTOTP rejected the current code: %v", err)
		}
		if diff := got - step; diff < -totpSkewSteps || diff > totpSkewSteps {
			t.Fatalf("verifyTOTP matched step %d, outside the window around %d", got, step)
		}
		if matched := hotp(key, uint64(got), totpDigits); matched != want {
			t.Fatalf("verifyTOTP matched step %d whose code %q is not the submitted code %q", got, matched, want)
		}
		if _, err := verifyTOTP(valid, want, now, got); !errors.Is(err, ErrTOTPReplay) {
			t.Fatalf("verifyTOTP accepted a replayed code, err = %v", err)
		}

		for _, offset := range []int64{-totpSkewSteps, totpSkewSteps} {
			if step+offset < 0 {
				continue
			}
			neighbor := hotp(key, uint64(step+offset), totpDigits)
			if _, err := verifyTOTP(valid, neighbor, now, -1); err != nil {
				t.Fatalf("verifyTOTP rejected the code at step%+d: %v", offset, err)
			}
		}
		for _, offset := range []int64{-totpSkewSteps - 1, totpSkewSteps + 1} {
			if step+offset < 0 {
				continue
			}
			outside := hotp(key, uint64(step+offset), totpDigits)
			if _, collides := inWindow[outside]; collides {
				// 外侧码与窗口内某个码相同：verifyTOTP 无从区分，跳过这条断言。
				continue
			}
			if _, err := verifyTOTP(valid, outside, now, -1); !errors.Is(err, ErrTOTPInvalidCode) {
				t.Fatalf("verifyTOTP accepted the code at step%+d, err = %v", offset, err)
			}
		}
	})
}

// fuzzEntries 把模糊输入切成若干条白名单条目；条数封顶避免单次迭代退化成
// O(条目数) 的慢用例。
func fuzzEntries(blob string) []string {
	entries := strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == ';' || r == ','
	})
	if len(entries) > 16 {
		entries = entries[:16]
	}
	return entries
}

// FuzzIPMatcher 覆盖白名单匹配器：条目可以是精确地址、CIDR，也可以是任何无法
// 解析的字符串（历史上这些会被原样放进精确表）。这里钉住匹配器的核心契约：
//
//   - 精确条目必须匹配自身，且其规范化形式也必须匹配（IPv6 大小写/压缩形式）；
//   - 合法 CIDR 条目必须匹配它自己的网络地址；
//   - nil 匹配器永远不匹配，任意查询串都不会让它 panic。
func FuzzIPMatcher(f *testing.F) {
	f.Add("127.0.0.1\n10.0.0.0/8\n::1")
	f.Add("")
	f.Add("not-an-ip")
	f.Add("192.168.1.1;2001:db8::/32,::ffff:10.0.0.1")

	f.Fuzz(func(t *testing.T, blob string) {
		entries := fuzzEntries(blob)
		matcher := newIPMatcher(entries)

		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if strings.Contains(entry, "/") {
				if _, ipnet, err := net.ParseCIDR(entry); err == nil {
					if !matcher.Match(ipnet.IP.String()) {
						t.Fatalf("CIDR entry %q does not match its own network address %q", entry, ipnet.IP)
					}
				}
				continue
			}
			if !matcher.Match(entry) {
				t.Fatalf("exact entry %q does not match itself", entry)
			}
			if ip := net.ParseIP(entry); ip != nil && !matcher.Match(ip.String()) {
				t.Fatalf("exact entry %q does not match its normalized form %q", entry, ip)
			}
		}

		var nilMatcher *ipMatcher
		if nilMatcher.Match(blob) {
			t.Fatal("nil matcher matched an address")
		}
	})
}
