package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// 管理员两步验证（TOTP，RFC 6238）。
//
// 口径（冻结）：HMAC-SHA1、6 位、30 秒步长、接受 ±1 个时间窗；
// 密钥 20 字节随机数，Base32（无 padding）展示；同一时间步的码不可重放；
// 恢复码 10 个、12 位、一次性（存 SHA-256）。
//
// 这里只放算法与二维码，不碰会话/限流；会话与失败计数在 admin_auth.go。

const (
	totpIssuer  = "GoRemote"
	totpAccount = "admin"

	totpSecretBytes    = 20
	totpDigits         = 6
	totpPeriod         = 30 * time.Second
	totpSkewSteps      = 1
	totpChallengeTTL   = 5 * time.Minute
	totpChallengeTries = 3
	totpSetupTTL       = 10 * time.Minute

	recoveryCodeCount = 10
	recoveryCodeLen   = 12
	// 去掉易混淆的 0/O/1/I，剩 32 个字符：32^12 = 2^60。
	recoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

var (
	// ErrTOTPNotConfigured 表示管理员还没启用 TOTP。
	ErrTOTPNotConfigured = errors.New("totp is not configured")
	// ErrTOTPCorrupt 表示已启用但密钥无法解码或长度不对（state 被改坏、迁移失败等）。
	// 必须与「未启用」区分：Enabled() 仍为 true，认证 fail closed，
	// 但要显式暴露出来，否则会被误判成「码错了」或「没启用」。
	ErrTOTPCorrupt = errors.New("totp secret is corrupt")
	// ErrTOTPInvalidCode 表示动态码不正确（或格式不对）。
	ErrTOTPInvalidCode = errors.New("invalid totp code")
	// ErrTOTPReplay 表示该时间步的码已经被使用过（重放）。
	ErrTOTPReplay = errors.New("totp code replayed")
	// ErrTOTPChallengeInvalid 表示登录挑战不存在、已过期、IP 不匹配或尝试次数用尽。
	ErrTOTPChallengeInvalid = errors.New("invalid or expired totp challenge")
	// ErrTOTPSetupExpired 表示待激活的 setup 不存在或已过期。
	ErrTOTPSetupExpired = errors.New("totp setup is not pending or has expired")
	// ErrTOTPAlreadyEnabled 表示已经启用，不能重复启用。
	ErrTOTPAlreadyEnabled = errors.New("totp is already enabled")
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret 生成 20 字节随机密钥，返回 Base32（无 padding）文本。
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return totpBase32.EncodeToString(raw), nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if normalized == "" {
		return nil, ErrTOTPNotConfigured
	}
	key, err := totpBase32.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("decode totp secret: %w", err)
	}
	if len(key) != totpSecretBytes {
		return nil, fmt.Errorf("totp secret must be %d bytes, got %d", totpSecretBytes, len(key))
	}
	return key, nil
}

// normalizeTOTPCode 去掉用户输入里的空格和连字符。
func normalizeTOTPCode(code string) string {
	replacer := strings.NewReplacer(" ", "", "-", "", "\t", "")
	return strings.ToUpper(strings.TrimSpace(replacer.Replace(code)))
}

// hotp 是 RFC 4226 的 HOTP 截断，digits 位十进制。
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// totpStep 返回时刻所属的 30 秒时间步。
func totpStep(t time.Time) int64 {
	return t.Unix() / int64(totpPeriod/time.Second)
}

// TOTPCodeAt 计算某时刻的动态码（供测试与排障使用，导出便于 E2E 脚本引用）。
func TOTPCodeAt(secret string, at time.Time) (string, int64, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", 0, err
	}
	step := totpStep(at)
	return hotp(key, uint64(step), totpDigits), step, nil
}

// verifyTOTP 校验动态码，返回命中的时间步。
//
// 接受 step-1/step/step+1 三个窗口；命中但 step <= lastStep 时返回 ErrTOTPReplay，
// 由调用方决定是否更新 lastStep（申领成功才更新）。
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		// 只有完全空串才表示「未启用」；只有空白字符的密钥在 Enabled() 里算已启用，
		// 此时必须报损坏，不能谎称未启用。
		if secret == "" {
			return 0, ErrTOTPNotConfigured
		}
		// 只在这里把「密钥坏了」翻译成独立错误；细节进日志，不回显给客户端。
		return 0, fmt.Errorf("%w: %v", ErrTOTPCorrupt, err)
	}
	code = normalizeTOTPCode(code)
	if len(code) != totpDigits {
		return 0, ErrTOTPInvalidCode
	}

	current := totpStep(now)
	var matched int64 = -1
	for offset := -int64(totpSkewSteps); offset <= int64(totpSkewSteps); offset++ {
		step := current + offset
		if step < 0 {
			continue
		}
		want := hotp(key, uint64(step), totpDigits)
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			matched = step
			break
		}
	}
	if matched < 0 {
		return 0, ErrTOTPInvalidCode
	}
	if matched <= lastStep {
		return matched, ErrTOTPReplay
	}
	return matched, nil
}

// generateRecoveryCodes 生成一次性恢复码及其 SHA-256 哈希。
func generateRecoveryCodes(count int) (codes []string, hashes []string, err error) {
	codes = make([]string, 0, count)
	hashes = make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for len(codes) < count {
		raw := make([]byte, recoveryCodeLen)
		for i := range raw {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryCodeAlphabet))))
			if err != nil {
				return nil, nil, fmt.Errorf("generate recovery code: %w", err)
			}
			raw[i] = recoveryCodeAlphabet[n.Int64()]
		}
		code := string(raw)
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return codes, hashes, nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), " ", ""), "-", ""))
}

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// consumeRecoveryCode 用恢复码匹配哈希表；命中则返回移除后的剩余哈希。
// 始终遍历全部条目，避免用提前返回泄漏命中位置。
func consumeRecoveryCode(hashes []string, code string) (remaining []string, matched bool) {
	code = normalizeRecoveryCode(code)
	if code == "" {
		return hashes, false
	}
	target := []byte(hashRecoveryCode(code))
	idx := -1
	for i, hash := range hashes {
		if subtle.ConstantTimeCompare([]byte(hash), target) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return hashes, false
	}
	remaining = make([]string, 0, len(hashes)-1)
	remaining = append(remaining, hashes[:idx]...)
	remaining = append(remaining, hashes[idx+1:]...)
	return remaining, true
}

// provisioningURI 生成 otpauth:// 供验证器扫码/手抄。
func provisioningURI(secret string) string {
	label := url.PathEscape(totpIssuer + ":" + totpAccount)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", totpIssuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprintf("%d", totpDigits))
	params.Set("period", fmt.Sprintf("%d", int(totpPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + params.Encode()
}

// provisioningQR 把 otpauth URI 渲染成 PNG data URL，前端 <img src> 直接用。
func provisioningQR(uri string) (string, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("encode totp qr code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
