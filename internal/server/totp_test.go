package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// RFC 6238 附录 B 的官方 SHA-1 向量（8 位），本实现是 6 位，取后 6 位。
func TestTOTPRFC6238Vectors(t *testing.T) {
	t.Parallel()
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // ASCII "12345678901234567890" 的 Base32
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		got, step, err := TOTPCodeAt(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("TOTPCodeAt(%d): %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("T=%d: code = %s, want %s", tc.unix, got, tc.want)
		}
		if step != tc.unix/30 {
			t.Errorf("T=%d: step = %d, want %d", tc.unix, step, tc.unix/30)
		}
	}
}

func TestTOTPSecretFormat(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != totpSecretBytes {
		t.Fatalf("secret bytes = %d, want %d", len(key), totpSecretBytes)
	}
	if strings.Contains(secret, "=") {
		t.Fatal("base32 secret must not be padded")
	}
	other, _ := GenerateTOTPSecret()
	if secret == other {
		t.Fatal("secrets must be random")
	}
}

func TestTOTPVerifyWindowAndReplay(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	current := totpStep(now)

	code, step, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if step != current {
		t.Fatalf("step = %d, want %d", step, current)
	}

	// 当前窗
	got, err := verifyTOTP(secret, code, now, 0)
	if err != nil || got != current {
		t.Fatalf("current window verify: step=%d err=%v", got, err)
	}
	// 重放
	if _, err := verifyTOTP(secret, code, now, current); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("replay should be rejected, got %v", err)
	}
	// 上一步码：lastStep 已到 current 时应视为重放
	prevCode, _, err := TOTPCodeAt(secret, now.Add(-totpPeriod))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTOTP(secret, prevCode, now, current); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("previous window with lastStep=current should be replay, got %v", err)
	}
	if _, err := verifyTOTP(secret, prevCode, now, current-2); err != nil {
		t.Fatalf("previous window should be accepted when lastStep is older: %v", err)
	}
	// ±1 之外拒绝
	farCode, _, err := TOTPCodeAt(secret, now.Add(2*totpPeriod))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTOTP(secret, farCode, now, 0); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("step+2 should be rejected, got %v", err)
	}
	// 错误码
	if _, err := verifyTOTP(secret, wrongTOTPCode(t, secret, now), now, 0); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("wrong code should be rejected, got %v", err)
	}
	// 用户输入带空格/连字符也应接受
	spaced := code[:3] + " " + code[3:]
	if _, err := verifyTOTP(secret, spaced, now, 0); err != nil {
		t.Fatalf("spaced code should be accepted: %v", err)
	}
}

func wrongTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, _, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%06d", (n+1)%1000000)
}

func TestRecoveryCodesOnceOnly(t *testing.T) {
	t.Parallel()
	codes, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("codes=%d hashes=%d", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != recoveryCodeLen {
			t.Fatalf("code length = %d, want %d", len(code), recoveryCodeLen)
		}
		if seen[code] {
			t.Fatal("recovery codes must be unique")
		}
		seen[code] = true
	}

	remaining, ok := consumeRecoveryCode(hashes, codes[0])
	if !ok || len(remaining) != recoveryCodeCount-1 {
		t.Fatalf("first use should succeed, remaining=%d ok=%v", len(remaining), ok)
	}
	if _, reused := consumeRecoveryCode(remaining, codes[0]); reused {
		t.Fatal("recovery code must be single-use")
	}
	// 大小写/空格不敏感
	if _, ok := consumeRecoveryCode(hashes, strings.ToLower(codes[1])); !ok {
		t.Fatal("recovery code should be case-insensitive")
	}
}

// newTOTPTestStore 返回带 state 加密密钥的内存 store（启用 TOTP 的前置条件）。
func newTOTPTestStore(t *testing.T) *StateStore {
	t.Helper()
	store := newTestStateStore(defaultSettings())
	if err := store.SetEncryptionKey("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if !store.EncryptionEnabled() {
		t.Fatal("test store should report encryption enabled")
	}
	return store
}

// enableTOTPForTest 打开 TOTP 并返回密钥与恢复码。
func enableTOTPForTest(t *testing.T, auth *AdminAuth, store *StateStore, session string) (string, []string) {
	t.Helper()
	secret, uri, qr, err := auth.StartTOTPSetup(session)
	if err != nil {
		t.Fatalf("StartTOTPSetup: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("uri = %s", uri)
	}
	if !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("qr data url prefix = %.40s", qr)
	}
	code, _, err := TOTPCodeAt(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := auth.EnableTOTP(session, code)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if !auth.TOTPEnabled() {
		t.Fatal("TOTP should be enabled")
	}
	if cfg := store.TOTPConfig(); len(cfg.RecoveryHashes) != recoveryCodeCount {
		t.Fatalf("recovery hashes = %d", len(cfg.RecoveryHashes))
	}
	return secret, codes
}

func TestAdminAuthTOTPLoginFlow(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.10"
	// 密码通过 → 需要动态码
	if err := auth.CheckPassword(ip, "CorrectPassword1!"); err != nil {
		t.Fatalf("password check: %v", err)
	}
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	// 错误码被拒
	if err := auth.VerifyTOTPChallenge(ip, challenge, wrongTOTPCode(t, secret, time.Now())); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("wrong code should fail, got %v", err)
	}
	// 正确码（下一时间步，避开 lastStep）通过
	code, _, err := TOTPCodeAt(secret, time.Now().Add(totpPeriod))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, code); err != nil {
		t.Fatalf("valid code should pass: %v", err)
	}
	// 同一挑战不能复用
	if err := auth.VerifyTOTPChallenge(ip, challenge, code); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("challenge reuse should fail, got %v", err)
	}
	// 同一时间步的码不能重放
	next, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, next, code); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("replayed code should fail, got %v", err)
	}
}

func TestTOTPChallengeBoundToIP(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	challenge, err := auth.BeginTOTPChallenge("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ := TOTPCodeAt(secret, time.Now().Add(totpPeriod))
	if err := auth.VerifyTOTPChallenge("192.0.2.2", challenge, code); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("challenge must be bound to the issuing IP, got %v", err)
	}
	if err := auth.VerifyTOTPChallenge("192.0.2.1", challenge, code); err != nil {
		t.Fatalf("same IP should pass: %v", err)
	}
}

func TestTOTPChallengeExpiryAndAttempts(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	challenge, err := auth.BeginTOTPChallenge("192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.challenges[challenge].expiresAt = time.Now().Add(-time.Second)
	auth.mu.Unlock()
	if err := auth.VerifyTOTPChallenge("192.0.2.9", challenge, "123456"); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("expired challenge should be invalid, got %v", err)
	}

	challenge, err = auth.BeginTOTPChallenge("192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= totpChallengeTries; i++ {
		_ = auth.VerifyTOTPChallenge("192.0.2.9", challenge, "000000")
	}
	code, _, _ := TOTPCodeAt(secret, time.Now().Add(totpPeriod))
	if err := auth.VerifyTOTPChallenge("192.0.2.9", challenge, code); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("challenge should be burned after %d attempts, got %v", totpChallengeTries, err)
	}
}

// 密码正确也不清池：10 次错码后，即使密码步骤还能走，动态码步骤必须被锁。
func TestTOTPFailuresShareLoginLock(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	for i := 0; i < maxFailedAdminLogins; i++ {
		// 每轮都先「密码成功」并换一个 IP，验证它不会把失败池清零，
		// 也排除单 IP 锁先命中。
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		if err := auth.CheckPassword(ip, "CorrectPassword1!"); err != nil {
			t.Fatalf("attempt %d: password step: %v", i+1, err)
		}
		challenge, err := auth.BeginTOTPChallenge(ip)
		if err != nil {
			t.Fatalf("attempt %d: BeginTOTPChallenge: %v", i+1, err)
		}
		_ = auth.VerifyTOTPChallenge(ip, challenge, wrongTOTPCode(t, secret, time.Now()))
	}
	const freshIP = "198.51.100.200"
	if err := auth.CheckPassword(freshIP, "CorrectPassword1!"); err != nil {
		t.Fatalf("password step after failures: %v", err)
	}
	challenge, err := auth.BeginTOTPChallenge(freshIP)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(freshIP, challenge, wrongTOTPCode(t, secret, time.Now())); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("11th code attempt must be locked, got %v", err)
	}
}

func TestTOTPAccountLockBlocksOtherIPs(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	for i := 0; i < maxFailedAdminLogins; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1) // 每轮换 IP，只有账户级计数能拦住
		if err := auth.CheckPassword(ip, "CorrectPassword1!"); err != nil {
			t.Fatalf("password step %d should stay open: %v", i+1, err)
		}
		challenge, err := auth.BeginTOTPChallenge(ip)
		if err != nil {
			t.Fatalf("attempt %d: BeginTOTPChallenge: %v", i+1, err)
		}
		_ = auth.VerifyTOTPChallenge(ip, challenge, wrongTOTPCode(t, secret, time.Now()))
	}

	// 密码步骤不受账户锁影响：否则管理员连恢复码登录这条路都走不到。
	const freshIP = "203.0.113.250"
	if err := auth.CheckPassword(freshIP, "CorrectPassword1!"); err != nil {
		t.Fatalf("password step must ignore account-level backoff, got %v", err)
	}
	// 动态码在全新 IP 上也被账户级退避挡住。
	challenge, err := auth.BeginTOTPChallenge(freshIP)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(freshIP, challenge, wrongTOTPCode(t, secret, time.Now())); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("cross-IP dynamic-code lock should apply, got %v", err)
	}
}

// mustCode 返回偏移 offset 处的动态码（测试辅助）。
func mustCode(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()
	code, _, err := TOTPCodeAt(secret, time.Now().Add(offset))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// 同一个 challenge 三并发，只能有一个成功。
func TestTOTPConcurrentChallengeSingleSuccess(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.70"
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	code := mustCode(t, secret, totpPeriod)

	var success int32
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if auth.VerifyTOTPChallenge(ip, challenge, code) == nil {
				atomic.AddInt32(&success, 1)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("concurrent same-challenge successes = %d, want 1", success)
	}
}

// 同一个码经两个 challenge 并发提交，只能有一个成功。
func TestTOTPConcurrentReplaySingleSuccess(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.71"
	challenges := make([]string, 2)
	for i := range challenges {
		c, err := auth.BeginTOTPChallenge(ip)
		if err != nil {
			t.Fatal(err)
		}
		challenges[i] = c
	}
	code := mustCode(t, secret, totpPeriod)

	var success int32
	var wg sync.WaitGroup
	for _, c := range challenges {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			if auth.VerifyTOTPChallenge(ip, token, code) == nil {
				atomic.AddInt32(&success, 1)
			}
		}(c)
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("concurrent same-code successes = %d, want 1", success)
	}
}

// 恢复码并发消费只能成功一次。
func TestTOTPConcurrentRecoveryCodeSingleUse(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	_, codes := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.72"
	challenges := make([]string, 2)
	for i := range challenges {
		c, err := auth.BeginTOTPChallenge(ip)
		if err != nil {
			t.Fatal(err)
		}
		challenges[i] = c
	}

	var success int32
	var wg sync.WaitGroup
	for _, c := range challenges {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			if auth.VerifyTOTPChallenge(ip, token, codes[0]) == nil {
				atomic.AddInt32(&success, 1)
			}
		}(c)
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("concurrent recovery-code successes = %d, want 1", success)
	}
	if cfg := store.TOTPConfig(); len(cfg.RecoveryHashes) != recoveryCodeCount-1 {
		t.Fatalf("recovery hashes left = %d, want %d", len(cfg.RecoveryHashes), recoveryCodeCount-1)
	}
}

// 改密码必须走失败池：连续错密码后正确密码也会被锁。
func TestChangePasswordUsesFailurePool(t *testing.T) {
	t.Parallel()
	store := newTestStateStore(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	const ip = "203.0.113.9"
	for i := 0; i < maxFailedAdminLogins; i++ {
		_ = auth.ChangePassword(ip, "wrong", "NewPassword1!")
	}
	if err := auth.ChangePassword(ip, "CorrectPassword1!", "NewPassword1!"); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("change password after threshold should be locked, got %v", err)
	}
}

// 管理写接口独立限流：第 3 次请求必须 429（限流 2 次/分钟）。
func TestAdminWriteRateLimitMiddleware(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	srv := &Server{stateStore: store, adminAuth: auth}
	r := gin.New()
	r.POST("/api/admin/totp/setup", AdminWriteRateLimitMiddleware(NewRateLimiter(2, time.Minute)), srv.handleAPITOTPSetup)

	do := func() (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/admin/totp/setup", strings.NewReader(`{"password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.90:1234"
		r.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("Retry-After")
	}
	if code, _ := do(); code == http.StatusTooManyRequests {
		t.Fatalf("first request should not be rate limited")
	}
	do()
	if code, retry := do(); code != http.StatusTooManyRequests || retry == "" {
		t.Fatalf("third request = %d retry-after=%q, want 429 with Retry-After", code, retry)
	}
}

// 路由级状态码：401（密码错）、409（未启用/未加密）、429（账户锁定）。
func TestTOTPWriteRouteStatusCodes(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	srv := &Server{stateStore: store, adminAuth: auth}

	r := gin.New()
	r.PUT("/api/admin/password", srv.handleAPIChangeAdminPassword)
	r.POST("/api/admin/totp/setup", srv.handleAPITOTPSetup)
	r.POST("/api/admin/totp/disable", srv.handleAPITOTPDisable)

	post := func(path, body, ip string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":1234"
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	// 401：setup 密码错
	if code := post("/api/admin/totp/setup", `{"password":"wrong"}`, "192.0.2.91"); code != http.StatusUnauthorized {
		t.Fatalf("setup wrong password = %d, want 401", code)
	}
	// 409：未启用时关闭
	if code := post("/api/admin/totp/disable", `{"password":"CorrectPassword1!","code":"123456"}`, "192.0.2.92"); code != http.StatusConflict {
		t.Fatalf("disable when disabled = %d, want 409", code)
	}

	// 429：连续错密码后，改密接口返回 429
	const ip = "192.0.2.93"
	for i := 0; i < maxFailedAdminLogins; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/admin/password",
			strings.NewReader(`{"current_password":"wrong","new_password":"NewPassword1!"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":1234"
		r.ServeHTTP(rec, req)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/admin/password",
		strings.NewReader(`{"current_password":"CorrectPassword1!","new_password":"NewPassword1!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked change-password = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
}

// 路由级并发：同一个 challenge 并发提交，只有 1 次 200。
func TestTOTPLoginRouteConcurrentOnlyOneSession(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)
	srv := &Server{stateStore: store, adminAuth: auth}
	r := gin.New()
	r.POST("/api/login/totp", srv.handleLoginTOTP)

	const ip = "192.0.2.94"
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	code := mustCode(t, secret, totpPeriod)

	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			body := fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, code)
			req := httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = ip + ":1234"
			r.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("concurrent challenge gave %d sessions, want 1", ok)
	}
}

// IPv6 限流键按 /64 聚合，IPv4 去掉端口。
func TestClientIPKeyAggregatesIPv6Slash64(t *testing.T) {
	t.Parallel()
	a := clientIPKey("2001:db8:1:2::1")
	b := clientIPKey("2001:db8:1:2::ffff")
	if a != b {
		t.Fatalf("same /64 should share key: %q vs %q", a, b)
	}
	if clientIPKey("2001:db8:1:2::1") == clientIPKey("2001:db8:9:9::1") {
		t.Fatal("different /64 must not share key")
	}
	if clientIPKey("192.0.2.5:1234") != "192.0.2.5" {
		t.Fatalf("IPv4 key = %q", clientIPKey("192.0.2.5:1234"))
	}
}

// 关闭两步验证必须同时要密码 + 当前动态码。
func TestTOTPDisableRequiresBothFactors(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.30"
	if err := auth.DisableTOTP(ip, session, "wrong", mustCode(t, secret, totpPeriod)); !errors.Is(err, ErrAdminInvalidPassword) {
		t.Fatalf("wrong password should fail, got %v", err)
	}
	if err := auth.DisableTOTP(ip, session, "CorrectPassword1!", wrongTOTPCode(t, secret, time.Now())); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("wrong code should fail, got %v", err)
	}
	if !auth.TOTPEnabled() {
		t.Fatal("failed attempts must not disable TOTP")
	}
	if err := auth.DisableTOTP(ip, session, "CorrectPassword1!", mustCode(t, secret, totpPeriod)); err != nil {
		t.Fatalf("disable with both factors: %v", err)
	}
	if auth.TOTPEnabled() {
		t.Fatal("TOTP should be disabled")
	}
	if cfg := store.TOTPConfig(); cfg.Secret != "" || len(cfg.RecoveryHashes) != 0 {
		t.Fatal("disable must clear both secret and recovery hashes")
	}
}

// 恢复码可以关闭两步验证；关闭后恢复码表清空。
func TestTOTPRecoveryCodeCanDisable(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	_, codes := enableTOTPForTest(t, auth, store, session)

	if err := auth.RecoverTOTP("192.0.2.31", session, "wrong", codes[0]); !errors.Is(err, ErrAdminInvalidPassword) {
		t.Fatalf("recover with wrong password = %v, want ErrAdminInvalidPassword", err)
	}
	// 恢复码失败仍会计入失败池（豁免的只是账户锁，不是失败计数）。
	if err := auth.RecoverTOTP("192.0.2.31", session, "CorrectPassword1!", "ZZZZZZZZZZZZ"); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("recover with wrong recovery code = %v, want ErrTOTPInvalidCode", err)
	}
	auth.mu.Lock()
	accountFailures := auth.accountFailures
	auth.mu.Unlock()
	if accountFailures != 1 {
		t.Fatalf("wrong recovery code must still count in the account pool, got %d", accountFailures)
	}
	if err := auth.RecoverTOTP("192.0.2.31", session, "CorrectPassword1!", codes[0]); err != nil {
		t.Fatalf("recover with recovery code: %v", err)
	}
	if auth.TOTPEnabled() {
		t.Fatal("recovery code should disable TOTP")
	}
	if cfg := store.TOTPConfig(); cfg.Secret != "" || len(cfg.RecoveryHashes) != 0 {
		t.Fatalf("recovery should clear config, got %+v", cfg)
	}
	// 已经关闭后再走一次恢复：按「未启用」拒绝，不能重复利用旧恢复码。
	if err := auth.RecoverTOTP("192.0.2.31", session, "CorrectPassword1!", codes[1]); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("recover after disable = %v, want ErrTOTPNotConfigured", err)
	}
}

// 启用 TOTP 会吊销其它会话、保留当前会话。
func TestTOTPEnableRevokesOtherSessions(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	current, _ := auth.GenerateToken()
	other, _ := auth.GenerateToken()

	secret, _, _, err := auth.StartTOTPSetup(current)
	if err != nil {
		t.Fatalf("StartTOTPSetup: %v", err)
	}
	if _, err := auth.EnableTOTP(current, mustCode(t, secret, 0)); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if !auth.Validate(current) {
		t.Fatal("current session should survive enable")
	}
	if auth.Validate(other) {
		t.Fatal("other sessions must be revoked on enable")
	}
}

// 恢复码可以完成两步登录；同一个恢复码不能用两次。
func TestTOTPRecoveryCodeLogin(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	_, codes := enableTOTPForTest(t, auth, store, session)

	const ip = "192.0.2.32"
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, codes[0]); err != nil {
		t.Fatalf("recovery code login: %v", err)
	}
	if cfg := store.TOTPConfig(); len(cfg.RecoveryHashes) != recoveryCodeCount-1 {
		t.Fatalf("recovery hashes left = %d", len(cfg.RecoveryHashes))
	}
	challenge, err = auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, codes[0]); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("used recovery code should be rejected, got %v", err)
	}
}

// 加密 state 里的 TOTP 配置能完整往返，且明文层不出现密钥。
func TestStateStoreTOTPRoundTripEncrypted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const key = "0123456789abcdef0123456789abcdef"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTOTPConfig(TOTPConfig{Secret: secret, RecoveryHashes: []string{"h1", "h2"}, LastStep: 42}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("TOTP secret leaked into the plaintext state file")
	}
	var raw ServerState
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.TOTPSecret != "" || len(raw.TOTPRecoveryHashes) != 0 {
		t.Fatalf("plaintext layer should be cleared: %+v", raw)
	}

	loaded := NewStateStore(path)
	if err := loaded.SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := loaded.TOTPConfig()
	if cfg.Secret != secret || cfg.LastStep != 42 || len(cfg.RecoveryHashes) != 2 {
		t.Fatalf("round trip mismatch: %+v", cfg)
	}
}

// 旧 state 没有 TOTP 字段时按「未启用」加载，不影响升级。
func TestStateStoreLegacyStateWithoutTOTP(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "server-state.json")
	legacy := `{"server_sign_privkey":"","server_sign_pubkey":"","admin_password_hash":"","settings":{},"devices":[]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("load legacy state: %v", err)
	}
	cfg := store.TOTPConfig()
	if cfg.Enabled() || cfg.Secret != "" || len(cfg.RecoveryHashes) != 0 || cfg.LastStep != 0 {
		t.Fatalf("legacy state should load as disabled: %+v", cfg)
	}
}

// 没配加密 key 时（升级前的状态）TOTP 明文落盘仍能加载——这就是启动 WARN 的降级路径。
func TestStateStoreTOTPPlaintextDowngrade(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "server-state.json")
	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTOTPConfig(TOTPConfig{Secret: secret, RecoveryHashes: []string{"h1"}, LastStep: 7}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), secret) {
		t.Fatal("without state encryption the secret is expected to be plaintext (0600)")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode = %#o, want 0600 (TOTP secret is plaintext here)", perm)
	}

	loaded := NewStateStore(path)
	if err := loaded.Load(); err != nil {
		t.Fatalf("load plaintext TOTP state: %v", err)
	}
	cfg := loaded.TOTPConfig()
	if cfg.Secret != secret || cfg.LastStep != 7 || len(cfg.RecoveryHashes) != 1 {
		t.Fatalf("plaintext round trip mismatch: %+v", cfg)
	}
}

// provisioning URI/二维码：URI 参数齐全，PNG data URL 可解码且是 PNG。
func TestProvisioningQRIsPNG(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	uri := provisioningURI(secret)
	for _, want := range []string{"otpauth://totp/", "secret=" + secret, "issuer=GoRemote", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
	qr, err := provisioningQR(uri)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(qr, prefix) {
		t.Fatalf("qr data url prefix = %.40s", qr)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(qr, prefix))
	if err != nil {
		t.Fatal(err)
	}
	pngMagic := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if len(raw) < len(pngMagic) || !bytes.Equal(raw[:len(pngMagic)], pngMagic) {
		t.Fatal("qr payload is not a PNG")
	}
}

// 完整两步登录路由：第一步只发挑战（不下发会话），第二步才发 cookie。
func TestHandleLoginTwoStep(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)
	srv := &Server{stateStore: store, adminAuth: auth}
	r := gin.New()
	r.POST("/api/login", srv.handleLogin)
	r.POST("/api/login/totp", srv.handleLoginTOTP)

	post := func(path, body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.33:1234"
		r.ServeHTTP(rec, req)
		var parsed map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
		return rec, parsed
	}

	rec, body := post("/api/login", `{"password":"CorrectPassword1!"}`)
	if rec.Code != http.StatusOK || body["status"] != "totp_required" {
		t.Fatalf("password step = %d %v, want totp_required", rec.Code, body)
	}
	challenge, _ := body["challenge"].(string)
	if challenge == "" {
		t.Fatal("challenge should be issued")
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "go_remote_token" && cookie.Value != "" {
			t.Fatal("session cookie must not be issued before the second factor")
		}
	}

	// 错动态码：401 + 明确错误，且绝不能下发会话。
	rec, body = post("/api/login/totp", fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, wrongTOTPCode(t, secret, time.Now())))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code = %d (%s), want 401", rec.Code, rec.Body.String())
	}
	if msg, _ := body["error"].(string); msg != "invalid totp code" {
		t.Fatalf("wrong code error = %q, want %q", msg, "invalid totp code")
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "go_remote_token" && cookie.Value != "" {
			t.Fatal("wrong code must not issue a session cookie")
		}
	}

	// 同一个挑战还有剩余尝试次数，用正确码继续完成第二步。
	rec, body = post("/api/login/totp", fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, mustCode(t, secret, totpPeriod)))
	if rec.Code != http.StatusOK {
		t.Fatalf("totp step = %d (%s)", rec.Code, rec.Body.String())
	}
	var token string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "go_remote_token" {
			token = cookie.Value
		}
	}
	if token == "" || !auth.Validate(token) {
		t.Fatal("second step should issue a valid session cookie")
	}
}

// Retry-After 要给出窗口剩余秒数，前端才能提示「N 秒后再试」。
func TestRateLimiterRetryAfter(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()
	if !rl.Allow("k") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("k") {
		t.Fatal("second request should be limited")
	}
	seconds := rl.RetryAfter("k")
	if seconds < 1 || seconds > 60 {
		t.Fatalf("retry-after = %d, want 1..60", seconds)
	}
	if got := rl.RetryAfter("other"); got != 0 {
		t.Fatalf("retry-after for unknown key = %d, want 0", got)
	}
}

// 账户级退避必须封顶 5 分钟（不是 1 小时），且静默 1 小时降级、24 小时清零。
func TestTOTPAccountLockCapAndDecay(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	for i := 0; i < maxFailedAdminLogins*8; i++ {
		_ = auth.RecordTOTPFailure(fmt.Sprintf("203.0.113.%d", i%200+1))
	}

	auth.mu.Lock()
	level := auth.accountLockLevel
	lockFor := time.Until(auth.accountLockUntil)
	auth.mu.Unlock()
	if level != adminAccountLockMaxLevel {
		t.Fatalf("account lock level = %d, want cap %d", level, adminAccountLockMaxLevel)
	}
	if lockFor > 5*time.Minute+2*time.Second {
		t.Fatalf("account lock must be capped at 5 minutes, got %v", lockFor)
	}

	// 静默 2 小时：降 2 级。
	auth.mu.Lock()
	auth.lastAccountFailureAt = time.Now().Add(-2 * time.Hour)
	auth.accountLockUntil = time.Now().Add(-time.Minute)
	auth.decayAccountLockLocked(time.Now())
	level = auth.accountLockLevel
	auth.mu.Unlock()
	if level != adminAccountLockMaxLevel-2 {
		t.Fatalf("after 2h idle level = %d, want %d", level, adminAccountLockMaxLevel-2)
	}

	// 静默 24 小时：全部清零，锁失效。
	auth.mu.Lock()
	auth.lastAccountFailureAt = time.Now().Add(-25 * time.Hour)
	auth.decayAccountLockLocked(time.Now())
	level = auth.accountLockLevel
	failures := auth.accountFailures
	auth.mu.Unlock()
	if level != 0 || failures != 0 {
		t.Fatalf("after 24h idle level=%d failures=%d, want 0/0", level, failures)
	}
	if auth.accountLocked(time.Now()) {
		t.Fatal("account lock should be gone after reset")
	}
}

// 账户锁只拦动态码，恢复码登录必须豁免（攻击者不能靠刷失败把管理员锁死）。
func TestTOTPRecoveryCodeExemptFromAccountLock(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, codes := enableTOTPForTest(t, auth, store, session)

	lockAccount := func() {
		for i := 0; i < maxFailedAdminLogins; i++ {
			_ = auth.RecordTOTPFailure("203.0.113.40")
		}
	}
	lockAccount()

	const ip = "198.51.100.40"
	if err := auth.CheckPassword(ip, "CorrectPassword1!"); err != nil {
		t.Fatalf("password step must stay open while account is locked: %v", err)
	}
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, codes[0]); err != nil {
		t.Fatalf("recovery code must bypass account lock: %v", err)
	}
	auth.mu.Lock()
	level, failures := auth.accountLockLevel, auth.accountFailures
	auth.mu.Unlock()
	if level != 0 || failures != 0 {
		t.Fatalf("full auth should clear account pool, got level=%d failures=%d", level, failures)
	}

	// 动态码仍然受锁约束。
	lockAccount()
	challenge, err = auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, mustCode(t, secret, totpPeriod)); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("dynamic code should be locked, got %v", err)
	}
}

// 恢复码关闭（RecoverTOTP）同样豁免账户锁，是锁定期唯一的自助出口。
func TestTOTPRecoverEndpointExemptFromAccountLock(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	_, codes := enableTOTPForTest(t, auth, store, session)
	for i := 0; i < maxFailedAdminLogins; i++ {
		_ = auth.RecordTOTPFailure("203.0.113.41")
	}
	if err := auth.RecoverTOTP("198.51.100.41", session, "CorrectPassword1!", codes[0]); err != nil {
		t.Fatalf("recover must bypass account lock: %v", err)
	}
	if auth.TOTPEnabled() {
		t.Fatal("recover should disable TOTP")
	}
}

// 代理配置解析失败必须终止启动（静默降级会让所有请求塌成一个 IP）。
func TestConfigureTrustedProxies(t *testing.T) {
	t.Parallel()
	if _, err := configureTrustedProxies(gin.New(), []string{"not-an-ip"}); err == nil {
		t.Fatal("invalid trusted proxies must abort startup")
	}
	got, err := configureTrustedProxies(gin.New(), []string{" 127.0.0.1 ", "10.1.2.3/8", "::1"})
	if err != nil {
		t.Fatalf("valid proxies rejected: %v", err)
	}
	want := []string{"127.0.0.1/32", "10.0.0.0/8", "::1/128"}
	if len(got) != len(want) {
		t.Fatalf("effective proxies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("effective proxies = %v, want %v", got, want)
		}
	}
	if got, err := configureTrustedProxies(gin.New(), nil); err != nil || got != nil {
		t.Fatalf("empty proxy list = %v, %v", got, err)
	}
}

// Server.Stop 必须停掉 adminWriteLimiter 的清理协程，否则每次启停都泄漏一个 goroutine。
func TestServerStopStopsAdminWriteLimiter(t *testing.T) {
	t.Parallel()
	srv := &Server{
		adminWriteLimiter: NewRateLimiter(1, time.Minute),
		loginLimiter:      NewRateLimiter(1, time.Minute),
		stopCh:            make(chan struct{}),
		stateStore:        newTestStateStore(defaultSettings()),
		clients:           NewClientManager(),
	}
	srv.Stop()
	select {
	case <-srv.adminWriteLimiter.stopCh:
	default:
		t.Fatal("adminWriteLimiter cleanup loop should be stopped by Server.Stop")
	}
	select {
	case <-srv.loginLimiter.stopCh:
	default:
		t.Fatal("loginLimiter cleanup loop should be stopped by Server.Stop")
	}
}

// 认证类 429 必须带 Retry-After：IP 锁与账户级退避都能给出剩余秒数。
func TestLockRetryAfter(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)

	for i := 0; i < maxFailedAdminLogins; i++ {
		_ = auth.Login("203.0.113.70", "wrong")
	}
	if secs := auth.LockRetryAfter("203.0.113.70"); secs < 1 || secs > 5*60 {
		t.Fatalf("IP lock retry-after = %d, want 1..300", secs)
	}
	if secs := auth.LockRetryAfter("203.0.113.71"); secs != 0 {
		t.Fatalf("unrelated IP retry-after = %d, want 0", secs)
	}

	for i := 0; i < maxFailedAdminLogins; i++ {
		_ = auth.RecordTOTPFailure("203.0.113.72")
	}
	if secs := auth.LockRetryAfter("198.51.100.72"); secs < 1 || secs > 30 {
		t.Fatalf("account backoff retry-after = %d, want 1..30", secs)
	}
}

// 登录路由的锁定 429 带 Retry-After，前端才能显示秒数。
func TestLoginRouteLockCarriesRetryAfter(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTestStateStore(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	srv := &Server{stateStore: store, adminAuth: auth}
	r := gin.New()
	r.POST("/api/login", srv.handleLogin)

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.34:1234"
		r.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < maxFailedAdminLogins; i++ {
		_ = post(`{"password":"wrong"}`)
	}
	rec := post(`{"password":"wrong"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("locked login 429 must carry Retry-After")
	}
}

// P2-1：密钥损坏必须是独立错误，不能被当成「未启用」或「动态码错误」。
func TestTOTPCorruptSecretIsReported(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	if err := store.SetTOTPConfig(TOTPConfig{Secret: "NOT-BASE32-!!", RecoveryHashes: []string{"h1"}}); err != nil {
		t.Fatal(err)
	}
	// 仍然算「已启用」：绝不能因为密钥坏了就静默放行。
	if !auth.TOTPEnabled() {
		t.Fatal("corrupt secret must still count as enabled (fail closed)")
	}
	if err := auth.TOTPSelfCheck(); !errors.Is(err, ErrTOTPCorrupt) {
		t.Fatalf("TOTPSelfCheck = %v, want ErrTOTPCorrupt", err)
	}
	if _, err := verifyTOTP("NOT-BASE32-!!", "123456", time.Now(), 0); !errors.Is(err, ErrTOTPCorrupt) {
		t.Fatalf("verifyTOTP(illegal base32) = %v, want ErrTOTPCorrupt", err)
	}
	// 能解码但长度不是 20 字节，同样是损坏。
	if _, err := verifyTOTP("MFRGGZDF", "123456", time.Now(), 0); !errors.Is(err, ErrTOTPCorrupt) {
		t.Fatalf("verifyTOTP(short key) = %v, want ErrTOTPCorrupt", err)
	}
	// 只有空白字符的密钥也算损坏（Enabled() 判定为启用，就不能当成未启用）。
	if _, err := verifyTOTP("   ", "123456", time.Now(), 0); !errors.Is(err, ErrTOTPCorrupt) {
		t.Fatalf("verifyTOTP(blank) = %v, want ErrTOTPCorrupt", err)
	}
	// 空密钥才是「未启用」。
	if _, err := verifyTOTP("", "123456", time.Now(), 0); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("verifyTOTP(empty) = %v, want ErrTOTPNotConfigured", err)
	}
	// 未启用时自检不算损坏。
	clean := NewAdminAuth(newTestStateStore(defaultSettings()))
	if err := clean.TOTPSelfCheck(); err != nil {
		t.Fatalf("self check on disabled store = %v, want nil", err)
	}
}

// 密钥损坏时：第一步照常发挑战并标 recovery_only；动态码第二步 500，
// 恢复码仍能完成登录（无会话 → 拿到会话的 break-glass 路径）。
func TestTOTPCorruptSecretLoginRoute(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	const recoveryCode = "ABCDEFGHJKLM"
	if err := store.SetTOTPConfig(TOTPConfig{
		Secret:         "CORRUPT",
		RecoveryHashes: []string{hashRecoveryCode(recoveryCode)},
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{stateStore: store, adminAuth: auth}
	r := gin.New()
	r.POST("/api/login", srv.handleLogin)
	r.POST("/api/login/totp", srv.handleLoginTOTP)
	r.GET("/api/check-auth", srv.handleCheckAuth)

	do := func(path, body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.96:1234"
		r.ServeHTTP(rec, req)
		var parsed map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
		return rec, parsed
	}
	login := func() (string, map[string]any) {
		rec, body := do("/api/login", `{"password":"CorrectPassword1!"}`)
		if rec.Code != http.StatusOK || body["status"] != "totp_required" {
			t.Fatalf("password step = %d %v, want totp_required", rec.Code, body)
		}
		challenge, _ := body["challenge"].(string)
		if challenge == "" {
			t.Fatal("corrupt secret must still issue a challenge (recovery code login)")
		}
		if body["recovery_only"] != true {
			t.Fatalf("corrupt secret should be flagged recovery_only, got %v", body)
		}
		return challenge, body
	}

	// 动态码配置坏了：第二步明确 500，而不是含糊的「动态码错误」。
	challenge, _ := login()
	rec, body := do("/api/login/totp", fmt.Sprintf(`{"challenge":%q,"code":"123456"}`, challenge))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("dynamic code with corrupt secret = %d (%s), want 500", rec.Code, rec.Body.String())
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "misconfigured") {
		t.Fatalf("500 body should say misconfigured, got %v", body)
	}

	// 恢复码必须还能登录：这是无会话时唯一能拿到会话的出口。
	challenge, _ = login()
	rec, body = do("/api/login/totp", fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, recoveryCode))
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery code login with corrupt secret = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var token string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "go_remote_token" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("recovery code login should issue a session cookie")
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/check-auth", nil)
	req.AddCookie(&http.Cookie{Name: "go_remote_token", Value: token})
	r.ServeHTTP(rec, req)
	var authBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &authBody)
	if authBody["authenticated"] != true {
		t.Fatalf("recovery-code session should authenticate, got %v", authBody)
	}
}

// 无 state 加密密钥时禁止启用 TOTP：密钥会明文落盘，2FA 等于归零。
func TestTOTPSetupRequiresStateEncryption(t *testing.T) {
	t.Parallel()
	store := newTestStateStore(defaultSettings()) // 故意不配加密 key
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	if _, _, _, err := auth.StartTOTPSetup(session); !errors.Is(err, ErrStateEncryptionKeyRequired) {
		t.Fatalf("setup without encryption = %v, want ErrStateEncryptionKeyRequired", err)
	}
	if _, err := auth.EnableTOTP(session, "123456"); !errors.Is(err, ErrStateEncryptionKeyRequired) {
		t.Fatalf("enable without encryption = %v, want ErrStateEncryptionKeyRequired", err)
	}
}

// 密钥损坏时恢复码关闭必须仍然可用：这是唯一的自助出口。
func TestTOTPRecoverWorksWhenSecretCorrupt(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatal(err)
	}
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	const recoveryCode = "ABCDEFGHJKLM"
	if err := store.SetTOTPConfig(TOTPConfig{
		Secret:         "CORRUPT",
		RecoveryHashes: []string{hashRecoveryCode(recoveryCode)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := auth.RecoverTOTP("192.0.2.97", session, "CorrectPassword1!", recoveryCode); err != nil {
		t.Fatalf("recover with corrupt secret should succeed, got %v", err)
	}
	if cfg := store.TOTPConfig(); cfg.Secret != "" || len(cfg.RecoveryHashes) != 0 {
		t.Fatalf("recover should disable totp, got secret=%q hashes=%d", cfg.Secret, len(cfg.RecoveryHashes))
	}
}

// P2-2：启用那一刻不能把接下来的登录窗口一起烧掉——启用后立即可用当前码登录。
func TestTOTPEnableKeepsNextWindowUsable(t *testing.T) {
	t.Parallel()
	store := newTOTPTestStore(t)
	auth := NewAdminAuth(store)
	session, _ := auth.GenerateToken()
	secret, _ := enableTOTPForTest(t, auth, store, session)

	cfg := store.TOTPConfig()
	code, step, err := TOTPCodeAt(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if step <= cfg.LastStep {
		t.Fatalf("lastStep=%d leaves no usable window (current step=%d)", cfg.LastStep, step)
	}

	const ip = "192.0.2.61"
	challenge, err := auth.BeginTOTPChallenge(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyTOTPChallenge(ip, challenge, code); err != nil {
		t.Fatalf("immediate login after enable should succeed, got %v", err)
	}
}
