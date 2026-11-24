package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	setupLoopbackAddr = "127.0.0.1:47123"
	setupRemoteAddr   = "203.0.113.9:47123"
	setupStrongPwd    = "CorrectPassword1!"
)

func newSetupTestStore(t *testing.T) *StateStore {
	t.Helper()
	store := NewStateStore(filepath.Join(t.TempDir(), "server-state.json"))
	if err := store.Load(); err != nil {
		t.Fatalf("load state: %v", err)
	}
	return store
}

func newSetupTestServerWithStore(t *testing.T, store *StateStore) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	srv := &Server{
		stateStore:        store,
		adminAuth:         NewAdminAuth(store),
		setupMgr:          NewSetupManager(store),
		setupLimiter:      NewRateLimiter(setupRateLimit, setupRateWindow),
		adminWriteLimiter: NewRateLimiter(adminWriteLimit, adminWriteWindow),
	}
	t.Cleanup(func() {
		srv.setupLimiter.Stop()
		srv.adminWriteLimiter.Stop()
	})

	r := gin.New()
	r.Use(SetupGateMiddleware(srv.setupMgr))
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "index") })
	r.GET("/login.html", func(c *gin.Context) { c.String(http.StatusOK, "login") })
	r.GET("/setup.html", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.String(http.StatusOK, "setup")
	})
	r.GET("/static/app.js", func(c *gin.Context) { c.String(http.StatusOK, "js") })
	r.GET("/ws", func(c *gin.Context) { c.String(http.StatusOK, "ws") })
	r.GET("/api/setup/status", srv.handleSetupStatus)
	r.POST("/api/setup/password", SetupRateLimitMiddleware(srv.setupLimiter), srv.handleSetupPassword)
	r.POST("/api/setup/totp/start", AdminWriteRateLimitMiddleware(srv.adminWriteLimiter), srv.handleSetupTOTPStart)
	r.POST("/api/setup/totp/enable", AdminWriteRateLimitMiddleware(srv.adminWriteLimiter), srv.handleSetupTOTPEnable)
	r.POST("/api/setup/totp/skip", AdminWriteRateLimitMiddleware(srv.adminWriteLimiter), srv.handleSetupTOTPSkip)
	r.POST("/api/login", srv.handleLogin)
	r.POST("/api/login/totp", srv.handleLoginTOTP)
	r.POST("/api/logout", srv.handleLogout)
	r.GET("/api/check-auth", srv.handleCheckAuth)
	r.GET("/api/clients", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return srv, r
}

func newSetupTestServer(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()
	return newSetupTestServerWithStore(t, newSetupTestStore(t))
}

func setupHTTP(r *gin.Engine, method, path, body, remoteAddr, token string, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set(setupTokenHeader, token)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "go_remote_token", Value: cookie})
	}
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func setupPost(r *gin.Engine, path, body, remoteAddr, token, cookie string) *httptest.ResponseRecorder {
	return setupHTTP(r, http.MethodPost, path, body, remoteAddr, token, cookie)
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return body
}

func sessionCookieValue(rec *httptest.ResponseRecorder) string {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "go_remote_token" && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

func TestInitNewDoesNotCreateAdminPassword(t *testing.T) {
	t.Parallel()
	store := newSetupTestStore(t)
	if store.AdminPasswordInitialized() {
		t.Fatal("fresh state must start uninitialized")
	}
	if store.VerifyAdminPassword(setupStrongPwd) {
		t.Fatal("fresh state must not accept any password")
	}
	if !NewSetupManager(store).NeedsSetup() {
		t.Fatal("fresh state must need setup")
	}
}

func TestSetInitialAdminPasswordAtomic(t *testing.T) {
	t.Parallel()
	store := newSetupTestStore(t)
	ok, err := store.SetInitialAdminPassword(setupStrongPwd)
	if err != nil || !ok {
		t.Fatalf("first set = %v, %v; want true, nil", ok, err)
	}
	if ok, err := store.SetInitialAdminPassword("AnotherPassword2!"); err != nil || ok {
		t.Fatalf("second set = %v, %v; want false, nil", ok, err)
	}
	if !store.VerifyAdminPassword(setupStrongPwd) {
		t.Fatal("initial password should be stored")
	}
	if store.VerifyAdminPassword("AnotherPassword2!") {
		t.Fatal("second password must not overwrite the first")
	}
}

// 写盘失败必须回滚内存：否则进程内已初始化、磁盘仍是空 state，重启后回到向导。
func TestSetInitialAdminPasswordRollsBackOnSaveFailure(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	store := NewStateStore(filepath.Join(dir, "server-state.json"))
	if err := store.Load(); err != nil {
		t.Fatalf("load state: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	ok, err := store.SetInitialAdminPassword(setupStrongPwd)
	if err == nil || !ok {
		t.Fatalf("save failure = %v, %v; want true, error", ok, err)
	}
	if store.AdminPasswordInitialized() {
		t.Fatal("failed save must roll back the in-memory password hash")
	}
	if store.VerifyAdminPassword(setupStrongPwd) {
		t.Fatal("failed save must not leave a usable password")
	}

	// 恢复写权限后可重试成功（等价于磁盘故障排除后重试；重启同样回到未初始化）。
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ok, err = store.SetInitialAdminPassword(setupStrongPwd)
	if err != nil || !ok {
		t.Fatalf("retry after save failure = %v, %v; want true, nil", ok, err)
	}
	if !store.VerifyAdminPassword(setupStrongPwd) {
		t.Fatal("retried password should be stored")
	}
}

func TestSetupStatusGateAndRedirects(t *testing.T) {
	t.Parallel()
	_, r := newSetupTestServer(t)

	rec := setupHTTP(r, http.MethodGet, "/api/setup/status", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("status Cache-Control = %q", got)
	}
	body := decodeJSON(t, rec)
	if body["needs_setup"] != true || body["loopback"] != false {
		t.Fatalf("status body = %v", body)
	}

	for _, path := range []string{"/", "/login.html"} {
		rec = setupHTTP(r, http.MethodGet, path, "", setupRemoteAddr, "", "")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/setup.html" {
			t.Fatalf("%s = %d location=%q", path, rec.Code, rec.Header().Get("Location"))
		}
	}

	rec = setupHTTP(r, http.MethodGet, "/api/clients", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusConflict || decodeJSON(t, rec)["error"] != "setup required" {
		t.Fatalf("uninitialized API = %d %s", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/health", "/static/app.js", "/setup.html"} {
		rec = setupHTTP(r, http.MethodGet, path, "", setupRemoteAddr, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s should stay reachable, got %d", path, rec.Code)
		}
	}

	// 未初始化时 /ws 必须拒绝注册：否则匿名客户端可以占满 pending 设备表。
	rec = setupHTTP(r, http.MethodGet, "/ws", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ws before setup = %d, want 503", rec.Code)
	}

	rec = setupHTTP(r, http.MethodGet, "/api/setup/status", "", setupLoopbackAddr, "", "")
	if decodeJSON(t, rec)["loopback"] != true {
		t.Fatalf("loopback status body = %s", rec.Body.String())
	}
}

func TestSetupRejectsNonLoopbackWithoutToken(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-token setup = %d, want 403", rec.Code)
	}
	if sessionCookieValue(rec) != "" {
		t.Fatal("403 must not issue a session")
	}
	if srv.setupMgr.NeedsSetup() != true {
		t.Fatal("server must remain uninitialized")
	}
}

func TestSetupLoopbackRejectsProxiedExternalClient(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	// 模拟「反代与服务器同机」：RemoteAddr 是 loopback，但信任代理后 ClientIP 是外部地址。
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/setup/password", strings.NewReader(`{"password":"`+setupStrongPwd+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.RemoteAddr = setupLoopbackAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("proxied external client = %d, want 403", rec.Code)
	}
	if srv.setupMgr.NeedsSetup() != true {
		t.Fatal("server must remain uninitialized")
	}
}

// 本机反代但没配 --trusted-proxies 时，带转发头的请求不能算 loopback。
func TestSetupLoopbackRejectsUntrustedForwardedHeader(t *testing.T) {
	t.Parallel()
	_, r := newSetupTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/password", strings.NewReader(`{"password":"`+setupStrongPwd+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.60")
	req.RemoteAddr = setupLoopbackAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forwarded request without trusted proxies = %d, want 403", rec.Code)
	}
}

// 配了 --trusted-proxies 时 loopback 捷径必须整个关闭：
// 反代可能原样转发公网客户端的伪造头、不追加任何头、或因为信任列表配错而让
// gin 回落成 127.0.0.1——三种情况都无法与真本机直连区分，只能一律要求令牌。
func TestSetupLoopbackDisabledWhenTrustedProxiesConfigured(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	srv.config = &Config{}
	srv.config.Security.TrustedProxies = []string{"127.0.0.1"}
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		xff  string
		xri  string
	}{
		{name: "spoofed X-Forwarded-For loopback", xff: "127.0.0.1"},
		{name: "spoofed X-Real-IP loopback", xri: "127.0.0.1"},
		{name: "no forwarded headers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/setup/password",
				strings.NewReader(`{"password":"`+setupStrongPwd+`"}`))
			req.Header.Set("Content-Type", "application/json")
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xri != "" {
				req.Header.Set("X-Real-IP", tc.xri)
			}
			req.RemoteAddr = setupLoopbackAddr
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("setup with trusted proxies = %d %s, want 403", rec.Code, rec.Body.String())
			}
			if sessionCookieValue(rec) != "" {
				t.Fatal("403 must not issue a session")
			}
		})
	}

	// 状态接口必须如实报告 loopback=false，前端据此强制显示令牌输入框。
	rec := setupHTTP(r, http.MethodGet, "/api/setup/status", "", setupLoopbackAddr, "", "")
	if body := decodeJSON(t, rec); body["loopback"] != false {
		t.Fatalf("loopback status with trusted proxies = %v, want false", body)
	}
	if !srv.setupMgr.NeedsSetup() {
		t.Fatal("rejected requests must not initialize the server")
	}

	// 令牌路径仍然可用。
	rec = setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`,
		setupLoopbackAddr, srv.setupMgr.Token(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("token setup with trusted proxies = %d %s", rec.Code, rec.Body.String())
	}
	if sessionCookieValue(rec) == "" {
		t.Fatal("token setup should issue a session")
	}
}

func TestSetupLoopbackAllowsInitialization(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	oldToken := srv.setupMgr.Token()
	if len(oldToken) != setupTokenLength {
		t.Fatalf("token length = %d, want %d", len(oldToken), setupTokenLength)
	}

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback setup = %d %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieValue(rec)
	if cookie == "" || !srv.adminAuth.Validate(cookie) {
		t.Fatal("setup should auto-login with a valid session")
	}
	if srv.setupMgr.NeedsSetup() {
		t.Fatal("setup should be complete")
	}
	if !srv.stateStore.AdminPasswordInitialized() {
		t.Fatal("password should be persisted")
	}
	if srv.setupMgr.Token() != "" {
		t.Fatal("setup token must be burned after success")
	}

	// 初始化完成后：再带正确令牌（旧令牌）也必须 409。
	rec = setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, oldToken, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("setup after init = %d, want 409", rec.Code)
	}

	// 向导页在初始化完成后重定向回首页。
	rec = setupHTTP(r, http.MethodGet, "/setup.html", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup.html after init = %d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	// 正常登录路径不受影响。
	rec = setupPost(r, "/api/login", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK || sessionCookieValue(rec) == "" {
		t.Fatalf("login after setup = %d %s", rec.Code, rec.Body.String())
	}

	// 初始化完成后 /ws 恢复放行。
	rec = setupHTTP(r, http.MethodGet, "/ws", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/ws after setup = %d, want 200", rec.Code)
	}
}

func TestSetupTokenWrongAttemptsBurn(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	token := srv.setupMgr.Token()

	for i := 0; i < setupTokenMaxFailures; i++ {
		rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`,
			fmt.Sprintf("203.0.113.%d:47123", 10+i), "WRONG"+fmt.Sprint(i), "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d = %d, want 403", i+1, rec.Code)
		}
	}
	if srv.setupMgr.Token() != "" {
		t.Fatal("token should be burned after repeated failures")
	}
	if srv.setupMgr.NeedsSetup() != true {
		t.Fatal("failures must not initialize the server")
	}

	// 换一个 IP 避开请求限流，确认是「令牌烧毁」而不是「限流」。
	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`,
		"198.51.100.20:47123", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("burned token = %d, want 403", rec.Code)
	}
}

func TestSetupTokenExpired(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	token := srv.setupMgr.Token()
	srv.setupMgr.mu.Lock()
	srv.setupMgr.expiresAt = time.Now().Add(-time.Second)
	srv.setupMgr.mu.Unlock()

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expired token = %d, want 403", rec.Code)
	}
}

func TestSetupWeakPasswordRejected(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	rec := setupPost(r, "/api/setup/password", `{"password":"short"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("weak password = %d, want 400", rec.Code)
	}
	if !srv.setupMgr.NeedsSetup() {
		t.Fatal("weak password must not initialize the server")
	}
	rec = setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("strong password = %d", rec.Code)
	}
}

func TestSetupConcurrentSingleWinner(t *testing.T) {
	t.Parallel()
	store := newSetupTestStore(t)
	_, r := newSetupTestServerWithStore(t, store)

	passwords := []string{"CorrectPassword1!", "AnotherPassword2!"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []string
	for _, pwd := range passwords {
		wg.Add(1)
		go func(password string) {
			defer wg.Done()
			rec := setupPost(r, "/api/setup/password", `{"password":"`+password+`"}`, setupLoopbackAddr, "", "")
			if rec.Code == http.StatusOK {
				mu.Lock()
				winners = append(winners, password)
				mu.Unlock()
			} else if rec.Code != http.StatusConflict {
				t.Errorf("concurrent setup = %d %s", rec.Code, rec.Body.String())
			}
		}(pwd)
	}
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("concurrent winners = %v, want exactly 1", winners)
	}
	if !store.VerifyAdminPassword(winners[0]) {
		t.Fatalf("winner password %q should be stored", winners[0])
	}
	rec := setupPost(r, "/api/login", `{"password":"`+winners[0]+`"}`, setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login with winner = %d", rec.Code)
	}
}

func TestSetupWizardTOTPAndLogin(t *testing.T) {
	t.Parallel()
	store := NewStateStore(filepath.Join(t.TempDir(), "server-state.json"))
	if err := store.SetEncryptionKey("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	srv, r := newSetupTestServerWithStore(t, store)

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("setup password = %d %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieValue(rec)

	// 第一步之后 needs_setup 已经是 false，但向导窗口仍允许可选 TOTP 步骤。
	if body := decodeJSON(t, setupHTTP(r, http.MethodGet, "/api/setup/status", "", setupLoopbackAddr, "", "")); body["needs_setup"] != false {
		t.Fatalf("status after password = %v", body)
	}
	rec = setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("wizard totp start = %d %s", rec.Code, rec.Body.String())
	}
	startBody := decodeJSON(t, rec)
	secret, _ := startBody["secret"].(string)
	if secret == "" {
		t.Fatal("wizard should return a secret")
	}
	if qr, _ := startBody["qr_data_url"].(string); !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("wizard qr = %.40q", qr)
	}

	code := mustCode(t, secret, 0)
	rec = setupPost(r, "/api/setup/totp/enable", fmt.Sprintf(`{"code":%q}`, code), setupLoopbackAddr, "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("wizard totp enable = %d %s", rec.Code, rec.Body.String())
	}
	enableBody := decodeJSON(t, rec)
	rawCodes, _ := enableBody["recovery_codes"].([]any)
	if len(rawCodes) != recoveryCodeCount {
		t.Fatalf("recovery codes = %d, want %d", len(rawCodes), recoveryCodeCount)
	}
	recoveryCode, _ := rawCodes[0].(string)

	// 向导会话必须仍然有效（enable 只吊销其它会话）。
	if !srv.adminAuth.Validate(cookie) {
		t.Fatal("setup session must survive TOTP enable")
	}
	// 启用成功后向导窗口关闭，端点永久 409。
	rec = setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("wizard start after enable = %d, want 409", rec.Code)
	}

	// 密码 + 动态码登录。
	rec = setupPost(r, "/api/login", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("two-step login step1 = %d", rec.Code)
	}
	challenge, _ := decodeJSON(t, rec)["challenge"].(string)
	if challenge == "" {
		t.Fatal("expected a TOTP challenge")
	}
	rec = setupPost(r, "/api/login/totp",
		fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, mustCode(t, secret, totpPeriod)),
		setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK || sessionCookieValue(rec) == "" {
		t.Fatalf("two-step login step2 = %d %s", rec.Code, rec.Body.String())
	}

	// 恢复码登录。
	rec = setupPost(r, "/api/login", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, "", "")
	challenge, _ = decodeJSON(t, rec)["challenge"].(string)
	rec = setupPost(r, "/api/login/totp",
		fmt.Sprintf(`{"challenge":%q,"code":%q}`, challenge, recoveryCode),
		setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery login = %d %s", rec.Code, rec.Body.String())
	}
}

// 登出会吊销会话，向导窗口必须同步关闭：否则拿到过 Cookie 的人还能在 10 分钟窗口内
// 生成 TOTP secret，把管理员第二因子绑到自己验证器上。
func TestSetupWizardEndsOnLogout(t *testing.T) {
	t.Parallel()
	store := NewStateStore(filepath.Join(t.TempDir(), "server-state.json"))
	if err := store.SetEncryptionKey("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	srv, r := newSetupTestServerWithStore(t, store)

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("setup password = %d %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieValue(rec)
	if cookie == "" {
		t.Fatal("expected setup session")
	}
	// 登出前向导窗口可用。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("wizard start before logout = %d %s", rec.Code, rec.Body.String())
	}

	if rec := setupPost(r, "/api/logout", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	if srv.adminAuth.Validate(cookie) {
		t.Fatal("logout must invalidate the session")
	}
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusConflict {
		t.Fatalf("wizard start after logout = %d, want 409", rec.Code)
	}
}

func TestSetupWizardRequiresGrant(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)

	// 未设置密码：没有向导会话，TOTP 端点 409。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", ""); rec.Code != http.StatusConflict {
		t.Fatalf("wizard start before setup = %d, want 409", rec.Code)
	}

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	cookie := sessionCookieValue(rec)
	if cookie == "" {
		t.Fatal("expected setup session")
	}

	// 换一个非向导会话：拒绝。
	otherSession, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", otherSession); rec.Code != http.StatusConflict {
		t.Fatalf("foreign session = %d, want 409", rec.Code)
	}
	// 换 IP：拒绝。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupRemoteAddr, "", cookie); rec.Code != http.StatusConflict {
		t.Fatalf("other IP = %d, want 409", rec.Code)
	}
	// 向导超时：拒绝。
	srv.setupMgr.mu.Lock()
	srv.setupMgr.wizardExpiresAt = time.Now().Add(-time.Second)
	srv.setupMgr.mu.Unlock()
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusConflict {
		t.Fatalf("expired wizard = %d, want 409", rec.Code)
	}

	// 重新开始向导并跳过：端点立即失效。
	rec = setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusConflict {
		// 已经初始化过，密码步骤 409，这是预期；直接重新打开向导窗口模拟跳过路径。
	}
	srv.setupMgr.BeginWizard(cookie, "127.0.0.1")
	if rec := setupPost(r, "/api/setup/totp/skip", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("wizard skip = %d %s", rec.Code, rec.Body.String())
	}
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusConflict {
		t.Fatalf("wizard start after skip = %d, want 409", rec.Code)
	}
}

func TestSetupLegacyStateUnaffected(t *testing.T) {
	t.Parallel()
	store := newSetupTestStore(t)
	if err := store.SetAdminPassword(setupStrongPwd); err != nil {
		t.Fatal(err)
	}
	srv, r := newSetupTestServerWithStore(t, store)
	if srv.setupMgr.NeedsSetup() {
		t.Fatal("legacy state with a password must not need setup")
	}
	if srv.setupMgr.Token() != "" {
		t.Fatal("initialized server must not generate a setup token")
	}
	if body := decodeJSON(t, setupHTTP(r, http.MethodGet, "/api/setup/status", "", setupRemoteAddr, "", "")); body["needs_setup"] != false {
		t.Fatalf("status = %v", body)
	}
	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("setup on initialized server = %d, want 409", rec.Code)
	}
	rec = setupHTTP(r, http.MethodGet, "/setup.html", "", setupRemoteAddr, "", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup.html on initialized server = %d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	rec = setupPost(r, "/api/login", `{"password":"`+setupStrongPwd+`"}`, setupRemoteAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login on legacy state = %d", rec.Code)
	}
}

// 初始化接口独立限流：同一 IP 第 11 次请求必须 429，并带 Retry-After。
func TestSetupRateLimited(t *testing.T) {
	t.Parallel()
	_, r := newSetupTestServer(t)
	const ip = "203.0.113.70:47123"
	for i := 0; i < setupRateLimit; i++ {
		rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, ip, "WRONG", "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should still pass the limiter", i+1)
		}
	}
	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, ip, "WRONG", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th setup request = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("setup 429 should carry Retry-After")
	}
}

// 令牌本身不是凭据：正确令牌 + 不达标密码只返回 400，不发会话，也不消耗令牌。
func TestSetupTokenAloneDoesNotIssueSession(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	token := srv.setupMgr.Token()
	rec := setupPost(r, "/api/setup/password", `{"password":"short"}`, setupRemoteAddr, token, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("weak password with valid token = %d, want 400", rec.Code)
	}
	if sessionCookieValue(rec) != "" {
		t.Fatal("setup token must not yield a session")
	}
	if !srv.setupMgr.NeedsSetup() || srv.setupMgr.Token() != token {
		t.Fatal("failed password must not consume the setup token")
	}
}

// IPv6 loopback 与 IPv4 一样免令牌。
func TestSetupLoopbackIPv6(t *testing.T) {
	t.Parallel()
	_, r := newSetupTestServer(t)
	rec := setupHTTP(r, http.MethodGet, "/api/setup/status", "", "[::1]:47123", "", "")
	body := decodeJSON(t, rec)
	if body["loopback"] != true {
		t.Fatalf("ipv6 loopback status = %v", body)
	}
	rec = setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, "[::1]:47123", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ipv6 loopback setup = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSetupResponsesNoStore(t *testing.T) {
	t.Parallel()
	srv, r := newSetupTestServer(t)
	cookieFreePaths := []string{"/api/setup/status", "/setup.html"}
	for _, path := range cookieFreePaths {
		rec := setupHTTP(r, http.MethodGet, path, "", setupRemoteAddr, "", "")
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q", path, got)
		}
	}

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("setup password Cache-Control = %q", got)
	}
	cookie := sessionCookieValue(rec)
	for name, body := range map[string]string{
		"/api/setup/totp/start":  "{}",
		"/api/setup/totp/enable": `{"code":"123456"}`,
		"/api/setup/totp/skip":   "{}",
	} {
		rec := setupPost(r, name, body, setupLoopbackAddr, "", cookie)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q", name, got)
		}
	}
	_ = srv
}

// 匿名请求不能销毁合法向导窗口：没带 Cookie 的 409 必须无副作用。
func TestSetupWizardSurvivesAnonymousRequest(t *testing.T) {
	t.Parallel()
	store := NewStateStore(filepath.Join(t.TempDir(), "server-state.json"))
	if err := store.SetEncryptionKey("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	_, r := newSetupTestServerWithStore(t, store)

	rec := setupPost(r, "/api/setup/password", `{"password":"`+setupStrongPwd+`"}`, setupLoopbackAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("setup password = %d %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieValue(rec)

	// 先确认向导窗口可用。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("wizard start before anonymous request = %d %s", rec.Code, rec.Body.String())
	}
	// 匿名请求被拒，但不得结束窗口。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", ""); rec.Code != http.StatusConflict {
		t.Fatalf("anonymous wizard start = %d, want 409", rec.Code)
	}
	// 合法会话仍然可用。
	if rec := setupPost(r, "/api/setup/totp/start", "{}", setupLoopbackAddr, "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("wizard start after anonymous request = %d %s", rec.Code, rec.Body.String())
	}
}

// 真实 Start() 上的未初始化门禁：防止将来调整中间件顺序时把门禁绕过。
func TestServerStartUninitializedGate(t *testing.T) {
	config, stateStore := newTestConfigUninitialized(t)
	if stateStore.AdminPasswordInitialized() {
		t.Fatal("helper must return uninitialized state")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := mustNewServer(t, config, embed.FS{})
	srv.Addr = addr
	go func() { _ = srv.Start() }()
	defer srv.Stop()

	base := "http://" + addr
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 未初始化状态接口：公开、200、needs_setup=true、直连 loopback=true。
	resp, err := client.Get(base + "/api/setup/status")
	if err != nil {
		t.Fatalf("setup status: %v", err)
	}
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		resp.Body.Close()
		t.Fatalf("decode status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || status["needs_setup"] != true || status["loopback"] != true {
		t.Fatalf("setup status = %d %v", resp.StatusCode, status)
	}

	// 业务 API 必须 409。
	resp, err = client.Get(base + "/api/clients")
	if err != nil {
		t.Fatalf("clients API: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("/api/clients before setup = %d, want 409", resp.StatusCode)
	}

	// 页面必须重定向到向导，且不能跟随重定向后再断言。
	noRedirect := &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err = noRedirect.Get(base + "/")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/setup.html" {
		t.Fatalf("root before setup = %d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Agent WebSocket 入口必须 503。
	resp, err = client.Get(base + "/ws")
	if err != nil {
		t.Fatalf("ws: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/ws before setup = %d, want 503", resp.StatusCode)
	}
}
