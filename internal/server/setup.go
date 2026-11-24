package server

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 首次初始化（setup wizard）。
//
// 设计要点：
//   - 首次启动不再生成/打印管理员密码；state 里 AdminPasswordHash == "" 即未初始化。
//   - 初始化请求只放行两类来源：无反代、直连本机的 loopback（且未配置 --trusted-proxies），
//     或携带一次性初始化令牌。只要配置了 --trusted-proxies，loopback 捷径整个关闭，
//     一律要求令牌——反代可以原样转发、覆写或不追加转发头，服务端无法可靠区分
//     公网伪造头与真本机直连。
//   - 令牌只换取「设置密码」这个动作的一次机会，本身不是凭据：它不能换会话，
//     也不携带任何权限；会话是在密码设置成功后按正常流程签发的。
//   - 令牌只在内存里：30 分钟有效，用一次即废，错误 10 次立即作废；
//     进程重启会换新令牌，旧令牌永久失效（磁盘上不多留一份秘密）。
const (
	setupTokenLength      = 10
	setupTokenTTL         = 30 * time.Minute
	setupTokenMaxFailures = 10
	setupWizardTTL        = 10 * time.Minute
	setupRateLimit        = 10
	setupRateWindow       = 5 * time.Minute
	setupTokenHeader      = "X-Setup-Token"
)

var (
	// ErrSetupAlreadyDone 表示初始化已经完成，setup 接口永久失效。
	ErrSetupAlreadyDone = errors.New("server is already initialized")
	// ErrSetupTokenInvalid 表示令牌缺失、错误、过期或已被烧毁。
	ErrSetupTokenInvalid = errors.New("invalid or expired setup token")
	// ErrSetupWizardExpired 表示初始化向导窗口已结束（启用/跳过/超时）。
	ErrSetupWizardExpired = errors.New("setup wizard is not active")
)

// 去掉 0/O/1/I 等易混字符，10 位约 50 bit 熵。
var setupTokenAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// SetupManager 持有首次初始化令牌与向导窗口状态，全部只在内存里。
type SetupManager struct {
	store *StateStore

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	burned    bool
	failures  int

	// 向导窗口：密码设置成功后签发的会话，可用于不重新输密码地启用 TOTP。
	wizardSession   string
	wizardIP        string
	wizardExpiresAt time.Time
}

// NewSetupManager 在未初始化时生成一次性令牌。
func NewSetupManager(store *StateStore) *SetupManager {
	m := &SetupManager{store: store}
	if store != nil && !store.AdminPasswordInitialized() {
		token, err := generateSetupToken()
		if err != nil {
			// 生成失败不是安全事件：此时只剩 loopback 路径，启动日志会体现为空令牌。
			slog.Error("failed to generate first-run setup token", "error", err)
			return m
		}
		m.token = token
		m.expiresAt = time.Now().Add(setupTokenTTL)
	}
	return m
}

func generateSetupToken() (string, error) {
	raw := make([]byte, setupTokenLength)
	for i := range raw {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(setupTokenAlphabet))))
		if err != nil {
			return "", fmt.Errorf("generate setup token: %w", err)
		}
		raw[i] = setupTokenAlphabet[n.Int64()]
	}
	return string(raw), nil
}

func normalizeSetupToken(raw string) string {
	replacer := strings.NewReplacer("-", "", " ", "", "\t", "", "_", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(raw)))
}

// NeedsSetup 报告管理员密码是否尚未设置。
func (m *SetupManager) NeedsSetup() bool {
	return m != nil && m.store != nil && !m.store.AdminPasswordInitialized()
}

// Token 返回内存里的一次性令牌（未初始化且生成失败时为空）。
func (m *SetupManager) Token() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

// TokenExpiresAt 返回令牌过期时刻。
func (m *SetupManager) TokenExpiresAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.expiresAt
}

// Authorize 判断本次初始化请求是否放行。
// 顺序：已初始化 → 拒绝；loopback（由 Server 按双条件判定）→ 放行；否则校验一次性令牌。
func (m *SetupManager) Authorize(rawToken string, loopback bool) error {
	if m == nil || !m.NeedsSetup() {
		return ErrSetupAlreadyDone
	}
	if loopback {
		return nil
	}
	return m.verifyToken(rawToken)
}

func (m *SetupManager) verifyToken(raw string) error {
	token := normalizeSetupToken(raw)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.burned || m.token == "" || time.Now().After(m.expiresAt) {
		return ErrSetupTokenInvalid
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(m.token)) == 1 {
		return nil
	}
	m.failures++
	if m.failures >= setupTokenMaxFailures {
		m.burned = true
		m.token = ""
		slog.Warn("first-run setup token burned after repeated invalid attempts", "attempts", m.failures)
	}
	return ErrSetupTokenInvalid
}

// BurnToken 在初始化成功后立即作废令牌。
func (m *SetupManager) BurnToken() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.burned = true
	m.token = ""
	m.mu.Unlock()
}

// BeginWizard 记录密码设置成功后签发的会话，允许它在 10 分钟内完成可选 TOTP 步骤。
func (m *SetupManager) BeginWizard(sessionToken, clientIP string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.wizardSession = sessionToken
	m.wizardIP = clientIPKey(clientIP)
	m.wizardExpiresAt = time.Now().Add(setupWizardTTL)
	m.mu.Unlock()
}

// AuthorizeWizard 校验 setup TOTP 端点：必须是初始化向导签发的会话、同一 IP、未超时。
func (m *SetupManager) AuthorizeWizard(sessionToken, clientIP string) error {
	if m == nil || sessionToken == "" {
		return ErrSetupWizardExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wizardSession == "" ||
		subtle.ConstantTimeCompare([]byte(sessionToken), []byte(m.wizardSession)) != 1 {
		return ErrSetupWizardExpired
	}
	if m.wizardIP != clientIPKey(clientIP) || time.Now().After(m.wizardExpiresAt) {
		return ErrSetupWizardExpired
	}
	return nil
}

// EndWizard 关闭向导窗口：TOTP 启用成功、用户跳过或窗口到期后调用。
func (m *SetupManager) EndWizard() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.wizardSession = ""
	m.wizardIP = ""
	m.wizardExpiresAt = time.Time{}
	m.mu.Unlock()
}

// setupLoopback 判定初始化请求是否来自「无反代、直连本机」。
//
// 一旦配置了 --trusted-proxies，loopback 捷径整个关闭。三种真实部署都证明无法靠
// 头部特征区分来源：
//  1. 反代原样转发公网客户端的 X-Real-IP: 127.0.0.1；
//  2. 同机反代不追加任何转发头，与直连逐字节相同；
//  3. 配了信任列表但没包含反代地址，gin 忽略转发头、把 ClientIP 回落成 127.0.0.1。
//
// 初始化是拿管理员权限的入口，这里不做启发式识别，统一要求一次性令牌。
// 未配置信任列表时仍保留 loopback 直连：但请求只要带 X-Forwarded-For / X-Real-IP
// 就不算 loopback（本机反代未配信任的兜底）。
func (s *Server) setupLoopback(c *gin.Context) bool {
	if s.config != nil && len(s.config.Security.TrustedProxies) > 0 {
		return false
	}
	if !isLoopbackPair(c.ClientIP(), c.Request.RemoteAddr) {
		return false
	}
	if c.GetHeader("X-Forwarded-For") != "" || c.GetHeader("X-Real-IP") != "" {
		return false
	}
	return true
}

// isLoopbackPair 要求 TCP 对端与经 --trusted-proxies 解析后的客户端 IP 都是 loopback。
// 只判 RemoteAddr 会出事：反向代理与服务器同机时，所有请求的 RemoteAddr 都是 127.0.0.1。
func isLoopbackPair(clientIP, remoteAddr string) bool {
	return isLoopbackIP(strings.Trim(clientIP, "[]")) && isLoopbackIP(strings.Trim(extractIP(remoteAddr), "[]"))
}

// SetupGateMiddleware 拦截未初始化状态：
// 页面重定向到 /setup.html，业务 API 返回 409；/health、/static、setup 自身放行；
// /ws 返回 503：未初始化实例不该接受 Agent 注册，否则匿名客户端可以占满 pending
// 设备表（上限 256），初始化后管理员还会看到一屏陌生设备。Agent 有重连退避，等初始化
// 完成后再连即可。
func SetupGateMiddleware(m *SetupManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/setup/") {
			c.Header("Cache-Control", "no-store")
		}

		if m == nil || !m.NeedsSetup() {
			if path == "/setup.html" {
				c.Redirect(http.StatusFound, "/")
				c.Abort()
				return
			}
			c.Next()
			return
		}

		switch {
		case path == "/health", path == "/setup.html", path == "/api/setup/status",
			strings.HasPrefix(path, "/static/"):
			c.Next()
		case strings.HasPrefix(path, "/api/setup/"):
			c.Next()
		case path == "/" || path == "/login.html":
			c.Redirect(http.StatusFound, "/setup.html")
			c.Abort()
		case path == "/ws":
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "setup required"})
		case strings.HasPrefix(path, "/api/"):
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "setup required"})
		default:
			c.Next()
		}
	}
}

// SetupRateLimitMiddleware 保护初始化接口，独立于登录/管理写接口限流。
func SetupRateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := clientIPKey(c.ClientIP())
		if !rl.Allow(key) {
			setRetryAfter(c, rl, key)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many setup attempts"})
			return
		}
		c.Next()
	}
}

func (s *Server) writeSetupError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrSetupAlreadyDone):
		c.JSON(http.StatusConflict, gin.H{"error": "server is already initialized"})
	case errors.Is(err, ErrSetupTokenInvalid):
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid or expired setup token"})
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "setup requires loopback access or a valid setup token"})
	}
}

// @Summary 查询初始化状态
// @Description 尚未设置管理密码时，除 /health 与 /api/setup/* 外的接口一律返回 409。
// @Tags setup
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/setup/status [get]
// handleSetupStatus 公开状态：前端据此决定是否显示令牌输入框、是否还需要初始化。
func (s *Server) handleSetupStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"needs_setup": s.setupMgr != nil && s.setupMgr.NeedsSetup(),
		"loopback":    s.setupLoopback(c),
	})
}

// @Summary 首次设置管理密码
// @Description 仅在未初始化时可用。请求体字段：password。成功后下发会话 Cookie。
// @Tags setup
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /api/setup/password [post]
// handleSetupPassword 设置首个管理员密码；成功后自动登录并进入向导第 2 步。
func (s *Server) handleSetupPassword(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	var req struct {
		Password string `json:"password"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}

	if err := s.setupMgr.Authorize(c.GetHeader(setupTokenHeader), s.setupLoopback(c)); err != nil {
		s.writeSetupError(c, err)
		return
	}
	if !strongAdminPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 12 characters and use at least 3 character types"})
		return
	}

	ok, err := s.stateStore.SetInitialAdminPassword(req.Password)
	if err != nil {
		slog.Error("failed to persist initial admin password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist admin password; restart the server and retry"})
		return
	}
	if !ok {
		// 并发下被别人抢先初始化：令牌一并作废，避免继续被试探。
		s.setupMgr.BurnToken()
		c.JSON(http.StatusConflict, gin.H{"error": "server is already initialized"})
		return
	}
	s.setupMgr.BurnToken()
	s.adminAuth.ClearFullAuthFailures(c.ClientIP())
	slog.Info("admin password initialized via setup wizard", "ip", clientIPKey(c.ClientIP()))

	sessionToken, err := s.adminAuth.GenerateToken()
	if err != nil {
		slog.Error("failed to create session after setup", "error", err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}
	s.setAdminCookie(c, sessionToken, int(adminSessionTTL.Seconds()))
	s.setupMgr.BeginWizard(sessionToken, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// requireSetupWizard 校验可选 TOTP 步骤：必须是初始化向导签发的、仍然有效的会话。
// 只比 Cookie 字符串不够：会话被登出/改密吊销后，10 分钟窗口内仍能拿到 TOTP secret，
// 等于把第二因子绑到别人验证器上。
func (s *Server) requireSetupWizard(c *gin.Context) bool {
	c.Header("Cache-Control", "no-store")
	sessionToken, _ := c.Cookie("go_remote_token")
	if !s.adminAuth.Validate(sessionToken) {
		// 只有「确实持有失效会话」才允许销毁向导窗口；匿名请求不得靠一次
		// 空 Cookie 调用把合法向导打掉。Logout/ChangePassword 会显式 EndWizard。
		if sessionToken != "" {
			s.setupMgr.EndWizard()
		}
		c.JSON(http.StatusConflict, gin.H{"error": "setup wizard is not active; sign in and enable two-factor authentication from the admin panel"})
		return false
	}
	if err := s.setupMgr.AuthorizeWizard(sessionToken, c.ClientIP()); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "setup wizard is not active; sign in and enable two-factor authentication from the admin panel"})
		return false
	}
	return true
}

// @Summary 开始两步验证设置
// @Description 返回待激活的 TOTP 密钥与二维码。请求体字段：password。
// @Tags setup
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /api/setup/totp/start [post]
// handleSetupTOTPStart 在向导里生成 TOTP 密钥与二维码（不需要再输密码）。
func (s *Server) handleSetupTOTPStart(c *gin.Context) {
	if !s.requireSetupWizard(c) {
		return
	}
	sessionToken, _ := c.Cookie("go_remote_token")
	secret, uri, qrDataURL, err := s.adminAuth.StartTOTPSetup(sessionToken)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{
			"secret":      secret,
			"otpauth_uri": uri,
			"qr_data_url": qrDataURL,
			"expires_in":  int(totpSetupTTL / time.Second),
		})
	case errors.Is(err, ErrStateEncryptionKeyRequired):
		c.JSON(http.StatusConflict, gin.H{"error": "state encryption is required to enable TOTP; set GOREMOTE_STATE_KEY or --state-key first"})
	case errors.Is(err, ErrTOTPAlreadyEnabled):
		c.JSON(http.StatusConflict, gin.H{"error": "totp is already enabled"})
	default:
		slog.Error("failed to start totp setup in wizard", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start totp setup"})
	}
}

// @Summary 确认两步验证
// @Description 用动态码确认待激活密钥，恢复码只在这次响应里出现一次。请求体字段：code。
// @Tags setup
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /api/setup/totp/enable [post]
// handleSetupTOTPEnable 确认动态码并返回仅此一次的恢复码；成功后向导窗口关闭。
func (s *Server) handleSetupTOTPEnable(c *gin.Context) {
	if !s.requireSetupWizard(c) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}

	sessionToken, _ := c.Cookie("go_remote_token")
	codes, err := s.adminAuth.EnableTOTP(sessionToken, req.Code)
	switch {
	case err == nil:
		s.setupMgr.EndWizard()
		slog.Info("admin totp enabled during setup wizard", "recovery_codes", len(codes))
		c.JSON(http.StatusOK, gin.H{"status": "ok", "recovery_codes": codes})
	case errors.Is(err, ErrTOTPInvalidCode):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp code"})
	case errors.Is(err, ErrTOTPSetupExpired):
		c.JSON(http.StatusConflict, gin.H{"error": "totp setup is not pending or has expired"})
	case errors.Is(err, ErrTOTPAlreadyEnabled):
		c.JSON(http.StatusConflict, gin.H{"error": "totp is already enabled"})
	case errors.Is(err, ErrStateEncryptionKeyRequired):
		c.JSON(http.StatusConflict, gin.H{"error": "state encryption is required to enable TOTP; set GOREMOTE_STATE_KEY or --state-key first"})
	default:
		slog.Error("failed to enable totp in wizard", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable two-factor authentication"})
	}
}

// @Summary 跳过两步验证
// @Description 初始化阶段不启用两步验证，直接进入面板。
// @Tags setup
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /api/setup/totp/skip [post]
// handleSetupTOTPSkip 用户选择暂不启用 TOTP：立即关闭向导窗口，
// 之后这两个 setup TOTP 端点永久 409（需要时登录管理面板再启用）。
func (s *Server) handleSetupTOTPSkip(c *gin.Context) {
	if !s.requireSetupWizard(c) {
		return
	}
	s.setupMgr.EndWizard()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
