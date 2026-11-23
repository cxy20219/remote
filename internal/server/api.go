package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
)

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}

	if err := s.adminAuth.Login(c.ClientIP(), req.Password); err != nil {
		if errors.Is(err, ErrAdminLoginLocked) {
			s.setAuthRetryAfter(c)
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	// 密码正确但启用了两步验证：签发一次性挑战，不发会话。
	if s.adminAuth.TOTPEnabled() {
		// 密钥损坏时仍然发挑战：第二步可以用恢复码登录（唯一的自助出口）。
		// 只是把 recovery_only 标出来，前端据此直接提示「请用恢复码」。
		recoveryOnly := s.adminAuth.TOTPSelfCheck() != nil
		if recoveryOnly {
			slog.Error("admin totp configuration is corrupt; only recovery codes can complete login")
		}
		challenge, err := s.adminAuth.BeginTOTPChallenge(c.ClientIP())
		if err != nil {
			slog.Error("failed to create totp challenge", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start two-factor authentication"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":        "totp_required",
			"challenge":     challenge,
			"expires_in":    int(totpChallengeTTL / time.Second),
			"recovery_only": recoveryOnly,
		})
		return
	}

	// 未启用 TOTP 时密码就是完整认证，此时才清零失败池。
	s.adminAuth.ClearFullAuthFailures(c.ClientIP())
	s.issueAdminSession(c)
}

// handleLoginTOTP 是两步登录的第二步：用挑战换正式会话。
func (s *Server) handleLoginTOTP(c *gin.Context) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if req.Challenge == "" || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge and code are required"})
		return
	}

	err := s.adminAuth.VerifyTOTPChallenge(c.ClientIP(), req.Challenge, req.Code)
	switch {
	case err == nil:
		s.issueAdminSession(c)
	case errors.Is(err, ErrAdminLoginLocked):
		s.setAuthRetryAfter(c)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
	case errors.Is(err, ErrTOTPChallengeInvalid):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired challenge"})
	case errors.Is(err, ErrTOTPInvalidCode):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp code"})
	case errors.Is(err, ErrTOTPCorrupt):
		c.JSON(http.StatusInternalServerError, gin.H{"error": "two-factor authentication is misconfigured; check server logs"})
	case errors.Is(err, ErrTOTPNotConfigured):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "totp is not enabled"})
	default:
		slog.Error("totp verification failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify two-factor authentication"})
	}
}

// setAuthRetryAfter 给认证类 429 补 Retry-After：取 IP 失败锁与账户级退避的剩余秒数。
func (s *Server) setAuthRetryAfter(c *gin.Context) {
	if seconds := s.adminAuth.LockRetryAfter(c.ClientIP()); seconds > 0 {
		c.Header("Retry-After", strconv.Itoa(seconds))
	}
}

func (s *Server) issueAdminSession(c *gin.Context) {
	token, err := s.adminAuth.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}
	s.setAdminCookie(c, token, int(adminSessionTTL.Seconds()))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// handleAPIGetTOTPStatus 返回两步验证状态（永不返回密钥）。
func (s *Server) handleAPIGetTOTPStatus(c *gin.Context) {
	cfg := s.stateStore.TOTPConfig()
	session, _ := c.Cookie("go_remote_token")
	c.JSON(http.StatusOK, gin.H{
		"enabled":             cfg.Enabled(),
		"setup_pending":       s.adminAuth.PendingTOTPSetup(session),
		"recovery_codes_left": len(cfg.RecoveryHashes),
	})
}

// handleAPITOTPSetup 生成待激活密钥与二维码；要求重新输入当前密码。
func (s *Server) handleAPITOTPSetup(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}
	if err := s.adminAuth.CheckPassword(c.ClientIP(), req.Password); err != nil {
		if errors.Is(err, ErrAdminLoginLocked) {
			s.setAuthRetryAfter(c)
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	session, _ := c.Cookie("go_remote_token")
	secret, uri, qrDataURL, err := s.adminAuth.StartTOTPSetup(session)
	switch {
	case err == nil:
	case errors.Is(err, ErrTOTPAlreadyEnabled):
		c.JSON(http.StatusConflict, gin.H{"error": "totp is already enabled"})
		return
	case errors.Is(err, ErrStateEncryptionKeyRequired):
		c.JSON(http.StatusConflict, gin.H{"error": "state encryption is required to enable TOTP; set GOREMOTE_STATE_KEY or --state-key first"})
		return
	default:
		slog.Error("failed to start totp setup", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start totp setup"})
		return
	}
	slog.Info("admin totp setup started", "ip", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"otpauth_uri": uri,
		"qr_data_url": qrDataURL,
		"expires_in":  int(totpSetupTTL / time.Second),
	})
}

// handleAPITOTPEnable 用动态码确认待激活密钥，恢复码只在这次响应里出现一次。
func (s *Server) handleAPITOTPEnable(c *gin.Context) {
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

	session, _ := c.Cookie("go_remote_token")
	codes, err := s.adminAuth.EnableTOTP(session, req.Code)
	switch {
	case err == nil:
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
		slog.Error("failed to enable totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable two-factor authentication"})
	}
}

// handleAPITOTPRecover 用恢复码关闭两步验证（手机丢失时的自助出口）。
func (s *Server) handleAPITOTPRecover(c *gin.Context) {
	var req struct {
		Password     string `json:"password"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if req.Password == "" || strings.TrimSpace(req.RecoveryCode) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password and recovery_code are required"})
		return
	}

	session, _ := c.Cookie("go_remote_token")
	err := s.adminAuth.RecoverTOTP(c.ClientIP(), session, req.Password, req.RecoveryCode)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	case errors.Is(err, ErrAdminLoginLocked):
		s.setAuthRetryAfter(c)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
	case errors.Is(err, ErrAdminInvalidPassword):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
	case errors.Is(err, ErrTOTPInvalidCode):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid recovery code"})
	case errors.Is(err, ErrTOTPNotConfigured):
		c.JSON(http.StatusConflict, gin.H{"error": "totp is not enabled"})
	default:
		slog.Error("failed to recover totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable two-factor authentication"})
	}
}

// handleAPITOTPDisable 关闭两步验证，必须同时提供密码与当前动态码。
func (s *Server) handleAPITOTPDisable(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if req.Password == "" || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password and code are required"})
		return
	}

	session, _ := c.Cookie("go_remote_token")
	err := s.adminAuth.DisableTOTP(c.ClientIP(), session, req.Password, req.Code)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	case errors.Is(err, ErrAdminLoginLocked):
		s.setAuthRetryAfter(c)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
	case errors.Is(err, ErrAdminInvalidPassword):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
	case errors.Is(err, ErrTOTPInvalidCode):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp code"})
	case errors.Is(err, ErrTOTPCorrupt):
		c.JSON(http.StatusInternalServerError, gin.H{"error": "two-factor authentication is misconfigured; check server logs"})
	case errors.Is(err, ErrTOTPNotConfigured):
		c.JSON(http.StatusConflict, gin.H{"error": "totp is not enabled"})
	default:
		slog.Error("failed to disable totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable two-factor authentication"})
	}
}

func (s *Server) handleAPIChangeAdminPassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}

	if err := s.adminAuth.ChangePassword(c.ClientIP(), req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, ErrAdminInvalidPassword):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is invalid"})
		case errors.Is(err, ErrAdminLoginLocked):
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "admin login temporarily locked"})
		case errors.Is(err, ErrAdminWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 12 characters and use at least 3 character types"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change password"})
		}
		return
	}

	s.setAdminCookie(c, "", -1)
	s.setupMgr.EndWizard()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleLogout(c *gin.Context) {
	token, _ := c.Cookie("go_remote_token")
	if token != "" && s.adminAuth.Validate(token) {
		s.adminAuth.Logout(token)
		s.setupMgr.EndWizard()
	}
	s.setAdminCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) setAdminCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteStrictMode)
	secure := s.tlsEnabled || c.Request.TLS != nil
	c.SetCookie("go_remote_token", token, maxAge, "/", "", secure, true)
}

func (s *Server) handleCheckAuth(c *gin.Context) {
	token, _ := c.Cookie("go_remote_token")
	if s.adminAuth.Validate(token) {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"authenticated": false})
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, _ := c.Cookie("go_remote_token")
		if s.adminAuth.Validate(token) {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if path == "/login.html" {
			c.Next()
			return
		}

		if strings.Contains(c.GetHeader("Accept"), "application/json") || strings.HasPrefix(path, "/api") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Redirect(http.StatusFound, "/login.html")
		c.Abort()
	}
}

type TunnelRequest struct {
	ClientID  string `json:"client_id"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Protocol  string `json:"protocol"`
	Exposure  string `json:"exposure"`
}

type settingsUpdateRequest struct {
	PortRangeStart      *int     `json:"port_range_start"`
	PortRangeEnd        *int     `json:"port_range_end"`
	MaxTunnelsPerClient *int     `json:"max_tunnels_per_client"`
	DefaultLocalAddr    *string  `json:"default_local_addr"`
	PublicHost          *string  `json:"public_host"`
	MaxConnPerMin       *int     `json:"max_conn_per_min"`
	LoginRateLimit      *int     `json:"login_rate_limit"`
	BlacklistThreshold  *int     `json:"blacklist_threshold"`
	MaxBodySizeMB       *int     `json:"max_body_size_mb"`
	HeartbeatInterval   *int     `json:"heartbeat_interval"`
	HeartbeatTimeout    *int     `json:"heartbeat_timeout"`
	GlobalWhitelist     []string `json:"global_whitelist"`
}

func normalizeTunnelTarget(localAddr string, localPort int, protocol string, defaultLocalAddr string) (string, string, error) {
	localAddr = strings.TrimSpace(localAddr)
	if localAddr == "" {
		localAddr = strings.TrimSpace(defaultLocalAddr)
	}
	if localAddr == "" {
		return "", "", fmt.Errorf("local_addr is required")
	}
	if len(localAddr) > 255 {
		return "", "", fmt.Errorf("local_addr is too long")
	}
	if strings.ContainsAny(localAddr, "\x00\r\n\t ") {
		return "", "", fmt.Errorf("local_addr contains invalid whitespace or control characters")
	}
	if host, port, err := net.SplitHostPort(localAddr); err == nil && host != "" && port != "" {
		return "", "", fmt.Errorf("local_addr must not include a port")
	}
	if strings.Contains(localAddr, ":") {
		if net.ParseIP(localAddr) == nil {
			return "", "", fmt.Errorf("local_addr must be a valid IP literal when it contains ':'")
		}
	} else if strings.ContainsAny(localAddr, "/?#@[]\\") {
		return "", "", fmt.Errorf("local_addr contains invalid characters")
	}

	if localPort < 1 || localPort > 65535 {
		return "", "", fmt.Errorf("local_port must be in range 1-65535")
	}

	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" {
		return "", "", fmt.Errorf("unsupported protocol %q: only tcp is supported", protocol)
	}

	return localAddr, protocol, nil
}

func decodeStrictJSON(c *gin.Context, dst interface{}) bool {
	contentType := c.GetHeader("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Content-Type must be application/json"})
		return false
	}

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return false
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return false
	}

	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return false
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: multiple JSON values"})
		return false
	}

	return true
}

func (s *Server) handleAPIClients(c *gin.Context) {
	clients := s.clients.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"clients": clients,
		"total":   len(clients),
	})
}

func (s *Server) handleAPIClientDetail(c *gin.Context) {
	client, ok := s.clients.SnapshotByID(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}
	c.JSON(http.StatusOK, client)
}

func (s *Server) handleAPIListClientTunnels(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	clientID := c.Param("client_id")
	tunnels := s.tunnelManager.ListTunnelsByClient(clientID)
	c.JSON(http.StatusOK, gin.H{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) requireTunnel(c *gin.Context) bool {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return false
	}
	return true
}

func (s *Server) handleAPICreateTunnel(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	var req TunnelRequest
	if !decodeStrictJSON(c, &req) {
		return
	}

	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}

	settings := s.stateStore.GetSettings()
	localAddr, protocol, err := normalizeTunnelTarget(req.LocalAddr, req.LocalPort, req.Protocol, settings.DefaultLocalAddr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.LocalAddr = localAddr
	req.Protocol = protocol

	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found or offline"})
		return
	}

	exposure, _, err := normalizeTunnelExposure(req.Exposure)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 先选一个空闲端口并占位。listener 立刻关掉：真正的 bind 在定义落盘
	// 之后由 applyTunnel 做（定义是真相，绑定是投影）。
	publicPort, ln, err := s.tunnelManager.AllocatePortForExposure(exposure)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no available ports"})
		return
	}
	ln.Close()

	tunnelID := generateUUID()
	if err := s.tunnelManager.CreateTunnel(
		tunnelID,
		req.ClientID,
		client,
		req.Protocol,
		req.LocalAddr,
		req.LocalPort,
		publicPort,
		exposure,
	); err != nil {
		s.tunnelManager.ReleasePort(publicPort)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 定义已经落盘：apply 失败只把 status 标成 port_conflict/apply_failed，
	// 不再回滚定义、也不把 HTTP 码改成 5xx。
	tunnel, err := s.tunnelManager.ApplyTunnel(tunnelID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"tunnel_id":   tunnelID,
		"public_port": publicPort,
		"access_addr": tunnelAccessAddr(s.advertisedTunnelHost(c.Request.Host), publicPort, exposure),
		"exposure":    exposure,
		"local_addr":  req.LocalAddr,
		"local_port":  req.LocalPort,
		"protocol":    req.Protocol,
		"status":      tunnel.Status,
	}
	if tunnel.LastError != "" {
		response["last_error"] = tunnel.LastError
	}
	c.JSON(http.StatusOK, response)
}

func (s *Server) advertisedTunnelHost(reqHost string) string {
	settings := s.stateStore.GetSettings()
	if settings.PublicHost != "" {
		return settings.PublicHost
	}

	if host, _, err := net.SplitHostPort(reqHost); err == nil && host != "" {
		return host
	}

	if reqHost != "" {
		return reqHost
	}

	if s.config.Server.Host != "" && s.config.Server.Host != "0.0.0.0" && s.config.Server.Host != "::" {
		return s.config.Server.Host
	}

	return "127.0.0.1"
}

func tunnelPublicAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func tunnelAccessAddr(host string, port int, exposure string) string {
	if exposure == TunnelExposureServerLocal {
		return tunnelPublicAddr(TunnelBindServerLocal, port)
	}
	return tunnelPublicAddr(host, port)
}

func (s *Server) handleAPIListTunnels(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	tunnels := s.tunnelManager.ListTunnels()
	c.JSON(http.StatusOK, gin.H{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) handleAPIGetTunnel(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	tunnelID := c.Param("tunnel_id")
	tunnel, ok := s.tunnelManager.GetTunnel(tunnelID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIDeleteTunnel(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	if _, err := s.tunnelManager.DeleteTunnel(c.Param("tunnel_id")); err != nil {
		if errors.Is(err, errTunnelNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) handleAPIUpdateTunnel(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	tunnelID := c.Param("tunnel_id")

	var req struct {
		LocalAddr  string `json:"local_addr"`
		LocalPort  int    `json:"local_port"`
		PublicPort int    `json:"public_port"`
		Protocol   string `json:"protocol"`
		Exposure   string `json:"exposure"`
	}

	if !decodeStrictJSON(c, &req) {
		return
	}

	settings := s.stateStore.GetSettings()
	localAddr, protocol, err := normalizeTunnelTarget(req.LocalAddr, req.LocalPort, req.Protocol, settings.DefaultLocalAddr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.LocalAddr = localAddr
	req.Protocol = protocol

	tunnel, err := s.tunnelManager.UpdateTunnel(tunnelID, req.LocalAddr, req.LocalPort, req.PublicPort, req.Protocol, req.Exposure)
	if err != nil {
		switch {
		case errors.Is(err, errTunnelNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		case errors.Is(err, errTunnelPersist):
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

// handleAPIRetryTunnel 手动重试一次绑定：已 active 幂等返回，设备离线 409。
func (s *Server) handleAPIRetryTunnel(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	tunnel, err := s.tunnelManager.RetryTunnel(c.Param("tunnel_id"))
	if err != nil {
		switch {
		case errors.Is(err, errTunnelNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		case errors.Is(err, errTunnelOffline):
			c.JSON(http.StatusConflict, gin.H{"error": "device is offline", "code": "DEVICE_OFFLINE"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIGetWhitelist(c *gin.Context) {
	clientID := c.Param("id")
	device := s.stateStore.GetDeviceByID(clientID)
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_id":    clientID,
		"hostname":     device.Hostname,
		"ip_whitelist": device.IPWhitelist,
	})
}

func (s *Server) handleAPIUpdateWhitelist(c *gin.Context) {
	clientID := c.Param("id")
	device := s.stateStore.GetDeviceByID(clientID)
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	var req struct {
		IPs []string `json:"ips"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if err := validateIPList(req.IPs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deduped := deduplicateIPs(req.IPs)
	s.stateStore.UpdateDevice(clientID, func(d *DeviceState) {
		d.IPWhitelist = deduped
	})

	c.JSON(http.StatusOK, gin.H{
		"client_id":    clientID,
		"hostname":     device.Hostname,
		"ip_whitelist": deduped,
	})
}

func (s *Server) handleAPIGetGlobalWhitelist(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIUpdateGlobalWhitelist(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if err := validateIPList(req.IPs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.SetGlobalWhitelist(req.IPs)

	c.JSON(http.StatusOK, gin.H{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIGetBlacklist(c *gin.Context) {
	entries := s.blacklist.List()
	violations := s.blacklist.AllViolations()
	c.JSON(http.StatusOK, gin.H{
		"blacklist":  entries,
		"violations": violations,
		"threshold":  s.blacklist.GetThreshold(),
	})
}

// blacklistMaxDurationMinutes 是手动封禁时长（duration_minutes）的上限：一年。
// 0 表示永久。上限的意义是防溢出，见 handleAPIAddBlacklist。
const blacklistMaxDurationMinutes = 525600

func (s *Server) handleAPIAddBlacklist(c *gin.Context) {
	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration_minutes"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	parsedIP := net.ParseIP(req.IP)
	if parsedIP == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address"})
		return
	}
	req.IP = parsedIP.String()

	reason := req.Reason
	if reason == "" {
		reason = "manual"
	}

	// 必须校验范围：没有上限时 time.Duration(minutes)*time.Minute 会溢出成
	// 非正数，而 AddManual 只在 duration > 0 时设过期时间，结果一条「拉黑
	// 1 分钟」的请求会变成永久封禁。0 表示永久，最长一年。
	if req.Duration < 0 || req.Duration > blacklistMaxDurationMinutes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "duration_minutes must be in range 0-525600 (0 means permanent, at most one year)"})
		return
	}

	var duration time.Duration
	if req.Duration > 0 {
		duration = time.Duration(req.Duration) * time.Minute
	}

	if err := s.blacklist.AddManual(req.IP, reason, duration); err != nil {
		message := "failed to persist the blacklist entry; the IP was not blocked"
		if errors.Is(err, ErrBlacklistFull) {
			message = "blacklist is full and contains only manual entries; remove some entries before adding new ones"
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": message})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ip":      req.IP,
		"reason":  reason,
		"message": "IP added to blacklist",
	})
}

func (s *Server) handleAPIRemoveBlacklist(c *gin.Context) {
	// 通配符参数带前导 "/"，先剥掉。自动拉黑的条目键是 IPv6 /64，
	// 里面本来就含 "/"，所以这里不能再按路径切分。
	ip := strings.TrimPrefix(c.Param("ip"), "/")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}

	if err := s.blacklist.Remove(ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist the blacklist removal; the IP is still blocked"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "IP removed from blacklist"})
}

func (s *Server) handleAPIGetBlacklistThreshold(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"threshold": s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIUpdateBlacklistThreshold(c *gin.Context) {
	var req struct {
		Threshold int `json:"threshold"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}

	if req.Threshold < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threshold must be >= 0"})
		return
	}

	s.blacklist.SetThreshold(req.Threshold)
	s.UpdateSettings(func(st *ServerSettings) {
		st.BlacklistThreshold = req.Threshold
	})

	c.JSON(http.StatusOK, gin.H{
		"threshold": s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIPortStatus(c *gin.Context) {
	if !s.requireTunnel(c) {
		return
	}

	status := s.tunnelManager.GetPortStatus()
	c.JSON(http.StatusOK, status)
}

func (s *Server) handleAPIListDevices(c *gin.Context) {
	devices := s.stateStore.GetAllDevices()
	type deviceInfo struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Hostname    string     `json:"hostname"`
		OS          string     `json:"os"`
		Status      string     `json:"status"`
		EncEnabled  bool       `json:"enc_enabled"`
		IPWhitelist []string   `json:"ip_whitelist"`
		FirstSeen   time.Time  `json:"first_seen"`
		ApprovedAt  *time.Time `json:"approved_at,omitempty"`
		Online      bool       `json:"online"`
	}

	result := make([]deviceInfo, 0, len(devices))
	for _, d := range devices {
		_, online := s.clients.Get(d.ID)
		result = append(result, deviceInfo{
			ID:          d.ID,
			Name:        d.Name,
			Hostname:    d.Hostname,
			OS:          d.OS,
			Status:      d.Status,
			EncEnabled:  d.EncEnabled,
			IPWhitelist: d.IPWhitelist,
			FirstSeen:   d.FirstSeen,
			ApprovedAt:  d.ApprovedAt,
			Online:      online,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"devices": result,
		"total":   len(result),
	})
}

func (s *Server) handleAPIListPendingDevices(c *gin.Context) {
	pending := s.stateStore.GetDevicesByStatus("pending")
	type pendingInfo struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Hostname  string    `json:"hostname"`
		OS        string    `json:"os"`
		FirstSeen time.Time `json:"first_seen"`
		RemoteIP  string    `json:"remote_ip"`
	}

	result := make([]pendingInfo, 0, len(pending))
	for _, d := range pending {
		remoteIP := ""
		if conn, ok := s.deviceMgr.GetPendingConn(d.ID); ok {
			remoteIP = conn.RemoteIP
		}
		result = append(result, pendingInfo{
			ID:        d.ID,
			Name:      d.Name,
			Hostname:  d.Hostname,
			OS:        d.OS,
			FirstSeen: d.FirstSeen,
			RemoteIP:  remoteIP,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"devices": result,
		"total":   len(result),
	})
}

func (s *Server) handleAPIApproveDevice(c *gin.Context) {
	deviceID := c.Param("id")

	device, encKeyEncrypted, serverDHPubkey, err := s.deviceMgr.ApproveDevice(deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if conn, ok := s.deviceMgr.GetPendingConn(deviceID); ok {
		okPayload := common.RegisterOKPayload{
			ClientID:        device.ID,
			EncKeyEncrypted: encKeyEncrypted,
			ServerDHPubkey:  serverDHPubkey,
			EncEnabled:      s.deviceEncryptionActive(device),
		}
		if err := s.handler.signRegisterOKPayload(&okPayload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if conn.Client != nil {
			conn.Client.SetEncryptionEnabled(okPayload.EncEnabled)
			if err := s.sendRegisterOK(conn.Client, okPayload); err != nil {
				slog.Warn("failed to send register_ok", "device_id", deviceID, "error", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "approved",
	})
}

func (s *Server) handleAPIDenyDevice(c *gin.Context) {
	deviceID := c.Param("id")
	device := s.stateStore.GetDeviceByID(deviceID)
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	if device.Status != deviceStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device is not pending"})
		return
	}

	if conn, ok := s.deviceMgr.GetPendingConn(deviceID); ok {
		failPayload := common.RegisterFailPayload{Reason: "registration denied by admin"}
		payloadJSON, _ := json.Marshal(failPayload)
		if conn.Client != nil {
			conn.Client.WriteJSON(common.Message{
				Type:    "register_fail",
				Payload: payloadJSON,
			})
			closeClientConn(conn.Client)
		}
	}

	if err := s.deviceMgr.DenyDevice(deviceID); err != nil {
		// 落盘失败是服务端故障（设备还在、拒绝没生效），不能报 400。
		if errors.Is(err, errDevicePersist) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "denied",
	})
}

func (s *Server) handleAPIDeleteDevice(c *gin.Context) {
	deviceID := c.Param("id")

	if s.stateStore.GetDeviceByID(deviceID) == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	// 先删定义并同步落盘：失败则设备与定义都不动。留在后面的 RemoveDevice
	// 也是同步 Save，所以不存在「删完 3 秒内崩溃又复活」的窗口。
	if s.tunnelManager != nil {
		if err := s.tunnelManager.RemoveClientTunnels(deviceID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete tunnel definitions"})
			return
		}
	}

	if err := s.deviceMgr.DeleteDevice(deviceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete device"})
		return
	}

	if client, ok := s.clients.Get(deviceID); ok {
		_ = sendDeviceDeleted(client, "device deleted by admin")
		closeClientConn(client)
		s.clients.Remove(deviceID)
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "deleted",
	})
}

func (s *Server) handleAPIUpdateDeviceConfig(c *gin.Context) {
	deviceID := c.Param("id")

	var req struct {
		Name        string   `json:"name"`
		EncEnabled  *bool    `json:"enc_enabled"`
		IPWhitelist []string `json:"ip_whitelist"`
	}
	if !decodeStrictJSON(c, &req) {
		return
	}
	if err := validateIPList(req.IPWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	encEnabled := false
	if req.EncEnabled != nil {
		encEnabled = *req.EncEnabled
	} else {
		device := s.stateStore.GetDeviceByID(deviceID)
		if device != nil {
			encEnabled = device.EncEnabled
		}
	}

	device, err := s.deviceMgr.UpdateDeviceConfig(deviceID, req.Name, encEnabled, req.IPWhitelist)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if client, ok := s.clients.Get(deviceID); ok && s.handler != nil {
		client.SetEncryptionEnabled(s.deviceEncryptionActive(device))
		okPayload, err := s.handler.registerOKPayloadForDevice(device)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := sendRegisterUpdate(client, "enc_config_update", okPayload); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id":    device.ID,
		"name":         device.Name,
		"enc_enabled":  device.EncEnabled,
		"ip_whitelist": device.IPWhitelist,
	})
}

func (s *Server) handleAPIRegenKey(c *gin.Context) {
	deviceID := c.Param("id")

	device, encKeyEncrypted, serverDHPubkey, err := s.deviceMgr.RegenerateEncKey(deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if client, ok := s.clients.Get(deviceID); ok {
		okPayload := common.RegisterOKPayload{
			ClientID:        device.ID,
			EncKeyEncrypted: encKeyEncrypted,
			ServerDHPubkey:  serverDHPubkey,
			EncEnabled:      s.deviceEncryptionActive(device),
		}
		if err := s.handler.signRegisterOKPayload(&okPayload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		client.SetEncryptionEnabled(okPayload.EncEnabled)
		if err := sendRegisterUpdate(client, "enc_key_update", okPayload); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "key_regenerated",
	})
}

func (s *Server) handleAPIGetSettings(c *gin.Context) {
	settings := s.stateStore.GetSettings()
	c.JSON(http.StatusOK, settings)
}

func (s *Server) handleAPIUpdateSettings(c *gin.Context) {
	var req settingsUpdateRequest
	if !decodeStrictJSON(c, &req) {
		return
	}

	var validationErr error
	s.UpdateSettings(func(settings *ServerSettings) {
		candidate := cloneSettings(*settings)
		applySettingsUpdate(&candidate, &req, &validationErr)
		if validationErr == nil {
			*settings = candidate
		}
	})
	if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		return
	}

	c.JSON(http.StatusOK, s.stateStore.GetSettings())
}

func applySettingsUpdate(settings *ServerSettings, req *settingsUpdateRequest, validationErr *error) {
	fail := func(message string) {
		if *validationErr == nil {
			*validationErr = fmt.Errorf("%s", message)
		}
	}

	if req.PortRangeStart != nil {
		if *req.PortRangeStart < 1 || *req.PortRangeStart > 65535 {
			fail("port_range_start must be in range 1-65535")
			return
		}
		settings.PortRangeStart = *req.PortRangeStart
	}
	if req.PortRangeEnd != nil {
		if *req.PortRangeEnd < 1 || *req.PortRangeEnd > 65535 {
			fail("port_range_end must be in range 1-65535")
			return
		}
		settings.PortRangeEnd = *req.PortRangeEnd
	}
	if settings.PortRangeStart > settings.PortRangeEnd {
		fail("port_range_start must be <= port_range_end")
		return
	}
	if req.MaxTunnelsPerClient != nil {
		if *req.MaxTunnelsPerClient < 0 || *req.MaxTunnelsPerClient > 10000 {
			fail("max_tunnels_per_client must be in range 0-10000")
			return
		}
		settings.MaxTunnelsPerClient = *req.MaxTunnelsPerClient
	}
	if req.DefaultLocalAddr != nil {
		addr := strings.TrimSpace(*req.DefaultLocalAddr)
		if addr == "" || strings.ContainsAny(addr, "\x00\r\n\t ") {
			fail("default_local_addr is invalid")
			return
		}
		settings.DefaultLocalAddr = addr
	}
	if req.PublicHost != nil {
		host := strings.TrimSpace(*req.PublicHost)
		if len(host) > 255 || strings.ContainsAny(host, " \t\r\n/?#@") || strings.Contains(host, "://") {
			fail("public_host must be a bare host name or IP address")
			return
		}
		settings.PublicHost = host
	}
	if req.MaxConnPerMin != nil {
		if *req.MaxConnPerMin < 0 || *req.MaxConnPerMin > 1000000 {
			fail("max_conn_per_min must be in range 0-1000000")
			return
		}
		settings.MaxConnPerMin = *req.MaxConnPerMin
	}
	if req.LoginRateLimit != nil {
		if *req.LoginRateLimit < 0 || *req.LoginRateLimit > 1000000 {
			fail("login_rate_limit must be in range 0-1000000")
			return
		}
		settings.LoginRateLimit = *req.LoginRateLimit
	}
	if req.BlacklistThreshold != nil {
		if *req.BlacklistThreshold < 0 || *req.BlacklistThreshold > 1000000 {
			fail("blacklist_threshold must be in range 0-1000000")
			return
		}
		settings.BlacklistThreshold = *req.BlacklistThreshold
	}
	if req.MaxBodySizeMB != nil {
		if *req.MaxBodySizeMB < 0 || *req.MaxBodySizeMB > 1024 {
			fail("max_body_size_mb must be in range 0-1024")
			return
		}
		settings.MaxBodySizeMB = *req.MaxBodySizeMB
	}
	if req.HeartbeatInterval != nil {
		if *req.HeartbeatInterval < 1 || *req.HeartbeatInterval > 86400 {
			fail("heartbeat_interval must be in range 1-86400")
			return
		}
		settings.HeartbeatInterval = *req.HeartbeatInterval
	}
	if req.HeartbeatTimeout != nil {
		if *req.HeartbeatTimeout < 1 || *req.HeartbeatTimeout > 86400 {
			fail("heartbeat_timeout must be in range 1-86400")
			return
		}
		settings.HeartbeatTimeout = *req.HeartbeatTimeout
	}
	if req.GlobalWhitelist != nil {
		if err := validateIPList(req.GlobalWhitelist); err != nil {
			fail(err.Error())
			return
		}
		settings.GlobalWhitelist = deduplicateIPs(req.GlobalWhitelist)
	}
}
