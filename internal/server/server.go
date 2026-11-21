package server

import (
	"context"
	"crypto/ed25519"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"goremote/internal/common"
	"goremote/internal/server/netplane"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 2 * time.Minute
	httpMaxHeaderBytes    = 32 * 1024

	minConnectionReadTimeout = 60 * time.Second

	// 管理写接口（改密、TOTP setup/disable/recover）独立限流：10 次 / 5 分钟。
	// 一次正常启用流程约 3-4 次，5 次会把「启用 + 关闭」这种合法序列顶到 429。
	adminWriteLimit  = 10
	adminWriteWindow = 5 * time.Minute
)

type Server struct {
	Addr       string
	tlsEnabled bool
	tlsCert    string
	tlsKey     string

	config   *Config
	staticFS embed.FS

	clients       *ClientManager
	handler       *Handler
	tunnelManager *TunnelManager
	adminAuth     *AdminAuth
	setupMgr      *SetupManager
	cryptoMgr     *common.CryptoManager
	stateStore    *StateStore
	deviceMgr     *DeviceManager
	loginLimiter  *RateLimiter
	setupLimiter  *RateLimiter
	// adminWriteLimiter 是管理写接口（改密、TOTP 开关）的独立限流：
	// 这些接口位于 session 之后，不能只靠登录限流兜底。
	adminWriteLimiter *RateLimiter
	connLimiter       *RateLimiter
	portLimiter       *RateLimiter
	blacklist         *BlacklistManager

	globalWhitelist  atomic.Pointer[ipMatcher]
	heartbeatTimeout atomic.Int64
	heartbeatPeriod  atomic.Int64

	upgrader    websocket.Upgrader
	engine      *gin.Engine
	httpSrv     *http.Server
	stopCh      chan struct{}
	stopOnce    sync.Once
	stopErr     error
	wg          sync.WaitGroup
	lifecycleMu sync.Mutex
	stopped     bool

	maxBodyBytes atomic.Int64

	// 组网（WireGuard）：netplane 是唯一写内核的一方；wgLocks 是 per-device
	// 操作锁（只有 HTTP 写接口持锁，后台 reconcile 不取，见 netplane 注释）。
	netplane  *netplane.Plane
	wgLocksMu sync.Mutex
	wgLocks   map[string]*sync.Mutex
	wgHubMu   sync.Mutex
}

func NewServer(config *Config, staticFS embed.FS) *Server {
	statePath := filepath.Join(config.DataDir(), "server-state.json")
	stateStore := NewStateStore(statePath)
	if err := stateStore.SetEncryptionKey(config.Security.StateKey); err != nil {
		slog.Error("invalid state encryption key", "error", err)
		panic(err)
	}
	if err := stateStore.Load(); err != nil {
		slog.Error("failed to load server state", "error", err)
		panic(err)
	}
	if len(stateStore.GetServerSignPrivkey()) != ed25519.PrivateKeySize || len(stateStore.GetServerSignPubkey()) != ed25519.PublicKeySize {
		slog.Error("server signing keys are missing or corrupted")
		panic("server signing keys are missing or corrupted")
	}

	adminAuth := NewAdminAuth(stateStore)
	setupMgr := NewSetupManager(stateStore)
	cryptoMgr := common.NewCryptoManager()
	deviceMgr := NewDeviceManager(stateStore, cryptoMgr)

	settings := stateStore.GetSettings()
	s := &Server{
		Addr:              config.Addr(),
		tlsEnabled:        config.Server.TLS.Enabled,
		tlsCert:           config.Server.TLS.Cert,
		tlsKey:            config.Server.TLS.Key,
		config:            config,
		staticFS:          staticFS,
		clients:           NewClientManager(),
		stateStore:        stateStore,
		adminAuth:         adminAuth,
		setupMgr:          setupMgr,
		cryptoMgr:         cryptoMgr,
		deviceMgr:         deviceMgr,
		blacklist:         NewBlacklistManager(settings.BlacklistThreshold),
		loginLimiter:      NewRateLimiter(settings.LoginRateLimit, time.Minute),
		setupLimiter:      NewRateLimiter(setupRateLimit, setupRateWindow),
		adminWriteLimiter: NewRateLimiter(adminWriteLimit, adminWriteWindow),
		connLimiter:       NewRateLimiter(settings.MaxConnPerMin, time.Minute),
		portLimiter:       NewRateLimiter(settings.MaxConnPerMin, time.Minute),
		stopCh:            make(chan struct{}),
	}

	s.clients.SetStore(stateStore)
	s.handler = NewHandler(s)

	if config.Tunnel.Enabled {
		s.tunnelManager = NewTunnelManager(s, settings.PortRangeStart, settings.PortRangeEnd)
	}
	s.globalWhitelist.Store(newIPMatcher(settings.GlobalWhitelist))
	s.applyRuntimeSettings(settings)

	// 组网：即使没有设备绑定也可以构造；reconcile 在没有 peer 时不碰内核。
	s.netplane = netplane.New(netplane.Config{
		Store:   stateStore,
		Backend: netplane.NewExecBackend(wgInterfaceName),
	})

	s.upgrader = websocket.Upgrader{
		CheckOrigin:     s.buildOriginChecker(config.Security.AllowedOrigins),
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}

	return s
}

func (s *Server) Start() error {
	s.lifecycleMu.Lock()
	if s.stopped {
		s.lifecycleMu.Unlock()
		return nil
	}
	slog.Info("server starting", "addr", s.Addr)

	// 代理配置必须在启动时校验：解析失败还继续跑，会静默退化成「不信任任何代理」，
	// 反代部署下所有请求塌成一个 IP——按 IP 的限流、失败池、自动拉黑全部打在代理上，
	// challenge 的 IP 绑定也同时失效。所以这里直接中止启动。
	gin.SetMode(gin.ReleaseMode)
	s.engine = gin.New()
	effectiveProxies, perr := configureTrustedProxies(s.engine, s.config.Security.TrustedProxies)
	if perr != nil {
		s.lifecycleMu.Unlock()
		return perr
	}
	if len(effectiveProxies) > 0 {
		slog.Info("trusted proxies configured", "proxies", effectiveProxies)
	}

	// 两步验证的密钥只在 state 加密区里才真正加密；没配密钥时是 0600 明文文件，
	// 每次启动都要显式提醒，不能静默降级。
	if totpCfg := s.stateStore.TOTPConfig(); totpCfg.Enabled() && !s.stateStore.EncryptionEnabled() {
		slog.Warn("admin TOTP is enabled but state encryption is disabled; the TOTP secret is stored in plaintext in server-state.json (mode 0600). Set GOREMOTE_STATE_KEY or --state-key to move it into the encrypted state blob")
	}
	// 密钥损坏时所有二次验证都会 fail closed；启动就要喊一声，否则登录会表现成
	// 「验证已过期 / 动态码错误」，排查方向完全是错的。
	if err := s.adminAuth.TOTPSelfCheck(); err != nil {
		slog.Warn("admin TOTP configuration is corrupt; every two-factor login will be rejected until TOTP is reset via recovery code", "error", err)
	}
	if s.setupMgr.NeedsSetup() {
		if token := s.setupMgr.Token(); token != "" {
			slog.Warn("首次初始化令牌（仅用于首次初始化，30 分钟内有效，用一次即废）",
				"token", token,
				"expires_at", s.setupMgr.TokenExpiresAt().Format(time.RFC3339))
			if len(s.config.Security.TrustedProxies) == 0 {
				slog.Info("也可以从服务器本机 loopback 打开 /setup.html 初始化，免令牌（例如 ssh -L 8080:127.0.0.1:8080）")
			} else {
				slog.Info("已配置 --trusted-proxies，loopback 免令牌已关闭；请使用上面的初始化令牌完成向导")
			}
		} else if len(s.config.Security.TrustedProxies) == 0 {
			slog.Warn("首次初始化令牌生成失败，只允许从服务器本机 loopback 完成初始化")
		} else {
			slog.Error("首次初始化令牌生成失败且已配置 --trusted-proxies：当前没有任何可用的初始化入口，检查随机源后重启")
		}
	}
	if !s.tlsEnabled && !isLoopbackHost(s.config.Server.Host) {
		slog.Warn("server listens on a non-loopback interface without TLS; admin cookies and control traffic are sent in plaintext")
	}

	s.stateStore.StartSyncLoop()

	s.engine.Use(gin.Recovery())
	// 摘二次认证凭据必须早于任何可能 panic 的中间件：gin 的 Recovery 只脱敏
	// Authorization，X-Reauth-* 若留在请求头上会原文进 stderr。
	s.engine.Use(reauthHeaderMiddleware())
	s.engine.Use(SecurityHeadersMiddleware())
	s.engine.Use(DynamicBodySizeLimitMiddleware(func() int64 {
		return s.maxBodyBytes.Load()
	}))
	s.engine.Use(SetupGateMiddleware(s.setupMgr))

	s.engine.GET("/ws", ConnRateLimitMiddleware(s.connLimiter, s), s.handleConn)
	s.engine.GET("/health", s.handleHealth)
	s.engine.GET("/api/setup/status", s.handleSetupStatus)
	s.engine.POST("/api/setup/password", SetupRateLimitMiddleware(s.setupLimiter), s.handleSetupPassword)
	s.engine.POST("/api/setup/totp/start", AdminWriteRateLimitMiddleware(s.adminWriteLimiter), s.handleSetupTOTPStart)
	s.engine.POST("/api/setup/totp/enable", AdminWriteRateLimitMiddleware(s.adminWriteLimiter), s.handleSetupTOTPEnable)
	s.engine.POST("/api/setup/totp/skip", AdminWriteRateLimitMiddleware(s.adminWriteLimiter), s.handleSetupTOTPSkip)
	s.engine.POST("/api/login", LoginRateLimitMiddleware(s.loginLimiter, s), s.handleLogin)
	s.engine.POST("/api/login/totp", LoginRateLimitMiddleware(s.loginLimiter, s), s.handleLoginTOTP)
	s.engine.POST("/api/logout", s.handleLogout)
	s.engine.GET("/api/check-auth", s.handleCheckAuth)

	staticSub, subErr := fs.Sub(s.staticFS, "static")
	if subErr != nil {
		slog.Error("failed to open embedded static assets", "error", subErr)
		staticSub = embed.FS{}
	}
	s.engine.GET("/login.html", func(c *gin.Context) {
		data, _ := fs.ReadFile(staticSub, "login.html")
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})
	s.engine.GET("/setup.html", func(c *gin.Context) {
		data, _ := fs.ReadFile(staticSub, "setup.html")
		c.Header("Cache-Control", "no-store")
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	protected := s.engine.Group("/")
	protected.Use(s.authMiddleware())
	protected.Use(BrowserOriginGuardMiddleware())
	{
		protected.GET("/api/clients", s.handleAPIClients)
		protected.GET("/api/clients/:id", s.handleAPIClientDetail)
		protected.GET("/api/client-tunnels/:client_id", s.handleAPIListClientTunnels)
		protected.POST("/api/tunnels", s.handleAPICreateTunnel)
		protected.GET("/api/clients/:id/whitelist", s.handleAPIGetWhitelist)
		protected.PUT("/api/clients/:id/whitelist", s.handleAPIUpdateWhitelist)
		protected.GET("/api/security/global-whitelist", s.handleAPIGetGlobalWhitelist)
		protected.PUT("/api/security/global-whitelist", s.handleAPIUpdateGlobalWhitelist)
		protected.GET("/api/security/blacklist", s.handleAPIGetBlacklist)
		protected.POST("/api/security/blacklist", s.handleAPIAddBlacklist)
		protected.DELETE("/api/security/blacklist/:ip", s.handleAPIRemoveBlacklist)
		protected.GET("/api/security/blacklist-threshold", s.handleAPIGetBlacklistThreshold)
		protected.PUT("/api/security/blacklist-threshold", s.handleAPIUpdateBlacklistThreshold)
		adminWrite := AdminWriteRateLimitMiddleware(s.adminWriteLimiter)
		protected.PUT("/api/admin/password", adminWrite, s.handleAPIChangeAdminPassword)
		protected.GET("/api/admin/totp", s.handleAPIGetTOTPStatus)
		protected.POST("/api/admin/totp/setup", adminWrite, s.handleAPITOTPSetup)
		protected.POST("/api/admin/totp/enable", s.handleAPITOTPEnable)
		protected.POST("/api/admin/totp/disable", adminWrite, s.handleAPITOTPDisable)
		protected.POST("/api/admin/totp/recover", adminWrite, s.handleAPITOTPRecover)
		protected.GET("/api/tunnels", s.handleAPIListTunnels)
		protected.GET("/api/tunnels/:tunnel_id", s.handleAPIGetTunnel)
		protected.PUT("/api/tunnels/:tunnel_id", s.handleAPIUpdateTunnel)
		protected.DELETE("/api/tunnels/:tunnel_id", s.handleAPIDeleteTunnel)
		protected.GET("/api/port-status", s.handleAPIPortStatus)

		protected.GET("/api/devices", s.handleAPIListDevices)
		protected.GET("/api/devices/pending", s.handleAPIListPendingDevices)
		protected.POST("/api/devices/pending/:id/approve", s.handleAPIApproveDevice)
		protected.POST("/api/devices/pending/:id/deny", s.handleAPIDenyDevice)
		protected.DELETE("/api/devices/:id", s.handleAPIDeleteDevice)
		protected.PUT("/api/devices/:id/config", s.handleAPIUpdateDeviceConfig)
		protected.PUT("/api/devices/:id/regen-key", s.handleAPIRegenKey)
		// 组网写接口：先限流（429 早于 bcrypt），再二次认证（403），最后进 handler。
		protected.GET("/api/devices/:id/vpn", s.handleAPIGetDeviceVPN)
		protected.PUT("/api/devices/:id/vpn", adminWrite, s.reauthMiddleware(), s.handleAPIPutDeviceVPN)
		protected.DELETE("/api/devices/:id/vpn", adminWrite, s.reauthMiddleware(), s.handleAPIDeleteDeviceVPN)
		protected.GET("/api/vpn/status", s.handleAPIGetVPNStatus)
		protected.POST("/api/vpn/reconcile", adminWrite, s.reauthMiddleware(), s.handleAPIPostVPNReconcile)
		protected.GET("/api/settings", s.handleAPIGetSettings)
		protected.PUT("/api/settings", s.handleAPIUpdateSettings)

		protected.StaticFS("/static", http.FS(staticSub))
		protected.GET("/", func(c *gin.Context) {
			data, _ := fs.ReadFile(staticSub, "index.html")
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		})
		if s.config.Swagger.Enabled {
			protected.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		}
	}

	// 首轮 reconcile 在监听之前完成（最长 10s）；失败不阻塞面板启动，
	// fail closed 由 infraErr 表达，VPN 写接口一律 503。
	//
	// 组网已配置但 state 未加密时拒绝启动 netplane（实现须知 #6）：hub 私钥
	// 是唯一能对所有设备做主动 MITM 的密钥，不能以 0600 明文落盘后照常运行。
	// 面板继续服务，状态接口用 blocked=STATE_ENCRYPTION_REQUIRED 给 banner。
	if s.netplane != nil {
		if s.vpnEncryptionBlocked() {
			slog.Error("wireguard networking is disabled: state encryption is required while wireguard is configured; set GOREMOTE_STATE_KEY (at least 32 characters) or --state-key, then restart")
			s.netplane.RefuseStart("STATE_ENCRYPTION_REQUIRED", stateEncryptionRequiredMessage)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.netplane.Start(ctx)
			cancel()
			if detail := s.netplane.InfraError(); detail != "" {
				slog.Warn("wireguard initial reconcile failed; VPN writes will answer 503 until it recovers", "error", detail)
			}
			// ACL 没就绪时接口是 down 的（fail-closed），日志必须说清「不是慢，
			// 是 VPN 直接不通」，否则运维会以为 peer 之间只是没隔离。
			if status := s.netplane.Status(); !status.ACLReady && len(status.Peers) > 0 {
				slog.Warn("wireguard ACL is not active; the interface is kept down (fail-closed) and VPN traffic will not flow",
					"error", status.InfraError)
			}
		}
	}

	s.wg.Add(1)
	go s.startHeartbeatChecker()

	s.httpSrv = s.newHTTPServer()
	s.lifecycleMu.Unlock()

	var err error
	if s.tlsEnabled {
		slog.Info("server starting with TLS", "cert", s.tlsCert)
		err = s.httpSrv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	} else {
		err = s.httpSrv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// configureTrustedProxies 校验并应用 --trusted-proxies；空列表等于不信任任何代理。
// 解析失败必须让启动失败——静默降级会毁掉按 IP 的限流、失败池和 challenge 绑定。
func configureTrustedProxies(engine *gin.Engine, proxies []string) ([]string, error) {
	cleaned := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		if trimmed := strings.TrimSpace(proxy); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	if len(cleaned) == 0 {
		cleaned = nil
	}
	if err := engine.SetTrustedProxies(cleaned); err != nil {
		return nil, fmt.Errorf("invalid --trusted-proxies %q: %w", strings.Join(cleaned, ","), err)
	}
	return normalizedProxyList(cleaned), nil
}

// normalizedProxyList 按 gin 的口径展示生效的代理地址：裸 IP 补 /32 或 /128，
// CIDR 用网络地址（10.1.2.3/8 → 10.0.0.0/8），日志里看到的就是实际匹配用的网段。
func normalizedProxyList(proxies []string) []string {
	if len(proxies) == 0 {
		return nil
	}
	out := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		if !strings.Contains(proxy, "/") {
			if ip := net.ParseIP(proxy); ip != nil {
				if ip.To4() != nil {
					out = append(out, proxy+"/32")
				} else {
					out = append(out, proxy+"/128")
				}
				continue
			}
			out = append(out, proxy)
			continue
		}
		if _, network, err := net.ParseCIDR(proxy); err == nil {
			out = append(out, network.String())
			continue
		}
		out = append(out, proxy)
	}
	return out
}

func (s *Server) newHTTPServer() *http.Server {
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           s.engine,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
	if s.tlsEnabled {
		srv.TLSConfig = common.SecureTLSConfig()
	}
	return srv
}

func (s *Server) Stop() error {
	s.stopOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.stopped = true
		slog.Info("server stopping")
		close(s.stopCh)

		if s.tunnelManager != nil {
			s.tunnelManager.CloseAll()
		}
		for _, client := range s.clients.List() {
			closeClientConn(client)
		}
		s.clients.RemoveAll()
		if s.deviceMgr != nil {
			s.deviceMgr.CloseAllPendingConns()
		}
		if s.netplane != nil {
			s.netplane.Stop()
		}
		s.stateStore.Stop()
		s.wg.Wait()

		if s.loginLimiter != nil {
			s.loginLimiter.Stop()
		}
		if s.setupLimiter != nil {
			s.setupLimiter.Stop()
		}
		if s.adminWriteLimiter != nil {
			s.adminWriteLimiter.Stop()
		}
		if s.connLimiter != nil {
			s.connLimiter.Stop()
		}
		if s.portLimiter != nil {
			s.portLimiter.Stop()
		}
		if s.blacklist != nil {
			s.blacklist.Stop()
		}
		if s.httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.stopErr = s.httpSrv.Shutdown(ctx)
			cancel()
		}
		s.lifecycleMu.Unlock()
	})
	return s.stopErr
}

func (s *Server) handleConn(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("failed to upgrade connection", "error", err)
		return
	}
	conn.SetReadLimit(common.MaxWebSocketMessageSize)

	remoteAddr := c.Request.RemoteAddr
	slog.Debug("connection opened", "remote", remoteAddr)

	client := &Client{
		Conn:       conn,
		RemoteAddr: remoteAddr,
	}

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		msg, err := readWSMessage(conn)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("connection error", "error", err)
			}
			s.deviceMgr.RemovePendingConnIfMatch(client.ClientID, client)
			break
		}

		if err := s.handler.Handle(client, msg); err != nil {
			slog.Error("failed to handle message",
				"type", msg.Type,
				"error", err)
		}

		if msg.Type == "register" && client.ClientID != "" {
			var payload common.RegisterPayload
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err == nil {
				if payload.ReAuth {
					device := s.stateStore.GetDeviceByID(client.ClientID)
					if device != nil && device.Status == deviceStatusAuthorized {
						go s.readLoop(client)
						return
					}
				}
			}

			pendingConn, ok := s.deviceMgr.GetPendingConn(client.ClientID)
			if ok && pendingConn.Client == client {
				go s.pendingLoop(client)
				return
			}
		}

		if client.ClientID == "" {
			slog.Debug("registration failed, closing connection", "remote", remoteAddr)
			break
		}
	}

	conn.Close()
	slog.Debug("connection closed", "remote", remoteAddr)
}

func (s *Server) pendingLoop(client *Client) {
	defer func() {
		s.deviceMgr.RemovePendingConnIfMatch(client.ClientID, client)
		client.Conn.Close()
	}()

	for {
		client.Conn.SetReadDeadline(time.Now().Add(s.connectionReadTimeout()))
		msg, err := readWSMessage(client.Conn)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("pending connection error", "client_id", client.ClientID, "error", err)
			}
			return
		}

		if msg.Type == "ping" {
			client.WriteJSON(common.Message{Type: "pong"})
		}

		device := s.stateStore.GetDeviceByID(client.ClientID)
		if device != nil && device.Status == deviceStatusAuthorized {
			slog.Info("device approved, transition to working state",
				"client_id", client.ClientID)
			s.deviceMgr.DetachPendingConnIfMatch(client.ClientID, client)
			if s.tunnelManager != nil {
				s.tunnelManager.CloseTunnelsByClient(client.ClientID)
			}
			okPayload, err := s.handler.registerOKPayloadForDevice(device)
			if err != nil {
				slog.Error("failed to prepare register_ok", "client_id", client.ClientID, "error", err)
				return
			}
			client.SetEncryptionEnabled(s.deviceEncryptionActive(device))
			if err := s.sendRegisterOK(client, okPayload); err != nil {
				slog.Warn("failed to send register_ok on approval", "client_id", client.ClientID, "error", err)
			}
			s.clients.Add(client)
			s.readLoop(client)
			return
		}
		if device == nil {
			slog.Info("device removed while pending", "client_id", client.ClientID)
			return
		}
	}
}

func (s *Server) readLoop(client *Client) {
	defer func() {
		if client.ClientID != "" {
			current := s.clients.IsCurrent(client.ClientID, client)
			if current && s.tunnelManager != nil {
				s.tunnelManager.CloseTunnelsByClient(client.ClientID)
			}
			if current {
				s.clients.RemoveIfMatch(client.ClientID, client)
				slog.Info("client disconnected", "client_id", client.ClientID)
			} else {
				slog.Debug("stale client connection closed", "client_id", client.ClientID)
			}
		}
		client.Conn.Close()
	}()

	for {
		client.Conn.SetReadDeadline(time.Now().Add(s.connectionReadTimeout()))
		msg, err := readWSMessage(client.Conn)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("connection error", "client_id", client.ClientID, "error", err)
			}
			return
		}

		if !s.clients.TouchIfMatch(client.ClientID, client) {
			slog.Debug("stale client connection dropped", "client_id", client.ClientID)
			return
		}

		if err := s.handler.Handle(client, msg); err != nil {
			slog.Error("failed to handle message",
				"client_id", client.ClientID,
				"type", msg.Type,
				"error", err)
		}
	}
}

func readWSMessage(conn *websocket.Conn) (*common.Message, error) {
	messageType, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	switch messageType {
	case websocket.TextMessage:
		var msg common.Message
		if err := common.DecodeStrictJSON(data, &msg); err != nil {
			return nil, err
		}
		return &msg, nil
	case websocket.BinaryMessage:
		payload, err := common.DecodeBinaryTunnelDataFrame(data)
		if err != nil {
			return nil, err
		}
		return &common.Message{Type: "tunnel_data_bin", BinaryData: payload}, nil
	default:
		return nil, fmt.Errorf("unsupported websocket message type: %d", messageType)
	}
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) startHeartbeatChecker() {
	defer s.wg.Done()

	timer := time.NewTimer(s.heartbeatPeriodDuration())
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			s.checkClientsTimeout(s.heartbeatTimeoutDuration())
			timer.Reset(s.heartbeatPeriodDuration())
		case <-s.stopCh:
			return
		}
	}
}

func (s *Server) heartbeatPeriodDuration() time.Duration {
	ns := s.heartbeatPeriod.Load()
	if ns <= 0 {
		return 30 * time.Second
	}
	return time.Duration(ns)
}

func (s *Server) heartbeatTimeoutDuration() time.Duration {
	ns := s.heartbeatTimeout.Load()
	if ns <= 0 {
		return 90 * time.Second
	}
	return time.Duration(ns)
}

func (s *Server) connectionReadTimeout() time.Duration {
	timeout := s.heartbeatTimeoutDuration()
	if timeout < minConnectionReadTimeout {
		return minConnectionReadTimeout
	}
	return timeout
}

func (s *Server) checkClientsTimeout(timeout time.Duration) {
	now := time.Now()
	s.clients.mu.Lock()
	var toClose []*Client
	for _, client := range s.clients.clients {
		if now.Sub(client.LastPing) > timeout {
			slog.Warn("client heartbeat timeout", "client_id", client.ClientID)
			toClose = append(toClose, client)
		}
	}
	s.clients.mu.Unlock()

	for _, client := range toClose {
		client.Conn.Close()
	}
}

func (s *Server) GetGlobalWhitelist() []string {
	settings := s.stateStore.GetSettings()
	return settings.GlobalWhitelist
}

func (s *Server) SetGlobalWhitelist(ips []string) {
	deduped := deduplicateIPs(ips)
	s.UpdateSettings(func(st *ServerSettings) {
		st.GlobalWhitelist = deduped
	})
}

func (s *Server) UpdateSettings(fn func(*ServerSettings)) {
	s.stateStore.UpdateSettings(fn)
	s.applyRuntimeSettings(s.stateStore.GetSettings())
}

func (s *Server) applyRuntimeSettings(settings ServerSettings) {
	if s.tunnelManager != nil {
		s.tunnelManager.SetPortRange(settings.PortRangeStart, settings.PortRangeEnd)
	}
	if s.loginLimiter != nil {
		s.loginLimiter.SetLimit(settings.LoginRateLimit)
	}
	if s.connLimiter != nil {
		s.connLimiter.SetLimit(settings.MaxConnPerMin)
	}
	if s.portLimiter != nil {
		s.portLimiter.SetLimit(settings.MaxConnPerMin)
	}
	if s.blacklist != nil {
		s.blacklist.SetThreshold(settings.BlacklistThreshold)
	}
	s.maxBodyBytes.Store(maxBodySizeBytes(settings.MaxBodySizeMB))
	s.globalWhitelist.Store(newIPMatcher(settings.GlobalWhitelist))

	heartbeatPeriod := time.Duration(settings.HeartbeatInterval) * time.Second
	if heartbeatPeriod <= 0 {
		heartbeatPeriod = 30 * time.Second
	}
	heartbeatTimeout := time.Duration(settings.HeartbeatTimeout) * time.Second
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = 90 * time.Second
	}
	s.heartbeatPeriod.Store(int64(heartbeatPeriod))
	s.heartbeatTimeout.Store(int64(heartbeatTimeout))
}

func (s *Server) deviceEncryptionActive(device *DeviceState) bool {
	if device == nil || !device.EncEnabled || device.EncKey == "" || device.DeviceDHPubkey == "" {
		return false
	}
	return s.cryptoMgr != nil && s.cryptoMgr.HasKey(device.ID)
}

func (s *Server) decryptTunnelBytes(client *Client, data []byte) ([]byte, error) {
	if client == nil || !client.EncryptionEnabled() {
		return data, nil
	}
	if s.cryptoMgr == nil {
		return nil, fmt.Errorf("encryption manager is not initialized")
	}
	return s.cryptoMgr.DecryptBytes(client.ClientID, data)
}

func (s *Server) IsGloballyWhitelisted(ip string) bool {
	return s.globalWhitelist.Load().Match(ip)
}

func (s *Server) buildOriginChecker(allowedOrigins []string) func(r *http.Request) bool {
	if len(allowedOrigins) == 0 {
		slog.Warn("no allowed_origins configured, rejecting browser WebSocket origins by default")
		return func(r *http.Request) bool {
			return r.Header.Get("Origin") == ""
		}
	}

	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		normalized, ok := normalizeOrigin(o)
		if !ok {
			slog.Warn("ignoring invalid allowed origin", "origin", o)
			continue
		}
		originSet[normalized] = true
	}

	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}

		normalized, ok := normalizeOrigin(origin)
		if !ok {
			slog.Warn("invalid Origin header", "origin", origin)
			return false
		}

		if originSet[normalized] {
			return true
		}

		slog.Warn("WebSocket origin denied", "origin", origin)
		return false
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeOrigin(raw string) (string, bool) {
	raw = strings.TrimRight(strings.TrimSpace(strings.ToLower(raw)), "/")
	if raw == "" {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func generateUUID() string {
	return uuid.New().String()
}

func deduplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		result = append(result, ip)
	}
	return result
}
