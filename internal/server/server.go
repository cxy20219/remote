package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
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
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 2 * time.Minute
	httpMaxHeaderBytes    = 32 * 1024
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
	cryptoMgr     *common.CryptoManager
	stateStore    *StateStore
	deviceMgr     *DeviceManager
	loginLimiter  *RateLimiter
	connLimiter   *RateLimiter
	portLimiter   *RateLimiter
	blacklist     *BlacklistManager

	upgrader websocket.Upgrader
	engine   *gin.Engine
	httpSrv  *http.Server
	stopCh   chan struct{}
	stopOnce sync.Once

	maxBodyBytes atomic.Int64
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

	state := stateStore.GetState()
	if state.AdminPassword != "" {
		slog.Info("========================================")
		slog.Info("Admin password (first run only)", "password", state.AdminPassword)
		slog.Info("========================================")
		stateStore.ClearAdminPassword()
	}

	adminAuth := NewAdminAuth(stateStore)
	cryptoMgr := common.NewCryptoManager()
	deviceMgr := NewDeviceManager(stateStore, cryptoMgr)

	settings := stateStore.GetSettings()

	blacklist := NewBlacklistManager(settings.BlacklistThreshold)

	globalWhitelist := make([]string, len(settings.GlobalWhitelist))
	copy(globalWhitelist, settings.GlobalWhitelist)

	s := &Server{
		Addr:         config.Addr(),
		tlsEnabled:   config.Server.TLS.Enabled,
		tlsCert:      config.Server.TLS.Cert,
		tlsKey:       config.Server.TLS.Key,
		config:       config,
		staticFS:     staticFS,
		clients:      NewClientManager(),
		handler:      nil,
		stateStore:   stateStore,
		adminAuth:    adminAuth,
		cryptoMgr:    cryptoMgr,
		deviceMgr:    deviceMgr,
		blacklist:    blacklist,
		loginLimiter: NewRateLimiter(settings.LoginRateLimit, time.Minute),
		connLimiter:  NewRateLimiter(settings.MaxConnPerMin, time.Minute),
		portLimiter:  NewRateLimiter(settings.MaxConnPerMin, time.Minute),
		stopCh:       make(chan struct{}),
	}

	s.clients.SetStore(stateStore)
	s.handler = NewHandler(s)

	if config.Tunnel.Enabled {
		s.tunnelManager = NewTunnelManager(s, settings.PortRangeStart, settings.PortRangeEnd)
	}
	s.maxBodyBytes.Store(maxBodySizeBytes(settings.MaxBodySizeMB))

	s.upgrader = websocket.Upgrader{
		CheckOrigin:     s.buildOriginChecker(config.Security.AllowedOrigins),
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}

	return s
}

func (s *Server) Start() error {
	slog.Info("server starting", "addr", s.Addr)

	stateStore := s.stateStore
	stateStore.StartSyncLoop()

	gin.SetMode(gin.ReleaseMode)
	s.engine = gin.New()
	if err := s.engine.SetTrustedProxies(nil); err != nil {
		slog.Error("failed to disable trusted proxies", "error", err)
	}
	s.engine.Use(gin.Recovery())
	s.engine.Use(SecurityHeadersMiddleware())
	s.engine.Use(DynamicBodySizeLimitMiddleware(func() int64 {
		return s.maxBodyBytes.Load()
	}))

	s.engine.GET("/ws", ConnRateLimitMiddleware(s.connLimiter, s), s.handleConn)
	s.engine.GET("/health", s.handleHealth)
	s.engine.POST("/api/login", LoginRateLimitMiddleware(s.loginLimiter, s), s.handleLogin)
	s.engine.POST("/api/logout", s.handleLogout)
	s.engine.GET("/api/check-auth", s.handleCheckAuth)

	staticSub, _ := fs.Sub(s.staticFS, "static")
	s.engine.GET("/login.html", func(c *gin.Context) {
		data, _ := fs.ReadFile(staticSub, "login.html")
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
		protected.PUT("/api/admin/password", s.handleAPIChangeAdminPassword)
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

	go s.startHeartbeatChecker()

	s.httpSrv = s.newHTTPServer()

	if s.tlsEnabled {
		slog.Info("server starting with TLS", "cert", s.tlsCert)
		return s.httpSrv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}

	return s.httpSrv.ListenAndServe()
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
	slog.Info("server stopping")
	s.stopOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
	s.stateStore.Stop()
	if s.tunnelManager != nil {
		s.tunnelManager.CloseAll()
	}
	if s.loginLimiter != nil {
		s.loginLimiter.Stop()
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
		defer cancel()
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
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
			if err := jsonUnmarshal(msg.Payload, &payload); err == nil {
				if payload.ReAuth {
					device := s.stateStore.GetDeviceByID(client.ClientID)
					if device != nil && device.Status == "authorized" {
						go s.readLoop(client)
						return
					}
				}
			}

			pendingConn, ok := s.deviceMgr.GetPendingConn(client.ClientID)
			if ok && pendingConn.Conn != nil {
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

func jsonUnmarshal(data []byte, v interface{}) error {
	return common.DecodeStrictJSON(data, v)
}

func (s *Server) pendingLoop(client *Client) {
	defer func() {
		s.deviceMgr.RemovePendingConnIfMatch(client.ClientID, client)
		client.Conn.Close()
	}()

	settings := s.stateStore.GetSettings()
	timeout := time.Duration(settings.HeartbeatTimeout) * time.Second
	if timeout <= 0 {
		timeout = 90 * time.Second
	} else if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}

	for {
		client.Conn.SetReadDeadline(time.Now().Add(timeout))
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
		if device != nil && device.Status == "authorized" {
			slog.Info("device approved, transition to working state",
				"client_id", client.ClientID)
			s.deviceMgr.DetachPendingConnIfMatch(client.ClientID, client)
			if s.tunnelManager != nil {
				s.tunnelManager.CloseTunnelsByClient(client.ClientID)
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
				s.deviceMgr.RemoveAuthorizedConn(client.ClientID)
				slog.Info("client disconnected", "client_id", client.ClientID)
			} else {
				slog.Debug("stale client connection closed", "client_id", client.ClientID)
			}
		}
		client.Conn.Close()
	}()

	settings := s.stateStore.GetSettings()
	timeout := time.Duration(settings.HeartbeatTimeout) * time.Second
	if timeout <= 0 {
		timeout = 90 * time.Second
	}

	for {
		client.Conn.SetReadDeadline(time.Now().Add(timeout))
		msg, err := readWSMessage(client.Conn)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("connection error", "client_id", client.ClientID, "error", err)
			}
			return
		}

		s.clients.UpdateActivityIfMatch(client.ClientID, client)

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
	settings := s.stateStore.GetSettings()
	interval := time.Duration(settings.HeartbeatInterval) * time.Second
	timeout := time.Duration(settings.HeartbeatTimeout) * time.Second

	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkClientsTimeout(timeout)
		case <-s.stopCh:
			return
		}
	}
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

func (s *Server) GetClients() []*Client {
	return s.clients.List()
}

func (s *Server) GetGlobalWhitelist() []string {
	settings := s.stateStore.GetSettings()
	return settings.GlobalWhitelist
}

func (s *Server) SetGlobalWhitelist(ips []string) {
	deduped := deduplicateIPs(ips)
	s.stateStore.UpdateSettings(func(st *ServerSettings) {
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
}

func (s *Server) isDeviceEncryptionEnabled(clientID string) bool {
	if s == nil || s.stateStore == nil {
		return true
	}
	device := s.stateStore.GetDeviceByID(clientID)
	return device == nil || device.EncEnabled
}

func (s *Server) encryptTunnelBytes(clientID string, data []byte) ([]byte, error) {
	if !s.isDeviceEncryptionEnabled(clientID) {
		return data, nil
	}
	return s.cryptoMgr.EncryptBytes(clientID, data)
}

func (s *Server) decryptTunnelBytes(clientID string, data []byte) ([]byte, error) {
	if !s.isDeviceEncryptionEnabled(clientID) {
		return data, nil
	}
	return s.cryptoMgr.DecryptBytes(clientID, data)
}

func (s *Server) IsGloballyWhitelisted(ip string) bool {
	whitelist := s.GetGlobalWhitelist()
	return isIPWhitelisted(ip, whitelist)
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
		if ok {
			originSet[normalized] = true
		}
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
