package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"goremote/internal/common"
)

// Server is the WebSocket server
type Server struct {
	Addr       string
	tlsEnabled bool
	tlsCert    string
	tlsKey     string

	config *Config

	clients        *ClientManager
	handler        *Handler
	tunnelManager  *TunnelManager
	adminAuth      *AdminAuth

	upgrader websocket.Upgrader
	engine   *gin.Engine
	httpSrv  *http.Server
}

// NewServer creates a new Server
func NewServer(config *Config) *Server {
	// Validate TLS certificate files if TLS is enabled
	if config.Server.TLS.Enabled {
		if config.Server.TLS.Cert == "" || config.Server.TLS.Key == "" {
			slog.Warn("TLS enabled but cert or key path is empty")
		}
	}

	s := &Server{
		Addr:       net.JoinHostPort(config.Server.Host, fmt.Sprintf("%d", config.Server.Port)),
		tlsEnabled: config.Server.TLS.Enabled,
		tlsCert:    config.Server.TLS.Cert,
		tlsKey:     config.Server.TLS.Key,
		config:     config,
		clients:    NewClientManager(),
		handler:    nil,
	}

	s.handler = NewHandler(s)
	s.adminAuth = NewAdminAuth(config.Admin.Password)

	// Initialize tunnel manager
	if config.Tunnel.Enabled {
		s.tunnelManager = NewTunnelManager(s, config.Tunnel.PortRangeStart, config.Tunnel.PortRangeEnd)
	}

	s.upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for now
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return s
}

// Start starts the server
func (s *Server) Start() error {
	slog.Info("server starting", "addr", s.Addr)

	// Setup Gin engine
	gin.SetMode(gin.ReleaseMode)
	s.engine = gin.New()
	s.engine.Use(gin.Recovery())

	// Public routes (no auth required)
	s.engine.GET("/ws", s.handleConn)
	s.engine.GET("/health", s.handleHealth)
	s.engine.POST("/api/login", s.handleLogin)
	s.engine.POST("/api/logout", s.handleLogout)
	s.engine.GET("/api/check-auth", s.handleCheckAuth)
	s.engine.StaticFile("/login.html", "./static/login.html")

	// Protected routes
	protected := s.engine.Group("/")
	protected.Use(s.authMiddleware())
	{
		protected.GET("/api/clients", s.handleAPIClients)
		protected.GET("/api/clients/:id", s.handleAPIClientDetail)
		protected.GET("/api/client-tunnels/:client_id", s.handleAPIListClientTunnels)
		protected.POST("/api/tunnels", s.handleAPICreateTunnel)
		protected.GET("/api/tunnels", s.handleAPIListTunnels)
		protected.GET("/api/tunnels/:tunnel_id", s.handleAPIGetTunnel)
		protected.PUT("/api/tunnels/:tunnel_id", s.handleAPIUpdateTunnel)
		protected.DELETE("/api/tunnels/:tunnel_id", s.handleAPIDeleteTunnel)
		protected.Static("/static", "./static")
		protected.StaticFile("/", "./static/index.html")
		if s.config.Swagger.Enabled {
			protected.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		}
	}

	// Start heartbeat checker
	go s.startHeartbeatChecker()

	s.httpSrv = &http.Server{
		Addr:    s.Addr,
		Handler: s.engine,
	}

	if s.tlsEnabled {
		slog.Info("server starting with TLS", "cert", s.tlsCert)
		return s.httpSrv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}

	return s.httpSrv.ListenAndServe()
}

// Stop stops the server gracefully
func (s *Server) Stop() error {
	slog.Info("server stopping")
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}

// handleConn handles WebSocket connections
func (s *Server) handleConn(c *gin.Context) {
	// Upgrade to WebSocket
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("failed to upgrade connection", "error", err)
		return
	}

	remoteAddr := c.Request.RemoteAddr
	slog.Info("connection opened", "remote", remoteAddr)

	// Create client with temporary ID until registered
	client := &Client{
		Conn: conn,
	}

	// Read messages
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var msg common.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("connection error", "error", err)
			}
			break
		}

		// Handle the message
		if err := s.handler.Handle(client, &msg); err != nil {
			slog.Error("failed to handle message",
				"type", msg.Type,
				"error", err)
		}

		// For register messages, client ID is set after registration
		if msg.Type == "register" && client.ClientID != "" {
			// Client registered successfully, start reading loop for this client
			go s.readLoop(client)
			return
		}
		if msg.Type == "register" && client.ClientID == "" {
			// Registration failed, close connection
			slog.Warn("registration failed, closing connection", "remote", remoteAddr)
			break
		}
	}

	conn.Close()
	slog.Info("connection closed", "remote", remoteAddr)
}

// readLoop reads messages from a registered client
func (s *Server) readLoop(client *Client) {
	defer func() {
		if client.ClientID != "" {
			// 清理该客户端的所有隧道
			if s.tunnelManager != nil {
				for _, t := range s.tunnelManager.ListTunnelsByClient(client.ClientID) {
					if err := s.tunnelManager.CloseTunnel(t.TunnelID); err != nil {
						slog.Warn("failed to close tunnel on disconnect", "tunnel_id", t.TunnelID, "error", err)
					}
				}
			}
			s.clients.Remove(client.ClientID)
			slog.Info("client disconnected", "client_id", client.ClientID)
		}
		client.Conn.Close()
	}()

	for {
		// 设置读超时，防止客户端非正常断开后长时间阻塞
		client.Conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		var msg common.Message
		if err := client.Conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Warn("connection error", "client_id", client.ClientID, "error", err)
			}
			return
		}

		if err := s.handler.Handle(client, &msg); err != nil {
			slog.Error("failed to handle message",
				"client_id", client.ClientID,
				"type", msg.Type,
				"error", err)
		}
	}
}

// handleHealth 健康检查
// @Summary 健康检查
// @Description 服务健康状态检查
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// startHeartbeatChecker starts the heartbeat timeout checker
func (s *Server) startHeartbeatChecker() {
	interval := time.Duration(s.config.Heartbeat.Interval) * time.Second
	timeout := time.Duration(s.config.Heartbeat.Timeout) * time.Second

	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		s.checkClientsTimeout(timeout)
	}
}

// checkClientsTimeout checks for timed out clients
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

// GetClients returns all connected clients
func (s *Server) GetClients() []*Client {
	return s.clients.List()
}

func generateUUID() string {
	return uuid.New().String()
}
