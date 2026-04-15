package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

// Server is the WebSocket server
type Server struct {
	Addr       string
	tlsEnabled bool
	tlsCert    string
	tlsKey     string

	config *Config

	clients       *ClientManager
	tasks         *TaskStore
	handler       *Handler
	uploadManager *UploadManager

	upgrader websocket.Upgrader
	server   *http.Server
}

// NewServer creates a new Server
func NewServer(config *Config) *Server {
	s := &Server{
		Addr:         fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port),
		tlsEnabled:   config.Server.TLS.Enabled,
		tlsCert:      config.Server.TLS.Cert,
		tlsKey:       config.Server.TLS.Key,
		config:        config,
		clients:       NewClientManager(),
		tasks:         NewTaskStore(),
		handler:       nil,
		uploadManager: NewUploadManager(),
	}

	s.handler = NewHandler(s)

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

	// Setup HTTP server with WebSocket handler
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleConn)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/clients", s.handleAPIClients)
	mux.HandleFunc("/api/clients/", s.handleAPIClientDetail)
	mux.HandleFunc("/api/exec", s.handleAPIExec)
	mux.HandleFunc("/api/tasks", s.handleAPITasks)
	mux.HandleFunc("/api/tasks/", s.handleAPITaskDetail)

	s.server = &http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}

	// Start heartbeat checker
	go s.startHeartbeatChecker()

	if s.tlsEnabled {
		slog.Info("server starting with TLS", "cert", s.tlsCert)
		return s.server.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}

	return s.server.ListenAndServe()
}

// Stop stops the server
func (s *Server) Stop() error {
	slog.Info("server stopping")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// handleConn handles WebSocket connections
func (s *Server) handleConn(w http.ResponseWriter, r *http.Request) {
	// Upgrade to WebSocket
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("failed to upgrade connection", "error", err)
		return
	}

	remoteAddr := r.RemoteAddr
	slog.Info("connection opened", "remote", remoteAddr)

	// Create client with temporary ID until registered
	client := &Client{
		Conn: conn,
	}

	// Read messages
	for {
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
	}

	conn.Close()
	slog.Info("connection closed", "remote", remoteAddr)
}

// readLoop reads messages from a registered client
func (s *Server) readLoop(client *Client) {
	defer func() {
		if client.ClientID != "" {
			s.clients.Remove(client.ClientID)
			slog.Info("client disconnected", "client_id", client.ClientID)
		}
		client.Conn.Close()
	}()

	for {
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

// handleHealth handles health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// startHeartbeatChecker starts the heartbeat timeout checker
func (s *Server) startHeartbeatChecker() {
	interval := time.Duration(s.config.Heartbeat.Interval) * time.Second
	timeout := time.Duration(s.config.Heartbeat.Timeout) * time.Second

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
	defer s.clients.mu.Unlock()

	for _, client := range s.clients.clients {
		if now.Sub(client.LastPing) > timeout {
			slog.Warn("client heartbeat timeout", "client_id", client.ClientID)
			client.Conn.Close()
		}
	}
}

// GetClients returns all connected clients
func (s *Server) GetClients() []*Client {
	return s.clients.List()
}

// GetTasks returns all tasks
func (s *Server) GetTasks() []*Task {
	return s.tasks.List()
}

// GetTask returns a task by ID
func (s *Server) GetTask(taskID string) *Task {
	return s.tasks.Get(taskID)
}

// SendCommand sends a command to a client
func (s *Server) SendCommand(clientID, taskID, command string, timeout int) error {
	client, ok := s.clients.Get(clientID)
	if !ok {
		return fmt.Errorf("client not found: %s", clientID)
	}

	payload := common.ExecPayload{
		TaskID:  taskID,
		Command: command,
		Timeout: timeout,
	}
	payloadJSON, _ := json.Marshal(payload)

	return client.Conn.WriteJSON(common.Message{
		Type:    "exec",
		Payload: payloadJSON,
	})
}

// generateUUID generates a simple UUID (for demo purposes)
// In production, use github.com/google/uuid
func generateUUID() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", time.Now().UnixNano(),
		time.Now().Unix()&0xffff, 0x4000, 0x8000, time.Now().UnixNano())
}
