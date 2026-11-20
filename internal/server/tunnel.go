package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

const (
	TunnelExposurePublic      = "public"
	TunnelExposureServerLocal = "server_local"

	TunnelBindAll         = "0.0.0.0"
	TunnelBindServerLocal = "127.0.0.1"

	externalConnQueueSize  = 32
	externalQueueWaitLimit = 15 * time.Second
	externalReadTimeout    = 15 * time.Minute
	externalWriteTimeout   = 30 * time.Second
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, common.TunnelChunkSize)
		return &b
	},
}

// Tunnel 隧道信息
type Tunnel struct {
	TunnelID   string    `json:"tunnel_id"`
	ClientID   string    `json:"client_id"`
	Client     *Client   `json:"-"` // WebSocket 连接 (not serialized)
	Protocol   string    `json:"protocol"`
	PublicPort int       `json:"public_port"`
	Exposure   string    `json:"exposure"`
	BindAddr   string    `json:"bind_addr"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  int       `json:"local_port"`
	CreatedAt  time.Time `json:"created_at"`
}

type extChunk struct {
	data []byte
	eof  bool
}

// ExternalConn tracks one public-side TCP connection. A dedicated writer
// goroutine drains the queue so transient slow writes do not stall the shared
// WebSocket receive loop; sustained backpressure is bounded by queue wait.
type ExternalConn struct {
	ConnID   string
	TunnelID string
	Conn     net.Conn

	queue     chan extChunk
	done      chan struct{}
	closeOnce sync.Once
}

func newExternalConn(connID, tunnelID string, conn net.Conn) *ExternalConn {
	return &ExternalConn{
		ConnID:   connID,
		TunnelID: tunnelID,
		Conn:     conn,
		queue:    make(chan extChunk, externalConnQueueSize),
		done:     make(chan struct{}),
	}
}

func (ec *ExternalConn) push(chunk extChunk) bool {
	select {
	case <-ec.done:
		return false
	default:
	}
	select {
	case <-ec.done:
		return false
	case ec.queue <- chunk:
		return true
	default:
	}

	// The queue is a burst buffer. When it fills, apply backpressure to the
	// shared WebSocket for a bounded time instead of dropping live TCP data.
	timer := time.NewTimer(externalQueueWaitLimit)
	defer timer.Stop()
	select {
	case <-ec.done:
		return false
	case ec.queue <- chunk:
		return true
	case <-timer.C:
		return false
	}
}

func (ec *ExternalConn) stop() {
	ec.closeOnce.Do(func() {
		close(ec.done)
		_ = ec.Conn.Close()
	})
}

// TunnelManager 隧道管理器
type TunnelManager struct {
	mu               sync.RWMutex
	tunnels          map[string]*Tunnel       // tunnelID -> Tunnel
	publicPorts      map[int]string           // listenPort -> tunnelID
	extConns         map[string]*ExternalConn // connID -> ExternalConn
	unavailablePorts map[int]struct{}         // 系统占用的端口（惰性检测）
	portStart        int
	portEnd          int
	listeners        map[int]net.Listener // publicPort -> 监听器
	server           *Server
	closed           bool
}

// NewTunnelManager creates a new TunnelManager
func NewTunnelManager(server *Server, portStart, portEnd int) *TunnelManager {
	return &TunnelManager{
		tunnels:          make(map[string]*Tunnel),
		publicPorts:      make(map[int]string),
		extConns:         make(map[string]*ExternalConn),
		unavailablePorts: make(map[int]struct{}),
		portStart:        portStart,
		portEnd:          portEnd,
		listeners:        make(map[int]net.Listener),
		server:           server,
	}
}

func normalizeTunnelExposure(exposure string) (string, string, error) {
	exposure = strings.ToLower(strings.TrimSpace(exposure))
	if exposure == "" {
		exposure = TunnelExposurePublic
	}

	switch exposure {
	case TunnelExposurePublic:
		return TunnelExposurePublic, TunnelBindAll, nil
	case TunnelExposureServerLocal:
		return TunnelExposureServerLocal, TunnelBindServerLocal, nil
	default:
		return "", "", fmt.Errorf("unsupported exposure %q: use public or server_local", exposure)
	}
}

func listenAddrForBind(bindAddr string, port int) string {
	bindAddr = strings.TrimSpace(bindAddr)
	if bindAddr == "" || bindAddr == TunnelBindAll {
		return fmt.Sprintf(":%d", port)
	}
	return net.JoinHostPort(bindAddr, fmt.Sprintf("%d", port))
}

// AllocatePortForExposure 按入口类型分配端口并创建监听器。
func (tm *TunnelManager) AllocatePortForExposure(exposure string) (int, net.Listener, error) {
	_, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return 0, nil, err
	}
	return tm.allocatePortForBind(bindAddr)
}

func (tm *TunnelManager) allocatePortForBind(bindAddr string) (int, net.Listener, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return 0, nil, fmt.Errorf("tunnel manager is shutting down")
	}
	for port := tm.portStart; port <= tm.portEnd; port++ {
		if _, used := tm.publicPorts[port]; used {
			continue
		}
		if _, unavailable := tm.unavailablePorts[port]; unavailable {
			continue
		}
		ln, err := net.Listen("tcp", listenAddrForBind(bindAddr, port))
		if err != nil {
			tm.unavailablePorts[port] = struct{}{}
			slog.Warn("port occupied by system, skipping", "port", port, "bind_addr", bindAddr, "error", err)
			continue
		}
		tm.publicPorts[port] = "" // 标记为已用
		return port, ln, nil
	}
	return 0, nil, fmt.Errorf("no available ports in range %d-%d", tm.portStart, tm.portEnd)
}

// ReleasePort 释放端口（同时从 unavailablePorts 移除，下次可重新检测）
func (tm *TunnelManager) ReleasePort(port int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.publicPorts, port)
	delete(tm.unavailablePorts, port)
}

// CreateTunnel 创建隧道
func (tm *TunnelManager) CreateTunnel(tunnelID, clientID string, client *Client, protocol, localAddr string, localPort, publicPort int, exposure string) error {
	normalizedExposure, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return err
	}
	maxTunnels := tm.maxTunnelsPerClient()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return fmt.Errorf("tunnel manager is shutting down")
	}
	if _, exists := tm.tunnels[tunnelID]; exists {
		return fmt.Errorf("tunnel already exists: %s", tunnelID)
	}
	if maxTunnels > 0 {
		count := 0
		for _, t := range tm.tunnels {
			if t.ClientID == clientID {
				count++
			}
		}
		if count >= maxTunnels {
			return fmt.Errorf("max tunnels per client reached: %d", maxTunnels)
		}
	}
	if existingID, used := tm.publicPorts[publicPort]; used && existingID != "" {
		return fmt.Errorf("public port %d already in use", publicPort)
	}

	tunnel := &Tunnel{
		TunnelID:   tunnelID,
		ClientID:   clientID,
		Client:     client,
		Protocol:   protocol,
		PublicPort: publicPort,
		Exposure:   normalizedExposure,
		BindAddr:   bindAddr,
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		CreatedAt:  time.Now(),
	}

	tm.tunnels[tunnelID] = tunnel
	tm.publicPorts[publicPort] = tunnelID

	slog.Info("tunnel created",
		"tunnel_id", tunnelID,
		"client_id", clientID,
		"public_port", publicPort,
		"exposure", normalizedExposure,
		"bind_addr", bindAddr,
		"local_addr", localAddr,
		"local_port", localPort)

	return nil
}

func (tm *TunnelManager) GetTunnel(tunnelID string) (Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return Tunnel{}, false
	}
	return *tunnel, true
}

// ListTunnels 返回所有隧道
func (tm *TunnelManager) ListTunnels() []Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnels := make([]Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, *t)
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
	})
	return tunnels
}

// ListTunnelsByClient 返回指定客户端的隧道
func (tm *TunnelManager) ListTunnelsByClient(clientID string) []Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var tunnels []Tunnel
	for _, t := range tm.tunnels {
		if t.ClientID == clientID {
			tunnels = append(tunnels, *t)
		}
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
	})
	return tunnels
}

// CloseTunnel 关闭隧道
func (tm *TunnelManager) CloseTunnel(tunnelID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	tm.closeTunnelConnectionsLocked(tunnelID)

	if listener, ok := tm.listeners[tunnel.PublicPort]; ok {
		listener.Close()
		delete(tm.listeners, tunnel.PublicPort)
	}

	delete(tm.publicPorts, tunnel.PublicPort)
	delete(tm.tunnels, tunnelID)

	slog.Info("tunnel closed", "tunnel_id", tunnelID)
	return nil
}

func (tm *TunnelManager) maxTunnelsPerClient() int {
	if tm.server == nil || tm.server.stateStore == nil {
		return 0
	}
	return tm.server.stateStore.GetSettings().MaxTunnelsPerClient
}

func (tm *TunnelManager) CloseTunnelsByClient(clientID string) {
	tm.mu.RLock()
	tunnelIDs := make([]string, 0)
	for _, tunnel := range tm.tunnels {
		if tunnel.ClientID == clientID {
			tunnelIDs = append(tunnelIDs, tunnel.TunnelID)
		}
	}
	tm.mu.RUnlock()

	for _, tunnelID := range tunnelIDs {
		if err := tm.CloseTunnel(tunnelID); err != nil {
			slog.Warn("failed to close tunnel for client", "client_id", clientID, "tunnel_id", tunnelID, "error", err)
		}
	}
}

func (tm *TunnelManager) CloseAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.closed = true

	for _, ec := range tm.extConns {
		ec.stop()
	}
	for _, listener := range tm.listeners {
		listener.Close()
	}

	tm.extConns = make(map[string]*ExternalConn)
	tm.listeners = make(map[int]net.Listener)
	tm.tunnels = make(map[string]*Tunnel)
	tm.publicPorts = make(map[int]string)

	slog.Info("all tunnels closed")
}

// UpdateTunnel updates a tunnel target, exposure and/or public port.
func (tm *TunnelManager) UpdateTunnel(tunnelID string, localAddr string, localPort int, newPublicPort int, protocol string, exposure string) (*Tunnel, error) {
	tm.mu.Lock()

	if tm.closed {
		tm.mu.Unlock()
		return nil, fmt.Errorf("tunnel manager is shutting down")
	}
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		tm.mu.Unlock()
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	if tunnel.Exposure == "" {
		tunnel.Exposure = TunnelExposurePublic
	}
	if tunnel.BindAddr == "" {
		tunnel.BindAddr = TunnelBindAll
	}
	if strings.TrimSpace(exposure) == "" {
		exposure = tunnel.Exposure
	}
	normalizedExposure, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		tm.mu.Unlock()
		return nil, err
	}
	portChanged := newPublicPort > 0 && newPublicPort != tunnel.PublicPort
	bindChanged := bindAddr != tunnel.BindAddr
	var client *Client

	if portChanged || bindChanged {
		targetPort := tunnel.PublicPort
		if newPublicPort > 0 {
			targetPort = newPublicPort
		}
		if targetPort < tm.portStart || targetPort > tm.portEnd {
			tm.mu.Unlock()
			return nil, fmt.Errorf("public port %d out of range [%d, %d]", targetPort, tm.portStart, tm.portEnd)
		}
		if existingID, used := tm.publicPorts[targetPort]; used && existingID != "" && existingID != tunnelID {
			tm.mu.Unlock()
			return nil, fmt.Errorf("public port %d already in use", targetPort)
		}

		var ln net.Listener
		if targetPort == tunnel.PublicPort && bindChanged {
			if oldListener, ok := tm.listeners[tunnel.PublicPort]; ok {
				delete(tm.listeners, tunnel.PublicPort)
				oldListener.Close()
			}
			ln, err = net.Listen("tcp", listenAddrForBind(bindAddr, targetPort))
			if err != nil {
				if rollback, rollbackErr := net.Listen("tcp", listenAddrForBind(tunnel.BindAddr, tunnel.PublicPort)); rollbackErr == nil {
					tm.listeners[tunnel.PublicPort] = rollback
					go tm.acceptLoop(tunnel.PublicPort, tunnelID)
				}
				tm.mu.Unlock()
				return nil, fmt.Errorf("failed to bind port %d on %s: %w", targetPort, bindAddr, err)
			}
		} else {
			ln, err = net.Listen("tcp", listenAddrForBind(bindAddr, targetPort))
			if err != nil {
				tm.mu.Unlock()
				return nil, fmt.Errorf("failed to bind port %d on %s: %w", targetPort, bindAddr, err)
			}
		}

		tm.closeTunnelConnectionsLocked(tunnelID)
		if oldListener, ok := tm.listeners[tunnel.PublicPort]; ok && targetPort != tunnel.PublicPort {
			oldListener.Close()
			delete(tm.listeners, tunnel.PublicPort)
		}

		oldPort := tunnel.PublicPort
		oldExposure := tunnel.Exposure
		oldBindAddr := tunnel.BindAddr
		delete(tm.publicPorts, oldPort)
		tm.publicPorts[targetPort] = tunnelID
		tunnel.PublicPort = targetPort
		tunnel.Exposure = normalizedExposure
		tunnel.BindAddr = bindAddr
		tm.listeners[targetPort] = ln

		slog.Info("tunnel listener changed",
			"tunnel_id", tunnelID,
			"old_port", oldPort,
			"new_port", targetPort,
			"old_exposure", oldExposure,
			"new_exposure", normalizedExposure,
			"old_bind_addr", oldBindAddr,
			"new_bind_addr", bindAddr)

		go tm.acceptLoop(targetPort, tunnelID)
	}

	targetChanged := localAddr != tunnel.LocalAddr || localPort != tunnel.LocalPort || protocol != tunnel.Protocol
	if targetChanged {
		// The agent will drop every local connection when the target changes;
		// existing public connections must not be silently re-dialed against
		// the new target.
		tm.closeTunnelConnectionsLocked(tunnelID)
	}
	client = tunnel.Client
	tunnel.LocalAddr = localAddr
	tunnel.LocalPort = localPort
	tunnel.Protocol = protocol
	tunnel.Exposure = normalizedExposure
	tunnel.BindAddr = bindAddr
	tunnelCopy := *tunnel

	slog.Info("tunnel updated", "tunnel_id", tunnelID, "public_port", tunnel.PublicPort, "exposure", tunnel.Exposure, "bind_addr", tunnel.BindAddr, "local_addr", localAddr, "local_port", localPort, "protocol", protocol)
	tm.mu.Unlock()

	// Notify the agent outside the manager lock: a slow WebSocket write must
	// not block tunnel administration for every other client.
	if (targetChanged || portChanged || bindChanged) && client != nil {
		if err := sendTunnelClose(client, tunnelID); err != nil {
			slog.Warn("failed to notify agent about tunnel target change", "tunnel_id", tunnelID, "error", err)
		}
		if err := sendTunnelOpen(client, tunnelID, localAddr, localPort, protocol); err != nil {
			slog.Warn("failed to send updated tunnel target to agent", "tunnel_id", tunnelID, "error", err)
		}
	}

	return &tunnelCopy, nil
}

// closeTunnelConnectionsLocked closes all external connections of a tunnel.
// The caller must hold tm.mu.
func (tm *TunnelManager) closeTunnelConnectionsLocked(tunnelID string) {
	var connIDs []string
	for connID, ec := range tm.extConns {
		if ec.TunnelID == tunnelID {
			ec.stop()
			connIDs = append(connIDs, connID)
		}
	}
	for _, connID := range connIDs {
		delete(tm.extConns, connID)
	}
}

// AddExternalConn registers a public-side connection. It fails when the
// tunnel disappeared between accept and registration.
func (tm *TunnelManager) AddExternalConn(connID, tunnelID string, conn net.Conn) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.tunnels[tunnelID]; !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	ec := newExternalConn(connID, tunnelID, conn)
	tm.extConns[connID] = ec
	go tm.runExternalWriter(connID, ec)
	return nil
}

// RemoveExternalConn removes and closes an external connection.
func (tm *TunnelManager) RemoveExternalConn(connID string) {
	tm.mu.Lock()
	ec := tm.extConns[connID]
	delete(tm.extConns, connID)
	tm.mu.Unlock()
	if ec != nil {
		ec.stop()
	}
}

func (tm *TunnelManager) removeExternalConnIfMatch(connID string, ec *ExternalConn) {
	tm.mu.Lock()
	if tm.extConns[connID] == ec {
		delete(tm.extConns, connID)
	}
	tm.mu.Unlock()
}

func (tm *TunnelManager) runExternalWriter(connID string, ec *ExternalConn) {
	for {
		select {
		case <-ec.done:
			return
		case chunk := <-ec.queue:
			if len(chunk.data) > 0 {
				ec.Conn.SetWriteDeadline(time.Now().Add(externalWriteTimeout))
				err := writeFull(ec.Conn, chunk.data)
				ec.Conn.SetWriteDeadline(time.Time{})
				if err != nil {
					slog.Debug("external connection write failed", "conn_id", connID, "error", err)
					ec.stop()
					tm.removeExternalConnIfMatch(connID, ec)
					tm.sendTunnelEOFToTunnel(ec.TunnelID, connID)
					return
				}
			}
			if chunk.eof {
				ec.stop()
				tm.removeExternalConnIfMatch(connID, ec)
				return
			}
		}
	}
}

// AcceptOnListener 使用已分配的 listener 开始监听（避免 TOCTOU 竞态）
func (tm *TunnelManager) AcceptOnListener(publicPort int, tunnelID string, ln net.Listener) error {
	tm.mu.Lock()
	if tm.closed {
		tm.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("tunnel manager is shutting down")
	}
	if _, ok := tm.tunnels[tunnelID]; !ok {
		tm.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	tm.listeners[publicPort] = ln
	tm.mu.Unlock()

	slog.Info("tunnel listener started", "public_port", publicPort, "tunnel_id", tunnelID, "listen_addr", ln.Addr().String())

	go tm.acceptLoop(publicPort, tunnelID)
	return nil
}

// acceptLoop 接受外部连接
func (tm *TunnelManager) acceptLoop(publicPort int, tunnelID string) {
	tm.mu.RLock()
	listener, ok := tm.listeners[publicPort]
	tunnel, tunnelOk := tm.tunnels[tunnelID]
	tm.mu.RUnlock()

	if !ok || !tunnelOk {
		slog.Error("acceptLoop: listener or tunnel not found",
			"public_port", publicPort,
			"tunnel_id", tunnelID)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			tm.mu.RLock()
			currentListener, stillOk := tm.listeners[publicPort]
			tm.mu.RUnlock()
			if !stillOk || currentListener != listener {
				return
			}
			slog.Warn("accept error", "public_port", publicPort, "error", err)
			continue
		}

		remoteIP := extractIP(conn.RemoteAddr().String())

		if isLoopbackIP(remoteIP) {
			slog.Debug("external connection from localhost, bypassing rate limit",
				"tunnel_id", tunnelID)
		} else if tm.server != nil {
			if tm.server.blacklist.IsBlacklisted(remoteIP) {
				slog.Warn("external connection from blacklisted IP, rejecting",
					"remote_ip", remoteIP, "tunnel_id", tunnelID)
				conn.Close()
				continue
			}
			if !tm.server.IsGloballyWhitelisted(remoteIP) {
				whitelisted := false
				if tm.server.clients != nil && tunnel.ClientID != "" {
					whitelist := tm.server.clients.GetIPWhitelist(tunnel.ClientID)
					whitelisted = isIPWhitelisted(remoteIP, whitelist)
				}
				if whitelisted {
					slog.Debug("external connection whitelisted, bypassing rate limit",
						"remote_ip", remoteIP, "tunnel_id", tunnelID, "client_id", tunnel.ClientID)
				} else if tm.server.portLimiter != nil && !tm.server.portLimiter.Allow(remoteIP) {
					slog.Warn("external connection rate limited (anti-scanning)",
						"remote_ip", remoteIP, "tunnel_id", tunnelID)
					tm.server.blacklist.AddViolation(remoteIP)
					conn.Close()
					continue
				}
			}
		}

		connID := tunnelID + "-" + uuid.NewString()
		go tm.handleExternalConn(connID, tunnel, conn)
	}
}

// handleExternalConn reads from the public connection and forwards frames to
// the agent.
func (tm *TunnelManager) handleExternalConn(connID string, tunnel *Tunnel, extConn net.Conn) {
	common.TuneTCPConn(extConn)

	tunnelID := tunnel.TunnelID
	client := tunnel.Client
	if client == nil || tm.server == nil {
		extConn.Close()
		return
	}
	if err := tm.AddExternalConn(connID, tunnelID, extConn); err != nil {
		extConn.Close()
		return
	}
	defer func() {
		tm.RemoveExternalConn(connID)
		tm.sendTunnelEOF(tunnelID, connID, client)
	}()

	slog.Debug("external connection accepted",
		"conn_id", connID,
		"tunnel_id", tunnelID,
		"remote", extConn.RemoteAddr())

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		extConn.SetReadDeadline(time.Now().Add(externalReadTimeout))
		n, err := extConn.Read(buf)
		if n > 0 {
			frame, frameErr := tm.server.encodeTunnelFrame(client, tunnelID, connID, buf[:n], false)
			if frameErr != nil {
				slog.Error("failed to encode tunnel data frame", "conn_id", connID, "error", frameErr)
				return
			}
			if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				slog.Warn("failed to send tunnel_data_bin to agent", "conn_id", connID, "error", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Warn("external conn read error", "conn_id", connID, "error", err)
			} else {
				slog.Debug("external conn closed", "conn_id", connID, "error", err)
			}
			return
		}
	}
}

func (tm *TunnelManager) sendTunnelEOF(tunnelID, connID string, client *Client) {
	if client == nil {
		return
	}
	frame, err := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, nil, true)
	if err != nil {
		return
	}
	if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		slog.Debug("failed to send tunnel EOF frame", "tunnel_id", tunnelID, "conn_id", connID, "error", err)
	}
}

func (tm *TunnelManager) sendTunnelEOFToTunnel(tunnelID, connID string) {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	var client *Client
	if ok {
		client = tunnel.Client
	}
	tm.mu.RUnlock()
	tm.sendTunnelEOF(tunnelID, connID, client)
}

// encodeTunnelFrame encrypts (when enabled) and encodes one tunnel data frame
// without copying the ciphertext a second time.
func (s *Server) encodeTunnelFrame(client *Client, tunnelID, connID string, data []byte, isEOF bool) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("tunnel client is not connected")
	}
	if !client.EncryptionEnabled() {
		return common.EncodeBinaryTunnelDataFrame(tunnelID, connID, data, isEOF)
	}
	if s.cryptoMgr == nil {
		return nil, fmt.Errorf("encryption manager is not initialized")
	}

	frame, payload, err := common.NewBinaryTunnelDataFrame(tunnelID, connID, len(data)+common.TunnelEncryptionOverhead, isEOF)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.cryptoMgr.EncryptTo(client.ClientID, payload, data)
	if err != nil {
		return nil, err
	}
	return frame[:len(frame)+len(encrypted)], nil
}

// PortStatus 端口范围状态摘要
type PortStatus struct {
	RangeStart     int   `json:"range_start"`
	RangeEnd       int   `json:"range_end"`
	TotalPorts     int   `json:"total_ports"`
	Allocated      int   `json:"allocated"`
	Unavailable    []int `json:"unavailable"`
	AvailableCount int   `json:"available_count"`
}

// SetPortRange 热更新端口范围
func (tm *TunnelManager) SetPortRange(start, end int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.portStart = start
	tm.portEnd = end
}

// GetPortStatus 返回端口范围使用状况
func (tm *TunnelManager) GetPortStatus() PortStatus {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	total := tm.portEnd - tm.portStart + 1
	if total < 0 {
		total = 0
	}
	unavailable := make([]int, 0, len(tm.unavailablePorts))
	for port := range tm.unavailablePorts {
		if port >= tm.portStart && port <= tm.portEnd {
			unavailable = append(unavailable, port)
		}
	}
	sort.Ints(unavailable)

	allocated := 0
	for port := range tm.publicPorts {
		if port >= tm.portStart && port <= tm.portEnd {
			allocated++
		}
	}
	available := total - allocated - len(unavailable)
	if available < 0 {
		available = 0
	}

	return PortStatus{
		RangeStart:     tm.portStart,
		RangeEnd:       tm.portEnd,
		TotalPorts:     total,
		Allocated:      allocated,
		Unavailable:    unavailable,
		AvailableCount: available,
	}
}

// HandleAgentData enqueues data from the agent for the public connection. The
// per-connection writer drains the queue asynchronously so a slow external
// client cannot stall the shared WebSocket receive loop.
func (tm *TunnelManager) HandleAgentData(tunnelID, connID string, data []byte, isEOF bool) error {
	tm.mu.RLock()
	ec, ok := tm.extConns[connID]
	tm.mu.RUnlock()

	if !ok {
		slog.Debug("external connection already closed, dropping tunnel data",
			"tunnel_id", tunnelID,
			"conn_id", connID,
			"is_eof", isEOF,
			"bytes", len(data))
		return nil
	}
	if ec.TunnelID != tunnelID {
		return fmt.Errorf("conn %s does not belong to tunnel %s", connID, tunnelID)
	}

	if !ec.push(extChunk{data: data, eof: isEOF}) {
		slog.Warn("external connection queue stalled, closing connection",
			"tunnel_id", tunnelID,
			"conn_id", connID)
		tm.RemoveExternalConn(connID)
		tm.sendTunnelEOFToTunnel(tunnelID, connID)
	}
	return nil
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func sendTunnelOpen(client *Client, tunnelID, localAddr string, localPort int, protocol string) error {
	if client == nil {
		return fmt.Errorf("tunnel client is not connected")
	}
	payloadJSON, err := json.Marshal(common.TunnelOpenPayload{
		TunnelID:  tunnelID,
		LocalAddr: localAddr,
		LocalPort: localPort,
		Protocol:  protocol,
	})
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{Type: "tunnel_open", Payload: payloadJSON})
}

func sendTunnelClose(client *Client, tunnelID string) error {
	if client == nil {
		return fmt.Errorf("tunnel client is not connected")
	}
	payloadJSON, err := json.Marshal(common.TunnelClosePayload{TunnelID: tunnelID})
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{Type: "tunnel_close", Payload: payloadJSON})
}
