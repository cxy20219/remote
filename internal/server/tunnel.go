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
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, common.TunnelChunkSize)
		return &b
	},
}

// Tunnel 隧道信息
type Tunnel struct {
	TunnelID   string
	ClientID   string
	Client     *Client `json:"-"` // WebSocket 连接 (not serialized)
	Protocol   string
	PublicPort int    // 服务端监听端口（公网映射或服务端本机代理）
	Exposure   string // "public" / "server_local"
	BindAddr   string // 监听地址，public 默认为 0.0.0.0，server_local 为 127.0.0.1
	LocalAddr  string // 客户端本地地址
	LocalPort  int
	CreatedAt  time.Time
	Status     string // "active" / "closing"
}

// ExternalConn 外部连接信息
type ExternalConn struct {
	ConnID   string
	TunnelID string
	Conn     net.Conn // TCP 连接
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

// AllocatePort 分配一个可用端口并创建监听器（原子操作，避免 TOCTOU 竞态）
func (tm *TunnelManager) AllocatePort() (int, net.Listener, error) {
	return tm.AllocatePortForExposure(TunnelExposurePublic)
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
	tm.mu.Lock()
	defer tm.mu.Unlock()

	normalizedExposure, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return err
	}

	// 检查客户端隧道数量限制
	if tm.server.config.Tunnel.MaxTunnelsPerClient > 0 {
		count := 0
		for _, t := range tm.tunnels {
			if t.ClientID == clientID && t.Status == "active" {
				count++
			}
		}
		if count >= tm.server.config.Tunnel.MaxTunnelsPerClient {
			return fmt.Errorf("max tunnels per client reached: %d", tm.server.config.Tunnel.MaxTunnelsPerClient)
		}
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
		Status:     "active",
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

// GetTunnel 获取隧道
func (tm *TunnelManager) GetTunnel(tunnelID string) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnel, ok := tm.tunnels[tunnelID]
	return tunnel, ok
}

// GetTunnelByPort 根据公网端口获取隧道
func (tm *TunnelManager) GetTunnelByPort(publicPort int) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnelID, ok := tm.publicPorts[publicPort]
	if !ok {
		return nil, false
	}
	tunnel, ok := tm.tunnels[tunnelID]
	return tunnel, ok
}

// ListTunnels 返回所有隧道
func (tm *TunnelManager) ListTunnels() []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
	})
	return tunnels
}

// ListTunnelsByClient 返回指定客户端的隧道
func (tm *TunnelManager) ListTunnelsByClient(clientID string) []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var tunnels []*Tunnel
	for _, t := range tm.tunnels {
		if t.ClientID == clientID {
			tunnels = append(tunnels, t)
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

	tunnel.Status = "closing"

	// 关闭所有外部连接
	tm.closeTunnelConnections(tunnelID)

	// 关闭监听器
	if listener, ok := tm.listeners[tunnel.PublicPort]; ok {
		listener.Close()
		delete(tm.listeners, tunnel.PublicPort)
	}

	// 释放端口
	delete(tm.publicPorts, tunnel.PublicPort)
	delete(tm.tunnels, tunnelID)

	slog.Info("tunnel closed", "tunnel_id", tunnelID)
	return nil
}

func (tm *TunnelManager) CloseAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, ec := range tm.extConns {
		ec.Conn.Close()
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

func (tm *TunnelManager) UpdateTunnel(tunnelID string, localAddr string, localPort int, newPublicPort int, protocol string, exposure string) (*Tunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	if tunnel.Status != "active" {
		return nil, fmt.Errorf("tunnel is not active, current status: %s", tunnel.Status)
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
		return nil, err
	}
	portChanged := newPublicPort > 0 && newPublicPort != tunnel.PublicPort
	bindChanged := bindAddr != tunnel.BindAddr

	if portChanged || bindChanged {
		targetPort := tunnel.PublicPort
		if newPublicPort > 0 {
			targetPort = newPublicPort
		}
		if targetPort < tm.portStart || targetPort > tm.portEnd {
			return nil, fmt.Errorf("public port %d out of range [%d, %d]", targetPort, tm.portStart, tm.portEnd)
		}
		if existingID, used := tm.publicPorts[targetPort]; used && existingID != "" && existingID != tunnelID {
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
				return nil, fmt.Errorf("failed to bind port %d on %s: %w", targetPort, bindAddr, err)
			}
		} else {
			ln, err = net.Listen("tcp", listenAddrForBind(bindAddr, targetPort))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to bind port %d on %s: %w", targetPort, bindAddr, err)
		}

		tm.closeTunnelConnections(tunnelID)
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

	// 通知 Agent 更新目标地址
	targetChanged := localAddr != tunnel.LocalAddr || localPort != tunnel.LocalPort || protocol != tunnel.Protocol
	if targetChanged {
		payloadJSON, _ := json.Marshal(common.TunnelClosePayload{TunnelID: tunnelID})
		tunnel.Client.WriteJSON(common.Message{
			Type:    "tunnel_close",
			Payload: payloadJSON,
		})
	}

	tunnel.LocalAddr = localAddr
	tunnel.LocalPort = localPort
	tunnel.Protocol = protocol
	tunnel.Exposure = normalizedExposure
	tunnel.BindAddr = bindAddr

	if targetChanged {
		openPayload := common.TunnelOpenPayload{
			TunnelID:  tunnelID,
			LocalAddr: localAddr,
			LocalPort: localPort,
			Protocol:  protocol,
		}
		payloadJSON, _ := json.Marshal(openPayload)
		tunnel.Client.WriteJSON(common.Message{
			Type:    "tunnel_open",
			Payload: payloadJSON,
		})
	}

	slog.Info("tunnel updated", "tunnel_id", tunnelID, "public_port", tunnel.PublicPort, "exposure", tunnel.Exposure, "bind_addr", tunnel.BindAddr, "local_addr", localAddr, "local_port", localPort, "protocol", protocol)
	return tunnel, nil
}

// closeTunnelConnections 关闭隧道的所有外部连接
func (tm *TunnelManager) closeTunnelConnections(tunnelID string) {
	var connIDs []string
	for connID, ec := range tm.extConns {
		if ec.TunnelID == tunnelID {
			ec.Conn.Close()
			connIDs = append(connIDs, connID)
		}
	}
	for _, connID := range connIDs {
		delete(tm.extConns, connID)
	}
}

// AddExternalConn 添加外部连接
func (tm *TunnelManager) AddExternalConn(connID, tunnelID string, conn net.Conn) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.extConns[connID] = &ExternalConn{
		ConnID:   connID,
		TunnelID: tunnelID,
		Conn:     conn,
	}
}

// GetExternalConn 获取外部连接
func (tm *TunnelManager) GetExternalConn(connID string) (*ExternalConn, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	ec, ok := tm.extConns[connID]
	return ec, ok
}

// RemoveExternalConn 移除外部连接
func (tm *TunnelManager) RemoveExternalConn(connID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if ec, ok := tm.extConns[connID]; ok {
		ec.Conn.Close()
		delete(tm.extConns, connID)
	}
}

// Listen 开始监听服务端端口（创建新 listener，外部调用）
func (tm *TunnelManager) Listen(publicPort int, tunnelID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	return tm.startListener(publicPort, tunnelID, tunnel.BindAddr)
}

// AcceptOnListener 使用已分配的 listener 开始监听（避免 TOCTOU 竞态）
func (tm *TunnelManager) AcceptOnListener(publicPort int, tunnelID string, ln net.Listener) error {
	tm.mu.Lock()
	tm.listeners[publicPort] = ln
	tm.mu.Unlock()

	slog.Info("tunnel listener started", "public_port", publicPort, "tunnel_id", tunnelID, "listen_addr", ln.Addr().String())

	go tm.acceptLoop(publicPort, tunnelID)
	return nil
}

// startListener 启动监听器（不加锁，由调用方保证线程安全）
func (tm *TunnelManager) startListener(publicPort int, tunnelID string, bindAddr string) error {
	addr := listenAddrForBind(bindAddr, publicPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", publicPort, err)
	}

	tm.listeners[publicPort] = listener
	slog.Info("tunnel listener started", "public_port", publicPort, "tunnel_id", tunnelID, "listen_addr", listener.Addr().String())

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
			// 检查监听器是否已关闭
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

		if remoteIP == "127.0.0.1" || remoteIP == "::1" {
			slog.Debug("external connection from localhost, bypassing rate limit",
				"tunnel_id", tunnelID)
		} else {
			if tm.server.blacklist.IsBlacklisted(remoteIP) {
				slog.Warn("external connection from blacklisted IP, rejecting",
					"remote_ip", remoteIP, "tunnel_id", tunnelID)
				conn.Close()
				continue
			}
			if tm.server.IsGloballyWhitelisted(remoteIP) {
				slog.Debug("external connection globally whitelisted, bypassing rate limit",
					"remote_ip", remoteIP, "tunnel_id", tunnelID)
			} else if tm.server.clients != nil && tunnel.ClientID != "" {
				whitelist := tm.server.clients.GetIPWhitelist(tunnel.ClientID)
				if isIPWhitelisted(remoteIP, whitelist) {
					slog.Debug("external connection whitelisted, bypassing rate limit",
						"remote_ip", remoteIP, "tunnel_id", tunnelID, "client_id", tunnel.ClientID)
				} else if tm.server.portLimiter != nil && !tm.server.portLimiter.Allow(remoteIP) {
					slog.Warn("external connection rate limited (anti-scanning)",
						"remote_ip", remoteIP, "tunnel_id", tunnelID)
					tm.server.blacklist.AddViolation(remoteIP)
					conn.Close()
					continue
				}
			} else if tm.server.portLimiter != nil && !tm.server.portLimiter.Allow(remoteIP) {
				slog.Warn("external connection rate limited (anti-scanning)",
					"remote_ip", remoteIP, "tunnel_id", tunnelID)
				tm.server.blacklist.AddViolation(remoteIP)
				conn.Close()
				continue
			}
		}

		// 生成 connID 并处理连接
		connID := fmt.Sprintf("%s-%s", tunnelID, uuid.New().String()[:8])
		go tm.handleExternalConn(connID, tunnel, conn)
	}
}

// handleExternalConn 处理外部连接
func (tm *TunnelManager) handleExternalConn(connID string, tunnel *Tunnel, extConn net.Conn) {
	common.TuneTCPConn(extConn)

	tunnelID := tunnel.TunnelID
	clientID := tunnel.ClientID
	client := tunnel.Client

	tm.AddExternalConn(connID, tunnelID, extConn)
	defer tm.RemoveExternalConn(connID)

	slog.Debug("external connection accepted",
		"conn_id", connID,
		"tunnel_id", tunnelID,
		"remote", extConn.RemoteAddr())

	readDeadline := 15 * time.Minute
	extConn.SetReadDeadline(time.Now().Add(readDeadline))

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		n, err := extConn.Read(buf)
		if n > 0 {
			extConn.SetReadDeadline(time.Now().Add(readDeadline))
		}
		if n > 0 {
			encrypted, encErr := tm.server.cryptoMgr.EncryptBytes(clientID, buf[:n])
			if encErr != nil {
				slog.Error("failed to encrypt tunnel data",
					"conn_id", connID,
					"error", encErr)
				return
			}
			frame, frameErr := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, encrypted, false)
			if frameErr != nil {
				slog.Error("failed to encode tunnel data frame",
					"conn_id", connID,
					"error", frameErr)
				return
			}
			if client == nil {
				slog.Warn("tunnel client disconnected, dropping data",
					"tunnel_id", tunnelID)
				return
			}
			err := client.WriteMessage(websocket.BinaryMessage, frame)
			if err != nil {
				slog.Warn("failed to send tunnel_data_bin to agent",
					"conn_id", connID,
					"error", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Warn("external conn read error",
					"conn_id", connID,
					"error", err)
			} else {
				slog.Debug("external conn closed",
					"conn_id", connID,
					"error", err)
			}
			if client != nil {
				if frame, frameErr := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, nil, true); frameErr == nil {
					client.WriteMessage(websocket.BinaryMessage, frame)
				}
			}
			return
		}
	}
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
	unavailable := make([]int, 0, len(tm.unavailablePorts))
	for port := range tm.unavailablePorts {
		unavailable = append(unavailable, port)
	}
	sort.Ints(unavailable)

	return PortStatus{
		RangeStart:     tm.portStart,
		RangeEnd:       tm.portEnd,
		TotalPorts:     total,
		Allocated:      len(tm.publicPorts),
		Unavailable:    unavailable,
		AvailableCount: total - len(tm.publicPorts) - len(tm.unavailablePorts),
	}
}

// SendToClient 向客户端发送隧道数据
func (tm *TunnelManager) SendToClient(tunnelID, connID string, data []byte, isEOF bool) error {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	tm.mu.RUnlock()

	if !ok || tunnel.Client == nil {
		return fmt.Errorf("tunnel or client not found: %s", tunnelID)
	}

	if tm.server.cryptoMgr == nil {
		return fmt.Errorf("encryption not available")
	}

	if isEOF && len(data) == 0 {
		frame, err := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, nil, true)
		if err != nil {
			return err
		}
		return tunnel.Client.WriteMessage(websocket.BinaryMessage, frame)
	}

	encrypted, err := tm.server.cryptoMgr.EncryptBytes(tunnel.ClientID, data)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	frame, err := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, encrypted, isEOF)
	if err != nil {
		return err
	}
	return tunnel.Client.WriteMessage(websocket.BinaryMessage, frame)
}

// HandleAgentData 处理来自 Agent 的隧道数据，转发到外部连接
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

	if len(data) > 0 {
		ec.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := ec.Conn.Write(data); err != nil {
			tm.RemoveExternalConn(connID)
			if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("external connection closed while writing tunnel data",
					"tunnel_id", tunnelID,
					"conn_id", connID,
					"error", err)
				return nil
			}
			return err
		}
		ec.Conn.SetWriteDeadline(time.Time{})
	}

	if isEOF {
		tm.RemoveExternalConn(connID)
	}

	return nil
}

// SendTunnelError 发送隧道错误到 Agent
func (tm *TunnelManager) SendTunnelError(tunnelID, connID, errMsg string) error {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	tm.mu.RUnlock()

	if !ok || tunnel.Client == nil {
		return fmt.Errorf("tunnel or client not found: %s", tunnelID)
	}

	payload := common.TunnelErrorPayload{
		TunnelID: tunnelID,
		ConnID:   connID,
		Error:    errMsg,
	}
	payloadJSON, _ := json.Marshal(payload)

	return tunnel.Client.WriteJSON(common.Message{
		Type:    "tunnel_error",
		Payload: payloadJSON,
	})
}
