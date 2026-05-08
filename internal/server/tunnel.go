package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"goremote/internal/common"
)

// Tunnel 隧道信息
type Tunnel struct {
	TunnelID   string
	ClientID   string
	Client     *Client   `json:"-"` // WebSocket 连接 (not serialized)
	Protocol   string
	PublicPort int    // 监听的公网端口
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
	mu          sync.RWMutex
	tunnels     map[string]*Tunnel       // tunnelID -> Tunnel
	publicPorts map[int]string           // publicPort -> tunnelID
	extConns    map[string]*ExternalConn // connID -> ExternalConn
	portStart   int
	portEnd     int
	listeners   map[int]net.Listener // publicPort -> 监听器
	server      *Server
}

// NewTunnelManager creates a new TunnelManager
func NewTunnelManager(server *Server, portStart, portEnd int) *TunnelManager {
	return &TunnelManager{
		tunnels:     make(map[string]*Tunnel),
		publicPorts: make(map[int]string),
		extConns:    make(map[string]*ExternalConn),
		portStart:   portStart,
		portEnd:     portEnd,
		listeners:   make(map[int]net.Listener),
		server:      server,
	}
}

// AllocatePort 分配一个可用端口
func (tm *TunnelManager) AllocatePort() (int, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for port := tm.portStart; port <= tm.portEnd; port++ {
		if _, used := tm.publicPorts[port]; !used {
			tm.publicPorts[port] = "" // 临时标记为已用
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports in range %d-%d", tm.portStart, tm.portEnd)
}

// ReleasePort 释放端口
func (tm *TunnelManager) ReleasePort(port int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.publicPorts, port)
}

// CreateTunnel 创建隧道
func (tm *TunnelManager) CreateTunnel(tunnelID, clientID string, client *Client, protocol, localAddr string, localPort, publicPort int) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

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

func (tm *TunnelManager) UpdateTunnel(tunnelID string, localAddr string, localPort int, newPublicPort int, protocol string) (*Tunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	if tunnel.Status != "active" {
		return nil, fmt.Errorf("tunnel is not active, current status: %s", tunnel.Status)
	}

	// 处理公网端口变更
	portChanged := newPublicPort > 0 && newPublicPort != tunnel.PublicPort
	if portChanged {
		// 校验端口范围
		if newPublicPort < tm.portStart || newPublicPort > tm.portEnd {
			return nil, fmt.Errorf("public port %d out of range [%d, %d]", newPublicPort, tm.portStart, tm.portEnd)
		}
		// 校验端口未被其他隧道占用
		if existingID, used := tm.publicPorts[newPublicPort]; used && existingID != "" && existingID != tunnelID {
			return nil, fmt.Errorf("public port %d already in use", newPublicPort)
		}

		// 关闭旧监听器和连接
		tm.closeTunnelConnections(tunnelID)
		if oldListener, ok := tm.listeners[tunnel.PublicPort]; ok {
			oldListener.Close()
			delete(tm.listeners, tunnel.PublicPort)
		}

		// 更新端口映射
		oldPort := tunnel.PublicPort
		delete(tm.publicPorts, oldPort)
		tm.publicPorts[newPublicPort] = tunnelID
		tunnel.PublicPort = newPublicPort

		slog.Info("tunnel public port changed", "tunnel_id", tunnelID, "old_port", oldPort, "new_port", newPublicPort)

		// 启动新监听器（内部不加锁，因为当前已持有锁）
		if err := tm.startListener(newPublicPort, tunnelID); err != nil {
			// 回滚端口映射
			delete(tm.publicPorts, newPublicPort)
			tm.publicPorts[tunnel.PublicPort] = tunnelID
			return nil, fmt.Errorf("failed to start listener on new port %d: %w", newPublicPort, err)
		}
	}

	// 通知 Agent 更新目标地址
	targetChanged := localAddr != tunnel.LocalAddr || localPort != tunnel.LocalPort || protocol != tunnel.Protocol || portChanged
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

	slog.Info("tunnel updated", "tunnel_id", tunnelID, "public_port", tunnel.PublicPort, "local_addr", localAddr, "local_port", localPort, "protocol", protocol)
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

// Listen 开始监听公网端口（加锁，外部调用）
func (tm *TunnelManager) Listen(publicPort int, tunnelID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.startListener(publicPort, tunnelID)
}

// startListener 启动监听器（不加锁，由调用方保证线程安全）
func (tm *TunnelManager) startListener(publicPort int, tunnelID string) error {
	addr := fmt.Sprintf(":%d", publicPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", publicPort, err)
	}

	tm.listeners[publicPort] = listener
	slog.Info("tunnel listener started", "public_port", publicPort, "tunnel_id", tunnelID)

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
			_, stillOk := tm.listeners[publicPort]
			tm.mu.RUnlock()
			if !stillOk {
				return
			}
			slog.Warn("accept error", "public_port", publicPort, "error", err)
			continue
		}

		// 生成 connID 并处理连接
		connID := fmt.Sprintf("%s-%d", tunnelID, time.Now().UnixNano())
		go tm.handleExternalConn(connID, tunnel, conn)
	}
}

// handleExternalConn 处理外部连接
func (tm *TunnelManager) handleExternalConn(connID string, tunnel *Tunnel, extConn net.Conn) {
	tm.AddExternalConn(connID, tunnel.TunnelID, extConn)
	defer tm.RemoveExternalConn(connID)

	slog.Info("external connection accepted",
		"conn_id", connID,
		"tunnel_id", tunnel.TunnelID,
		"remote", extConn.RemoteAddr())

	// 通知 Agent 有新的外部连接，等待本地连接建立
	// Agent 收到 tunnel_data 时会建立到本地服务的连接

	// 用于缓冲读写
	buf := make([]byte, 32*1024)
	for {
		n, err := extConn.Read(buf)
		if n > 0 {
			encoded, encErr := tm.server.crypto.Encrypt(buf[:n])
			if encErr != nil {
				slog.Error("failed to encrypt tunnel data",
					"conn_id", connID,
					"error", encErr)
				return
			}
			payload := common.TunnelDataPayload{
				TunnelID: tunnel.TunnelID,
				ConnID:   connID,
				Data:     encoded,
				IsEOF:    false,
			}
			payloadJSON, _ := json.Marshal(payload)
			err := tunnel.Client.WriteJSON(common.Message{
				Type:    "tunnel_data",
				Payload: payloadJSON,
			})
			if err != nil {
				slog.Warn("failed to send tunnel_data to agent",
					"conn_id", connID,
					"error", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				slog.Warn("external conn read error",
					"conn_id", connID,
					"error", err)
			}
			// 发送 EOF 通知
			payload := common.TunnelDataPayload{
				TunnelID: tunnel.TunnelID,
				ConnID:   connID,
				Data:     "",
				IsEOF:    true,
			}
			payloadJSON, _ := json.Marshal(payload)
			tunnel.Client.WriteJSON(common.Message{
				Type:    "tunnel_data",
				Payload: payloadJSON,
			})
			return
		}
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

	if tm.server.crypto == nil {
		return fmt.Errorf("encryption not available")
	}

	encoded, err := tm.server.crypto.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	payload := common.TunnelDataPayload{
		TunnelID: tunnelID,
		ConnID:   connID,
		Data:     encoded,
		IsEOF:    isEOF,
	}
	payloadJSON, _ := json.Marshal(payload)

	return tunnel.Client.WriteJSON(common.Message{
		Type:    "tunnel_data",
		Payload: payloadJSON,
	})
}

// HandleAgentData 处理来自 Agent 的隧道数据，转发到外部连接
func (tm *TunnelManager) HandleAgentData(tunnelID, connID string, data []byte, isEOF bool) error {
	tm.mu.RLock()
	ec, ok := tm.extConns[connID]
	tm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("external connection not found: %s", connID)
	}

	if _, err := ec.Conn.Write(data); err != nil {
		return err
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
