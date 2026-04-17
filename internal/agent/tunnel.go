package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"goremote/internal/common"
)

// Tunnel 隧道信息
type Tunnel struct {
	TunnelID   string
	LocalAddr  string
	LocalPort  int
	Protocol   string
	PublicPort int // 服务端分配的公网端口
}

// LocalConn 本地连接（按 conn_id 区分）
type LocalConn struct {
	ConnID   string
	TunnelID string
	Conn     net.Conn // 连接本地服务的 conn
}

// TunnelManager 隧道管理器
type TunnelManager struct {
	mu         sync.RWMutex
	tunnels    map[string]*Tunnel     // tunnelID -> Tunnel
	localConns map[string]*LocalConn // connID -> LocalConn
	readLoops  map[string]bool       // connID -> 是否已有读取 goroutine
	agent      *Agent
}

// NewTunnelManager creates a new TunnelManager
func NewTunnelManager(agent *Agent) *TunnelManager {
	return &TunnelManager{
		tunnels:    make(map[string]*Tunnel),
		localConns: make(map[string]*LocalConn),
		readLoops:  make(map[string]bool),
		agent:      agent,
	}
}

// CreateTunnel 创建隧道记录
func (tm *TunnelManager) CreateTunnel(tunnelID, localAddr string, localPort int, protocol string, publicPort int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.tunnels[tunnelID] = &Tunnel{
		TunnelID:   tunnelID,
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		Protocol:   protocol,
		PublicPort: publicPort,
	}

	slog.Info("tunnel created",
		"tunnel_id", tunnelID,
		"local_addr", localAddr,
		"local_port", localPort,
		"public_port", publicPort)
}

// GetTunnel 获取隧道
func (tm *TunnelManager) GetTunnel(tunnelID string) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
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
	return tunnels
}

// CloseTunnel 关闭隧道
func (tm *TunnelManager) CloseTunnel(tunnelID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, ok := tm.tunnels[tunnelID]; !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	// 关闭所有本地连接
	for connID, lc := range tm.localConns {
		if lc.TunnelID == tunnelID {
			lc.Conn.Close()
			delete(tm.localConns, connID)
		}
	}

	delete(tm.tunnels, tunnelID)
	slog.Info("tunnel closed", "tunnel_id", tunnelID)

	return nil
}

// GetOrCreateLocalConn 获取或创建到本地服务的连接
func (tm *TunnelManager) GetOrCreateLocalConn(connID, tunnelID string) (net.Conn, error) {
	tm.mu.RLock()
	lc, ok := tm.localConns[connID]
	tm.mu.RUnlock()

	if ok {
		return lc.Conn, nil
	}

	// 需要创建新连接
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// 再次检查（防止并发）
	if lc, ok := tm.localConns[connID]; ok {
		return lc.Conn, nil
	}

	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	// 连接到本地服务
	addr := fmt.Sprintf("%s:%d", tunnel.LocalAddr, tunnel.LocalPort)
	conn, err := net.DialTimeout(tunnel.Protocol, addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to local service: %w", err)
	}

	lc = &LocalConn{
		ConnID:   connID,
		TunnelID: tunnelID,
		Conn:     conn,
	}
	tm.localConns[connID] = lc

	slog.Info("local connection established",
		"conn_id", connID,
		"tunnel_id", tunnelID,
		"local_addr", addr)

	return conn, nil
}

// CloseLocalConn 关闭本地连接
func (tm *TunnelManager) CloseLocalConn(connID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if lc, ok := tm.localConns[connID]; ok {
		lc.Conn.Close()
		delete(tm.localConns, connID)
		slog.Info("local connection closed", "conn_id", connID)
	}
}

// HandleData 处理来自服务端的隧道数据，转发到本地服务
func (tm *TunnelManager) HandleData(connID, tunnelID string, data []byte, isEOF bool) error {
	conn, err := tm.GetOrCreateLocalConn(connID, tunnelID)
	if err != nil {
		// 发送错误到服务端
		tm.SendError(tunnelID, connID, err.Error())
		return err
	}

	if _, err := conn.Write(data); err != nil {
		tm.CloseLocalConn(connID)
		tm.SendError(tunnelID, connID, err.Error())
		return err
	}

	if isEOF {
		tm.CloseLocalConn(connID)
	}

	return nil
}

// HandleLocalResponse 处理本地服务响应，转发给服务端
func (tm *TunnelManager) HandleLocalResponse(connID, tunnelID string, data []byte, isEOF bool) error {
	// 验证隧道存在
	if _, ok := tm.GetTunnel(tunnelID); !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	payload := common.TunnelDataPayload{
		TunnelID: tunnelID,
		ConnID:   connID,
		Data:     base64.StdEncoding.EncodeToString(data),
		IsEOF:    isEOF,
	}
	payloadJSON, _ := json.Marshal(payload)

	err := tm.agent.connector.Send(&common.Message{
		Type:    "tunnel_data",
		Payload: payloadJSON,
	})

	if isEOF {
		tm.CloseLocalConn(connID)
	}

	return err
}

// SendError 发送隧道错误到服务端
func (tm *TunnelManager) SendError(tunnelID, connID, errMsg string) {
	payload := common.TunnelErrorPayload{
		TunnelID: tunnelID,
		ConnID:   connID,
		Error:    errMsg,
	}
	payloadJSON, _ := json.Marshal(payload)
	tm.agent.connector.Send(&common.Message{
		Type:    "tunnel_error",
		Payload: payloadJSON,
	})
}

// ReadFromLocal 启动从本地连接读取响应的 goroutine
func (tm *TunnelManager) ReadFromLocal(connID, tunnelID string, localConn net.Conn) {
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				if err := tm.HandleLocalResponse(connID, tunnelID, buf[:n], false); err != nil {
					slog.Warn("failed to send response to server",
						"conn_id", connID,
						"error", err)
					break
				}
			}
			if err != nil {
				if err != io.EOF {
					slog.Warn("local conn read error",
						"conn_id", connID,
						"error", err)
				}
				// 发送 EOF
				tm.HandleLocalResponse(connID, tunnelID, nil, true)
				break
			}
		}
	}()
}

// OpenTunnel 发起创建隧道请求
func (tm *TunnelManager) OpenTunnel(localAddr string, localPort int, protocol string) (string, int, error) {
	tunnelID := fmt.Sprintf("tunnel-%d", time.Now().UnixNano())

	payload := common.TunnelOpenPayload{
		TunnelID:  tunnelID,
		LocalAddr: localAddr,
		LocalPort: localPort,
		Protocol:  protocol,
	}
	payloadJSON, _ := json.Marshal(payload)

	err := tm.agent.connector.Send(&common.Message{
		Type:    "tunnel_open",
		Payload: payloadJSON,
	})
	if err != nil {
		return "", 0, err
	}

	return tunnelID, 0, nil // publicPort 将在 ack 中获取
}

// CloseTunnelConn 关闭指定连接
func (tm *TunnelManager) CloseTunnelConn(tunnelID, connID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if lc, ok := tm.localConns[connID]; ok {
		lc.Conn.Close()
		delete(tm.localConns, connID)
	}

	payload := common.TunnelClosePayload{
		TunnelID: tunnelID,
		ConnID:   connID,
	}
	payloadJSON, _ := json.Marshal(payload)
	return tm.agent.connector.Send(&common.Message{
		Type:    "tunnel_close",
		Payload: payloadJSON,
	})
}

// StartReadLoop 启动读取本地响应的 goroutine（如果还没有启动）
func (tm *TunnelManager) StartReadLoop(connID, tunnelID string) {
	tm.mu.Lock()
	if tm.readLoops[connID] {
		tm.mu.Unlock()
		return
	}
	tm.readLoops[connID] = true

	lc, ok := tm.localConns[connID]
	tm.mu.Unlock()

	if !ok {
		return
	}

	go tm.readFromLocal(connID, tunnelID, lc.Conn)
}

// readFromLocal 从本地连接读取响应
func (tm *TunnelManager) readFromLocal(connID, tunnelID string, localConn net.Conn) {
	defer func() {
		tm.mu.Lock()
		delete(tm.readLoops, connID)
		tm.mu.Unlock()
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			if err := tm.HandleLocalResponse(connID, tunnelID, buf[:n], false); err != nil {
				slog.Warn("failed to send response to server",
					"conn_id", connID,
					"error", err)
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				slog.Warn("local conn read error",
					"conn_id", connID,
					"error", err)
			}
			tm.HandleLocalResponse(connID, tunnelID, nil, true)
			break
		}
	}
}
