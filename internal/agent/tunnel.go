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

// Tunnel tracks agent-side tunnel metadata.
type Tunnel struct {
	TunnelID   string
	LocalAddr  string
	LocalPort  int
	Protocol   string
	PublicPort int
}

// LocalConn represents one proxied local connection keyed by conn_id.
type LocalConn struct {
	ConnID   string
	TunnelID string
	Conn     net.Conn
}

// TunnelManager manages local tunnel state on the agent.
type TunnelManager struct {
	mu         sync.RWMutex
	tunnels    map[string]*Tunnel
	localConns map[string]*LocalConn
	readLoops  map[string]bool
	agent      *Agent
}

func localServiceAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// NewTunnelManager creates a new TunnelManager.
func NewTunnelManager(agent *Agent) *TunnelManager {
	return &TunnelManager{
		tunnels:    make(map[string]*Tunnel),
		localConns: make(map[string]*LocalConn),
		readLoops:  make(map[string]bool),
		agent:      agent,
	}
}

// CreateTunnel stores tunnel metadata.
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

// GetTunnel returns tunnel metadata by ID.
func (tm *TunnelManager) GetTunnel(tunnelID string) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnel, ok := tm.tunnels[tunnelID]
	return tunnel, ok
}

// ListTunnels returns all known tunnels.
func (tm *TunnelManager) ListTunnels() []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	return tunnels
}

// CloseTunnel removes a tunnel and closes any related local connections.
func (tm *TunnelManager) CloseTunnel(tunnelID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, ok := tm.tunnels[tunnelID]; !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}

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

// GetOrCreateLocalConn returns the local service connection for connID.
func (tm *TunnelManager) GetOrCreateLocalConn(connID, tunnelID string) (net.Conn, error) {
	tm.mu.RLock()
	lc, ok := tm.localConns[connID]
	tm.mu.RUnlock()
	if ok {
		return lc.Conn, nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if lc, ok := tm.localConns[connID]; ok {
		return lc.Conn, nil
	}

	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	addr := localServiceAddr(tunnel.LocalAddr, tunnel.LocalPort)
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

// CloseLocalConn closes a proxied local connection by connID.
func (tm *TunnelManager) CloseLocalConn(connID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if lc, ok := tm.localConns[connID]; ok {
		lc.Conn.Close()
		delete(tm.localConns, connID)
		slog.Info("local connection closed", "conn_id", connID)
	}
}

// HandleData forwards data from the server to the local service.
func (tm *TunnelManager) HandleData(connID, tunnelID string, data []byte, isEOF bool) error {
	conn, err := tm.GetOrCreateLocalConn(connID, tunnelID)
	if err != nil {
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

// HandleLocalResponse forwards local service data back to the server.
func (tm *TunnelManager) HandleLocalResponse(connID, tunnelID string, data []byte, isEOF bool) error {
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

// SendError forwards a tunnel error to the server.
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

// ReadFromLocal starts a goroutine that reads from one local connection.
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
				tm.HandleLocalResponse(connID, tunnelID, nil, true)
				break
			}
		}
	}()
}

// OpenTunnel asks the server to create a new tunnel.
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

	return tunnelID, 0, nil
}

// CloseTunnelConn closes one proxied connection and informs the server.
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

// StartReadLoop starts the local read loop once per connID.
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
