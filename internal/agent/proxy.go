package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"goremote/internal/common"
)

type ProxyConn struct {
	ProxyID string
	ConnID  string
	Conn    net.Conn
}

type ProxyManager struct {
	mu        sync.RWMutex
	proxies   map[string]struct{}
	conns     map[string]*ProxyConn
	readLoops map[string]bool
	agent     *Agent
}

func NewProxyManager(agent *Agent) *ProxyManager {
	return &ProxyManager{
		proxies:   make(map[string]struct{}),
		conns:     make(map[string]*ProxyConn),
		readLoops: make(map[string]bool),
		agent:     agent,
	}
}

func (pm *ProxyManager) OpenProxyConn(proxyID, connID, host string, port int) error {
	pm.mu.Lock()
	pm.proxies[proxyID] = struct{}{}
	pm.mu.Unlock()

	if err := validateProxyTarget(host, port); err != nil {
		pm.SendError(proxyID, connID, err.Error())
		return err
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		pm.SendError(proxyID, connID, err.Error())
		return fmt.Errorf("failed to connect proxy target: %w", err)
	}
	common.TuneTCPConn(conn)

	pm.mu.Lock()
	if existing, ok := pm.conns[connID]; ok {
		pm.mu.Unlock()
		conn.Close()
		return fmt.Errorf("proxy conn already exists: %s/%s", existing.ProxyID, connID)
	}
	pm.conns[connID] = &ProxyConn{ProxyID: proxyID, ConnID: connID, Conn: conn}
	pm.mu.Unlock()

	slog.Debug("proxy target connected", "proxy_id", proxyID, "conn_id", connID, "target", addr)
	pm.StartReadLoop(proxyID, connID)
	return nil
}

func validateProxyTarget(host string, port int) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("target host is required")
	}
	if strings.ContainsAny(host, "\x00\r\n\t ") {
		return fmt.Errorf("target host contains invalid whitespace or control characters")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("target port must be in range 1-65535")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("localhost target is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("unsafe target IP is not allowed")
		}
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return fmt.Errorf("metadata service target is not allowed")
		}
	}
	return nil
}

func (pm *ProxyManager) HandleServerData(proxyID, connID string, data []byte, isEOF bool) error {
	pm.mu.RLock()
	pc, ok := pm.conns[connID]
	pm.mu.RUnlock()
	if !ok {
		return nil
	}
	if pc.ProxyID != proxyID {
		return fmt.Errorf("conn %s does not belong to proxy %s", connID, proxyID)
	}

	if len(data) > 0 {
		pc.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := pc.Conn.Write(data); err != nil {
			pm.CloseProxyConn(proxyID, connID)
			pm.SendError(proxyID, connID, err.Error())
			return err
		}
		pc.Conn.SetWriteDeadline(time.Time{})
	}
	if isEOF {
		pm.CloseProxyConn(proxyID, connID)
	}
	return nil
}

func (pm *ProxyManager) StartReadLoop(proxyID, connID string) {
	pm.mu.Lock()
	if pm.readLoops[connID] {
		pm.mu.Unlock()
		return
	}
	pc, ok := pm.conns[connID]
	if !ok {
		pm.mu.Unlock()
		return
	}
	pm.readLoops[connID] = true
	pm.mu.Unlock()

	go pm.readFromTarget(proxyID, connID, pc.Conn)
}

func (pm *ProxyManager) readFromTarget(proxyID, connID string, conn net.Conn) {
	defer func() {
		pm.mu.Lock()
		delete(pm.readLoops, connID)
		pm.mu.Unlock()
	}()

	bufPtr := agentBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer agentBufPool.Put(bufPtr)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := pm.SendData(proxyID, connID, buf[:n], false); sendErr != nil {
				slog.Warn("failed to send proxy response", "proxy_id", proxyID, "conn_id", connID, "error", sendErr)
				break
			}
		}
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Warn("proxy target read error", "proxy_id", proxyID, "conn_id", connID, "error", err)
			}
			pm.SendData(proxyID, connID, nil, true)
			break
		}
	}
}

func (pm *ProxyManager) SendData(proxyID, connID string, data []byte, isEOF bool) error {
	if isEOF && len(data) == 0 {
		frame, err := common.EncodeBinaryTunnelDataFrame(proxyID, connID, nil, true)
		if err != nil {
			return err
		}
		if err := pm.agent.connector.SendBinary(frame); err != nil {
			pm.CloseProxyConn(proxyID, connID)
			return err
		}
		pm.CloseProxyConn(proxyID, connID)
		return nil
	}

	encrypted, err := pm.agent.encryptTunnelBytes(data)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}
	frame, err := common.EncodeBinaryTunnelDataFrame(proxyID, connID, encrypted, isEOF)
	if err != nil {
		return err
	}
	if err := pm.agent.connector.SendBinary(frame); err != nil {
		if isEOF {
			pm.CloseProxyConn(proxyID, connID)
		}
		return err
	}
	if isEOF {
		pm.CloseProxyConn(proxyID, connID)
	}
	return nil
}

func (pm *ProxyManager) CloseProxy(proxyID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for connID, pc := range pm.conns {
		if pc.ProxyID == proxyID {
			pc.Conn.Close()
			delete(pm.conns, connID)
			delete(pm.readLoops, connID)
		}
	}
	delete(pm.proxies, proxyID)
}

func (pm *ProxyManager) CloseProxyConn(proxyID, connID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pc, ok := pm.conns[connID]; ok && pc.ProxyID == proxyID {
		pc.Conn.Close()
		delete(pm.conns, connID)
		delete(pm.readLoops, connID)
	}
}

func (pm *ProxyManager) Cleanup() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for connID, pc := range pm.conns {
		pc.Conn.Close()
		delete(pm.conns, connID)
	}
	pm.proxies = make(map[string]struct{})
	pm.readLoops = make(map[string]bool)
}

func (pm *ProxyManager) HasProxy(proxyID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.proxies[proxyID]
	return ok
}

func (pm *ProxyManager) HasConn(connID, proxyID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	pc, ok := pm.conns[connID]
	return ok && pc.ProxyID == proxyID
}

func (pm *ProxyManager) SendError(proxyID, connID, errMsg string) {
	payload := common.ProxyErrorPayload{ProxyID: proxyID, ConnID: connID, Error: errMsg}
	payloadJSON, _ := json.Marshal(payload)
	if err := pm.agent.connector.Send(&common.Message{Type: "proxy_error", Payload: payloadJSON}); err != nil {
		slog.Warn("failed to send proxy error to server", "proxy_id", proxyID, "conn_id", connID, "error", err)
	}
}
