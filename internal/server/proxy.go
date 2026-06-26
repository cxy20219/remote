package server

import (
	"bytes"
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
	ProxyProtocolSOCKS5 = "socks5"

	socks5Version          = byte(0x05)
	socks5NoAuth           = byte(0x00)
	socks5UserPassAuth     = byte(0x02)
	socks5NoAcceptableAuth = byte(0xff)
	socks5ConnectCommand   = byte(0x01)
	socks5Reserved         = byte(0x00)
	socks5IPv4             = byte(0x01)
	socks5Domain           = byte(0x03)
	socks5IPv6             = byte(0x04)
)

type Proxy struct {
	ProxyID      string    `json:"proxy_id"`
	ClientID     string    `json:"client_id"`
	Client       *Client   `json:"-"`
	Protocol     string    `json:"protocol"`
	PublicPort   int       `json:"public_port"`
	Exposure     string    `json:"exposure"`
	BindAddr     string    `json:"bind_addr"`
	Username     string    `json:"username,omitempty"`
	AuthEnabled  bool      `json:"auth_enabled"`
	CreatedAt    time.Time `json:"created_at"`
	Status       string    `json:"status"`
	reservedPort bool
	password     string
}

type ProxyConn struct {
	ConnID  string
	ProxyID string
	Conn    net.Conn
}

type ProxyManager struct {
	mu        sync.RWMutex
	proxies   map[string]*Proxy
	listeners map[int]net.Listener
	extConns  map[string]*ProxyConn
	server    *Server
}

func NewProxyManager(server *Server) *ProxyManager {
	return &ProxyManager{
		proxies:   make(map[string]*Proxy),
		listeners: make(map[int]net.Listener),
		extConns:  make(map[string]*ProxyConn),
		server:    server,
	}
}

func (pm *ProxyManager) CreateProxy(clientID string, client *Client, publicPort int, exposure, username, password string) (*Proxy, error) {
	exposure, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return nil, err
	}

	username = strings.TrimSpace(username)
	authEnabled := username != "" || password != ""
	if exposure == TunnelExposurePublic && !authEnabled {
		return nil, fmt.Errorf("public proxy requires username/password authentication")
	}
	if authEnabled && (username == "" || password == "") {
		return nil, fmt.Errorf("username and password are both required when proxy auth is enabled")
	}

	proxyID := generateUUID()
	ln, reservedPort, err := pm.listen(publicPort, exposure, bindAddr, proxyID)
	if err != nil {
		return nil, err
	}
	if publicPort == 0 {
		publicPort = ln.Addr().(*net.TCPAddr).Port
	}

	proxy := &Proxy{
		ProxyID:      proxyID,
		ClientID:     clientID,
		Client:       client,
		Protocol:     ProxyProtocolSOCKS5,
		PublicPort:   publicPort,
		Exposure:     exposure,
		BindAddr:     bindAddr,
		Username:     username,
		AuthEnabled:  authEnabled,
		CreatedAt:    time.Now(),
		Status:       "active",
		reservedPort: reservedPort,
		password:     password,
	}

	pm.mu.Lock()
	pm.proxies[proxy.ProxyID] = proxy
	pm.listeners[publicPort] = ln
	pm.mu.Unlock()

	go pm.acceptLoop(proxy.ProxyID, publicPort, ln)
	slog.Info("proxy created", "proxy_id", proxy.ProxyID, "client_id", clientID, "public_port", publicPort, "exposure", exposure, "bind_addr", ln.Addr().String())
	return proxy, nil
}

func (pm *ProxyManager) listen(publicPort int, exposure, bindAddr, proxyID string) (net.Listener, bool, error) {
	if publicPort == 0 {
		if pm.server == nil || pm.server.tunnelManager == nil {
			return nil, false, fmt.Errorf("tunnel port allocator is not available")
		}
		_, ln, err := pm.server.tunnelManager.AllocatePortForExposure(exposure)
		return ln, true, err
	}
	reservedPort := false
	if pm.server != nil && pm.server.tunnelManager != nil {
		reserved, err := pm.server.tunnelManager.ReservePort(publicPort, proxyID)
		if err != nil {
			return nil, false, err
		}
		reservedPort = reserved
	}
	ln, err := net.Listen("tcp", listenAddrForBind(bindAddr, publicPort))
	if err != nil {
		if reservedPort {
			pm.server.tunnelManager.ReleasePort(publicPort)
		}
		return nil, false, fmt.Errorf("failed to bind proxy port %d on %s: %w", publicPort, bindAddr, err)
	}
	return ln, reservedPort, nil
}

func (pm *ProxyManager) GetProxy(proxyID string) (*Proxy, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	proxy, ok := pm.proxies[proxyID]
	return proxy, ok
}

func (pm *ProxyManager) HasProxy(proxyID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.proxies[proxyID]
	return ok
}

func (pm *ProxyManager) ListProxies() []*Proxy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	proxies := make([]*Proxy, 0, len(pm.proxies))
	for _, proxy := range pm.proxies {
		proxies = append(proxies, proxy)
	}
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].CreatedAt.Before(proxies[j].CreatedAt)
	})
	return proxies
}

func (pm *ProxyManager) ListProxiesByClient(clientID string) []*Proxy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	proxies := make([]*Proxy, 0)
	for _, proxy := range pm.proxies {
		if proxy.ClientID == clientID {
			proxies = append(proxies, proxy)
		}
	}
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].CreatedAt.Before(proxies[j].CreatedAt)
	})
	return proxies
}

func (pm *ProxyManager) CloseProxy(proxyID string) error {
	pm.mu.Lock()
	proxy, ok := pm.proxies[proxyID]
	if !ok {
		pm.mu.Unlock()
		return fmt.Errorf("proxy not found: %s", proxyID)
	}
	proxy.Status = "closing"
	if listener, ok := pm.listeners[proxy.PublicPort]; ok {
		listener.Close()
		delete(pm.listeners, proxy.PublicPort)
	}
	for connID, conn := range pm.extConns {
		if conn.ProxyID == proxyID {
			conn.Conn.Close()
			delete(pm.extConns, connID)
		}
	}
	delete(pm.proxies, proxyID)
	pm.mu.Unlock()

	if proxy.reservedPort && pm.server.tunnelManager != nil {
		pm.server.tunnelManager.ReleasePort(proxy.PublicPort)
	}
	if proxy.Client != nil {
		payloadJSON, _ := json.Marshal(common.ProxyClosePayload{ProxyID: proxyID})
		proxy.Client.WriteJSON(common.Message{Type: "proxy_close", Payload: payloadJSON})
	}

	slog.Info("proxy closed", "proxy_id", proxyID)
	return nil
}

func (pm *ProxyManager) CloseProxiesByClient(clientID string) {
	pm.mu.RLock()
	proxyIDs := make([]string, 0)
	for _, proxy := range pm.proxies {
		if proxy.ClientID == clientID {
			proxyIDs = append(proxyIDs, proxy.ProxyID)
		}
	}
	pm.mu.RUnlock()

	for _, proxyID := range proxyIDs {
		if err := pm.CloseProxy(proxyID); err != nil {
			slog.Warn("failed to close proxy for client", "client_id", clientID, "proxy_id", proxyID, "error", err)
		}
	}
}

func (pm *ProxyManager) CloseAll() {
	pm.mu.RLock()
	proxyIDs := make([]string, 0, len(pm.proxies))
	for proxyID := range pm.proxies {
		proxyIDs = append(proxyIDs, proxyID)
	}
	pm.mu.RUnlock()

	for _, proxyID := range proxyIDs {
		if err := pm.CloseProxy(proxyID); err != nil {
			slog.Warn("failed to close proxy", "proxy_id", proxyID, "error", err)
		}
	}
}

func (pm *ProxyManager) acceptLoop(proxyID string, publicPort int, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			pm.mu.RLock()
			current := pm.listeners[publicPort]
			pm.mu.RUnlock()
			if current != listener {
				return
			}
			slog.Warn("proxy accept error", "proxy_id", proxyID, "public_port", publicPort, "error", err)
			continue
		}

		proxy, ok := pm.GetProxy(proxyID)
		if !ok {
			conn.Close()
			return
		}
		if !pm.allowExternalConn(proxy, conn) {
			conn.Close()
			continue
		}
		go pm.handleSOCKS5Conn(proxy, conn)
	}
}

func (pm *ProxyManager) allowExternalConn(proxy *Proxy, conn net.Conn) bool {
	remoteIP := extractIP(conn.RemoteAddr().String())
	if remoteIP == "127.0.0.1" || remoteIP == "::1" {
		return true
	}
	if pm.server.IsGloballyWhitelisted(remoteIP) {
		return true
	}
	if pm.server.clients != nil && proxy.ClientID != "" {
		if isIPWhitelisted(remoteIP, pm.server.clients.GetIPWhitelist(proxy.ClientID)) {
			return true
		}
	}
	if pm.server.blacklist.IsBlacklisted(remoteIP) {
		slog.Warn("proxy connection from blacklisted IP, rejecting", "remote_ip", remoteIP, "proxy_id", proxy.ProxyID)
		return false
	}
	if pm.server.portLimiter != nil && !pm.server.portLimiter.Allow(remoteIP) {
		slog.Warn("proxy connection rate limited", "remote_ip", remoteIP, "proxy_id", proxy.ProxyID)
		pm.server.blacklist.AddViolation(remoteIP)
		return false
	}
	return true
}

func (pm *ProxyManager) handleSOCKS5Conn(proxy *Proxy, extConn net.Conn) {
	common.TuneTCPConn(extConn)
	defer extConn.Close()

	targetHost, targetPort, err := pm.socks5Handshake(proxy, extConn)
	if err != nil {
		slog.Debug("socks5 handshake failed", "proxy_id", proxy.ProxyID, "error", err)
		return
	}
	if err := validateProxyTarget(targetHost, targetPort); err != nil {
		pm.writeSOCKS5Reply(extConn, 0x02)
		slog.Warn("proxy target rejected", "proxy_id", proxy.ProxyID, "target", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)), "error", err)
		return
	}

	connID := fmt.Sprintf("%s-%s", proxy.ProxyID, uuid.New().String()[:8])
	pm.addExternalConn(connID, proxy.ProxyID, extConn)
	defer pm.removeExternalConn(connID)

	openPayload := common.ProxyOpenPayload{ProxyID: proxy.ProxyID, ConnID: connID, Host: targetHost, Port: targetPort}
	payloadJSON, _ := json.Marshal(openPayload)
	if err := proxy.Client.WriteJSON(common.Message{Type: "proxy_open", Payload: payloadJSON}); err != nil {
		slog.Warn("failed to send proxy_open to agent", "proxy_id", proxy.ProxyID, "conn_id", connID, "error", err)
		return
	}
	if err := pm.writeSOCKS5Reply(extConn, 0x00); err != nil {
		return
	}

	pm.readFromExternal(proxy, connID, extConn)
}

func (pm *ProxyManager) socks5Handshake(proxy *Proxy, conn net.Conn) (string, int, error) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	methods, err := readSOCKS5Methods(conn)
	if err != nil {
		return "", 0, err
	}
	method := socks5NoAcceptableAuth
	if proxy.AuthEnabled && bytes.Contains(methods, []byte{socks5UserPassAuth}) {
		method = socks5UserPassAuth
	} else if !proxy.AuthEnabled && bytes.Contains(methods, []byte{socks5NoAuth}) {
		method = socks5NoAuth
	}
	if _, err := conn.Write([]byte{socks5Version, method}); err != nil {
		return "", 0, err
	}
	if method == socks5NoAcceptableAuth {
		return "", 0, fmt.Errorf("no acceptable auth method")
	}
	if method == socks5UserPassAuth {
		if err := pm.authenticateSOCKS5(proxy, conn); err != nil {
			return "", 0, err
		}
	}

	return readSOCKS5ConnectRequest(conn)
}

func readSOCKS5Methods(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported socks version: %d", header[0])
	}
	if header[1] == 0 {
		return nil, fmt.Errorf("missing socks auth methods")
	}
	methods := make([]byte, int(header[1]))
	_, err := io.ReadFull(conn, methods)
	return methods, err
}

func (pm *ProxyManager) authenticateSOCKS5(proxy *Proxy, conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported socks auth version: %d", header[0])
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	password := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if string(username) != proxy.Username || string(password) != proxy.password {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid socks username/password")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSOCKS5ConnectRequest(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socks5Version || header[2] != socks5Reserved {
		return "", 0, fmt.Errorf("invalid socks connect header")
	}
	if header[1] != socks5ConnectCommand {
		return "", 0, fmt.Errorf("unsupported socks command: %d", header[1])
	}

	var host string
	switch header[3] {
	case socks5IPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	case socks5Domain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		if lenBuf[0] == 0 {
			return "", 0, fmt.Errorf("empty socks domain")
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		host = string(domain)
	case socks5IPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	default:
		return "", 0, fmt.Errorf("unsupported socks address type: %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return host, port, nil
}

func (pm *ProxyManager) writeSOCKS5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socks5Version, code, socks5Reserved, socks5IPv4, 0, 0, 0, 0, 0, 0})
	return err
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

func (pm *ProxyManager) addExternalConn(connID, proxyID string, conn net.Conn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.extConns[connID] = &ProxyConn{ConnID: connID, ProxyID: proxyID, Conn: conn}
}

func (pm *ProxyManager) removeExternalConn(connID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if conn, ok := pm.extConns[connID]; ok {
		conn.Conn.Close()
		delete(pm.extConns, connID)
	}
}

func (pm *ProxyManager) readFromExternal(proxy *Proxy, connID string, extConn net.Conn) {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	readDeadline := 15 * time.Minute
	for {
		extConn.SetReadDeadline(time.Now().Add(readDeadline))
		n, err := extConn.Read(buf)
		if n > 0 {
			encrypted, encErr := pm.server.encryptTunnelBytes(proxy.ClientID, buf[:n])
			if encErr != nil {
				slog.Error("failed to encrypt proxy data", "proxy_id", proxy.ProxyID, "conn_id", connID, "error", encErr)
				return
			}
			frame, frameErr := common.EncodeBinaryTunnelDataFrame(proxy.ProxyID, connID, encrypted, false)
			if frameErr != nil {
				slog.Error("failed to encode proxy data frame", "proxy_id", proxy.ProxyID, "conn_id", connID, "error", frameErr)
				return
			}
			if proxy.Client == nil {
				return
			}
			if err := proxy.Client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				slog.Warn("failed to send proxy data to agent", "proxy_id", proxy.ProxyID, "conn_id", connID, "error", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Warn("proxy external conn read error", "proxy_id", proxy.ProxyID, "conn_id", connID, "error", err)
			}
			if proxy.Client != nil {
				if frame, frameErr := common.EncodeBinaryTunnelDataFrame(proxy.ProxyID, connID, nil, true); frameErr == nil {
					proxy.Client.WriteMessage(websocket.BinaryMessage, frame)
				}
			}
			return
		}
	}
}

func (pm *ProxyManager) HandleAgentData(proxyID, connID string, data []byte, isEOF bool) error {
	pm.mu.RLock()
	conn, ok := pm.extConns[connID]
	pm.mu.RUnlock()
	if !ok {
		slog.Debug("proxy external connection already closed, dropping data", "proxy_id", proxyID, "conn_id", connID)
		return nil
	}
	if conn.ProxyID != proxyID {
		return fmt.Errorf("conn %s does not belong to proxy %s", connID, proxyID)
	}

	if len(data) > 0 {
		conn.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Conn.Write(data); err != nil {
			pm.removeExternalConn(connID)
			if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}
		conn.Conn.SetWriteDeadline(time.Time{})
	}

	if isEOF {
		pm.removeExternalConn(connID)
	}
	return nil
}

func (pm *ProxyManager) HandleProxyError(proxyID, connID, errMsg string) error {
	slog.Warn("proxy error from agent", "proxy_id", proxyID, "conn_id", connID, "error", errMsg)
	if connID != "" {
		pm.removeExternalConn(connID)
	}
	return nil
}
