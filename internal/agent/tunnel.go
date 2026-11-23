package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"goremote/internal/common"
)

const (
	localConnQueueSize  = 32
	localQueueWaitLimit = 15 * time.Second
	localDialTimeout    = 10 * time.Second
	localWriteTimeout   = 30 * time.Second
)

var agentBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, common.TunnelChunkSize)
		return &b
	},
}

// Tunnel tracks agent-side tunnel metadata.
type Tunnel struct {
	TunnelID  string
	LocalAddr string
	LocalPort int
	Protocol  string
}

type tunnelChunk struct {
	data []byte
	eof  bool
}

// localConn owns one proxied local service connection. Frames are queued by
// the WebSocket receive loop and written in order by a dedicated goroutine, so
// a slow local service cannot block other tunnels.
type localConn struct {
	connID   string
	tunnelID string

	queue chan tunnelChunk
	done  chan struct{}

	closeOnce    sync.Once
	connMu       sync.Mutex
	conn         net.Conn
	serverClosed atomic.Bool
}

func newLocalConn(connID, tunnelID string) *localConn {
	return &localConn{
		connID:   connID,
		tunnelID: tunnelID,
		queue:    make(chan tunnelChunk, localConnQueueSize),
		done:     make(chan struct{}),
	}
}

func (lc *localConn) push(chunk tunnelChunk) bool {
	select {
	case <-lc.done:
		return false
	default:
	}
	select {
	case <-lc.done:
		return false
	case lc.queue <- chunk:
		return true
	default:
	}

	// Absorb short bursts, then apply backpressure to the WebSocket for a
	// bounded time rather than corrupting a live TCP stream.
	timer := time.NewTimer(localQueueWaitLimit)
	defer timer.Stop()
	select {
	case <-lc.done:
		return false
	case lc.queue <- chunk:
		return true
	case <-timer.C:
		return false
	}
}

func (lc *localConn) setConn(conn net.Conn) {
	lc.connMu.Lock()
	lc.conn = conn
	lc.connMu.Unlock()
}

func (lc *localConn) currentConn() net.Conn {
	lc.connMu.Lock()
	defer lc.connMu.Unlock()
	return lc.conn
}

func (lc *localConn) stop() {
	lc.closeOnce.Do(func() {
		close(lc.done)
		if conn := lc.currentConn(); conn != nil {
			_ = conn.Close()
		}
	})
}

// TunnelManager manages local tunnel state on the agent.
type TunnelManager struct {
	mu         sync.RWMutex
	tunnels    map[string]*Tunnel
	localConns map[string]*localConn
	agent      *Agent
}

func localServiceAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// NewTunnelManager creates a new TunnelManager.
func NewTunnelManager(agent *Agent) *TunnelManager {
	return &TunnelManager{
		tunnels:    make(map[string]*Tunnel),
		localConns: make(map[string]*localConn),
		agent:      agent,
	}
}

// CreateTunnel stores tunnel metadata.
func (tm *TunnelManager) CreateTunnel(tunnelID, localAddr string, localPort int, protocol string) {
	tm.mu.Lock()
	oldTunnelConns := tm.detachTunnelConnsLocked(tunnelID)
	tm.tunnels[tunnelID] = &Tunnel{
		TunnelID:  tunnelID,
		LocalAddr: localAddr,
		LocalPort: localPort,
		Protocol:  protocol,
	}
	tm.mu.Unlock()

	for _, lc := range oldTunnelConns {
		lc.stop()
	}

	slog.Info("tunnel created",
		"tunnel_id", tunnelID,
		"local_addr", localAddr,
		"local_port", localPort)
}

// Cleanup closes all tunnels and local connections. Call on reconnect.
func (tm *TunnelManager) Cleanup() {
	tm.mu.Lock()
	conns := make([]*localConn, 0, len(tm.localConns))
	for connID, lc := range tm.localConns {
		conns = append(conns, lc)
		delete(tm.localConns, connID)
	}
	tm.tunnels = make(map[string]*Tunnel)
	tm.mu.Unlock()

	for _, lc := range conns {
		lc.stop()
	}
	slog.Info("tunnel manager cleaned up", "connections", len(conns))
}

// CloseTunnel removes a tunnel and closes any related local connections.
func (tm *TunnelManager) CloseTunnel(tunnelID string) error {
	tm.mu.Lock()
	if _, ok := tm.tunnels[tunnelID]; !ok {
		tm.mu.Unlock()
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	conns := tm.detachTunnelConnsLocked(tunnelID)
	delete(tm.tunnels, tunnelID)
	tm.mu.Unlock()

	for _, lc := range conns {
		lc.stop()
	}
	slog.Info("tunnel closed", "tunnel_id", tunnelID)
	return nil
}

// detachTunnelConnsLocked removes all local connections of a tunnel from the
// map. The caller must hold tm.mu.
func (tm *TunnelManager) detachTunnelConnsLocked(tunnelID string) []*localConn {
	conns := make([]*localConn, 0)
	for connID, lc := range tm.localConns {
		if lc.tunnelID == tunnelID {
			conns = append(conns, lc)
			delete(tm.localConns, connID)
		}
	}
	return conns
}

// Dispatch queues one tunnel data frame for the local connection. It blocks
// only when the per-connection queue is full, for a bounded time.
func (tm *TunnelManager) Dispatch(connID, tunnelID string, data []byte, isEOF bool) {
	lc, err := tm.getOrCreateLocalConn(connID, tunnelID)
	if err != nil {
		tm.SendError(tunnelID, connID, err.Error())
		if isEOF {
			tm.CloseLocalConn(connID)
		}
		return
	}

	if !lc.push(tunnelChunk{data: data, eof: isEOF}) {
		slog.Warn("local connection queue stalled, closing connection",
			"conn_id", connID, "tunnel_id", tunnelID)
		tm.CloseLocalConn(connID)
		if !isEOF {
			tm.SendError(tunnelID, connID, "local connection queue overflow")
		}
	}
}

func (tm *TunnelManager) getOrCreateLocalConn(connID, tunnelID string) (*localConn, error) {
	tm.mu.Lock()
	if lc, ok := tm.localConns[connID]; ok {
		tm.mu.Unlock()
		return lc, nil
	}
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		tm.mu.Unlock()
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	lc := newLocalConn(connID, tunnelID)
	tm.localConns[connID] = lc
	localAddr, localPort, protocol := tunnel.LocalAddr, tunnel.LocalPort, tunnel.Protocol
	tm.mu.Unlock()

	go tm.runLocalConn(lc, localAddr, localPort, protocol)
	return lc, nil
}

func (tm *TunnelManager) runLocalConn(lc *localConn, localAddr string, localPort int, protocol string) {
	defer tm.removeLocalConn(lc)

	addr := localServiceAddr(localAddr, localPort)
	conn, err := net.DialTimeout(protocol, addr, localDialTimeout)
	if err != nil {
		tm.SendError(lc.tunnelID, lc.connID, fmt.Sprintf("failed to connect to local service: %v", err))
		return
	}
	common.TuneTCPConn(conn)
	lc.setConn(conn)

	select {
	case <-lc.done:
		_ = conn.Close()
		return
	default:
	}

	go tm.readFromLocal(lc, conn)
	slog.Debug("local connection established",
		"conn_id", lc.connID,
		"tunnel_id", lc.tunnelID,
		"local_addr", addr)

	for {
		select {
		case <-lc.done:
			return
		case chunk := <-lc.queue:
			if len(chunk.data) > 0 {
				conn.SetWriteDeadline(time.Now().Add(localWriteTimeout))
				err := writeFull(conn, chunk.data)
				conn.SetWriteDeadline(time.Time{})
				if err != nil {
					slog.Debug("local connection write failed", "conn_id", lc.connID, "error", err)
					tm.SendError(lc.tunnelID, lc.connID, err.Error())
					return
				}
			}
			if chunk.eof {
				lc.serverClosed.Store(true)
				return
			}
		}
	}
}

func (tm *TunnelManager) readFromLocal(lc *localConn, conn net.Conn) {
	bufPtr := agentBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer agentBufPool.Put(bufPtr)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if forwardErr := tm.forwardLocalData(lc.connID, lc.tunnelID, buf[:n]); forwardErr != nil {
				slog.Warn("failed to send response to server",
					"conn_id", lc.connID,
					"error", forwardErr)
				break
			}
		}
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				slog.Warn("local conn read error", "conn_id", lc.connID, "error", err)
			} else {
				slog.Debug("local conn closed", "conn_id", lc.connID, "error", err)
			}
			break
		}
	}

	// When the server closed its side first, echoing EOF is pointless noise.
	if !lc.serverClosed.Load() {
		if err := tm.sendLocalEOF(lc.connID, lc.tunnelID); err != nil {
			slog.Debug("failed to send tunnel EOF", "conn_id", lc.connID, "error", err)
		}
	}
	tm.removeLocalConn(lc)
}

func (tm *TunnelManager) forwardLocalData(connID, tunnelID string, data []byte) error {
	tm.mu.RLock()
	if _, ok := tm.tunnels[tunnelID]; !ok {
		tm.mu.RUnlock()
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	tm.mu.RUnlock()

	frame, err := tm.agent.encodeTunnelFrame(tunnelID, connID, data, false)
	if err != nil {
		return err
	}
	return tm.agent.connector.SendBinary(frame)
}

func (tm *TunnelManager) sendLocalEOF(connID, tunnelID string) error {
	frame, err := tm.agent.encodeTunnelFrame(tunnelID, connID, nil, true)
	if err != nil {
		return err
	}
	return tm.agent.connector.SendBinary(frame)
}

// CloseLocalConn closes a proxied local connection by connID.
func (tm *TunnelManager) CloseLocalConn(connID string) {
	tm.mu.Lock()
	lc := tm.localConns[connID]
	delete(tm.localConns, connID)
	tm.mu.Unlock()

	if lc != nil {
		lc.stop()
	}
}

func (tm *TunnelManager) removeLocalConn(lc *localConn) {
	tm.mu.Lock()
	if tm.localConns[lc.connID] == lc {
		delete(tm.localConns, lc.connID)
	}
	tm.mu.Unlock()
	lc.stop()
}

// SendError forwards a tunnel error to the server.
func (tm *TunnelManager) SendError(tunnelID, connID, errMsg string) {
	payload := common.TunnelErrorPayload{
		TunnelID: tunnelID,
		ConnID:   connID,
		Error:    errMsg,
	}
	payloadJSON, _ := json.Marshal(payload)
	if err := tm.agent.connector.Send(&common.Message{
		Type:    "tunnel_error",
		Payload: payloadJSON,
	}); err != nil {
		slog.Warn("failed to send tunnel error to server", "tunnel_id", tunnelID, "conn_id", connID, "error", err)
	}
}

// encodeTunnelFrame encrypts (when enabled) and encodes one tunnel frame
// without copying the ciphertext twice.
func (a *Agent) encodeTunnelFrame(tunnelID, connID string, data []byte, isEOF bool) ([]byte, error) {
	if !a.isEncryptionEnabled() {
		return common.EncodeBinaryTunnelDataFrame(tunnelID, connID, data, isEOF)
	}
	if a.cryptoMgr == nil {
		return nil, fmt.Errorf("encryption manager is not initialized")
	}

	// 协商了 v2 才写 v2 帧；老服务端（无响应头）保持 v1。
	version := byte(common.TunnelFrameVersionLegacy)
	if a.aadEnabled() {
		version = common.TunnelFrameVersionAAD
	}
	frame, payload, err := common.NewBinaryTunnelDataFrameVersion(tunnelID, connID, len(data)+common.TunnelEncryptionOverhead, isEOF, version)
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	if version == common.TunnelFrameVersionAAD {
		encrypted, err = a.cryptoMgr.EncryptToAAD(a.GetClientID(), payload, data, frame)
	} else {
		encrypted, err = a.cryptoMgr.EncryptTo(a.GetClientID(), payload, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}
	return frame[:len(frame)+len(encrypted)], nil
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
