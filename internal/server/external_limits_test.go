package server

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

func newLimitsTestManager(t *testing.T, srv *Server) *TunnelManager {
	t.Helper()
	tm := NewTunnelManager(srv, 10000, 10000)
	t.Cleanup(tm.CloseAll)
	return tm
}

func addTestTunnel(tm *TunnelManager, tunnelID string) {
	tm.mu.Lock()
	tm.tunnels[tunnelID] = &Tunnel{TunnelID: tunnelID}
	tm.mu.Unlock()
}

// 读缓冲固定 32KB：单连接常驻从 256KB 降下来，是本次内存项的主要收益。
func TestBufPoolAllocates32KB(t *testing.T) {
	if externalConnBufSize != 32*1024 {
		t.Fatalf("externalConnBufSize = %d, want 32768", externalConnBufSize)
	}
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	if got := len(*bufPtr); got != externalConnBufSize {
		t.Fatalf("buffered pool allocated %d bytes, want %d", got, externalConnBufSize)
	}
}

// 每条隧道 64 条公网连接，第 65 条立即失败（关闭由调用方做，不排队）。
func TestExternalConnPerTunnelLimit(t *testing.T) {
	tm := newLimitsTestManager(t, &Server{})
	addTestTunnel(tm, "tunnel-1")

	clients := make([]net.Conn, 0, maxExternalConnsPerTunnel+1)
	defer func() {
		for _, conn := range clients {
			conn.Close()
		}
	}()

	for i := 0; i < maxExternalConnsPerTunnel; i++ {
		local, remote := net.Pipe()
		clients = append(clients, remote)
		if err := tm.AddExternalConn("conn-"+strconv.Itoa(i), "tunnel-1", local); err != nil {
			t.Fatalf("AddExternalConn #%d: %v", i, err)
		}
	}

	local, remote := net.Pipe()
	clients = append(clients, remote)
	err := tm.AddExternalConn("conn-over", "tunnel-1", local)
	if !errors.Is(err, errExternalConnPerTunnelLimit) {
		t.Fatalf("65th connection error = %v, want errExternalConnPerTunnelLimit", err)
	}
	// 超限的连接不登记，也就不会占住写协程或读缓冲。
	tm.extMu.RLock()
	got := len(tm.extConns)
	tm.extMu.RUnlock()
	if got != maxExternalConnsPerTunnel {
		t.Fatalf("registered connections = %d, want %d", got, maxExternalConnsPerTunnel)
	}
}

// 全局上限 1024：单隧道上限不先触发时，全局也必须挡住。
func TestExternalConnGlobalLimit(t *testing.T) {
	tm := newLimitsTestManager(t, &Server{})

	tunnels := maxExternalConnsTotal/maxExternalConnsPerTunnel + 1
	clients := make([]net.Conn, 0, maxExternalConnsTotal+1)
	defer func() {
		for _, conn := range clients {
			conn.Close()
		}
	}()

	added := 0
	for i := 0; i < tunnels && added < maxExternalConnsTotal; i++ {
		tunnelID := "tunnel-" + string(rune('a'+i))
		addTestTunnel(tm, tunnelID)
		for j := 0; j < maxExternalConnsPerTunnel && added < maxExternalConnsTotal; j++ {
			local, remote := net.Pipe()
			clients = append(clients, remote)
			if err := tm.AddExternalConn("conn-"+tunnelID+"-"+strconv.Itoa(j), tunnelID, local); err != nil {
				t.Fatalf("AddExternalConn #%d: %v", added, err)
			}
			added++
		}
	}

	lastTunnel := "tunnel-" + string(rune('a'+tunnels-1))
	addTestTunnel(tm, lastTunnel)
	local, remote := net.Pipe()
	clients = append(clients, remote)
	err := tm.AddExternalConn("conn-global-over", lastTunnel, local)
	if !errors.Is(err, errExternalConnGlobalLimit) {
		t.Fatalf("connection beyond the global cap error = %v, want errExternalConnGlobalLimit", err)
	}
}

// 空闲读超时可配置，未配置时回落默认值（不能退化成 0 立刻超时）。
func TestExternalIdleTimeoutConfigAndDefault(t *testing.T) {
	configured := newLimitsTestManager(t, &Server{config: &Config{Tunnel: TunnelConfig{ExternalIdleTimeout: 90 * time.Second}}})
	if got := configured.externalIdleTimeout(); got != 90*time.Second {
		t.Fatalf("configured idle timeout = %v, want 90s", got)
	}

	def := newLimitsTestManager(t, &Server{})
	if got := def.externalIdleTimeout(); got != defaultExternalIdleTimeout {
		t.Fatalf("default idle timeout = %v, want %v", got, defaultExternalIdleTimeout)
	}
	if defaultExternalIdleTimeout >= 15*time.Minute {
		t.Fatalf("default idle timeout = %v, must be below the old 15 minutes", defaultExternalIdleTimeout)
	}

	zero := newLimitsTestManager(t, &Server{config: &Config{}})
	if got := zero.externalIdleTimeout(); got != defaultExternalIdleTimeout {
		t.Fatalf("zero-configured idle timeout = %v, want default %v", got, defaultExternalIdleTimeout)
	}
}

// 一条不发数据的公网连接必须按配置的空闲超时被关掉并摘除。
func TestExternalConnClosedAfterIdleTimeout(t *testing.T) {
	_, store := newTestConfig(t)
	srv := &Server{
		config:     &Config{Tunnel: TunnelConfig{ExternalIdleTimeout: 150 * time.Millisecond}},
		stateStore: store,
		clients:    NewClientManager(),
		cryptoMgr:  common.NewCryptoManager(),
	}
	tm := newLimitsTestManager(t, srv)
	addTestTunnel(tm, "tunnel-idle")

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}
	local, remote := net.Pipe()
	defer remote.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tm.handleExternalConn("conn-idle", &Tunnel{TunnelID: "tunnel-idle"}, client, local)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle external connection was not closed within 3s")
	}

	tm.extMu.RLock()
	_, stillRegistered := tm.extConns["conn-idle"]
	tm.extMu.RUnlock()
	if stillRegistered {
		t.Fatal("idle connection must be removed from extConns")
	}
	_ = agentConn
}

// 32KB 读缓冲不能改变转发语义：大块写入要拆成多帧，字节总量一致。
func TestExternalConnReadBufferKeepsDataIntact(t *testing.T) {
	_, store := newTestConfig(t)
	srv := &Server{
		stateStore: store,
		clients:    NewClientManager(),
		cryptoMgr:  common.NewCryptoManager(),
	}
	tm := newLimitsTestManager(t, srv)
	addTestTunnel(tm, "tunnel-data")

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}
	local, remote := net.Pipe()

	const total = 200 * 1024
	payload := bytes.Repeat([]byte("goremote"), total/8)

	writeDone := make(chan error, 1)
	go func() {
		defer remote.Close()
		written := 0
		for written < len(payload) {
			n, err := remote.Write(payload[written:])
			written += n
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		tm.handleExternalConn("conn-data", &Tunnel{TunnelID: "tunnel-data"}, client, local)
	}()

	received := 0
	frames := 0
	for received < total {
		agentConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		messageType, data, err := agentConn.ReadMessage()
		if err != nil {
			t.Fatalf("read tunnel frame: %v (received %d/%d)", err, received, total)
		}
		if messageType != websocket.BinaryMessage {
			t.Fatalf("message type = %d, want binary", messageType)
		}
		frame, err := common.DecodeBinaryTunnelDataFrame(data)
		if err != nil {
			t.Fatalf("decode tunnel frame: %v", err)
		}
		if len(frame.Data) > externalConnBufSize {
			t.Fatalf("frame payload = %d bytes, larger than the read buffer %d", len(frame.Data), externalConnBufSize)
		}
		received += len(frame.Data)
		frames++
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if received != total {
		t.Fatalf("received %d bytes, want %d", received, total)
	}
	if frames < 2 {
		t.Fatalf("200KB payload arrived in %d frame(s); the 32KB buffer should split it", frames)
	}

	remote.Close()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not exit after the peer closed")
	}
}
