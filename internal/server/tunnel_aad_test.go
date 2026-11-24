package server

import (
	"bytes"
	"embed"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

// startTestServerWithConfig 用给定配置起一个真实 HTTP 服务端并等到 /health。
func startTestServerWithConfig(t *testing.T, config *Config) *Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := mustNewServer(t, config, embed.FS{})
	srv.Addr = addr
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return srv
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newAADHandlerFixture 造一个带 tunnelManager 和加密 key 的 handler 环境。
func newAADHandlerFixture(t *testing.T) (*Server, *Handler, *Client) {
	t.Helper()
	_, store := newTestConfig(t)
	srv := &Server{
		stateStore: store,
		clients:    NewClientManager(),
		cryptoMgr:  common.NewCryptoManager(),
		stopCh:     make(chan struct{}),
	}
	srv.tunnelManager = NewTunnelManager(srv, testTunnelPortStart, testTunnelPortEnd)
	t.Cleanup(srv.tunnelManager.CloseAll)
	srv.handler = NewHandler(srv)

	client := &Client{ClientID: "dev-1", aadEnabled: true}
	client.SetEncryptionEnabled(true)
	if err := srv.tunnelManager.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, ""); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}
	return srv, srv.handler, client
}

// ④ 协商矩阵（服务端侧）：只有新服务端 + AAD 开关打开 + proto=2 才回 AAD 头；
// 老 agent（无 query）永远拿不到任何协商头。
func TestServerAADNegotiationMatrix(t *testing.T) {
	newConfig := func(t *testing.T, aad bool) *Config {
		t.Helper()
		config, _ := newTestConfig(t)
		config.Tunnel.AAD = aad
		return config
	}

	t.Run("new server + new agent", func(t *testing.T) {
		srv := startTestServerWithConfig(t, newConfig(t, true))
		_, resp := dialReauthWS(t, srv.Addr, "?proto=2")
		if got := resp.Header.Get("X-Goremote-Proto"); got != "2" {
			t.Fatalf("proto header = %q, want 2", got)
		}
		if got := resp.Header.Get("X-Goremote-AAD"); got != "1" {
			t.Fatalf("aad header = %q, want 1", got)
		}
	})

	t.Run("new server AAD disabled + new agent", func(t *testing.T) {
		srv := startTestServerWithConfig(t, newConfig(t, false))
		_, resp := dialReauthWS(t, srv.Addr, "?proto=2")
		if got := resp.Header.Get("X-Goremote-Proto"); got != "2" {
			t.Fatalf("proto header = %q, want 2", got)
		}
		if got := resp.Header.Get("X-Goremote-AAD"); got != "" {
			t.Fatalf("aad header = %q, want none when the switch is off", got)
		}
	})

	t.Run("new server + old agent", func(t *testing.T) {
		srv := startTestServerWithConfig(t, newConfig(t, true))
		_, resp := dialReauthWS(t, srv.Addr, "")
		if got := resp.Header.Get("X-Goremote-Proto"); got != "" {
			t.Fatalf("legacy client proto header = %q, want none", got)
		}
		if got := resp.Header.Get("X-Goremote-AAD"); got != "" {
			t.Fatalf("legacy client aad header = %q, want none", got)
		}
	})
}

// ③ 服务端：协商了 v2 的连接收到 v1 数据帧 → 拒绝并关闭连接。
func TestServerRejectsV1DataFrameOnAADConnection(t *testing.T) {
	config, _ := newTestConfig(t)
	srv := &Server{
		config:  config,
		clients: NewClientManager(),
		stopCh:  make(chan struct{}),
	}
	srv.handler = NewHandler(srv)
	srv.tunnelManager = NewTunnelManager(srv, testTunnelPortStart, testTunnelPortEnd)
	t.Cleanup(srv.tunnelManager.CloseAll)

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn, aadEnabled: true}
	client.SetEncryptionEnabled(true)
	srv.clients.Add(client)

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.readLoop(client)
	}()

	frame, err := common.EncodeBinaryTunnelDataFrame("tunnel-1", "conn-1", []byte("legacy"), false)
	if err != nil {
		t.Fatalf("encode v1 frame: %v", err)
	}
	if err := agentConn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatalf("write v1 frame: %v", err)
	}

	agentConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := agentConn.ReadMessage(); err == nil {
		t.Fatal("server must close the connection after a v1 frame on an AAD-negotiated link")
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("connection stayed open: %v", err)
		}
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readLoop did not exit after the AAD violation")
	}
	waitForCondition(t, time.Second, func() bool {
		return len(srv.clients.List()) == 0
	}, "violating client should be removed from the client manager")
}

// ③ 服务端：未协商的连接收到 v2 帧同样拒收（handler 层）。
func TestServerRejectsV2FrameWithoutNegotiation(t *testing.T) {
	_, handler, client := newAADHandlerFixture(t)
	client.aadEnabled = false

	frame, _, err := common.NewBinaryTunnelDataFrameVersion("tunnel-1", "conn-1", 1, false, common.TunnelFrameVersionAAD)
	if err != nil {
		t.Fatalf("build v2 frame: %v", err)
	}
	frame = append(frame, 'x')
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	err = handler.handleTunnelDataBinary(client, &common.Message{Type: "tunnel_data_bin", BinaryData: payload})
	if !errors.Is(err, common.ErrTunnelAADUnexpected) {
		t.Fatalf("error = %v, want ErrTunnelAADUnexpected", err)
	}
}

// v1 EOF 帧沿用明文（服务端 sendTunnelEOF 的现状）：协商了 v2 也不能被误杀。
func TestServerAcceptsV1EOFOnAADConnection(t *testing.T) {
	_, handler, client := newAADHandlerFixture(t)

	frame, err := common.EncodeBinaryTunnelDataFrame("tunnel-1", "conn-1", nil, true)
	if err != nil {
		t.Fatalf("encode EOF: %v", err)
	}
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := handler.handleTunnelDataBinary(client, &common.Message{Type: "tunnel_data_bin", BinaryData: payload}); err != nil {
		t.Fatalf("v1 EOF frame must be accepted on an AAD connection: %v", err)
	}
}

// ① 服务端出向帧版本跟随协商结果，v1/v2 都能解密回原文。
func TestServerFrameVersionFollowsAAD(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	cryptoMgr := common.NewCryptoManager()
	if err := cryptoMgr.SetKey("dev-1", key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	srv := &Server{cryptoMgr: cryptoMgr}
	data := []byte("tunnel payload")

	for _, aad := range []bool{false, true} {
		client := &Client{ClientID: "dev-1", aadEnabled: aad}
		client.SetEncryptionEnabled(true)

		frame, err := srv.encodeTunnelFrame(client, "tunnel-1", "conn-1", data, false)
		if err != nil {
			t.Fatalf("encodeTunnelFrame(aad=%v): %v", aad, err)
		}
		payload, err := common.DecodeBinaryTunnelDataFrame(frame)
		if err != nil {
			t.Fatalf("decode(aad=%v): %v", aad, err)
		}
		wantVersion := common.TunnelFrameVersionLegacy
		if aad {
			wantVersion = common.TunnelFrameVersionAAD
		}
		if payload.Version != wantVersion {
			t.Fatalf("aad=%v frame version = %d, want %d", aad, payload.Version, wantVersion)
		}
		plain, err := srv.decryptTunnelBytes(client, payload.Data, payload.AAD())
		if err != nil {
			t.Fatalf("decrypt(aad=%v): %v", aad, err)
		}
		if !bytes.Equal(plain, data) {
			t.Fatalf("aad=%v round-trip = %q, want %q", aad, plain, data)
		}
	}
}

// ① 入向 v2 帧走完整 handler → 外部连接链路，AAD 必须和加密端一致。
func TestServerHandlerDecryptsV2DataFrame(t *testing.T) {
	srv, handler, client := newAADHandlerFixture(t)

	key := bytes.Repeat([]byte{9}, 32)
	if err := srv.cryptoMgr.SetKey("dev-1", key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	ctx, err := common.NewCryptoContextFromKey(key)
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		serverSide.Close()
		clientSide.Close()
	})
	if err := srv.tunnelManager.AddExternalConn("conn-1", "tunnel-1", serverSide); err != nil {
		t.Fatalf("AddExternalConn: %v", err)
	}

	data := []byte("agent -> server v2 payload")
	frame, _, err := common.NewBinaryTunnelDataFrameVersion("tunnel-1", "conn-1", len(data)+common.TunnelEncryptionOverhead, false, common.TunnelFrameVersionAAD)
	if err != nil {
		t.Fatalf("build v2 frame: %v", err)
	}
	encrypted, err := ctx.EncryptToAAD(nil, data, frame)
	if err != nil {
		t.Fatalf("EncryptToAAD: %v", err)
	}
	full := append(frame, encrypted...)
	payload, err := common.DecodeBinaryTunnelDataFrame(full)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if err := handler.handleTunnelDataBinary(client, &common.Message{Type: "tunnel_data_bin", BinaryData: payload}); err != nil {
		t.Fatalf("handleTunnelDataBinary: %v", err)
	}

	clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(data))
	if _, err := io.ReadFull(clientSide, got); err != nil {
		t.Fatalf("read forwarded payload: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("forwarded payload = %q, want %q", got, data)
	}
}
