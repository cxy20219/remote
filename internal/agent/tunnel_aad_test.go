package agent

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

func newAADTestAgent(t *testing.T) *Agent {
	t.Helper()
	identity := &AgentIdentity{
		ClientID:   "dev-1",
		EncKey:     common.EncodeBytes(bytes.Repeat([]byte{3}, 32)),
		EncEnabled: true,
	}
	agent := NewAgent(&Config{}, identity)
	agent.SetClientID("dev-1")
	if !agent.isEncryptionEnabled() {
		t.Fatal("test setup: encryption should be enabled")
	}
	return agent
}

// newAADTestWSPair 返回 (agent 侧, 对端)；agent 侧直接塞进 Connector。
func newAADTestWSPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverConns := make(chan *websocket.Conn, 1)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConns <- conn
	}))
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	peerConn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		httpServer.Close()
		t.Fatalf("dial test websocket: %v", err)
	}
	agentConn := <-serverConns
	t.Cleanup(func() {
		agentConn.Close()
		peerConn.Close()
		httpServer.Close()
	})
	return agentConn, peerConn
}

// ① agent 出向帧版本跟随协商结果；未协商保持 v1。
func TestAgentFrameVersionFollowsNegotiation(t *testing.T) {
	data := []byte("agent payload")
	for _, aad := range []bool{false, true} {
		agent := newAADTestAgent(t)
		agent.connector.mu.Lock()
		agent.connector.aad = aad
		agent.connector.mu.Unlock()

		frame, err := agent.encodeTunnelFrame("tunnel-1", "conn-1", data, false)
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
		plain, err := agent.decryptTunnelBytes(payload.Data, payload.AAD())
		if err != nil {
			t.Fatalf("decrypt(aad=%v): %v", aad, err)
		}
		if !bytes.Equal(plain, data) {
			t.Fatalf("aad=%v round-trip = %q", aad, plain)
		}
	}
}

// ③ agent：协商了 v2 的连接收到 v1 数据帧 → 连接循环以 ErrTunnelAADRequired 退出。
func TestAgentRejectsV1DataFrameOnAADConnection(t *testing.T) {
	agent := newAADTestAgent(t)
	agentConn, peerConn := newAADTestWSPair(t)
	agent.connector.conn = agentConn
	agent.connector.closed = false
	agent.connector.proto = 2
	agent.connector.aad = true

	errCh := make(chan error, 1)
	go func() { errCh <- agent.handleConnection() }()

	frame, err := common.EncodeBinaryTunnelDataFrame("tunnel-1", "conn-1", []byte("legacy"), false)
	if err != nil {
		t.Fatalf("encode v1 frame: %v", err)
	}
	if err := peerConn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatalf("write v1 frame: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, common.ErrTunnelAADRequired) {
			t.Fatalf("handleConnection error = %v, want ErrTunnelAADRequired", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handleConnection did not exit after the AAD violation")
	}
}

// ③ agent：未协商的连接收到 v2 帧同样拒收。
func TestAgentRejectsV2FrameWithoutNegotiation(t *testing.T) {
	agent := newAADTestAgent(t)
	frame, _, err := common.NewBinaryTunnelDataFrameVersion("tunnel-1", "conn-1", 1, false, common.TunnelFrameVersionAAD)
	if err != nil {
		t.Fatalf("build v2 frame: %v", err)
	}
	frame = append(frame, 'x')
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	err = agent.handler.handleTunnelDataBinary(&common.Message{Type: "tunnel_data_bin", BinaryData: payload})
	if !errors.Is(err, common.ErrTunnelAADUnexpected) {
		t.Fatalf("error = %v, want ErrTunnelAADUnexpected", err)
	}
}

// v1 EOF 帧沿用明文：协商了 v2 也不能被误杀。
func TestAgentAcceptsV1EOFOnAADConnection(t *testing.T) {
	agent := newAADTestAgent(t)
	agent.connector.mu.Lock()
	agent.connector.aad = true
	agent.connector.mu.Unlock()

	frame, err := common.EncodeBinaryTunnelDataFrame("tunnel-1", "conn-1", nil, true)
	if err != nil {
		t.Fatalf("encode EOF: %v", err)
	}
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := agent.handler.handleTunnelDataBinary(&common.Message{Type: "tunnel_data_bin", BinaryData: payload}); err != nil {
		t.Fatalf("v1 EOF frame must be accepted on an AAD connection: %v", err)
	}
}
