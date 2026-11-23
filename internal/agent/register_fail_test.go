package agent

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

func newRegisterFailTestAgent(t *testing.T, clientID string) (*Agent, *AgentIdentity) {
	t.Helper()
	identity := &AgentIdentity{
		ClientID:   clientID,
		EncKey:     common.EncodeBytes(bytes.Repeat([]byte{3}, 32)),
		EncEnabled: true,
	}
	agent := NewAgent(&Config{}, identity)
	agent.SetClientID(clientID)
	if !agent.cryptoMgr.HasKey(clientID) {
		t.Fatal("test setup: encrypted identity key should be loaded")
	}
	return agent, identity
}

// ⑤a clock_skew：保留 ClientID、EncKey 与加密状态，错误里给出可操作建议。
func TestHandleRegisterFailKeepsIdentityOnClockSkew(t *testing.T) {
	agent, identity := newRegisterFailTestAgent(t, "client-1")

	err := agent.handleRegisterFail(common.ClockSkewReasonPrefix + "+312s")
	if err == nil {
		t.Fatal("clock skew must still surface as an error so the reconnect loop backs off")
	}
	if identity.ClientID != "client-1" {
		t.Fatalf("identity.ClientID = %q, want it kept", identity.ClientID)
	}
	if got := agent.GetClientID(); got != "client-1" {
		t.Fatalf("agent client id = %q, want it kept", got)
	}
	if !agent.cryptoMgr.HasKey("client-1") {
		t.Fatal("encryption key must survive a clock-skew failure")
	}
	if !agent.encEnabled.Load() {
		t.Fatal("encryption state must survive a clock-skew failure")
	}
	if !strings.Contains(err.Error(), "NTP") {
		t.Fatalf("error %q should tell the operator to enable NTP", err)
	}
	if !strings.Contains(err.Error(), "+312s") {
		t.Fatalf("error %q should carry the reported skew", err)
	}
}

// ⑤b 其他 reason 维持原行为：清身份、丢密钥，等待重新审批。
func TestHandleRegisterFailClearsIdentityOnOtherReasons(t *testing.T) {
	agent, identity := newRegisterFailTestAgent(t, "client-1")

	err := agent.handleRegisterFail("device key mismatch; re-approval required")
	if err == nil {
		t.Fatal("register_fail should return an error")
	}
	if identity.ClientID != "" {
		t.Fatalf("identity.ClientID = %q, want it cleared", identity.ClientID)
	}
	if got := agent.GetClientID(); got != "" {
		t.Fatalf("agent client id = %q, want it cleared", got)
	}
	if agent.cryptoMgr.HasKey("client-1") {
		t.Fatal("cleared identity must drop the device encryption key")
	}
	if agent.encEnabled.Load() {
		t.Fatal("cleared identity must disable tunnel encryption state")
	}
}

// ⑥ 连接侧：客户端声明 proto=2 并读取 101 的 X-Goremote-Proto。
func TestConnectorNegotiatesProto(t *testing.T) {
	newServer := func(t *testing.T, responseProto string) (string, <-chan string) {
		t.Helper()
		protoCh := make(chan string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			protoCh <- r.URL.Query().Get("proto")
			headers := http.Header{}
			if responseProto != "" {
				headers.Set("X-Goremote-Proto", responseProto)
			}
			conn, err := (&websocket.Upgrader{}).Upgrade(w, r, headers)
			if err != nil {
				return
			}
			defer conn.Close()
			time.Sleep(100 * time.Millisecond)
		}))
		t.Cleanup(server.Close)
		return strings.TrimPrefix(server.URL, "http://"), protoCh
	}

	t.Run("new server", func(t *testing.T) {
		addr, protoCh := newServer(t, "2")
		connector := NewConnector(addr, false, "", false, nil)
		if err := connector.Connect(); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer connector.Close()

		if got := <-protoCh; got != "2" {
			t.Fatalf("dial query proto = %q, want 2", got)
		}
		if got := connector.ServerProto(); got != 2 {
			t.Fatalf("negotiated server proto = %d, want 2", got)
		}
	})

	t.Run("legacy server", func(t *testing.T) {
		addr, protoCh := newServer(t, "")
		connector := NewConnector(addr, false, "", false, nil)
		if err := connector.Connect(); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer connector.Close()

		if got := <-protoCh; got != "2" {
			t.Fatalf("dial query proto = %q, want 2", got)
		}
		if got := connector.ServerProto(); got != 1 {
			t.Fatalf("legacy server proto = %d, want 1", got)
		}
	})
}
