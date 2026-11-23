package agent

import (
	"testing"

	"goremote/internal/common"
)

func TestLocalServiceAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "ipv4", host: "127.0.0.1", port: 22, want: "127.0.0.1:22"},
		{name: "hostname", host: "example.com", port: 8080, want: "example.com:8080"},
		{name: "ipv6", host: "::1", port: 443, want: "[::1]:443"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := localServiceAddr(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("localServiceAddr(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestAgentEncodeTunnelFrameEncryptedRoundTrip(t *testing.T) {
	cryptoMgr := common.NewCryptoManager()
	if err := cryptoMgr.SetKey("client-enc", make([]byte, 32)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	a := &Agent{cryptoMgr: cryptoMgr}
	a.SetClientID("client-enc")
	a.encEnabled.Store(true)

	data := []byte("agent encrypted payload")
	frame, err := a.encodeTunnelFrame("tunnel-1", "conn-1", data, false)
	if err != nil {
		t.Fatalf("encodeTunnelFrame: %v", err)
	}
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBinaryTunnelDataFrame: %v", err)
	}
	if string(payload.Data) == string(data) {
		t.Fatal("expected ciphertext when encryption is enabled")
	}
	decrypted, err := a.decryptTunnelBytes(payload.Data, payload.AAD())
	if err != nil {
		t.Fatalf("decryptTunnelBytes: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("round-trip mismatch: %q", decrypted)
	}
}

func TestAgentTunnelBytesAllowPlaintextWhenEncryptionDisabled(t *testing.T) {
	a := &Agent{cryptoMgr: common.NewCryptoManager()}
	a.SetClientID("client-plain")

	data := []byte("plain")
	frame, err := a.encodeTunnelFrame("tunnel-1", "conn-1", data, false)
	if err != nil {
		t.Fatalf("encodeTunnelFrame: %v", err)
	}
	payload, err := common.DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBinaryTunnelDataFrame: %v", err)
	}
	if string(payload.Data) != string(data) {
		t.Fatalf("disabled encryption should pass plaintext through, got %q", payload.Data)
	}
	decrypted, err := a.decryptTunnelBytes(payload.Data, payload.AAD())
	if err != nil {
		t.Fatalf("decryptTunnelBytes: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("disabled encryption should decode plaintext, got %q", decrypted)
	}
}
