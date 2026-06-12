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

func TestAgentTunnelBytesAllowPlaintextWhenEncryptionDisabled(t *testing.T) {
	a := &Agent{
		clientID:  "client-plain",
		identity:  &AgentIdentity{ClientID: "client-plain", EncEnabled: false},
		cryptoMgr: common.NewCryptoManager(),
	}

	data := []byte("plain")
	encrypted, err := a.encryptTunnelBytes(data)
	if err != nil {
		t.Fatalf("encryptTunnelBytes: %v", err)
	}
	if string(encrypted) != string(data) {
		t.Fatalf("disabled encryption should pass plaintext through, got %q", encrypted)
	}
	decrypted, err := a.decryptTunnelBytes(encrypted)
	if err != nil {
		t.Fatalf("decryptTunnelBytes: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("disabled encryption should decode plaintext, got %q", decrypted)
	}
}
