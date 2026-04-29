package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

func generateServerCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return
}

func TestNewServer_TLSEnabled(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateServerCert(t, dir)

	config := &Config{
		Server: ServerConfig{
			Host: "127.0.0.1", Port: 8443,
			TLS: TLSConfig{Enabled: true, Cert: certPath, Key: keyPath},
		},
		Auth:   AuthConfig{Key: "test-key"},
		Tunnel: TunnelConfig{Enabled: false},
	}

	srv := NewServer(config)

	if !srv.tlsEnabled {
		t.Fatal("tlsEnabled should be true")
	}
	if srv.tlsCert != certPath {
		t.Fatalf("tlsCert = %q, want %q", srv.tlsCert, certPath)
	}
	if srv.tlsKey != keyPath {
		t.Fatalf("tlsKey = %q, want %q", srv.tlsKey, keyPath)
	}
}

func TestNewServer_TLSDisabled(t *testing.T) {
	config := &Config{
		Server: ServerConfig{Host: "127.0.0.1", Port: 8080, TLS: TLSConfig{Enabled: false}},
		Auth:   AuthConfig{Key: "test-key"},
		Tunnel: TunnelConfig{Enabled: false},
	}

	srv := NewServer(config)

	if srv.tlsEnabled {
		t.Fatal("tlsEnabled should be false")
	}
	if srv.tlsCert != "" {
		t.Fatal("tlsCert should be empty")
	}
	if srv.tlsKey != "" {
		t.Fatal("tlsKey should be empty")
	}
}

func TestServerTLS_WebSocketUpgradeAndRegister(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateServerCert(t, dir)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := &Config{
		Server: ServerConfig{
			Host: "127.0.0.1", Port: 0,
			TLS: TLSConfig{Enabled: true, Cert: certPath, Key: keyPath},
		},
		Auth:      AuthConfig{Key: "test-key"},
		Heartbeat: HeartbeatConfig{Interval: 30, Timeout: 90},
		Tunnel:    TunnelConfig{Enabled: false},
	}

	srv := NewServer(config)
	srv.Addr = addr

	go func() {
		srv.Start()
	}()

	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		HandshakeTimeout: 3 * time.Second,
	}

	var conn *websocket.Conn
	for i := 0; i < 30; i++ {
		conn, _, err = dialer.Dial("wss://"+addr+"/ws", nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect via WSS: %v", err)
	}
	defer conn.Close()

	payload := common.RegisterPayload{Key: "test-key", Hostname: "test-host", OS: "linux"}
	payloadJSON, _ := json.Marshal(payload)
	if err := conn.WriteJSON(common.Message{Type: "register", Payload: payloadJSON}); err != nil {
		t.Fatalf("failed to send register: %v", err)
	}

	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.Type != "register_ok" {
		t.Fatalf("expected register_ok, got %s", resp.Type)
	}

	var okPayload common.RegisterOKPayload
	if err := json.Unmarshal(resp.Payload, &okPayload); err != nil {
		t.Fatalf("failed to parse register_ok payload: %v", err)
	}
	if okPayload.ClientID == "" {
		t.Fatal("expected non-empty client_id")
	}
}

func TestServerTLS_RejectPlainWS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateServerCert(t, dir)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := &Config{
		Server: ServerConfig{
			Host: "127.0.0.1", Port: 0,
			TLS: TLSConfig{Enabled: true, Cert: certPath, Key: keyPath},
		},
		Auth:      AuthConfig{Key: "test-key"},
		Heartbeat: HeartbeatConfig{Interval: 30, Timeout: 90},
		Tunnel:    TunnelConfig{Enabled: false},
	}

	srv := NewServer(config)
	srv.Addr = addr

	go func() {
		srv.Start()
	}()

	// Wait for server to be ready over TLS
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		HandshakeTimeout: 3 * time.Second,
	}

	for i := 0; i < 30; i++ {
		_, _, err = dialer.Dial("wss://"+addr+"/ws", nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Now try plain WS - should fail because server is TLS-only
	plainDialer := &websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
	}
	_, _, err = plainDialer.Dial("ws://"+addr+"/ws", nil)
	if err == nil {
		t.Fatal("expected error when connecting with plain WS to TLS server")
	}
}
