package agent

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
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

// generateCAAndServerCert creates a CA cert and a server cert signed by the CA.
func generateCAAndServerCert(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("failed to write CA: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	certPath = filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatalf("failed to write server cert: %v", err)
	}

	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	}), 0o600); err != nil {
		t.Fatalf("failed to write server key: %v", err)
	}

	return
}

// startTLSWSServer starts a minimal TLS WebSocket server and returns its address.
func startTLSWSServer(t *testing.T, certFile, keyFile string) string {
	t.Helper()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			var msg common.Message
			if err := conn.ReadJSON(&msg); err != nil {
				break
			}
			if msg.Type == "register" {
				var payload common.RegisterPayload
				json.Unmarshal(msg.Payload, &payload)
				okPayload := common.RegisterOKPayload{ClientID: "test-client-id"}
				okPayloadJSON, _ := json.Marshal(okPayload)
				conn.WriteJSON(common.Message{Type: "register_ok", Payload: okPayloadJSON})
			} else if msg.Type == "ping" {
				conn.WriteJSON(common.Message{Type: "pong"})
			}
		}
	})

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load server cert: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}

	addr := listener.Addr().String()

	go func() {
		http.Serve(listener, mux)
	}()

	for i := 0; i < 30; i++ {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("TLS server did not become ready")
	return ""
}

func TestConnectorConnectTLS_ValidCA(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	c := NewConnector(addr, true, caPath, "test-key", false)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect with TLS should succeed: %v", err)
	}
	defer c.Close()

	if !c.IsConnected() {
		t.Fatal("expected connected state after successful TLS connect")
	}
}

func TestConnectorConnectTLS_RegisterOverTLS(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	c := NewConnector(addr, true, caPath, "test-key", false)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Close()

	if err := c.Register("test-host", "linux"); err != nil {
		t.Fatalf("Register over TLS failed: %v", err)
	}

	msg, err := c.Receive()
	if err != nil {
		t.Fatalf("failed to receive register_ok: %v", err)
	}
	if msg.Type != "register_ok" {
		t.Fatalf("expected register_ok, got %s", msg.Type)
	}
}

func TestConnectorConnectTLS_InvalidCAFile(t *testing.T) {
	dir := t.TempDir()
	_, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	c := NewConnector(addr, true, filepath.Join(dir, "nonexistent.pem"), "test-key", false)
	if err := c.Connect(); err == nil {
		t.Fatal("expected error connecting with invalid CA file")
	}
}

func TestConnectorConnectTLS_WrongCA(t *testing.T) {
	dir := t.TempDir()
	_, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	wrongCA := generateTestCACertPEM(t)
	wrongCAPath := filepath.Join(dir, "wrong-ca.pem")
	if err := os.WriteFile(wrongCAPath, wrongCA, 0o600); err != nil {
		t.Fatalf("failed to write wrong CA: %v", err)
	}

	c := NewConnector(addr, true, wrongCAPath, "test-key", false)
	if err := c.Connect(); err == nil {
		t.Fatal("expected error connecting with wrong CA (cert not signed by this CA)")
	}
}

func TestConnectorConnectTLS_NoCA_UsesSystemPool(t *testing.T) {
	dir := t.TempDir()
	_, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	c := NewConnector(addr, true, "", "test-key", false)
	err := c.Connect()
	if err == nil {
		t.Fatal("expected error: self-signed cert not in system cert pool")
	}
}

func TestConnectorConnectTLS_Disabled(t *testing.T) {
	dir := t.TempDir()
	_, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	c := NewConnector(addr, false, "", "test-key", false)
	err := c.Connect()
	if err == nil {
		t.Fatal("expected error: connecting to TLS server without TLS")
	}
}

func TestConnectorConnectTLS_MultipleCertsInCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := generateCAAndServerCert(t, dir)
	addr := startTLSWSServer(t, certPath, keyPath)

	// Append an additional (unrelated) CA cert to the CA file
	extraCACert := generateTestCACertPEM(t)
	caData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}
	multiCAPath := filepath.Join(dir, "multi-ca.pem")
	if err := os.WriteFile(multiCAPath, append(caData, extraCACert...), 0o600); err != nil {
		t.Fatalf("failed to write multi-CA file: %v", err)
	}

	c := NewConnector(addr, true, multiCAPath, "test-key", false)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect with multi-CA file should succeed: %v", err)
	}
	defer c.Close()

	if !c.IsConnected() {
		t.Fatal("expected connected state")
	}
}
