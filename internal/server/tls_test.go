package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
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

func generateServerCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return
}

// newTestConfig 返回**已初始化**（已设置管理员密码）的测试服务端配置。
// 需要验证首启门禁的用例请用 newTestConfigUninitialized，别在这里隐式依赖前置状态。
func newTestConfig(t *testing.T) (*Config, *StateStore) {
	t.Helper()
	config, stateStore := newTestConfigUninitialized(t)
	if _, err := stateStore.SetInitialAdminPassword("TestPassword123!"); err != nil {
		t.Fatalf("initialize admin password: %v", err)
	}
	return config, stateStore
}

// mustNewServer 把构造失败直接判成测试失败：状态读不出来时继续跑只会得到
// 更难懂的失败。生产路径里 NewServer 返回错误并由 main 以退出码 2 结束。
func mustNewServer(t *testing.T, config *Config, staticFS embed.FS) *Server {
	t.Helper()
	srv, err := NewServer(config, staticFS)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// newTestConfigUninitialized 返回未初始化（AdminPasswordHash 为空）的配置。
func newTestConfigUninitialized(t *testing.T) (*Config, *StateStore) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "server-state.json")
	stateStore := NewStateStore(statePath)
	if err := stateStore.Load(); err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	config := &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 0,
		},
		dataDir: dir,
	}

	return config, stateStore
}

func TestNewServer_TLSEnabled(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateServerCert(t, dir)
	config, _ := newTestConfig(t)
	config.Server.TLS = TLSConfig{Enabled: true, Cert: certPath, Key: keyPath}

	srv := mustNewServer(t, config, embed.FS{})

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
	config, _ := newTestConfig(t)

	srv := mustNewServer(t, config, embed.FS{})

	if srv.tlsEnabled {
		t.Fatal("tlsEnabled should be false")
	}
}

func TestNewHTTPServerHardeningDefaults(t *testing.T) {
	config, _ := newTestConfig(t)
	srv := mustNewServer(t, config, embed.FS{})

	httpSrv := srv.newHTTPServer()
	if httpSrv.ReadHeaderTimeout != httpReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", httpSrv.ReadHeaderTimeout, httpReadHeaderTimeout)
	}
	if httpSrv.ReadTimeout != httpReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", httpSrv.ReadTimeout, httpReadTimeout)
	}
	if httpSrv.WriteTimeout != httpWriteTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", httpSrv.WriteTimeout, httpWriteTimeout)
	}
	if httpSrv.IdleTimeout != httpIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", httpSrv.IdleTimeout, httpIdleTimeout)
	}
	if httpSrv.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", httpSrv.MaxHeaderBytes, httpMaxHeaderBytes)
	}
	if httpSrv.TLSConfig != nil {
		t.Fatal("TLSConfig should be nil when TLS is disabled")
	}

	srv.tlsEnabled = true
	httpSrv = srv.newHTTPServer()
	if httpSrv.TLSConfig == nil {
		t.Fatal("expected TLSConfig when TLS is enabled")
	}
	if httpSrv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS MinVersion = %x, want TLS 1.3", httpSrv.TLSConfig.MinVersion)
	}
}

func TestBuildOriginCheckerRejectsBrowserOriginByDefault(t *testing.T) {
	srv := &Server{}
	check := srv.buildOriginChecker(nil)

	if !check(&http.Request{Header: http.Header{}}) {
		t.Fatal("agent-style request without Origin should be allowed")
	}

	req := &http.Request{Header: http.Header{"Origin": []string{"https://evil.example"}}}
	if check(req) {
		t.Fatal("browser request with Origin should be rejected when no allowed origins are configured")
	}
}

func TestBuildOriginCheckerRequiresExactOrigin(t *testing.T) {
	srv := &Server{}
	check := srv.buildOriginChecker([]string{"https://admin.example:8443"})

	allowed := &http.Request{Header: http.Header{"Origin": []string{"https://admin.example:8443"}}}
	if !check(allowed) {
		t.Fatal("configured origin should be allowed")
	}

	differentPort := &http.Request{Header: http.Header{"Origin": []string{"https://admin.example"}}}
	if check(differentPort) {
		t.Fatal("same host with different implicit port should be rejected")
	}

	differentScheme := &http.Request{Header: http.Header{"Origin": []string{"http://admin.example:8443"}}}
	if check(differentScheme) {
		t.Fatal("same host with different scheme should be rejected")
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

	config, stateStore := newTestConfig(t)
	config.Server.TLS = TLSConfig{Enabled: true, Cert: certPath, Key: keyPath}

	srv := mustNewServer(t, config, embed.FS{})
	srv.Addr = addr
	srv.stateStore = stateStore

	go func() {
		srv.Start()
	}()
	defer srv.Stop()

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

	payload := common.RegisterPayload{DevicePubkey: "test-pubkey", Hostname: "test-host", OS: "linux"}
	payloadJSON, _ := json.Marshal(payload)
	if err := conn.WriteJSON(common.Message{Type: "register", Payload: payloadJSON}); err != nil {
		t.Fatalf("failed to send register: %v", err)
	}

	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.Type != "register_pending" && resp.Type != "register_fail" {
		t.Fatalf("expected register_pending or register_fail, got %s", resp.Type)
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

	config, stateStore := newTestConfig(t)
	config.Server.TLS = TLSConfig{Enabled: true, Cert: certPath, Key: keyPath}

	srv := mustNewServer(t, config, embed.FS{})
	srv.Addr = addr
	srv.stateStore = stateStore

	go func() {
		srv.Start()
	}()
	defer srv.Stop()

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

	plainDialer := &websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
	}
	_, _, err = plainDialer.Dial("ws://"+addr+"/ws", nil)
	if err == nil {
		t.Fatal("expected error when connecting with plain WS to TLS server")
	}
}
