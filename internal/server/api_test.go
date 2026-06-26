package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func TestAdvertisedTunnelHost(t *testing.T) {
	tests := []struct {
		name     string
		settings ServerSettings
		config   *Config
		reqHost  string
		want     string
	}{
		{
			name:     "public host wins",
			settings: ServerSettings{PublicHost: "server.example.com"},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "127.0.0.1:8080",
			want:     "server.example.com",
		},
		{
			name:     "request host strips port",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "api.example.com:8080",
			want:     "api.example.com",
		},
		{
			name:     "request host supports ipv6",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "[2001:db8::1]:8080",
			want:     "2001:db8::1",
		},
		{
			name:     "fallback to configured host",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "10.0.0.5"}},
			reqHost:  "",
			want:     "10.0.0.5",
		},
		{
			name:     "fallback to loopback",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "",
			want:     "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{
				config:     tc.config,
				stateStore: NewStateStoreWithSettings(tc.settings),
			}
			got := srv.advertisedTunnelHost(tc.reqHost)
			if got != tc.want {
				t.Fatalf("advertisedTunnelHost(%q) = %q, want %q", tc.reqHost, got, tc.want)
			}
		})
	}
}

func TestTunnelPublicAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "hostname", host: "server.example.com", port: 15001, want: "server.example.com:15001"},
		{name: "ipv4", host: "127.0.0.1", port: 15001, want: "127.0.0.1:15001"},
		{name: "ipv6", host: "2001:db8::1", port: 15001, want: "[2001:db8::1]:15001"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelPublicAddr(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("tunnelPublicAddr(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestTunnelAccessAddr(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		exposure string
		want     string
	}{
		{name: "public uses advertised host", host: "server.example.com", port: 15001, exposure: TunnelExposurePublic, want: "server.example.com:15001"},
		{name: "server local uses loopback", host: "server.example.com", port: 15001, exposure: TunnelExposureServerLocal, want: "127.0.0.1:15001"},
		{name: "empty exposure defaults public", host: "server.example.com", port: 15001, exposure: "", want: "server.example.com:15001"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelAccessAddr(tc.host, tc.port, tc.exposure)
			if got != tc.want {
				t.Fatalf("tunnelAccessAddr(%q, %d, %q) = %q, want %q", tc.host, tc.port, tc.exposure, got, tc.want)
			}
		})
	}
}

func TestNormalizeTunnelTarget(t *testing.T) {
	tests := []struct {
		name      string
		localAddr string
		localPort int
		protocol  string
		wantAddr  string
		wantProto string
		wantErr   bool
	}{
		{name: "default addr and protocol", localPort: 22, wantAddr: "127.0.0.1", wantProto: "tcp"},
		{name: "trim and lowercase protocol", localAddr: " localhost ", localPort: 8080, protocol: "TCP", wantAddr: "localhost", wantProto: "tcp"},
		{name: "reject udp", localAddr: "127.0.0.1", localPort: 53, protocol: "udp", wantErr: true},
		{name: "reject port zero", localAddr: "127.0.0.1", localPort: 0, protocol: "tcp", wantErr: true},
		{name: "reject port above range", localAddr: "127.0.0.1", localPort: 70000, protocol: "tcp", wantErr: true},
		{name: "reject addr with embedded port", localAddr: "127.0.0.1:22", localPort: 22, protocol: "tcp", wantErr: true},
		{name: "allow ipv6 host", localAddr: "::1", localPort: 22, protocol: "tcp", wantAddr: "::1", wantProto: "tcp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, proto, err := normalizeTunnelTarget(tc.localAddr, tc.localPort, tc.protocol, "127.0.0.1")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != tc.wantAddr || proto != tc.wantProto {
				t.Fatalf("got addr/proto %q/%q, want %q/%q", addr, proto, tc.wantAddr, tc.wantProto)
			}
		})
	}
}

func TestUpdateBlacklistThresholdPersistsSettings(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := NewStateStoreWithSettings(defaultSettings())
	srv := &Server{
		stateStore: store,
		blacklist:  NewBlacklistManager(100),
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/security/blacklist-threshold", strings.NewReader(`{"threshold":7}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	srv.handleAPIUpdateBlacklistThreshold(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := srv.blacklist.GetThreshold(); got != 7 {
		t.Fatalf("blacklist threshold = %d, want 7", got)
	}
	if got := store.GetSettings().BlacklistThreshold; got != 7 {
		t.Fatalf("stored blacklist threshold = %d, want 7", got)
	}
}

func TestDecodeStrictJSONRejectsUnknownFieldsAndWrongContentType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var req struct {
		Name string `json:"name"`
	}

	wrongType := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(wrongType)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{"name":"ok"}`))
	if decodeStrictJSON(ctx, &req) {
		t.Fatal("expected non-json content type to be rejected")
	}
	if wrongType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", wrongType.Code, http.StatusUnsupportedMediaType)
	}

	unknown := httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(unknown)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{"name":"ok","extra":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if decodeStrictJSON(ctx, &req) {
		t.Fatal("expected unknown field to be rejected")
	}
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", unknown.Code, http.StatusBadRequest)
	}

	multiple := httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(multiple)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{"name":"ok"}{"name":"again"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if decodeStrictJSON(ctx, &req) {
		t.Fatal("expected multiple JSON documents to be rejected")
	}
	if multiple.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", multiple.Code, http.StatusBadRequest)
	}
}

func TestHandleAPIChangeAdminPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := NewStateStoreWithSettings(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	srv := &Server{stateStore: store, adminAuth: NewAdminAuth(store)}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/password", strings.NewReader(`{"current_password":"CorrectPassword1!","new_password":"NewPassword1!"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	srv.handleAPIChangeAdminPassword(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if store.VerifyAdminPassword("CorrectPassword1!") {
		t.Fatal("old password should not verify")
	}
	if !store.VerifyAdminPassword("NewPassword1!") {
		t.Fatal("new password should verify")
	}
}

func TestHandleAPIGetSettingsRedactsProxySubscriptionToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	settings := defaultSettings()
	settings.ProxySubscribeToken = "secret-token"
	srv := &Server{stateStore: NewStateStoreWithSettings(settings)}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/settings", nil)

	srv.handleAPIGetSettings(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp ServerSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if resp.ProxySubscribeToken != "" || strings.Contains(rec.Body.String(), "secret-token") {
		t.Fatalf("subscription token leaked in settings response: %s", rec.Body.String())
	}
	if got := srv.stateStore.GetSettings().ProxySubscribeToken; got != "secret-token" {
		t.Fatalf("stored token changed to %q", got)
	}
}

func TestHandleAPIResetProxySubscriptionGeneratesToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := NewStateStoreWithSettings(defaultSettings())
	srv := &Server{stateStore: store, config: &Config{Server: ServerConfig{Host: "0.0.0.0", Port: 8080}}}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/proxy-subscription/reset", nil)
	ctx.Request.Host = "admin.example.com:8080"

	srv.handleAPIResetProxySubscription(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	settings := store.GetSettings()
	if settings.ProxySubscribeToken == "" {
		t.Fatal("subscription token should be stored")
	}
	var resp struct {
		Enabled         bool   `json:"enabled"`
		SubscriptionURL string `json:"subscription_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Enabled || !strings.Contains(resp.SubscriptionURL, settings.ProxySubscribeToken) {
		t.Fatalf("response = %+v, token = %q", resp, settings.ProxySubscribeToken)
	}
}

func TestProxySubscriptionRendersOnlyPublicAuthenticatedProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	settings := defaultSettings()
	settings.ProxySubscribeToken = "token-1"
	srv := &Server{stateStore: NewStateStoreWithSettings(settings), config: &Config{Server: ServerConfig{Host: "0.0.0.0", Port: 8080}}}
	srv.proxyManager = NewProxyManager(srv)
	srv.proxyManager.proxies["public"] = &Proxy{
		ProxyID:     "public",
		ClientID:    "client-1",
		Protocol:    ProxyProtocolSOCKS5,
		PublicPort:  10000,
		Exposure:    TunnelExposurePublic,
		Username:    "user",
		AuthEnabled: true,
		Status:      "active",
		password:    "pass",
	}
	srv.proxyManager.proxies["local"] = &Proxy{
		ProxyID:    "local",
		ClientID:   "client-2",
		Protocol:   ProxyProtocolSOCKS5,
		PublicPort: 10001,
		Exposure:   TunnelExposureServerLocal,
		Status:     "active",
	}

	router := gin.New()
	router.GET("/proxy-subscription/:token", srv.handleProxySubscription)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy-subscription/token-1", nil)
	req.Host = "admin.example.com:8080"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var sub clashSubscription
	if err := yaml.Unmarshal(rec.Body.Bytes(), &sub); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if len(sub.Proxies) != 1 {
		t.Fatalf("proxy count = %d, want 1: %s", len(sub.Proxies), rec.Body.String())
	}
	proxy := sub.Proxies[0]
	if proxy.Server != "admin.example.com" || proxy.Port != 10000 || proxy.Username != "user" || proxy.Password != "pass" || proxy.UDP {
		t.Fatalf("proxy = %+v", proxy)
	}
}

func TestProxySubscriptionRejectsInvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	settings := defaultSettings()
	settings.ProxySubscribeToken = "token-1"
	srv := &Server{stateStore: NewStateStoreWithSettings(settings), proxyManager: NewProxyManager(nil), config: &Config{Server: ServerConfig{Host: "0.0.0.0", Port: 8080}}}
	router := gin.New()
	router.GET("/proxy-subscription/:token", srv.handleProxySubscription)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/proxy-subscription/bad", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
