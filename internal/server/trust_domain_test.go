package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newTrustDomainServer 构造一台「设备白名单里有 203.0.113.7」的服务端。
func newTrustDomainServer(t *testing.T) (*Server, *BlacklistManager) {
	t.Helper()
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{
		ID:          "dev-whitelist",
		Status:      deviceStatusAuthorized,
		IPWhitelist: []string{"203.0.113.7"},
	})
	clients := NewClientManager()
	clients.SetStore(store)

	bm := NewBlacklistManager(1000, "")
	t.Cleanup(bm.Stop)

	return &Server{blacklist: bm, clients: clients}, bm
}

func doRequest(engine *gin.Engine, method, path, remoteAddr string) int {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	return recorder.Code
}

const deviceWhitelistedAddr = "203.0.113.7:45678"

// 设备白名单只服务隧道反扫描，不能再豁免管理面登录限流。
func TestDeviceWhitelistDoesNotBypassLoginRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, _ := newTrustDomainServer(t)
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	engine := gin.New()
	engine.POST("/api/login", LoginRateLimitMiddleware(rl, srv), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	if code := doRequest(engine, http.MethodPost, "/api/login", deviceWhitelistedAddr); code != http.StatusOK {
		t.Fatalf("first login attempt = %d, want 200", code)
	}
	if code := doRequest(engine, http.MethodPost, "/api/login", deviceWhitelistedAddr); code != http.StatusOK {
		t.Fatalf("second login attempt = %d, want 200", code)
	}
	if code := doRequest(engine, http.MethodPost, "/api/login", deviceWhitelistedAddr); code != http.StatusTooManyRequests {
		t.Fatalf("third login attempt from a device-whitelisted IP = %d, want 429 (device whitelist must not bypass admin rate limiting)", code)
	}
}

// 设备白名单同样不再豁免 WS 连接限流。
func TestDeviceWhitelistDoesNotBypassWSRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, _ := newTrustDomainServer(t)
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	engine := gin.New()
	engine.GET("/ws", ConnRateLimitMiddleware(rl, srv), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	if code := doRequest(engine, http.MethodGet, "/ws", deviceWhitelistedAddr); code != http.StatusOK {
		t.Fatalf("first ws connection = %d, want 200", code)
	}
	if code := doRequest(engine, http.MethodGet, "/ws", deviceWhitelistedAddr); code != http.StatusTooManyRequests {
		t.Fatalf("second ws connection from a device-whitelisted IP = %d, want 429", code)
	}
}

// 全局白名单（管理员的可信来源）继续豁免管理面限流。
func TestGlobalWhitelistStillBypassesLoginRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, _ := newTrustDomainServer(t)
	srv.globalWhitelist.Store(newIPMatcher([]string{"198.51.100.1"}))
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	engine := gin.New()
	engine.POST("/api/login", LoginRateLimitMiddleware(rl, srv), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for attempt := 0; attempt < 5; attempt++ {
		if code := doRequest(engine, http.MethodPost, "/api/login", "198.51.100.1:45678"); code != http.StatusOK {
			t.Fatalf("attempt %d from the global whitelist = %d, want 200", attempt, code)
		}
	}
}

// 黑名单优先于白名单：管理员显式封禁的地址即使命中白名单也必须被拒。
func TestBlacklistWinsOverGlobalWhitelist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, bm := newTrustDomainServer(t)
	srv.globalWhitelist.Store(newIPMatcher([]string{"198.51.100.1"}))
	if err := bm.AddManual("198.51.100.1", "manual", time.Hour); err != nil {
		t.Fatalf("AddManual: %v", err)
	}
	rl := NewRateLimiter(10, time.Minute)
	defer rl.Stop()

	engine := gin.New()
	engine.POST("/api/login", LoginRateLimitMiddleware(rl, srv), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	if code := doRequest(engine, http.MethodPost, "/api/login", "198.51.100.1:45678"); code != http.StatusForbidden {
		t.Fatalf("blacklisted+whitelisted login = %d, want 403 (blacklist must win)", code)
	}

	wsEngine := gin.New()
	wsEngine.GET("/ws", ConnRateLimitMiddleware(rl, srv), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	if code := doRequest(wsEngine, http.MethodGet, "/ws", "198.51.100.1:45678"); code != http.StatusForbidden {
		t.Fatalf("blacklisted+whitelisted ws = %d, want 403", code)
	}
}
