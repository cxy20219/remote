package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimiterZeroLimitDisablesLimiter(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)

	for i := 0; i < 20; i++ {
		if !rl.Allow("192.0.2.10") {
			t.Fatalf("zero limit should disable limiter, denied at attempt %d", i)
		}
	}
}

func TestRateLimiterSetLimitAppliesImmediately(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)

	if !rl.Allow("192.0.2.20") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("192.0.2.20") {
		t.Fatal("second request should be denied before limit update")
	}

	rl.SetLimit(0)
	if !rl.Allow("192.0.2.20") {
		t.Fatal("zero limit should disable limiter immediately")
	}

	rl.Stop()
	rl.Stop()
}

func TestBlacklistManagerStopIsIdempotent(t *testing.T) {
	bm := NewBlacklistManager(1)
	bm.Stop()
	bm.Stop()
}

func TestDynamicBodySizeLimitMiddlewareUsesLatestLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	maxBytes := int64(4)
	router := gin.New()
	router.Use(DynamicBodySizeLimitMiddleware(func() int64 {
		return maxBytes
	}))
	router.POST("/echo", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.String(http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		c.String(http.StatusOK, "ok")
	})

	tooLarge := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("abcdef"))
	router.ServeHTTP(tooLarge, req)
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected body to be limited, got status %d", tooLarge.Code)
	}

	maxBytes = 16
	allowed := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("abcdef"))
	router.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected updated body limit to allow request, got status %d", allowed.Code)
	}
}

func TestBrowserOriginGuardMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(BrowserOriginGuardMiddleware())
	router.GET("/api/settings", func(c *gin.Context) {
		c.String(http.StatusOK, "read")
	})
	router.POST("/api/settings", func(c *gin.Context) {
		c.String(http.StatusOK, "write")
	})

	cases := []struct {
		name    string
		method  string
		origin  string
		referer string
		want    int
	}{
		{name: "safe get allows cross origin", method: http.MethodGet, origin: "https://evil.example", want: http.StatusOK},
		{name: "post without browser headers allowed for cli", method: http.MethodPost, want: http.StatusOK},
		{name: "same origin post allowed", method: http.MethodPost, origin: "http://admin.example", want: http.StatusOK},
		{name: "cross origin post rejected", method: http.MethodPost, origin: "https://evil.example", want: http.StatusForbidden},
		{name: "same origin referer allowed", method: http.MethodPost, referer: "http://admin.example/page", want: http.StatusOK},
		{name: "cross origin referer rejected", method: http.MethodPost, referer: "http://evil.example/page", want: http.StatusForbidden},
		{name: "spoofed forwarded proto does not change origin", method: http.MethodPost, origin: "https://admin.example", want: http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "http://admin.example/api/settings", strings.NewReader("{}"))
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			if tc.name == "spoofed forwarded proto does not change origin" {
				req.Header.Set("X-Forwarded-Proto", "https")
			}

			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
