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
