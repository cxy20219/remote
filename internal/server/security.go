package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// isIPWhitelisted checks if an IP address is in the whitelist.
// Supports exact IP match and CIDR notation (e.g. "192.168.1.0/24").
func isIPWhitelisted(ipStr string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return false
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}
	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err == nil && ipnet.Contains(parsedIP) {
				return true
			}
		} else {
			if entry == ipStr {
				return true
			}
		}
	}
	return false
}

// SecurityHeadersMiddleware adds common security headers to all responses.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Next()
	}
}

// BodySizeLimitMiddleware limits HTTP request body size.
// maxBytes of 0 means no limit.
func BodySizeLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if maxBytes > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// RateLimiter is a simple sliding-window per-IP rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string]*rateLimitEntry
	limit    int
	window   time.Duration
}

type rateLimitEntry struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a rate limiter with the given request limit per time window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*rateLimitEntry),
		limit:    limit,
		window:   window,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the request from the given key (typically IP) is allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.requests[key]
	if !exists || now.After(entry.resetAt) {
		rl.requests[key] = &rateLimitEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}

	entry.count++
	return true
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.requests {
			if now.After(entry.resetAt) {
				delete(rl.requests, key)
			}
		}
		rl.mu.Unlock()
	}
}

// LoginRateLimitMiddleware returns a Gin middleware that rate-limits login attempts.
func LoginRateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.Allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, try again later"})
			return
		}
		c.Next()
	}
}

// ConnRateLimitMiddleware returns a Gin middleware that rate-limits WebSocket connections per IP.
// IPs present in any connected client's whitelist bypass the rate limit.
func ConnRateLimitMiddleware(rl *RateLimiter, cm *ClientManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rl == nil {
			c.Next()
			return
		}
		ip := extractIP(c.ClientIP())
		if cm.IsIPWhitelisted(ip) {
			c.Next()
			return
		}
		if !rl.Allow(ip) {
			slog.Warn("ws connection rate limited", "ip", ip)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "connection rate limit exceeded"})
			return
		}
		c.Next()
	}
}

// extractIP strips the port from an address string.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
