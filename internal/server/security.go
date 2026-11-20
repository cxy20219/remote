package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ipMatcher is a compiled IP whitelist. Rebuilding it on settings changes
// avoids re-parsing CIDR strings on every connection.
type ipMatcher struct {
	exact map[string]struct{}
	cidrs []*net.IPNet
}

func newIPMatcher(entries []string) *ipMatcher {
	matcher := &ipMatcher{exact: make(map[string]struct{})}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil {
				matcher.cidrs = append(matcher.cidrs, ipnet)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			matcher.exact[ip.String()] = struct{}{}
			continue
		}
		matcher.exact[entry] = struct{}{}
	}
	return matcher
}

func (m *ipMatcher) Match(ipStr string) bool {
	if m == nil {
		return false
	}
	if _, ok := m.exact[ipStr]; ok {
		return true
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP != nil {
		if _, ok := m.exact[parsedIP.String()]; ok {
			return true
		}
	}
	if len(m.cidrs) == 0 || parsedIP == nil {
		return false
	}
	for _, ipnet := range m.cidrs {
		if ipnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// isIPWhitelisted checks if an IP address is in the whitelist.
// Supports exact IP match and CIDR notation (e.g. "192.168.1.0/24").
func isIPWhitelisted(ipStr string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return false
	}
	return newIPMatcher(whitelist).Match(ipStr)
}

// validateIPList rejects malformed IP/CIDR entries before they are persisted.
func validateIPList(entries []string) error {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("invalid CIDR entry %q", entry)
			}
			continue
		}
		if net.ParseIP(entry) == nil {
			return fmt.Errorf("invalid IP entry %q", entry)
		}
	}
	return nil
}

// BlacklistEntry represents a single blacklisted IP with metadata.
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// IsExpired returns true if the entry has a non-zero expiration time that has passed.
func (e BlacklistEntry) IsExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// BlacklistManager manages IPs that are blocked due to rate-limit violations or manual addition.
type BlacklistManager struct {
	mu        sync.RWMutex
	entries   map[string]*BlacklistEntry
	violation map[string]*violationState
	threshold int
	stopCh    chan struct{}
	stopOnce  sync.Once
}

type violationState struct {
	count    int
	lastSeen time.Time
}

// NewBlacklistManager creates a new BlacklistManager with the given auto-blacklist threshold.
func NewBlacklistManager(threshold int) *BlacklistManager {
	bm := &BlacklistManager{
		entries:   make(map[string]*BlacklistEntry),
		violation: make(map[string]*violationState),
		threshold: threshold,
		stopCh:    make(chan struct{}),
	}
	go bm.cleanupLoop()
	return bm
}

// SetThreshold updates the auto-blacklist threshold.
func (bm *BlacklistManager) SetThreshold(threshold int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.threshold = threshold
}

// GetThreshold returns the current auto-blacklist threshold.
func (bm *BlacklistManager) GetThreshold() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.threshold
}

// IsBlacklisted returns true if the IP is currently blacklisted and not expired.
func (bm *BlacklistManager) IsBlacklisted(ip string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	entry, exists := bm.entries[ip]
	if !exists {
		return false
	}
	if entry.IsExpired() {
		return false
	}
	return true
}

const (
	autoBlacklistDuration = 24 * time.Hour
	violationRetention    = time.Hour
)

// AddViolation records a rate-limit violation for an IP.
// If cumulative violations reach the threshold, the IP is auto-blacklisted for
// a bounded period so a shared NAT address cannot be blocked forever.
// Returns true if the IP was auto-blacklisted.
func (bm *BlacklistManager) AddViolation(ip string) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.threshold <= 0 {
		return false
	}

	if entry, exists := bm.entries[ip]; exists && !entry.IsExpired() {
		return false
	}

	now := time.Now()
	violation := bm.violation[ip]
	if violation == nil {
		violation = &violationState{}
		bm.violation[ip] = violation
	}
	violation.count++
	violation.lastSeen = now
	if violation.count >= bm.threshold {
		bm.entries[ip] = &BlacklistEntry{
			IP:        ip,
			Reason:    "auto: rate-limit violations reached threshold",
			AddedAt:   now,
			ExpiresAt: now.Add(autoBlacklistDuration),
		}
		delete(bm.violation, ip)
		slog.Warn("IP auto-blacklisted", "ip", ip, "threshold", bm.threshold)
		return true
	}
	return false
}

// AddManual adds an IP to the blacklist manually.
func (bm *BlacklistManager) AddManual(ip string, reason string, duration time.Duration) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	entry := &BlacklistEntry{
		IP:      ip,
		Reason:  reason,
		AddedAt: time.Now(),
	}
	if duration > 0 {
		entry.ExpiresAt = time.Now().Add(duration)
	}
	bm.entries[ip] = entry
	delete(bm.violation, ip)
	slog.Info("IP manually blacklisted", "ip", ip, "reason", reason)
}

// Remove removes an IP from the blacklist.
func (bm *BlacklistManager) Remove(ip string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.entries, ip)
	delete(bm.violation, ip)
}

// List returns all current blacklist entries (excluding expired ones).
func (bm *BlacklistManager) List() []BlacklistEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make([]BlacklistEntry, 0, len(bm.entries))
	for _, entry := range bm.entries {
		if !entry.IsExpired() {
			result = append(result, *entry)
		}
	}
	return result
}

// AllViolations returns all IPs with their current violation counts.
func (bm *BlacklistManager) AllViolations() map[string]int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make(map[string]int, len(bm.violation))
	for ip, violation := range bm.violation {
		result[ip] = violation.count
	}
	return result
}

func (bm *BlacklistManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.cleanupExpired()
		case <-bm.stopCh:
			return
		}
	}
}

func (bm *BlacklistManager) cleanupExpired() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	for ip, entry := range bm.entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(bm.entries, ip)
			delete(bm.violation, ip)
		}
	}
	cutoff := now.Add(-violationRetention)
	for ip, violation := range bm.violation {
		if violation.lastSeen.Before(cutoff) {
			delete(bm.violation, ip)
		}
	}
}

func (bm *BlacklistManager) Stop() {
	if bm == nil {
		return
	}
	bm.stopOnce.Do(func() {
		close(bm.stopCh)
	})
}

// SecurityHeadersMiddleware adds common security headers to all responses.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		csp := "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Content-Security-Policy", csp)
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") || path == "/login.html" || path == "/" {
			c.Header("Cache-Control", "no-store")
		}
		c.Next()
	}
}

// DynamicBodySizeLimitMiddleware limits HTTP request bodies using the latest settings.
// getMaxBytes returning 0 keeps the request unlimited.
func DynamicBodySizeLimitMiddleware(getMaxBytes func() int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if getMaxBytes != nil {
			if maxBytes := getMaxBytes(); maxBytes > 0 {
				c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
			}
		}
		c.Next()
	}
}

// BrowserOriginGuardMiddleware rejects cross-site browser writes while still allowing CLI/API clients.
func BrowserOriginGuardMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeHTTPMethod(c.Request.Method) {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		if origin != "" {
			if !sameRequestOrigin(c.Request, origin) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin write rejected"})
				return
			}
			c.Next()
			return
		}

		referer := c.GetHeader("Referer")
		if referer != "" && !sameRequestOrigin(c.Request, referer) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin write rejected"})
			return
		}

		c.Next()
	}
}

func isSafeHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func sameRequestOrigin(r *http.Request, rawOrigin string) bool {
	origin, ok := normalizeOrigin(rawOrigin)
	if !ok {
		return false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	expected, ok := normalizeOrigin(scheme + "://" + r.Host)
	if !ok {
		return false
	}

	return origin == expected
}

func maxBodySizeBytes(maxBodySizeMB int) int64 {
	if maxBodySizeMB <= 0 {
		return 0
	}
	return int64(maxBodySizeMB) * 1024 * 1024
}

// RateLimiter is a simple sliding-window per-IP rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string]*rateLimitEntry
	limit    int
	window   time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

type rateLimitEntry struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a rate limiter with the given request limit per time window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if window <= 0 {
		window = time.Minute
	}

	rl := &RateLimiter{
		requests: make(map[string]*rateLimitEntry),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the request from the given key (typically IP) is allowed.
func (rl *RateLimiter) Allow(key string) bool {
	if rl == nil {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.limit <= 0 {
		return true
	}

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

// RetryAfter 返回该 key 距离窗口重置的秒数，用于 429 响应的 Retry-After 头。
func (rl *RateLimiter) RetryAfter(key string) int {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry := rl.requests[key]
	if entry == nil {
		return 0
	}
	remaining := time.Until(entry.resetAt)
	if remaining <= 0 {
		return 0
	}
	seconds := int((remaining + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

func setRetryAfter(c *gin.Context, rl *RateLimiter, key string) {
	if seconds := rl.RetryAfter(key); seconds > 0 {
		c.Header("Retry-After", strconv.Itoa(seconds))
	}
}

func (rl *RateLimiter) SetLimit(limit int) {
	if rl == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limit = limit
	if limit <= 0 {
		rl.requests = make(map[string]*rateLimitEntry)
	}
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupExpired()
		case <-rl.stopCh:
			return
		}
	}
}

func (rl *RateLimiter) cleanupExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, entry := range rl.requests {
		if now.After(entry.resetAt) {
			delete(rl.requests, key)
		}
	}
}

func (rl *RateLimiter) Stop() {
	if rl == nil {
		return
	}
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

// LoginRateLimitMiddleware returns a Gin middleware that rate-limits login attempts.
func LoginRateLimitMiddleware(rl *RateLimiter, s *Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if s.IsGloballyWhitelisted(ip) || s.clients.IsIPWhitelisted(ip) {
			c.Next()
			return
		}

		if s.blacklist.IsBlacklisted(ip) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "IP is blacklisted"})
			return
		}

		if key := clientIPKey(ip); !rl.Allow(key) {
			s.blacklist.AddViolation(ip)
			setRetryAfter(c, rl, key)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, try again later"})
			return
		}
		c.Next()
	}
}

// AdminWriteRateLimitMiddleware 限流管理写接口（位于 session 之后）：
// 这些接口每命中一次都可能消耗一次密码/动态码校验，必须有独立且更严的限流。
func AdminWriteRateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := clientIPKey(c.ClientIP())
		if !rl.Allow(key) {
			setRetryAfter(c, rl, key)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests, try again later"})
			return
		}
		c.Next()
	}
}

// ConnRateLimitMiddleware returns a Gin middleware that rate-limits WebSocket connections per IP.
// IPs present in global whitelist or any client's whitelist bypass the rate limit.
// Blacklisted IPs are directly rejected.
func ConnRateLimitMiddleware(rl *RateLimiter, s *Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		if rl == nil {
			c.Next()
			return
		}
		ip := extractIP(c.ClientIP())

		if s.IsGloballyWhitelisted(ip) || s.clients.IsIPWhitelisted(ip) {
			c.Next()
			return
		}

		if s.blacklist.IsBlacklisted(ip) {
			slog.Warn("ws connection from blacklisted IP rejected", "ip", ip)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "IP is blacklisted"})
			return
		}

		if !rl.Allow(clientIPKey(ip)) {
			s.blacklist.AddViolation(ip)
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

func isLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.IsLoopback()
}
