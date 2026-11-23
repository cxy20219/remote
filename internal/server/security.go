package server

import (
	"errors"
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

// 黑名单来源。淘汰只允许碰 auto：手动封禁必须一直有效到管理员手动解除，
// 否则攻击者只要用流量把表填满，就能把管理员封掉的 IP 洗掉。
const (
	blacklistSourceManual = "manual"
	blacklistSourceAuto   = "auto"
)

// ErrBlacklistFull 表示表里全是手动条目且已到上限，不能再插入（也绝不淘汰
// 手动条目）。
var ErrBlacklistFull = errors.New("blacklist is full of manual entries; remove some entries before adding more")

// BlacklistEntry represents a single blacklisted IP with metadata.
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
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

	// path 为空表示只在内存里跑（测试）；saveMu 串行化写盘，dirty 表示
	// 有自动拉黑还没落盘，wake 用来通知批量落盘协程。flushDelay 在构造后
	// 不再修改，测试用 newBlacklistManager 注入更短的窗口。
	path       string
	flushDelay time.Duration
	saveMu     sync.Mutex
	dirty      bool
	wake       chan struct{}
	wg         sync.WaitGroup

	// 回滚保护。changeSeq 单调递增，每次可回滚的变更（删除、腾位置淘汰）取
	// 一个号；lastDurableSeq 是最近一次成功落盘的快照所覆盖到的变更序号
	// （persist 取快照时记录，写完才更新）。回滚只在确认「磁盘还没反映本次
	// 变更」时执行：lastDurableSeq >= 本次变更序号说明那次成功写盘发生在本次
	// 变更之后，磁盘上已经没有被删掉/淘汰的条目，此时恢复内存旧值等于撤销
	// 一次已经成功的删除（审计发现：并发 Remove 成功后，失败方的回滚会把
	// 条目复活并在下次 flush 时写回磁盘）。
	changeSeq      uint64
	lastDurableSeq uint64
}

type violationState struct {
	count    int
	lastSeen time.Time
}

// NewBlacklistManager creates a BlacklistManager that persists entries to path.
// path == "" keeps the manager memory-only. A corrupt or unreadable file never
// prevents startup: it is logged, quarantined, and the manager starts empty.
func NewBlacklistManager(threshold int, path string) *BlacklistManager {
	return newBlacklistManager(threshold, path, blacklistFlushDelay)
}

// newBlacklistManager 允许测试注入更短的批量写窗口；生产路径用
// NewBlacklistManager 的默认值。
func newBlacklistManager(threshold int, path string, flushDelay time.Duration) *BlacklistManager {
	bm := &BlacklistManager{
		entries:    make(map[string]*BlacklistEntry),
		violation:  make(map[string]*violationState),
		threshold:  threshold,
		stopCh:     make(chan struct{}),
		path:       path,
		flushDelay: flushDelay,
		wake:       make(chan struct{}, 1),
	}
	if err := bm.load(); err != nil {
		slog.Error("failed to load blacklist; starting with an empty list", "error", err, "path", path)
	}
	bm.wg.Add(2)
	go func() {
		defer bm.wg.Done()
		bm.cleanupLoop()
	}()
	go bm.autoFlushLoop()
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
//
// 自动拉黑按 clientIPKey 记账（IPv6 聚合到 /64），手动封禁按单个地址记账，
// 所以两个键都要查：先精确匹配（手动封禁的单地址），再查聚合键（自动拉黑
// 覆盖整个 /64）。IPv4 下两者相同，行为不变。
func (bm *BlacklistManager) IsBlacklisted(ip string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if bm.isLiveLocked(ip) {
		return true
	}
	key := clientIPKey(ip)
	if key == ip {
		return false
	}
	return bm.isLiveLocked(key)
}

// isLiveLocked 判断键对应的条目存在且未过期；调用方必须持有 bm.mu。
func (bm *BlacklistManager) isLiveLocked(key string) bool {
	entry, exists := bm.entries[key]
	return exists && !entry.IsExpired()
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
	// 违规计数与自动拉黑一律按 clientIPKey 记账：IPv6 聚合到 /64。
	// 按原始地址记账时，在 /64 内换地址就能让计数重新开始，自动拉黑永远
	// 凑不满，违规表还会随地址数膨胀；隧道端口限流早就是 /64 聚合的，
	// 这里必须与它对齐。查询侧由 IsBlacklisted 同时匹配精确键与聚合键。
	ip = clientIPKey(ip)

	bm.mu.Lock()
	threshold := bm.threshold
	blacklisted := false
	logOverflow := false
	if threshold > 0 {
		if entry, exists := bm.entries[ip]; !exists || entry.IsExpired() {
			now := time.Now()
			violation := bm.violation[ip]
			if violation == nil {
				violation = &violationState{}
				bm.violation[ip] = violation
			}
			violation.count++
			violation.lastSeen = now
			if violation.count >= threshold {
				// 替换同一 IP 的过期条目不会让表变长，不需要腾位置。
				_, replacing := bm.entries[ip]
				ok := true
				if !replacing {
					_, ok = bm.makeRoomLocked()
				}
				if !ok {
					// 表满且全是手动条目：放弃这次自动拉黑，绝不淘汰手动封禁。
					// 保留违规计数，等空间释放后下一次违规再试。
					logOverflow = violation.count == threshold
				} else {
					bm.entries[ip] = &BlacklistEntry{
						IP:        ip,
						Reason:    "auto: rate-limit violations reached threshold",
						Source:    blacklistSourceAuto,
						AddedAt:   now,
						ExpiresAt: now.Add(autoBlacklistDuration),
					}
					delete(bm.violation, ip)
					// 自动拉黑不在这里写盘：攻击期间每个 IP 都写一次会放大 IO，
					// 交给 autoFlushLoop 攒 3 秒一批。
					bm.dirty = true
					blacklisted = true
				}
			}
		}
	}
	bm.mu.Unlock()

	if logOverflow {
		slog.Warn("blacklist is full of manual entries; skipped auto-blacklisting",
			"ip", ip, "max", blacklistMaxEntries)
	}
	if !blacklisted {
		return false
	}
	slog.Warn("IP auto-blacklisted", "ip", ip, "threshold", threshold)
	bm.signalFlush()
	return true
}

// AddManual adds an IP to the blacklist manually and persists it synchronously.
// It refuses to evict manual entries: when the table is full of them the caller
// gets ErrBlacklistFull.
//
// 写盘失败时不一定回滚：如果磁盘已经被同一窗口里另一次成功的写盘带上了这条
// 插入，就保留条目并返回成功（见 resolveFailedInsert），保证内存、磁盘和返回
// 值三者一致。
func (bm *BlacklistManager) AddManual(ip string, reason string, duration time.Duration) error {
	entry := &BlacklistEntry{
		IP:      ip,
		Reason:  reason,
		Source:  blacklistSourceManual,
		AddedAt: time.Now(),
	}
	if duration > 0 {
		entry.ExpiresAt = entry.AddedAt.Add(duration)
	}

	bm.mu.Lock()
	var evicted []evictedEntry
	if _, exists := bm.entries[ip]; !exists {
		var ok bool
		evicted, ok = bm.makeRoomLocked()
		if !ok {
			bm.mu.Unlock()
			return ErrBlacklistFull
		}
	}
	previous, hadEntry := bm.entries[ip]
	previousViolation, hadViolation := bm.violation[ip]
	attempt := insertAttempt{
		entry: entry,
		// 插入也是可回滚的变更：取号后才能判断「磁盘是否已经覆盖了它」。
		changeSeq:         bm.nextChangeSeqLocked(),
		previous:          previous,
		hadEntry:          hadEntry,
		previousViolation: previousViolation,
		hadViolation:      hadViolation,
		evicted:           evicted,
	}
	bm.entries[ip] = entry
	delete(bm.violation, ip)
	bm.mu.Unlock()

	if err := bm.persist(); err != nil {
		return bm.resolveFailedInsert(attempt, err)
	}
	slog.Info("IP manually blacklisted", "ip", ip, "reason", reason)
	return nil
}

// insertAttempt 是一次手动插入的现场，写盘失败时用它判断该回滚还是该保留。
type insertAttempt struct {
	entry             *BlacklistEntry
	changeSeq         uint64
	previous          *BlacklistEntry
	hadEntry          bool
	previousViolation *violationState
	hadViolation      bool
	evicted           []evictedEntry
}

// resolveFailedInsert 处理一次写盘失败的插入。判据是「磁盘是否已经覆盖了这次
// 插入」，两个证据来源：
//   - 序号不变量：lastDurableSeq >= 本次插入序号，说明有一次成功落盘的快照是在
//     这次插入之后取的，磁盘必然带着它。文件读不出来时这是唯一证据。
//   - 回读磁盘：文件里是否已经有与本次插入完全相同的条目。序号不变量看不到
//     不经过本管理器的写盘（外部写入、测试注入），回读是磁盘事实。
//
// 任一条成立且条目仍在内存里，就保留条目并返回 nil：调用方的意图（封禁这个
// IP）已经落盘，此时报错等于说「没封」，而重启后它又封着——这才是撒谎。否则
// 回滚内存并返回原错误。
func (bm *BlacklistManager) resolveFailedInsert(attempt insertAttempt, persistErr error) error {
	ip := attempt.entry.IP

	// 决策与写盘串行化：等可能在途的写盘落定，避免按过期的 lastDurableSeq
	// 决策，也避免回滚结果紧接着被另一次 rename 覆盖。
	bm.saveMu.Lock()
	defer bm.saveMu.Unlock()

	bm.mu.Lock()
	installed := bm.entries[ip] == attempt.entry
	covered := bm.rollbackSupersededLocked(attempt.changeSeq)
	bm.mu.Unlock()

	if installed && (covered || bm.blacklistFileHoldsEntry(attempt.entry)) {
		slog.Warn("failed to persist a manual blacklist entry, but it is already on disk; keeping it",
			"ip", ip, "error", persistErr)
		return nil
	}

	bm.mu.Lock()
	bm.rollbackInsertLocked(ip, attempt.entry, attempt.previous, attempt.hadEntry, attempt.previousViolation, attempt.hadViolation)
	bm.restoreEvictedLocked(attempt.evicted)
	bm.mu.Unlock()
	slog.Error("failed to persist manual blacklist entry; rolled back", "ip", ip, "error", persistErr)
	return persistErr
}

// nextChangeSeqLocked 为一次可回滚的变更（插入、删除、腾位置淘汰）取号。除
// 启动阶段（load，后台协程还没起来、没有并发）外，调用方必须持有 bm.mu。
func (bm *BlacklistManager) nextChangeSeqLocked() uint64 {
	bm.changeSeq++
	return bm.changeSeq
}

// rollbackSupersededLocked 报告本次变更是否已经被一次成功落盘的快照覆盖：
// 覆盖了就说明磁盘已经反映了这次变更，回滚必须放弃。调用方持有 bm.mu。
func (bm *BlacklistManager) rollbackSupersededLocked(changeSeq uint64) bool {
	return changeSeq <= bm.lastDurableSeq
}

// rollbackInsertLocked 回滚一次失败的插入。只有当前值仍是本次写入的指针时
// 才恢复：并发操作若已改过这个 IP，它的成功不能被覆盖。
func (bm *BlacklistManager) rollbackInsertLocked(ip string, installed, previous *BlacklistEntry, hadEntry bool, previousViolation *violationState, hadViolation bool) {
	if bm.entries[ip] != installed {
		return
	}
	if hadEntry {
		bm.entries[ip] = previous
	} else {
		delete(bm.entries, ip)
	}
	if hadViolation {
		bm.violation[ip] = previousViolation
	}
}

// rollbackRemovalLocked 回滚一次失败的删除。只有「当前状态仍是本次删除造成的
// 中间态」时才恢复，否则放弃：
//   - IP 已被别的操作重新加回：那是更新的状态，不能覆盖；
//   - 本次删除之后已有成功落盘的快照：磁盘上那条已经被删掉了，那次成功的
//     删除不能被撤销（审计发现：两个并发 Remove，失败的那个发现 IP 缺席就
//     把条目恢复，等于撤销了另一个）。
func (bm *BlacklistManager) rollbackRemovalLocked(ip string, previous *BlacklistEntry, previousViolation *violationState, changeSeq uint64) {
	if bm.entries[ip] != nil || bm.rollbackSupersededLocked(changeSeq) {
		return
	}
	if previous != nil {
		bm.entries[ip] = previous
	}
	if previousViolation != nil {
		bm.violation[ip] = previousViolation
	}
}

// Remove removes an IP from the blacklist and persists the change synchronously.
// A failed write restores the entry, so a reported success always means the
// removal survives a restart.
func (bm *BlacklistManager) Remove(ip string) error {
	bm.mu.Lock()
	changeSeq := bm.nextChangeSeqLocked()
	previous := bm.entries[ip]
	previousViolation := bm.violation[ip]
	delete(bm.entries, ip)
	delete(bm.violation, ip)
	bm.mu.Unlock()

	if err := bm.persist(); err != nil {
		// 同 AddManual：回滚决策和写盘串行化，避免把内存恢复到磁盘上已经不
		// 存在的旧状态。
		bm.saveMu.Lock()
		bm.mu.Lock()
		bm.rollbackRemovalLocked(ip, previous, previousViolation, changeSeq)
		bm.mu.Unlock()
		bm.saveMu.Unlock()
		slog.Error("failed to persist blacklist removal; restored", "ip", ip, "error", err)
		return err
	}
	return nil
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

// Stop 停掉后台协程并把还没落盘的自动条目补写一次。
func (bm *BlacklistManager) Stop() {
	if bm == nil {
		return
	}
	bm.stopOnce.Do(func() {
		close(bm.stopCh)
		bm.wg.Wait()
		if err := bm.flush(); err != nil {
			slog.Error("failed to flush blacklist on shutdown", "error", err)
		}
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
