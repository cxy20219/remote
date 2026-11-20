package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	adminSessionTTL        = 24 * time.Hour
	maxAdminSessions       = 64
	maxFailedAdminLogins   = 10
	adminLoginLockDuration = 5 * time.Minute
	adminFailureTTL        = time.Hour
	maxAdminFailureEntries = 4096
	minAdminPasswordLength = 12

	// 账户级（跨 IP）锁：只统计动态码失败。触发后按 5s → 30s → 5min 退避，
	// 封顶 5 分钟；1 小时无失败自动降一级，24 小时清零。密码失败不进这个池。
	adminAccountLockThreshold = maxFailedAdminLogins
	adminAccountLockMaxLevel  = 3
	adminAccountDecayStep     = time.Hour
	adminAccountResetAfter    = 24 * time.Hour
)

var (
	ErrAdminInvalidPassword = errors.New("invalid password")
	ErrAdminLoginLocked     = errors.New("admin login temporarily locked")
	ErrAdminWeakPassword    = errors.New("new password is too weak")
)

type AdminAuth struct {
	store    *StateStore
	mu       sync.RWMutex
	sessions map[string]*adminSession
	failures map[string]*adminLoginFailure

	// 两步验证的短命内存态（都不落盘）：
	//   challenges：密码通过后签发的登录挑战（绑定 IP、单次、限次）；
	//   pending   ：已扫码但还没输入动态码确认的待激活密钥（按 admin 会话绑定）。
	challenges map[string]*totpChallengeState
	pending    map[string]*totpPendingSetup

	// 账户级失败计数：只累加动态码失败（那一步天然要求先有正确密码），
	// 完整 2FA 成功才清零；静默 1 小时降一级、24 小时归零。
	accountFailures      int
	accountLockLevel     int
	accountLockUntil     time.Time
	lastAccountFailureAt time.Time
}

const maxTOTPChallenges = 256

type totpChallengeState struct {
	ip        string
	createdAt time.Time
	expiresAt time.Time
	attempts  int
	used      bool // 锁内原子占用：同一挑战只能有一个请求在验证
}

type totpPendingSetup struct {
	secret    string
	createdAt time.Time
	expiresAt time.Time
}

type adminSession struct {
	token     string
	createdAt time.Time
	expiresAt time.Time
}

type adminLoginFailure struct {
	failed      int
	lockedUntil time.Time
	lastSeen    time.Time
}

func NewAdminAuth(store *StateStore) *AdminAuth {
	return &AdminAuth{
		store:      store,
		sessions:   make(map[string]*adminSession),
		failures:   make(map[string]*adminLoginFailure),
		challenges: make(map[string]*totpChallengeState),
		pending:    make(map[string]*totpPendingSetup),
	}
}

// Login verifies the admin password for the given client IP.
//
// 密码失败只计入按来源 IP（IPv6 聚合到 /64）的池；跨 IP 的账户级池只统计
// 动态码失败，避免「不知道密码的人」靠刷密码把管理员锁死（见 recordTOTPFailure）。
// 密码正确**不清零**失败计数——只有完整两步验证成功才清。
func (a *AdminAuth) Login(ip, password string) error {
	return a.CheckPassword(ip, password)
}

// CheckPassword 校验管理员密码；成功返回 nil 但不清除失败计数。
func (a *AdminAuth) CheckPassword(ip, password string) error {
	if a == nil || a.store == nil {
		return ErrAdminInvalidPassword
	}
	key := clientIPKey(ip)
	now := time.Now()
	if err := a.checkIPLock(key, now); err != nil {
		return err
	}
	if a.store.VerifyAdminPassword(password) {
		return nil
	}
	return a.recordIPFailure(key, now)
}

// RecordTOTPFailure 把一次动态码/恢复码失败计入两个池：按 IP 的锁，以及
// 跨 IP 的账户级退避（账户级只统计这里，密码失败不参与）。
func (a *AdminAuth) RecordTOTPFailure(ip string) error {
	return a.recordTOTPFailure(clientIPKey(ip), time.Now())
}

// ClearFullAuthFailures 在完整认证成功后清零两个失败池（只有这里会清）。
func (a *AdminAuth) ClearFullAuthFailures(ip string) {
	key := clientIPKey(ip)
	a.mu.Lock()
	delete(a.failures, key)
	a.accountFailures = 0
	a.accountLockLevel = 0
	a.accountLockUntil = time.Time{}
	a.lastAccountFailureAt = time.Time{}
	a.mu.Unlock()
}

// checkIPLock 只检查按 IP 的失败锁。账户级锁不拦密码步骤：否则攻击者刷满次数后，
// 管理员连「用恢复码登录」这条路都走不通（恢复码就在登录第二步里）。
func (a *AdminAuth) checkIPLock(key string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLoginFailuresLocked(now)
	failure := a.failures[key]
	if failure != nil && now.Before(failure.lockedUntil) {
		return ErrAdminLoginLocked
	}
	if failure != nil && !failure.lockedUntil.IsZero() {
		delete(a.failures, key)
	}
	return nil
}

// recordIPFailureLocked 累加单个 IP 的失败数（调用方持有 a.mu），达到阈值时锁 5 分钟。
func (a *AdminAuth) recordIPFailureLocked(key string, now time.Time) bool {
	failure := a.failures[key]
	if failure == nil {
		failure = &adminLoginFailure{}
		a.failures[key] = failure
	}
	failure.failed++
	failure.lastSeen = now
	if failure.failed >= maxFailedAdminLogins {
		failure.failed = 0
		failure.lockedUntil = now.Add(adminLoginLockDuration)
		return true
	}
	return false
}

func (a *AdminAuth) recordIPFailure(key string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recordIPFailureLocked(key, now) {
		return ErrAdminLoginLocked
	}
	return ErrAdminInvalidPassword
}

// recordTOTPFailure 同时累加 IP 池与账户级池。账户级退避封顶 5 分钟，
// 且会先做静默衰减——锁不会无限续期到 1 小时。
func (a *AdminAuth) recordTOTPFailure(key string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.decayAccountLockLocked(now)
	locked := a.recordIPFailureLocked(key, now)

	a.accountFailures++
	a.lastAccountFailureAt = now
	if a.accountFailures%adminAccountLockThreshold == 0 {
		if a.accountLockLevel < adminAccountLockMaxLevel {
			a.accountLockLevel++
		}
		a.accountLockUntil = now.Add(adminAccountBackoff(a.accountLockLevel))
	}
	if now.Before(a.accountLockUntil) {
		locked = true
	}
	if locked {
		return ErrAdminLoginLocked
	}
	return ErrAdminInvalidPassword
}

// accountLocked 报告账户级退避是否生效，调用时先做静默衰减。
func (a *AdminAuth) accountLocked(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decayAccountLockLocked(now)
	return now.Before(a.accountLockUntil)
}

// LockRetryAfter 返回该来源当前还需要的等待秒数（IP 失败锁与账户级退避取较大者），
// 只用于给 429 响应加 Retry-After 头，不改变任何计数。
func (a *AdminAuth) LockRetryAfter(ip string) int {
	if a == nil || a.store == nil {
		return 0
	}
	now := time.Now()
	key := clientIPKey(ip)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.decayAccountLockLocked(now)
	until := a.accountLockUntil
	if failure := a.failures[key]; failure != nil && failure.lockedUntil.After(until) {
		until = failure.lockedUntil
	}
	if !now.Before(until) {
		return 0
	}
	seconds := int((until.Sub(now) + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

// decayAccountLockLocked 实现静默衰减：连续 1 小时没有动态码失败，等级降 1；
// 24 小时没有失败直接清零。调用方持有 a.mu。
func (a *AdminAuth) decayAccountLockLocked(now time.Time) {
	if a.lastAccountFailureAt.IsZero() {
		return
	}
	idle := now.Sub(a.lastAccountFailureAt)
	if idle >= adminAccountResetAfter {
		a.accountFailures = 0
		a.accountLockLevel = 0
		a.accountLockUntil = time.Time{}
		a.lastAccountFailureAt = time.Time{}
		return
	}
	if a.accountLockLevel <= 0 {
		return
	}
	steps := int(idle / adminAccountDecayStep)
	if steps <= 0 {
		return
	}
	if steps > a.accountLockLevel {
		steps = a.accountLockLevel
	}
	a.accountLockLevel -= steps
	a.lastAccountFailureAt = a.lastAccountFailureAt.Add(time.Duration(steps) * adminAccountDecayStep)
}

// adminAccountBackoff 是账户级退避：5s → 30s → 5min 封顶。
// 上限 5 分钟是有意的：账户级锁是 DoS 面，不能让人靠刷失败把管理员关一个小时。
func adminAccountBackoff(lockLevel int) time.Duration {
	switch {
	case lockLevel <= 1:
		return 5 * time.Second
	case lockLevel == 2:
		return 30 * time.Second
	default:
		return 5 * time.Minute
	}
}

// clientIPKey 把来源 IP 归一成限流键：IPv4 用原值，IPv6 聚合到 /64，
// 避免在 /64 内轮换地址绕过失败计数和请求限流。
func clientIPKey(raw string) string {
	ipStr := strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// randomToken 生成 n 字节随机数并做 URL-safe Base64（无 padding）。
func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (a *AdminAuth) pruneLoginFailuresLocked(now time.Time) {
	for ip, failure := range a.failures {
		if now.Before(failure.lockedUntil) {
			continue
		}
		if now.Sub(failure.lastSeen) > adminFailureTTL {
			delete(a.failures, ip)
		}
	}

	if len(a.failures) < maxAdminFailureEntries {
		return
	}
	// Bound memory if a distributed attack creates many entries: drop the
	// oldest unlocked entries first.
	type entry struct {
		ip       string
		lastSeen time.Time
	}
	entries := make([]entry, 0, len(a.failures))
	for ip, failure := range a.failures {
		if now.Before(failure.lockedUntil) {
			continue
		}
		entries = append(entries, entry{ip: ip, lastSeen: failure.lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastSeen.Before(entries[j].lastSeen)
	})
	remove := len(a.failures) - maxAdminFailureEntries/2
	for i := 0; i < remove && i < len(entries); i++ {
		delete(a.failures, entries[i].ip)
	}
	// If every remaining entry is locked, drop arbitrary entries to keep the
	// map bounded; the affected IP can try again later.
	for len(a.failures) >= maxAdminFailureEntries {
		for ip := range a.failures {
			delete(a.failures, ip)
			break
		}
	}
}

func (a *AdminAuth) ChangePassword(ip, currentPassword, newPassword string) error {
	if a == nil || a.store == nil {
		return ErrAdminInvalidPassword
	}
	if err := a.CheckPassword(ip, currentPassword); err != nil {
		return err
	}
	if !strongAdminPassword(newPassword) {
		return ErrAdminWeakPassword
	}
	if err := a.store.SetAdminPassword(newPassword); err != nil {
		return err
	}

	a.mu.Lock()
	a.sessions = make(map[string]*adminSession)
	a.mu.Unlock()
	// 未启用 TOTP 时密码就是完整认证，可以清零失败池；启用时保持计数。
	if !a.TOTPEnabled() {
		a.ClearFullAuthFailures(ip)
	}
	return nil
}

func strongAdminPassword(password string) bool {
	if len(password) < minAdminPasswordLength {
		return false
	}
	classes := 0
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case !unicode.IsSpace(r):
			hasSymbol = true
		}
	}
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	return classes >= 3
}

func (a *AdminAuth) GenerateToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate admin token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])

	now := time.Now()
	a.mu.Lock()
	a.pruneExpiredSessionsLocked(now)
	a.evictOldestSessionLocked(maxAdminSessions - 1)
	a.sessions[token] = &adminSession{
		token:     token,
		createdAt: now,
		expiresAt: now.Add(adminSessionTTL),
	}
	a.mu.Unlock()
	return token, nil
}

func (a *AdminAuth) Validate(token string) bool {
	if token == "" {
		return false
	}
	now := time.Now()
	a.mu.RLock()
	s, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(s.expiresAt) {
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		return false
	}
	return true
}

func (a *AdminAuth) Logout(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

func (a *AdminAuth) pruneExpiredSessionsLocked(now time.Time) {
	for token, session := range a.sessions {
		if now.After(session.expiresAt) {
			delete(a.sessions, token)
		}
	}
}

func (a *AdminAuth) evictOldestSessionLocked(maxRemaining int) {
	if maxRemaining < 0 {
		maxRemaining = 0
	}
	if len(a.sessions) <= maxRemaining {
		return
	}

	sessions := make([]*adminSession, 0, len(a.sessions))
	for _, session := range a.sessions {
		sessions = append(sessions, session)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].createdAt.Before(sessions[j].createdAt)
	})

	removeCount := len(a.sessions) - maxRemaining
	for i := 0; i < removeCount; i++ {
		delete(a.sessions, sessions[i].token)
	}
}

// --- 管理员两步验证（TOTP） ---

// TOTPEnabled 表示管理员已启用 TOTP。
func (a *AdminAuth) TOTPEnabled() bool {
	if a == nil || a.store == nil {
		return false
	}
	return a.store.TOTPConfig().Enabled()
}

// TOTPSelfCheck 自检已启用的 TOTP 配置：密钥必须能解码且长度正确。
// 未启用返回 nil；已启用但密钥损坏返回 ErrTOTPCorrupt。
// 启动时和登录入口都调用，保证 fail closed 的同时不会静默误报。
func (a *AdminAuth) TOTPSelfCheck() error {
	if a == nil || a.store == nil {
		return nil
	}
	cfg := a.store.TOTPConfig()
	if !cfg.Enabled() {
		return nil
	}
	// 走到这里 cfg.Enabled() 已保证 Secret 非空；解码失败（含只有空白字符）
	// 都说明 state 里的密钥不可用。
	if _, err := decodeTOTPSecret(cfg.Secret); err != nil {
		return fmt.Errorf("admin totp: %w: %v", ErrTOTPCorrupt, err)
	}
	return nil
}

// BeginTOTPChallenge 在密码校验通过后签发一次性登录挑战。
// 挑战绑定来源 IP（IPv6 按 /64 聚合），5 分钟过期，单次使用，最多 3 次尝试。
func (a *AdminAuth) BeginTOTPChallenge(ip string) (string, error) {
	if !a.TOTPEnabled() {
		return "", ErrTOTPNotConfigured
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	a.mu.Lock()
	a.pruneTOTPLocked(now)
	a.challenges[token] = &totpChallengeState{
		ip:        clientIPKey(ip),
		createdAt: now,
		expiresAt: now.Add(totpChallengeTTL),
	}
	a.mu.Unlock()
	return token, nil
}

// VerifyTOTPChallenge 校验挑战 + 动态码/恢复码。成功后调用方签发正式会话。
//
// 并发安全：挑战在锁内被原子占用（used），同一挑战同时只有一个请求能进入验证；
// 时间步推进走 CAS，同一个码并发提交时只有一个能成功。
func (a *AdminAuth) VerifyTOTPChallenge(ip, token, code string) error {
	if a == nil || a.store == nil || token == "" {
		return ErrTOTPChallengeInvalid
	}
	now := time.Now()
	key := clientIPKey(ip)

	a.mu.Lock()
	a.pruneTOTPLocked(now)
	challenge := a.challenges[token]
	if challenge == nil || now.After(challenge.expiresAt) || challenge.used || challenge.ip != key {
		a.mu.Unlock()
		return ErrTOTPChallengeInvalid
	}
	challenge.used = true
	challenge.attempts++
	if challenge.attempts > totpChallengeTries {
		delete(a.challenges, token)
		a.mu.Unlock()
		return ErrTOTPChallengeInvalid
	}
	a.mu.Unlock()

	cfg := a.store.TOTPConfig()
	if !cfg.Enabled() {
		a.releaseChallenge(token)
		return ErrTOTPNotConfigured
	}

	// 账户级锁只拦动态码。恢复码是手机丢失/密钥损坏时唯一的自助后路，
	// 必须豁免账户锁——否则攻击者刷满失败次数就能把管理员永久关在门外。
	accountLocked := a.accountLocked(now)
	corrupt := false
	// 动态码严格 6 位；12 位恢复码直接走恢复码分支，不做无谓的动态校验，
	// 也避免密钥损坏时每提交一次恢复码就刷一条「corrupt」错误日志。
	if !accountLocked && len(normalizeTOTPCode(code)) == totpDigits {
		step, err := verifyTOTP(cfg.Secret, code, now, cfg.LastStep)
		switch {
		case err == nil:
			if cerr := a.commitTOTPStep(step); cerr != nil {
				a.releaseChallenge(token)
				if errors.Is(cerr, ErrTOTPReplay) {
					slog.Warn("admin totp replay rejected on commit", "ip", key)
					if ferr := a.RecordTOTPFailure(ip); errors.Is(ferr, ErrAdminLoginLocked) {
						return ferr
					}
					return ErrTOTPInvalidCode
				}
				return cerr
			}
			a.finishChallenge(token)
			a.ClearFullAuthFailures(ip)
			return nil
		case errors.Is(err, ErrTOTPReplay):
			// 重放：计入失败池，对外仍是「动态码错误」，不泄漏时间步信息。
			slog.Warn("admin totp replay rejected", "ip", key)
			a.releaseChallenge(token)
			if ferr := a.RecordTOTPFailure(ip); errors.Is(ferr, ErrAdminLoginLocked) {
				return ferr
			}
			return ErrTOTPInvalidCode
		case errors.Is(err, ErrTOTPCorrupt):
			// 密钥坏了：动态码注定验不过，但恢复码消费必须继续放行（见下）。
			corrupt = true
			slog.Error("admin totp secret is corrupt; dynamic code cannot be verified", "ip", key, "error", err)
		}
	}

	// 恢复码：原子消费，并发下同一码只会成功一次。账户锁与密钥损坏都不拦它。
	remaining, consumed, cerr := a.store.ConsumeTOTPRecoveryCode(hashRecoveryCode(code))
	if cerr != nil {
		a.releaseChallenge(token)
		return cerr
	}
	if consumed {
		if !a.store.TOTPConfig().Enabled() {
			a.releaseChallenge(token)
			return ErrTOTPInvalidCode
		}
		a.finishChallenge(token)
		a.ClearFullAuthFailures(ip)
		slog.Warn("admin totp recovery code used", "ip", key, "remaining", remaining)
		return nil
	}

	if corrupt {
		// 挑战无法完成；配置故障不计入用户失败次数，避免把服务端问题算到管理员头上。
		a.finishChallenge(token)
		return ErrTOTPCorrupt
	}
	if accountLocked {
		a.releaseChallenge(token)
		return ErrAdminLoginLocked
	}

	slog.Warn("admin totp verification failed", "ip", key)
	a.releaseChallenge(token)
	if ferr := a.RecordTOTPFailure(ip); errors.Is(ferr, ErrAdminLoginLocked) {
		return ferr
	}
	return ErrTOTPInvalidCode
}

// commitTOTPStep 用 CAS 推进防重放时间步；并发下同一码只有一个调用者能推进成功。
func (a *AdminAuth) commitTOTPStep(step int64) error {
	for attempt := 0; attempt < 3; attempt++ {
		current := a.store.TOTPLastStep()
		if step <= current {
			return ErrTOTPReplay
		}
		if !a.store.CompareAndSwapTOTPLastStep(current, step) {
			continue
		}
		return a.store.Save()
	}
	return ErrTOTPReplay
}

// releaseChallenge 在验证失败后把挑战放回（保留剩余尝试次数），过期或次数用尽则删除。
func (a *AdminAuth) releaseChallenge(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	challenge := a.challenges[token]
	if challenge == nil {
		return
	}
	if challenge.attempts >= totpChallengeTries || time.Now().After(challenge.expiresAt) {
		delete(a.challenges, token)
		return
	}
	challenge.used = false
}

// StartTOTPSetup 生成待激活密钥并渲染二维码。密码校验由调用方先做。
func (a *AdminAuth) StartTOTPSetup(session string) (secret, uri, qrDataURL string, err error) {
	if session == "" {
		return "", "", "", ErrTOTPSetupExpired
	}
	if !a.store.EncryptionEnabled() {
		return "", "", "", ErrStateEncryptionKeyRequired
	}
	if a.store.TOTPConfig().Enabled() {
		return "", "", "", ErrTOTPAlreadyEnabled
	}
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", "", err
	}
	uri = provisioningURI(secret)
	qrDataURL, err = provisioningQR(uri)
	if err != nil {
		return "", "", "", err
	}

	now := time.Now()
	a.mu.Lock()
	a.pruneTOTPLocked(now)
	a.pending[session] = &totpPendingSetup{
		secret:    secret,
		createdAt: now,
		expiresAt: now.Add(totpSetupTTL),
	}
	a.mu.Unlock()
	return secret, uri, qrDataURL, nil
}

// PendingTOTPSetup 报告当前会话是否有未完成的激活流程。
func (a *AdminAuth) PendingTOTPSetup(session string) bool {
	if session == "" {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneTOTPLocked(now)
	setup := a.pending[session]
	return setup != nil && !now.After(setup.expiresAt)
}

// EnableTOTP 用动态码确认待激活密钥，落盘并返回**仅此一次**的恢复码。
func (a *AdminAuth) EnableTOTP(session, code string) ([]string, error) {
	if !a.store.EncryptionEnabled() {
		return nil, ErrStateEncryptionKeyRequired
	}
	cfg := a.store.TOTPConfig()
	if cfg.Enabled() {
		return nil, ErrTOTPAlreadyEnabled
	}

	now := time.Now()
	a.mu.Lock()
	a.pruneTOTPLocked(now)
	setup := a.pending[session]
	if setup == nil || now.After(setup.expiresAt) {
		delete(a.pending, session)
		a.mu.Unlock()
		return nil, ErrTOTPSetupExpired
	}
	secret := setup.secret
	a.mu.Unlock()

	step, err := verifyTOTP(secret, code, now, 0)
	if err != nil {
		return nil, ErrTOTPInvalidCode
	}
	codes, hashes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	// 防重放锚点只记到「确认时那个窗口之前」：确认用的码随后登录时仍可再用一次，
	// 不必对着登录页空等最多 90 秒；真正被烧掉的只有更早的窗口。
	lastStep := step - 1
	if lastStep < 0 {
		lastStep = 0
	}
	if err := a.store.SetTOTPConfig(TOTPConfig{Secret: secret, RecoveryHashes: hashes, LastStep: lastStep}); err != nil {
		return nil, err
	}
	a.finishPending(session)
	a.RevokeOtherSessions(session)
	slog.Info("admin totp enabled", "recovery_codes", len(codes))
	return codes, nil
}

// DisableTOTP 关闭两步验证，必须同时提供密码与当前动态码。
func (a *AdminAuth) DisableTOTP(ip, session, password, code string) error {
	cfg := a.store.TOTPConfig()
	if !cfg.Enabled() {
		return ErrTOTPNotConfigured
	}
	if err := a.CheckPassword(ip, password); err != nil {
		return err
	}
	// 关闭走的是动态码，账户级退避对它生效；恢复码关闭（RecoverTOTP）豁免。
	if a.accountLocked(time.Now()) {
		return ErrAdminLoginLocked
	}
	if _, err := verifyTOTP(cfg.Secret, code, time.Now(), cfg.LastStep); err != nil {
		if errors.Is(err, ErrTOTPCorrupt) {
			slog.Error("admin totp secret is corrupt; cannot verify disable request", "ip", clientIPKey(ip), "error", err)
			return ErrTOTPCorrupt
		}
		if ferr := a.RecordTOTPFailure(ip); errors.Is(ferr, ErrAdminLoginLocked) {
			return ferr
		}
		return ErrTOTPInvalidCode
	}
	if err := a.store.SetTOTPConfig(TOTPConfig{}); err != nil {
		return err
	}
	a.mu.Lock()
	a.pending = make(map[string]*totpPendingSetup)
	a.challenges = make(map[string]*totpChallengeState)
	a.mu.Unlock()
	a.RevokeOtherSessions(session)
	a.ClearFullAuthFailures(ip)
	slog.Info("admin totp disabled", "ip", clientIPKey(ip))
	return nil
}

// RecoverTOTP 用恢复码关闭两步验证：手机丢失、动态码不可用时的唯一自助出口。
// 仍然要求密码 + 一个有效的一次性恢复码（恢复码本身就是第二因子）。
//
// 注意：账户级锁的「豁免」只表示这条路径不会被锁挡住；错误的密码或恢复码
// 仍会计入 IP / 账户失败池，可能延长账户级锁。它不是免费的爆破通道。
func (a *AdminAuth) RecoverTOTP(ip, session, password, recoveryCode string) error {
	cfg := a.store.TOTPConfig()
	if !cfg.Enabled() {
		return ErrTOTPNotConfigured
	}
	if err := a.CheckPassword(ip, password); err != nil {
		return err
	}
	remaining, consumed, err := a.store.ConsumeTOTPRecoveryCode(hashRecoveryCode(recoveryCode))
	if err != nil {
		return err
	}
	if !consumed {
		if ferr := a.RecordTOTPFailure(ip); errors.Is(ferr, ErrAdminLoginLocked) {
			return ferr
		}
		return ErrTOTPInvalidCode
	}
	if err := a.store.SetTOTPConfig(TOTPConfig{}); err != nil {
		return err
	}
	a.mu.Lock()
	a.pending = make(map[string]*totpPendingSetup)
	a.challenges = make(map[string]*totpChallengeState)
	a.mu.Unlock()
	a.RevokeOtherSessions(session)
	a.ClearFullAuthFailures(ip)
	slog.Warn("admin totp disabled via recovery code", "ip", clientIPKey(ip), "remaining", remaining)
	return nil
}

// RevokeOtherSessions 吊销除 keep 以外的全部管理员会话（启用/关闭 TOTP 时用）。
func (a *AdminAuth) RevokeOtherSessions(keep string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for token := range a.sessions {
		if token != keep {
			delete(a.sessions, token)
		}
	}
}

func (a *AdminAuth) finishChallenge(token string) {
	a.mu.Lock()
	delete(a.challenges, token)
	a.mu.Unlock()
}

func (a *AdminAuth) finishPending(session string) {
	a.mu.Lock()
	delete(a.pending, session)
	a.mu.Unlock()
}

func (a *AdminAuth) pruneTOTPLocked(now time.Time) {
	for token, challenge := range a.challenges {
		if now.After(challenge.expiresAt) {
			delete(a.challenges, token)
		}
	}
	for session, setup := range a.pending {
		if now.After(setup.expiresAt) {
			delete(a.pending, session)
		}
	}
	if len(a.challenges) <= maxTOTPChallenges {
		return
	}
	type entry struct {
		token     string
		createdAt time.Time
	}
	entries := make([]entry, 0, len(a.challenges))
	for token, challenge := range a.challenges {
		entries = append(entries, entry{token: token, createdAt: challenge.createdAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].createdAt.Before(entries[j].createdAt) })
	remove := len(a.challenges) - maxTOTPChallenges/2
	for i := 0; i < remove && i < len(entries); i++ {
		delete(a.challenges, entries[i].token)
	}
}
