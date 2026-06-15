package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
	"unicode"
)

const (
	adminSessionTTL        = 24 * time.Hour
	maxAdminSessions       = 64
	maxFailedAdminLogins   = 10
	adminLoginLockDuration = 5 * time.Minute
	minAdminPasswordLength = 12
)

var (
	ErrAdminInvalidPassword = errors.New("invalid password")
	ErrAdminLoginLocked     = errors.New("admin login temporarily locked")
	ErrAdminWeakPassword    = errors.New("new password is too weak")
)

type AdminAuth struct {
	store        *StateStore
	mu           sync.RWMutex
	sessions     map[string]*adminSession
	failedLogins int
	lockedUntil  time.Time
}

type adminSession struct {
	token     string
	createdAt time.Time
	expiresAt time.Time
}

func NewAdminAuth(store *StateStore) *AdminAuth {
	return &AdminAuth{
		store:    store,
		sessions: make(map[string]*adminSession),
	}
}

func (a *AdminAuth) Login(password string) error {
	if a == nil || a.store == nil {
		return ErrAdminInvalidPassword
	}
	now := time.Now()
	a.mu.RLock()
	lockedUntil := a.lockedUntil
	a.mu.RUnlock()
	if now.Before(lockedUntil) {
		return ErrAdminLoginLocked
	}

	if !a.store.VerifyAdminPassword(password) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if time.Now().Before(a.lockedUntil) {
			return ErrAdminLoginLocked
		}
		a.failedLogins++
		if a.failedLogins >= maxFailedAdminLogins {
			a.lockedUntil = time.Now().Add(adminLoginLockDuration)
			a.failedLogins = 0
			return ErrAdminLoginLocked
		}
		return ErrAdminInvalidPassword
	}

	a.mu.Lock()
	a.failedLogins = 0
	a.lockedUntil = time.Time{}
	a.mu.Unlock()
	return nil
}

func (a *AdminAuth) ChangePassword(currentPassword, newPassword string) error {
	if a == nil || a.store == nil {
		return ErrAdminInvalidPassword
	}
	if !a.store.VerifyAdminPassword(currentPassword) {
		return ErrAdminInvalidPassword
	}
	if !strongAdminPassword(newPassword) {
		return ErrAdminWeakPassword
	}
	if err := a.store.SetAdminPassword(newPassword); err != nil {
		return err
	}

	a.mu.Lock()
	a.sessions = make(map[string]*adminSession)
	a.failedLogins = 0
	a.lockedUntil = time.Time{}
	a.mu.Unlock()
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
	a.pruneExpiredLocked(now)
	a.evictOldestLocked(maxAdminSessions - 1)
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

func (a *AdminAuth) pruneExpiredLocked(now time.Time) {
	for token, session := range a.sessions {
		if now.After(session.expiresAt) {
			delete(a.sessions, token)
		}
	}
}

func (a *AdminAuth) evictOldestLocked(maxRemaining int) {
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
