package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	adminSessionTTL  = 24 * time.Hour
	maxAdminSessions = 64
)

type AdminAuth struct {
	store    *StateStore
	mu       sync.RWMutex
	sessions map[string]*adminSession
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

func (a *AdminAuth) Login(password string) bool {
	if a == nil || a.store == nil {
		return false
	}
	return a.store.VerifyAdminPassword(password)
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
