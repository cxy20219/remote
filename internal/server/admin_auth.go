package server

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

type AdminAuth struct {
	store *StateStore
	mu    sync.RWMutex
	sessions map[string]*adminSession
}

type adminSession struct {
	token     string
	expiresAt time.Time
}

func NewAdminAuth(store *StateStore) *AdminAuth {
	return &AdminAuth{
		store:    store,
		sessions: make(map[string]*adminSession),
	}
}

func (a *AdminAuth) Login(password string) bool {
	return a.store.VerifyAdminPassword(password)
}

func (a *AdminAuth) GenerateToken() (string, error) {
	token := uuid.New().String()
	a.mu.Lock()
	a.sessions[token] = &adminSession{
		token:     token,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	a.mu.Unlock()
	return token, nil
}

func (a *AdminAuth) Validate(token string) bool {
	if token == "" {
		return false
	}
	a.mu.RLock()
	s, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(s.expiresAt) {
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