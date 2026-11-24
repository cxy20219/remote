package server

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestAdminAuthGenerateTokenUsesHighEntropyURLSafeToken(t *testing.T) {
	t.Parallel()
	auth := NewAdminAuth(nil)

	first, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	second, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken second: %v", err)
	}

	if first == second {
		t.Fatal("expected unique session tokens")
	}
	if len(first) < 40 || len(second) < 40 {
		t.Fatalf("expected high entropy tokens, got lengths %d and %d", len(first), len(second))
	}
	if !auth.Validate(first) || !auth.Validate(second) {
		t.Fatal("generated tokens should validate")
	}
}

func TestAdminAuthGenerateTokenPrunesExpiredSessions(t *testing.T) {
	t.Parallel()
	auth := NewAdminAuth(nil)
	auth.sessions["expired"] = &adminSession{
		token:     "expired",
		createdAt: time.Now().Add(-2 * adminSessionTTL),
		expiresAt: time.Now().Add(-time.Minute),
	}

	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if _, ok := auth.sessions["expired"]; ok {
		t.Fatal("expected expired session to be pruned")
	}
	if !auth.Validate(token) {
		t.Fatal("new session should validate")
	}
}

func TestAdminAuthSessionLimitEvictsOldest(t *testing.T) {
	t.Parallel()
	auth := NewAdminAuth(nil)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxAdminSessions; i++ {
		token := fmt.Sprintf("old-%02d", i)
		auth.sessions[token] = &adminSession{
			token:     token,
			createdAt: base.Add(time.Duration(i) * time.Second),
			expiresAt: time.Now().Add(adminSessionTTL),
		}
	}

	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if len(auth.sessions) != maxAdminSessions {
		t.Fatalf("expected %d sessions, got %d", maxAdminSessions, len(auth.sessions))
	}
	if _, ok := auth.sessions["old-00"]; ok {
		t.Fatal("expected oldest session to be evicted")
	}
	if !auth.Validate(token) {
		t.Fatal("new session should validate")
	}
}

func TestAdminAuthLocksAfterFailedLogins(t *testing.T) {
	t.Parallel()
	store := newTestStateStore(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	for i := 0; i < maxFailedAdminLogins-1; i++ {
		if err := auth.Login("192.0.2.1", "wrong"); !errors.Is(err, ErrAdminInvalidPassword) {
			t.Fatalf("failed login %d err = %v, want invalid password", i, err)
		}
	}
	if err := auth.Login("192.0.2.1", "wrong"); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("lock err = %v, want locked", err)
	}
	if err := auth.Login("192.0.2.1", "CorrectPassword1!"); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("locked login err = %v, want locked", err)
	}

	// 密码失败只进 IP 池，不触发账户级锁：换 IP 用正确密码仍能拿到第一步，
	// 否则管理员连恢复码登录的入口都会被攻击者刷没。
	if err := auth.Login("198.51.100.7", "CorrectPassword1!"); err != nil {
		t.Fatalf("password step must ignore account-level backoff, got %v", err)
	}

	// 只等该攻击者 IP 的锁窗口过去，同一 IP 才能恢复。
	auth.mu.Lock()
	if failure := auth.failures["192.0.2.1"]; failure != nil {
		failure.lockedUntil = time.Now().Add(-time.Second)
	}
	auth.mu.Unlock()
	if err := auth.Login("192.0.2.1", "CorrectPassword1!"); err != nil {
		t.Fatalf("locked IP should recover after its own window: %v", err)
	}
}

func TestAdminAuthChangePasswordRevokesSessions(t *testing.T) {
	t.Parallel()
	store := newTestStateStore(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := auth.ChangePassword("192.0.2.1", "CorrectPassword1!", "NewPassword1!"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if auth.Validate(token) {
		t.Fatal("old session should be revoked")
	}
	if err := auth.Login("192.0.2.1", "CorrectPassword1!"); !errors.Is(err, ErrAdminInvalidPassword) {
		t.Fatalf("old password err = %v, want invalid", err)
	}
	if err := auth.Login("192.0.2.1", "NewPassword1!"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
}

func TestAdminAuthRejectsWeakPassword(t *testing.T) {
	t.Parallel()
	store := newTestStateStore(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	if err := auth.ChangePassword("192.0.2.1", "CorrectPassword1!", "short1!"); !errors.Is(err, ErrAdminWeakPassword) {
		t.Fatalf("ChangePassword err = %v, want weak password", err)
	}
}
