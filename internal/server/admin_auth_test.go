package server

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestAdminAuthGenerateTokenUsesHighEntropyURLSafeToken(t *testing.T) {
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
	store := NewStateStoreWithSettings(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	for i := 0; i < maxFailedAdminLogins-1; i++ {
		if err := auth.Login("wrong"); !errors.Is(err, ErrAdminInvalidPassword) {
			t.Fatalf("failed login %d err = %v, want invalid password", i, err)
		}
	}
	if err := auth.Login("wrong"); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("lock err = %v, want locked", err)
	}
	if err := auth.Login("CorrectPassword1!"); !errors.Is(err, ErrAdminLoginLocked) {
		t.Fatalf("locked login err = %v, want locked", err)
	}
}

func TestAdminAuthChangePasswordRevokesSessions(t *testing.T) {
	store := NewStateStoreWithSettings(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	token, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := auth.ChangePassword("CorrectPassword1!", "NewPassword1!"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if auth.Validate(token) {
		t.Fatal("old session should be revoked")
	}
	if err := auth.Login("CorrectPassword1!"); !errors.Is(err, ErrAdminInvalidPassword) {
		t.Fatalf("old password err = %v, want invalid", err)
	}
	if err := auth.Login("NewPassword1!"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
}

func TestAdminAuthRejectsWeakPassword(t *testing.T) {
	store := NewStateStoreWithSettings(defaultSettings())
	if err := store.SetAdminPassword("CorrectPassword1!"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	auth := NewAdminAuth(store)

	if err := auth.ChangePassword("CorrectPassword1!", "short1!"); !errors.Is(err, ErrAdminWeakPassword) {
		t.Fatalf("ChangePassword err = %v, want weak password", err)
	}
}
