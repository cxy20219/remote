package server

import "testing"

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
