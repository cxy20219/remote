package agent

import (
	"testing"
	"time"
)

func TestReconnectBeforeRetryIncrementsAttempts(t *testing.T) {
	r := NewReconnect(0, 3, 0)

	r.beforeRetry()
	if r.attempts != 1 {
		t.Fatalf("expected attempts to be 1 after first retry, got %d", r.attempts)
	}

	r.beforeRetry()
	if r.attempts != 2 {
		t.Fatalf("expected attempts to be 2 after second retry, got %d", r.attempts)
	}
}

func TestReconnectResetClearsAttempts(t *testing.T) {
	r := NewReconnect(0, 2, 0)

	r.beforeRetry()
	r.beforeRetry()
	if r.shouldRetry() {
		t.Fatal("expected retry budget to be exhausted before reset")
	}

	r.reset()
	if !r.shouldRetry() {
		t.Fatal("expected retry budget to be restored after reset")
	}
	if r.attempts != 0 {
		t.Fatalf("expected attempts to reset to 0, got %d", r.attempts)
	}
}

func TestReconnectNextBackoffHonorsMaxInterval(t *testing.T) {
	r := NewReconnect(1, 0, 2)

	if got := r.nextBackoff(); got != 1*time.Second {
		t.Fatalf("expected first backoff to be 1s, got %v", got)
	}
	if got := r.nextBackoff(); got != 2*time.Second {
		t.Fatalf("expected second backoff to be capped at 2s, got %v", got)
	}
	if got := r.nextBackoff(); got != 2*time.Second {
		t.Fatalf("expected later backoff to remain capped at 2s, got %v", got)
	}
}
