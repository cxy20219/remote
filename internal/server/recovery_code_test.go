package server

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func newRecoveryCodeStore(t *testing.T, hashes ...string) (*StateStore, string) {
	t.Helper()
	config, store := newTestConfig(t)
	if err := store.SetTOTPConfig(TOTPConfig{Secret: "test-secret", RecoveryHashes: hashes}); err != nil {
		t.Fatalf("SetTOTPConfig: %v", err)
	}
	return store, filepath.Join(config.DataDir(), "server-state.json")
}

// 正常路径：命中一次后该码不可再用，剩余数量与磁盘一致。
func TestConsumeRecoveryCodeNormalPath(t *testing.T) {
	t.Parallel()
	store, path := newRecoveryCodeStore(t, "hash-a", "hash-b")

	remaining, consumed, err := store.ConsumeTOTPRecoveryCode("hash-a")
	if err != nil || !consumed || remaining != 1 {
		t.Fatalf("consume = (%d, %v, %v), want (1, true, nil)", remaining, consumed, err)
	}

	remaining, consumed, err = store.ConsumeTOTPRecoveryCode("hash-a")
	if err != nil || consumed || remaining != 1 {
		t.Fatalf("second consume = (%d, %v, %v), want (1, false, nil)", remaining, consumed, err)
	}

	reloaded := NewStateStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.TOTPConfig().RecoveryHashes; len(got) != 1 || got[0] != "hash-b" {
		t.Fatalf("persisted recovery hashes = %v, want [hash-b]", got)
	}
}

// 写盘失败：返回错误且该码仍然可用；后续成功写盘也不能把「失败的那次消费」
// 带进磁盘（否则接口报失败、重启后码却没了）。
func TestConsumeRecoveryCodeSaveFailureKeepsCode(t *testing.T) {
	t.Parallel()
	store, goodPath := newRecoveryCodeStore(t, "hash-a", "hash-b")

	// 让写盘失败：状态路径落在一个普通文件下面，MkdirAll 会失败。
	notADir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("prepare blocking file: %v", err)
	}
	store.path = filepath.Join(notADir, "server-state.json")

	remaining, consumed, err := store.ConsumeTOTPRecoveryCode("hash-a")
	if err == nil {
		t.Fatal("consume should fail when the state file cannot be written")
	}
	if consumed {
		t.Fatal("a failed consume must report consumed=false")
	}
	if remaining != 2 {
		t.Fatalf("remaining = %d, want 2 (memory must be untouched)", remaining)
	}

	// 修回路径后：该码必须还能用，且磁盘上仍有它。
	store.path = goodPath
	if err := store.Save(); err != nil {
		t.Fatalf("Save after restoring the path: %v", err)
	}
	reloaded := NewStateStore(goodPath)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.TOTPConfig().RecoveryHashes; len(got) != 2 {
		t.Fatalf("persisted hashes = %v, want both codes after a failed consume", got)
	}

	remaining, consumed, err = store.ConsumeTOTPRecoveryCode("hash-a")
	if err != nil || !consumed || remaining != 1 {
		t.Fatalf("consume after failure = (%d, %v, %v), want (1, true, nil)", remaining, consumed, err)
	}
}

// 并发消费同一个恢复码：只能有一个成功。
func TestConsumeRecoveryCodeConcurrent(t *testing.T) {
	t.Parallel()
	store, _ := newRecoveryCodeStore(t, "hash-a")

	var wg sync.WaitGroup
	results := make([]bool, 8)
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, consumed, err := store.ConsumeTOTPRecoveryCode("hash-a")
			results[i] = consumed
			errs[i] = err
		}(i)
	}
	wg.Wait()

	successes := 0
	for i, consumed := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if consumed {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumes = %d, want exactly 1", successes)
	}
	if hashes := store.TOTPConfig().RecoveryHashes; len(hashes) != 0 {
		t.Fatalf("recovery hashes = %v, want empty", hashes)
	}
}
