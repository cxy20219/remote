package server

import (
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
)

func getBackupStatus(t *testing.T, srv *Server) BackupStatusResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/backup/status", nil)
	srv.handleAPIBackupStatus(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("backup status returned %d, want 200", recorder.Code)
	}
	var response BackupStatusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode backup status: %v (body %s)", err, recorder.Body.String())
	}
	return response
}

// TestBackupStatusEndpoint 钉住字段名与语义：前端按这个形状显示「上次备份」。
func TestBackupStatusEndpoint(t *testing.T) {
	srv := newObserveTestServer(t)

	registered := false
	for _, route := range srv.engine.Routes() {
		if route.Method == http.MethodGet && route.Path == "/api/backup/status" {
			registered = true
		}
	}
	if !registered {
		t.Fatal("/api/backup/status is not registered on the router")
	}

	// 从未备份：200 + 零值，而不是 404 或 500。
	empty := getBackupStatus(t, srv)
	if empty.LastSuccessAt != "" || empty.LastArchive != "" || empty.LastSize != 0 || empty.LastMode != "" {
		t.Fatalf("a fresh install must report an empty ledger, got %+v", empty)
	}

	at := time.Date(2026, 11, 25, 1, 2, 3, 0, time.UTC)
	if err := RecordBackupSuccess(srv.config.DataDir(), "/var/backups/goremote-backup-x.tar.gz", 4096, "abc123", BackupModeEncryptedWithKey, at); err != nil {
		t.Fatalf("record backup: %v", err)
	}
	status := getBackupStatus(t, srv)
	if status.LastSuccessAt != at.Format(time.RFC3339) {
		t.Fatalf("last_success_at = %q", status.LastSuccessAt)
	}
	if status.LastArchive != "goremote-backup-x.tar.gz" {
		t.Fatalf("last_archive = %q, want only the file name (no server paths on the wire)", status.LastArchive)
	}
	if status.LastSize != 4096 || status.LastSHA256 != "abc123" {
		t.Fatalf("size/sha = %d/%q", status.LastSize, status.LastSHA256)
	}
	if status.LastMode != BackupModeEncryptedWithKey {
		t.Fatalf("last_mode = %q", status.LastMode)
	}
	if status.LastRestoreAt != "" {
		t.Fatalf("last_restore_at = %q, want empty before any restore", status.LastRestoreAt)
	}

	// 账本损坏不能让面板 500：退化成空账本。
	ledgerPath := BackupLedgerPath(srv.config.DataDir())
	if err := os.WriteFile(ledgerPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt the ledger: %v", err)
	}
	broken := getBackupStatus(t, srv)
	if broken.LastSuccessAt != "" {
		t.Fatalf("a corrupt ledger must degrade to empty, got %+v", broken)
	}
}

// TestStartHoldsDataDirLock 证明「服务在跑」这件事有一个内核级的判据，
// 而不是靠人去猜：Start 持锁，Stop 之后锁必须能重新拿到。
func TestStartHoldsDataDirLock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, _ := newTestConfig(t)
	srv := mustNewServer(t, config, embed.FS{})
	go func() { _ = srv.Start() }()

	lockPath := filepath.Join(config.DataDir(), ".lock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		lock, err := common.TryLockFile(lockPath)
		if err == nil {
			lock.Release()
			if time.Now().After(deadline) {
				t.Fatal("the server never took the data dir lock")
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if errors.Is(err, common.ErrLockBusy) {
			break
		}
		t.Fatalf("unexpected lock error: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	lock, err := common.TryLockFile(lockPath)
	if err != nil {
		t.Fatalf("the lock was not released after Stop: %v", err)
	}
	lock.Release()
}

// TestSecondServerOnSameDataDirRefusesToStart 是「服务在跑时不许恢复」的另一半：
// 同一份 data 上起第二个实例必须当场失败，并点名 data/.lock。
func TestSecondServerOnSameDataDirRefusesToStart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, _ := newTestConfig(t)
	first := mustNewServer(t, config, embed.FS{})
	go func() { _ = first.Start() }()

	lockPath := filepath.Join(config.DataDir(), ".lock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		lock, err := common.TryLockFile(lockPath)
		if err == nil {
			lock.Release()
			if time.Now().After(deadline) {
				t.Fatal("the first server never took the data dir lock")
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if errors.Is(err, common.ErrLockBusy) {
			break
		}
		t.Fatalf("unexpected lock error: %v", err)
	}

	secondConfig := newTestConfigForDir(t, config.DataDir())
	second := mustNewServer(t, secondConfig, embed.FS{})
	err := second.Start()
	if err == nil {
		_ = second.Stop()
		t.Fatal("a second server on the same data dir must refuse to start")
	}
	if !strings.Contains(err.Error(), "data/.lock") {
		t.Fatalf("the error must point at data/.lock, got: %v", err)
	}

	if err := first.Stop(); err != nil {
		t.Fatalf("stop the first server: %v", err)
	}
}

// newTestConfigForDir 复用已有的数据目录，构造一个指向它的配置。
func newTestConfigForDir(t *testing.T, dir string) *Config {
	t.Helper()
	statePath := filepath.Join(dir, "server-state.json")
	store := NewStateStore(statePath)
	if err := store.Load(); err != nil {
		t.Fatalf("load state from %s: %v", dir, err)
	}
	config := &Config{Server: ServerConfig{Host: "127.0.0.1", Port: 0}}
	config.SetDataDir(dir)
	return config
}
