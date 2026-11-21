package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func readBlacklistFile(t *testing.T, path string) blacklistFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blacklist file: %v", err)
	}
	var file blacklistFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode blacklist file %q: %v", data, err)
	}
	return file
}

func writeBlacklistFixture(t *testing.T, path string, entries []BlacklistEntry) []byte {
	t.Helper()
	data, err := json.Marshal(blacklistFile{Version: blacklistFileVersion, Entries: entries})
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return data
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestBlacklistManualEntrySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "blacklist.json")

	bm := NewBlacklistManager(10, path)
	if err := bm.AddManual("203.0.113.7", "manual ban", 0); err != nil {
		t.Fatalf("add manual: %v", err)
	}
	if err := bm.AddManual("203.0.113.8", "one hour", time.Hour); err != nil {
		t.Fatalf("add manual with duration: %v", err)
	}
	bm.Stop()

	// 手动操作是同步落盘：返回时文件必须已经在，权限也必须是约定的值。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("blacklist file must exist after AddManual: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("blacklist file mode = %o, want 600", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat blacklist dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("blacklist dir mode = %o, want 700", perm)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the temp file must be gone after a successful write, stat err=%v", err)
	}

	restarted := NewBlacklistManager(10, path)
	defer restarted.Stop()
	if !restarted.IsBlacklisted("203.0.113.7") {
		t.Fatal("a manual entry must survive a restart")
	}
	entries := restarted.List()
	if len(entries) != 2 {
		t.Fatalf("reloaded entries = %+v, want both manual entries", entries)
	}
	byIP := make(map[string]BlacklistEntry, len(entries))
	for _, entry := range entries {
		byIP[entry.IP] = entry
		if entry.Source != blacklistSourceManual {
			t.Fatalf("%s source = %q, want %q", entry.IP, entry.Source, blacklistSourceManual)
		}
	}
	permanent, ok := byIP["203.0.113.7"]
	if !ok {
		t.Fatal("the permanent entry is missing after a restart")
	}
	if !permanent.ExpiresAt.IsZero() {
		t.Fatalf("duration 0 must stay permanent, got expires_at=%v", permanent.ExpiresAt)
	}
	temporary, ok := byIP["203.0.113.8"]
	if !ok {
		t.Fatal("the timed entry is missing after a restart")
	}
	if !temporary.ExpiresAt.After(time.Now()) {
		t.Fatalf("a one-hour entry must keep a future expiry after a restart, got %v", temporary.ExpiresAt)
	}
}

// 自动拉黑走 3 秒批量写盘；窗口内的多次标记必须合并成一次写入。测试注入
// 更短的窗口，但断言的是同一套“窗口内不写、窗口后写一次”的行为。
func TestBlacklistAutoEntriesAreFlushedInBackground(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	const delay = 400 * time.Millisecond
	bm := newBlacklistManager(1, path, delay)
	defer bm.Stop()

	if !bm.AddViolation("198.51.100.9") || !bm.AddViolation("198.51.100.10") || !bm.AddViolation("198.51.100.11") {
		t.Fatal("threshold 1 should blacklist on every first violation")
	}
	bm.mu.RLock()
	dirty := bm.dirty
	bm.mu.RUnlock()
	if !dirty {
		t.Fatal("auto-blacklist should be deferred (dirty) instead of written synchronously")
	}

	time.Sleep(delay / 2)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the file must not be written before the debounce window elapses")
	}
	waitForFile(t, path, 10*delay)
	firstInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat blacklist file: %v", err)
	}

	// 同一窗口内的三次标记只产生一次落盘：再等一个窗口，mtime 不应变化。
	time.Sleep(delay + delay/2)
	secondInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat blacklist file: %v", err)
	}
	if !firstInfo.ModTime().Equal(secondInfo.ModTime()) {
		t.Fatal("multiple marks inside one window must coalesce into a single write")
	}

	file := readBlacklistFile(t, path)
	if file.Version != blacklistFileVersion {
		t.Fatalf("file version = %d, want %d", file.Version, blacklistFileVersion)
	}
	if len(file.Entries) != 3 {
		t.Fatalf("persisted entries = %d, want the 3 marks from one window", len(file.Entries))
	}
	for _, entry := range file.Entries {
		if entry.Source != blacklistSourceAuto {
			t.Fatalf("%s source = %q, want %q", entry.IP, entry.Source, blacklistSourceAuto)
		}
		if entry.ExpiresAt.IsZero() {
			t.Fatal("an auto entry must keep its 24h expiry")
		}
	}

	bm.Stop()
	restarted := NewBlacklistManager(1, path)
	defer restarted.Stop()
	for _, ip := range []string{"198.51.100.9", "198.51.100.10", "198.51.100.11"} {
		if !restarted.IsBlacklisted(ip) {
			t.Fatalf("%s must survive a restart", ip)
		}
	}
}

// 生产窗口固定为 3 秒：注入参数只给测试用，别把线上改成 50ms 也没人发现。
func TestBlacklistFlushWindowIsThreeSeconds(t *testing.T) {
	if blacklistFlushDelay != 3*time.Second {
		t.Fatalf("production blacklist flush window = %v, want 3s", blacklistFlushDelay)
	}
}

func TestBlacklistLoadDropsExpiredEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	now := time.Now()
	writeBlacklistFixture(t, path, []BlacklistEntry{
		{IP: "192.0.2.10", Reason: "live", Source: blacklistSourceAuto, AddedAt: now, ExpiresAt: now.Add(time.Hour)},
		{IP: "192.0.2.11", Reason: "expired", Source: blacklistSourceAuto, AddedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{IP: "192.0.2.12", Reason: "permanent", Source: blacklistSourceManual, AddedAt: now},
	})

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	if bm.IsBlacklisted("192.0.2.11") {
		t.Fatal("an entry that expired before startup must not block")
	}
	if !bm.IsBlacklisted("192.0.2.10") || !bm.IsBlacklisted("192.0.2.12") {
		t.Fatal("live and permanent entries must be loaded")
	}
	if got := len(bm.List()); got != 2 {
		t.Fatalf("loaded entries = %d, want 2 (the expired one dropped)", got)
	}
}

// 旧文件没有 source 字段：永久条目按手动、带过期时间按自动，保证升级后
// 手动封禁也不会被淘汰。
func TestBlacklistSourceBackfilledOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	now := time.Now()
	writeBlacklistFixture(t, path, []BlacklistEntry{
		{IP: "192.0.2.21", Reason: "legacy permanent", AddedAt: now.Add(-time.Hour)},
		{IP: "192.0.2.22", Reason: "legacy auto", AddedAt: now, ExpiresAt: now.Add(time.Hour)},
	})

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	sources := make(map[string]string)
	for _, entry := range bm.List() {
		sources[entry.IP] = entry.Source
	}
	if got := sources["192.0.2.21"]; got != blacklistSourceManual {
		t.Fatalf("a legacy permanent entry must be treated as manual, got %q", got)
	}
	if got := sources["192.0.2.22"]; got != blacklistSourceAuto {
		t.Fatalf("a legacy expiring entry must be treated as auto, got %q", got)
	}
}

// 表满时只淘汰 auto：手动封禁即使是最早添加的也必须保留，否则攻击者用
// 流量填满表就能把手动封禁洗掉（审计阻塞项）。
func TestBlacklistEvictionOnlyTargetsAutoEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	base := time.Now().Add(-time.Duration(blacklistMaxEntries) * time.Second)
	entries := make([]BlacklistEntry, 0, blacklistMaxEntries)
	for i := 0; i < 2; i++ {
		entries = append(entries, BlacklistEntry{
			IP:      fmt.Sprintf("203.0.113.%d", i+1),
			Reason:  "manual",
			Source:  blacklistSourceManual,
			AddedAt: base.Add(time.Duration(i) * time.Second),
		})
	}
	for i := 0; i < blacklistMaxEntries-2; i++ {
		entries = append(entries, BlacklistEntry{
			IP:        fmt.Sprintf("198.18.%d.%d", i/256, i%256),
			Reason:    "auto",
			Source:    blacklistSourceAuto,
			AddedAt:   base.Add(time.Duration(i+2) * time.Second),
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}
	writeBlacklistFixture(t, path, entries)

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	if got := len(bm.List()); got != blacklistMaxEntries {
		t.Fatalf("loaded entries = %d, want %d", got, blacklistMaxEntries)
	}

	// 表满时新增自动拉黑：只能淘汰最旧的 auto（198.18.0.0）。
	if !bm.AddViolation("203.0.113.200") {
		t.Fatal("an auto entry should be able to evict another auto entry")
	}
	if bm.IsBlacklisted("198.18.0.0") {
		t.Fatal("the oldest auto entry should be evicted")
	}
	if !bm.IsBlacklisted("198.18.0.1") {
		t.Fatal("only as many auto entries as needed should be evicted")
	}
	if !bm.IsBlacklisted("203.0.113.1") || !bm.IsBlacklisted("203.0.113.2") {
		t.Fatal("manual entries must never be evicted, even when they are the oldest")
	}
	if got := len(bm.List()); got != blacklistMaxEntries {
		t.Fatalf("entries = %d, want the cap %d", got, blacklistMaxEntries)
	}
}

// 全是手动条目的满表：新增手动返回 ErrBlacklistFull、自动拉黑直接放弃，
// 两种情况下都不淘汰任何条目，也不重写文件。
func TestBlacklistFullOfManualEntriesRejectsInserts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	base := time.Now().Add(-time.Duration(blacklistMaxEntries) * time.Second)
	entries := make([]BlacklistEntry, 0, blacklistMaxEntries)
	for i := 0; i < blacklistMaxEntries; i++ {
		entries = append(entries, BlacklistEntry{
			IP:      fmt.Sprintf("198.19.%d.%d", i/256, i%256),
			Reason:  "manual",
			Source:  blacklistSourceManual,
			AddedAt: base.Add(time.Duration(i) * time.Second),
		})
	}
	before := writeBlacklistFixture(t, path, entries)

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	if got := len(bm.List()); got != blacklistMaxEntries {
		t.Fatalf("loaded entries = %d, want %d", got, blacklistMaxEntries)
	}

	if err := bm.AddManual("203.0.113.9", "full", 0); !errors.Is(err, ErrBlacklistFull) {
		t.Fatalf("want ErrBlacklistFull, got %v", err)
	}
	if bm.IsBlacklisted("203.0.113.9") {
		t.Fatal("a rejected manual entry must not be added")
	}
	if !bm.IsBlacklisted("198.19.0.0") {
		t.Fatal("manual entries must survive a rejected insert")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blacklist file: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected insert must not rewrite the file")
	}

	if bm.AddViolation("203.0.113.10") {
		t.Fatal("auto-blacklisting must be skipped when the table is full of manual entries")
	}
	if bm.IsBlacklisted("203.0.113.10") || len(bm.List()) != blacklistMaxEntries {
		t.Fatal("a skipped auto-blacklist must not change the table")
	}

	// 解除一条手动条目后，容量恢复，新增可以继续。
	if err := bm.Remove("198.19.0.0"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := bm.AddManual("203.0.113.9", "full", 0); err != nil {
		t.Fatalf("after removing one entry the add should succeed: %v", err)
	}
	if !bm.IsBlacklisted("203.0.113.9") {
		t.Fatal("the new manual entry should be active")
	}
}

func TestBlacklistCorruptFileIsQuarantined(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "invalid json", content: "{not json"},
		{name: "unknown version", content: `{"version":2,"entries":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blacklist.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			bm := NewBlacklistManager(1, path)
			defer bm.Stop()
			if got := len(bm.List()); got != 0 {
				t.Fatalf("a corrupt file must start an empty list, got %d entries", got)
			}
			if _, err := os.Stat(path + ".corrupt"); err != nil {
				t.Fatalf("the corrupt file should be quarantined: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("the corrupt file should be moved away, stat err=%v", err)
			}

			// 服务照常：损坏文件不妨碍后续正常写入。
			if err := bm.AddManual("192.0.2.9", "after corrupt", 0); err != nil {
				t.Fatalf("add manual after a corrupt file: %v", err)
			}
			if !bm.IsBlacklisted("192.0.2.9") {
				t.Fatal("the manager should keep working after quarantining the file")
			}
		})
	}
}

// 插入时为腾位置淘汰的 auto 条目，必须和这次写入同成同败：落盘失败时
// 把它们放回去，内存不能比磁盘少一条。
func TestBlacklistPersistFailureRestoresEvictedEntries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "blacklist.json")
	base := time.Now().Add(-time.Duration(blacklistMaxEntries) * time.Second)
	entries := make([]BlacklistEntry, 0, blacklistMaxEntries)
	entries = append(entries, BlacklistEntry{
		IP:        "198.18.0.0",
		Reason:    "oldest auto",
		Source:    blacklistSourceAuto,
		AddedAt:   base,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	for i := 0; i < blacklistMaxEntries-1; i++ {
		entries = append(entries, BlacklistEntry{
			IP:      fmt.Sprintf("198.19.%d.%d", i/256, i%256),
			Reason:  "manual",
			Source:  blacklistSourceManual,
			AddedAt: base.Add(time.Duration(i+1) * time.Second),
		})
	}
	writeBlacklistFixture(t, path, entries)

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	if !bm.IsBlacklisted("198.18.0.0") {
		t.Fatal("the oldest auto entry should be loaded")
	}

	// 把数据目录换成一个普通文件：下一次写盘必然失败。
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove data dir: %v", err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatalf("replace data dir with a file: %v", err)
	}

	if err := bm.AddManual("203.0.113.77", "cannot persist", 0); err == nil {
		t.Fatal("a manual add must report the persistence failure")
	}
	if bm.IsBlacklisted("203.0.113.77") {
		t.Fatal("a failed manual add must be rolled back")
	}
	if !bm.IsBlacklisted("198.18.0.0") {
		t.Fatal("an entry evicted to make room must be restored when the write fails")
	}
	if got := len(bm.List()); got != blacklistMaxEntries {
		t.Fatalf("entries = %d, want the original %d", got, blacklistMaxEntries)
	}
}

func TestBlacklistWriteFailureRollsBackManualChange(t *testing.T) {
	// 父路径是个普通文件，MkdirAll/写盘必然失败。
	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	path := filepath.Join(blocker, "blacklist.json")

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	if err := bm.AddManual("192.0.2.77", "cannot persist", 0); err == nil {
		t.Fatal("a manual add must report the persistence failure")
	}
	if bm.IsBlacklisted("192.0.2.77") {
		t.Fatal("a failed manual add must be rolled back")
	}

	// 已经在内存里的条目：删除失败时必须恢复，不能让「删掉了」只存在于内存。
	if !bm.AddViolation("192.0.2.88") {
		t.Fatal("threshold 1 should blacklist on the first violation")
	}
	if err := bm.Remove("192.0.2.88"); err == nil {
		t.Fatal("a manual removal must report the persistence failure")
	}
	if !bm.IsBlacklisted("192.0.2.88") {
		t.Fatal("a failed removal must restore the entry")
	}
}

// 回滚只在「当前值仍是本次写入」时生效：并发操作已经成功写入新值时，
// 失败的旧操作不能把它覆盖回旧状态。
func TestBlacklistRollbackDoesNotClobberConcurrentSuccess(t *testing.T) {
	bm := NewBlacklistManager(1, "")
	defer bm.Stop()

	installed := &BlacklistEntry{IP: "192.0.2.31", Reason: "failed write", Source: blacklistSourceManual}
	newer := &BlacklistEntry{IP: "192.0.2.31", Reason: "concurrent success", Source: blacklistSourceManual}
	bm.mu.Lock()
	bm.entries["192.0.2.31"] = newer
	bm.rollbackInsertLocked("192.0.2.31", installed, nil, false, nil, false)
	current := bm.entries["192.0.2.31"]
	bm.mu.Unlock()
	if current != newer {
		t.Fatal("rollback overwrote a concurrent successful write")
	}

	// 删除失败的回滚：只有在 IP 仍然缺席时才恢复。
	removed := &BlacklistEntry{IP: "192.0.2.32", Reason: "still blocked", Source: blacklistSourceManual}
	bm.mu.Lock()
	bm.rollbackRemovalLocked("192.0.2.32", removed, true, nil, false)
	if bm.entries["192.0.2.32"] != removed {
		t.Fatal("a failed removal must restore the entry when the IP is still absent")
	}
	newerRemoval := &BlacklistEntry{IP: "192.0.2.32", Reason: "concurrent re-add", Source: blacklistSourceManual}
	bm.entries["192.0.2.32"] = newerRemoval
	bm.rollbackRemovalLocked("192.0.2.32", removed, true, nil, false)
	current = bm.entries["192.0.2.32"]
	bm.mu.Unlock()
	if current != newerRemoval {
		t.Fatal("a failed removal must not overwrite a concurrent re-add")
	}
}

// 每一步返回 nil 的操作都必须在重启后成立：不能出现「接口说成功了，内存
// 或磁盘里却没有」。
func TestBlacklistConcurrentAddRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	bm := newBlacklistManager(2, path, 50*time.Millisecond)

	var mu sync.Mutex
	expected := make(map[string]bool)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				ip := fmt.Sprintf("198.18.%d.%d", worker, i+1)
				switch i % 3 {
				case 0:
					if err := bm.AddManual(ip, "concurrent", time.Hour); err == nil {
						mu.Lock()
						expected[ip] = true
						mu.Unlock()
					}
				case 1:
					if err := bm.Remove(ip); err == nil {
						mu.Lock()
						expected[ip] = false
						mu.Unlock()
					}
				default:
					bm.AddViolation(ip)
					bm.IsBlacklisted(ip)
					bm.List()
				}
			}
		}(worker)
	}
	wg.Wait()

	bm.Stop()
	restarted := NewBlacklistManager(2, path)
	defer restarted.Stop()
	for ip, want := range expected {
		if got := restarted.IsBlacklisted(ip); got != want {
			t.Fatalf("after restart %s blacklisted = %v, want %v (the API reported success)", ip, got, want)
		}
	}
}

// API 契约：满表且全是手动条目时新增返回 500，文案要说清怎么恢复，不能
// 悄悄淘汰别人的封禁。
func TestAddBlacklistAPIReportsFullManualTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "blacklist.json")
	base := time.Now().Add(-time.Duration(blacklistMaxEntries) * time.Second)
	entries := make([]BlacklistEntry, 0, blacklistMaxEntries)
	for i := 0; i < blacklistMaxEntries; i++ {
		entries = append(entries, BlacklistEntry{
			IP:      fmt.Sprintf("198.19.%d.%d", i/256, i%256),
			Reason:  "manual",
			Source:  blacklistSourceManual,
			AddedAt: base.Add(time.Duration(i) * time.Second),
		})
	}
	writeBlacklistFixture(t, path, entries)

	bm := NewBlacklistManager(1, path)
	defer bm.Stop()
	server := &Server{blacklist: bm}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/security/blacklist", strings.NewReader(`{"ip":"203.0.113.9","duration_minutes":0}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	server.handleAPIAddBlacklist(ctx)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "full") || !strings.Contains(recorder.Body.String(), "remove some entries") {
		t.Fatalf("the error should explain how to recover, got %s", recorder.Body.String())
	}
	if bm.IsBlacklisted("203.0.113.9") {
		t.Fatal("a rejected entry must not be active")
	}
}
