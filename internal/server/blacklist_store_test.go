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
	"syscall"
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

// blacklistFileHasIP 直接读磁盘文件、不经过 BlacklistManager：测「调用方拿到
// 成功之后，磁盘上到底有没有这条」。返回 error 而不是 Fatal，方便在并发
// 测试的 worker 协程里用。
func blacklistFileHasIP(path, ip string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var file blacklistFile
	if err := json.Unmarshal(data, &file); err != nil {
		return false, fmt.Errorf("decode blacklist file %q: %w", data, err)
	}
	for _, entry := range file.Entries {
		if entry.IP == ip {
			return true, nil
		}
	}
	return false, nil
}

// requireBlacklistFileHasIP 断言磁盘上的黑名单里有（或没有）指定 IP。
func requireBlacklistFileHasIP(t *testing.T, path, ip string, want bool) {
	t.Helper()
	got, err := blacklistFileHasIP(path, ip)
	if err != nil {
		t.Fatalf("read blacklist file: %v", err)
	}
	if got != want {
		t.Fatalf("%s present on disk = %v, want %v", ip, got, want)
	}
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
	// 同步落盘的契约：AddManual 返回时磁盘上就必须已经有这条，不能靠 Stop
	// 或别的协程的批量 flush 兜底（独立读取方直接读文件）。
	requireBlacklistFileHasIP(t, path, "203.0.113.7", true)
	if err := bm.AddManual("203.0.113.8", "one hour", time.Hour); err != nil {
		t.Fatalf("add manual with duration: %v", err)
	}
	requireBlacklistFileHasIP(t, path, "203.0.113.8", true)
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
// 这条只钉默认常量；「批量落盘循环真的用了注入的窗口」由下面两条行为用例
// 约束——只改这里的话，把 autoFlushLoop 里的 delay 写死仍然能骗过去。
func TestBlacklistFlushWindowIsThreeSeconds(t *testing.T) {
	if blacklistFlushDelay != 3*time.Second {
		t.Fatalf("production blacklist flush window = %v, want 3s", blacklistFlushDelay)
	}
}

// 批量落盘必须真的用 bm.flushDelay，而不是某个写死的值。两条子用例把注入
// 窗口夹在两个互斥的区间里：短窗口实例必须在很短时间内落盘，长窗口实例在
// 这段时间内绝不能落盘。任何单一写死的值都会违反其中一条（写死 300ms 违反
// 前者之外的另一条，写死 3s 违反前者），所以这条用例能锁住行为而不是常量。
func TestBlacklistFlushHonoursInjectedWindow(t *testing.T) {
	t.Run("short window flushes quickly", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blacklist.json")
		bm := newBlacklistManager(1, path, 50*time.Millisecond)
		defer bm.Stop()

		if !bm.AddViolation("198.51.100.30") {
			t.Fatal("threshold 1 should blacklist on the first violation")
		}
		// 写死成 3s 之类的长窗口会在这里超时。
		waitForFile(t, path, 600*time.Millisecond)
	})

	t.Run("long window does not flush early", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blacklist.json")
		bm := newBlacklistManager(1, path, 3*time.Second)
		defer bm.Stop()

		if !bm.AddViolation("198.51.100.31") {
			t.Fatal("threshold 1 should blacklist on the first violation")
		}
		// 写死成 300ms 之类的短窗口会在这里提前落盘。900ms 仍远小于注入的
		// 3s，留足 CI 抖动余量。
		time.Sleep(900 * time.Millisecond)
		if _, err := os.Stat(path); err == nil {
			t.Fatal("the file was written before the injected 3s window elapsed")
		}
	})
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

	// 删除失败的回滚：只有在 IP 仍然缺席、且之后没有更晚的成功变更时才恢复。
	removed := &BlacklistEntry{IP: "192.0.2.32", Reason: "still blocked", Source: blacklistSourceManual}
	bm.mu.Lock()
	changeSeq := bm.nextChangeSeqLocked()
	bm.rollbackRemovalLocked("192.0.2.32", removed, nil, changeSeq)
	if bm.entries["192.0.2.32"] != removed {
		t.Fatal("a failed removal must restore the entry when the IP is still absent")
	}
	newerRemoval := &BlacklistEntry{IP: "192.0.2.32", Reason: "concurrent re-add", Source: blacklistSourceManual}
	bm.entries["192.0.2.32"] = newerRemoval
	bm.rollbackRemovalLocked("192.0.2.32", removed, nil, changeSeq)
	current = bm.entries["192.0.2.32"]
	bm.mu.Unlock()
	if current != newerRemoval {
		t.Fatal("a failed removal must not overwrite a concurrent re-add")
	}
}

// 审计探针（真 bug）：makeRoom 淘汰条目 X → 并发的 Remove(X) 返回 nil 并落盘
// → 本次插入写盘失败回滚。旧实现只看「IP 是否缺席」就把 X 放回内存，Stop 时
// 又被写回磁盘，等于把那次已经成功的删除永久撤销（探针结果：
// remove_err=<nil> memory_blocked=true disk_has=false → Stop 后 disk_has=true）。
//
// 中间态用真实路径构造：腾位置走 makeRoomLocked，删除走 Remove（真写盘）；
// 回滚调用的是 AddManual 失败分支里的同一个函数，不依赖调度概率。
func TestBlacklistEvictionRollbackDoesNotResurrectConcurrentRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "blacklist.json")
	const victim = "198.18.0.0"
	base := time.Now().Add(-time.Duration(blacklistMaxEntries) * time.Second)
	entries := make([]BlacklistEntry, 0, blacklistMaxEntries)
	entries = append(entries, BlacklistEntry{
		IP:        victim,
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

	// 1) AddManual 插入前的腾位置：最旧的 auto 条目被淘汰（仍在磁盘上）。
	bm.mu.Lock()
	evicted, ok := bm.makeRoomLocked()
	bm.mu.Unlock()
	if !ok || len(evicted) != 1 || evicted[0].entry.IP != victim {
		t.Fatalf("makeRoomLocked evicted %+v, want just %s", evicted, victim)
	}

	// 2) 并发的 Remove(victim) 成功并落盘：这一步是真实现、真写盘。
	if err := bm.Remove(victim); err != nil {
		t.Fatalf("concurrent remove: %v", err)
	}
	requireBlacklistFileHasIP(t, path, victim, false)

	// 3) 本次插入写盘失败后的回滚。
	bm.mu.Lock()
	bm.restoreEvictedLocked(evicted)
	bm.mu.Unlock()

	// 4) 那次成功的删除不能被撤销：内存里没有，Stop 之后磁盘上也不能再出现。
	if bm.IsBlacklisted(victim) {
		t.Fatal("rollback resurrected an entry that a concurrent Remove had deleted and persisted")
	}
	bm.Stop()
	requireBlacklistFileHasIP(t, path, victim, false)
}

// 审计探针（同一类问题）：两个并发 Remove，先删的那个写盘失败、后删的成功
// 落盘。失败方的回滚不能把这个 IP 恢复，否则等于撤销了另一个的成功。
func TestBlacklistRemovalRollbackDoesNotUndoConcurrentSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	const ip = "192.0.2.60"
	if err := bm.AddManual(ip, "concurrent", 0); err != nil {
		t.Fatalf("add manual: %v", err)
	}

	// 1) 失败的删除先完成内存删除、还没写盘（这就是 Remove 落盘前的中间态）。
	bm.mu.Lock()
	previous := bm.entries[ip]
	previousViolation := bm.violation[ip]
	changeSeq := bm.nextChangeSeqLocked()
	delete(bm.entries, ip)
	delete(bm.violation, ip)
	bm.mu.Unlock()

	// 2) 并发的 Remove(ip) 成功并落盘（真实现、真写盘）。
	if err := bm.Remove(ip); err != nil {
		t.Fatalf("concurrent remove: %v", err)
	}
	requireBlacklistFileHasIP(t, path, ip, false)

	// 3) 失败的删除回滚。
	bm.mu.Lock()
	bm.rollbackRemovalLocked(ip, previous, previousViolation, changeSeq)
	bm.mu.Unlock()

	if bm.IsBlacklisted(ip) {
		t.Fatal("a failed removal must not undo a concurrent successful removal")
	}
	bm.Stop()
	requireBlacklistFileHasIP(t, path, ip, false)
}

// 每一步返回 nil 的操作都必须在返回时就已经落到磁盘上：不能出现「接口说
// 成功了，内存或磁盘里却没有」。落盘校验在操作返回后立刻用一个独立读取方
// （直接读文件，不经过 BlacklistManager）完成，不依赖 Stop 或别的协程的
// flush——旧用例只在 Stop 之后重启校验，把 AddManual 的同步写改成交给批量
// 协程也能骗过去（别的 worker 的 AddViolation 触发 flush 会顺手带上它）。
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
						// 同步落盘：返回成功必须先出现在磁盘上。
						if has, err := blacklistFileHasIP(path, ip); err != nil || !has {
							t.Errorf("AddManual(%s) reported success but the entry is not on disk (has=%v, err=%v)", ip, has, err)
						}
						mu.Lock()
						expected[ip] = true
						mu.Unlock()
					}
				case 1:
					if err := bm.Remove(ip); err == nil {
						// 删除同理：返回成功就必须已经从磁盘上消失。
						if has, err := blacklistFileHasIP(path, ip); err != nil || has {
							t.Errorf("Remove(%s) reported success but the entry is still on disk (has=%v, err=%v)", ip, has, err)
						}
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

// 审计探针（第三条回滚路径）：AddManual 自己的写盘失败，但同一窗口里另一次
// 成功写盘已经把这条插入写进了磁盘。旧实现只看指针身份就回滚内存，于是
// 「接口 500、内存看不到、磁盘却有」——下次黑名单变更前重启，这条失败的手动
// 封禁会复活。修复后：磁盘已经有这条时保留内存并返回成功。
//
// 交错用 saveMu 卡住：插入先进入内存，本次写盘被挡住；测试在窗口内把内存里
// 这条原样写进文件（模拟「另一次成功写盘」，不经过管理器，所以序号不变量看不到
// 它，只能靠回读磁盘兜底），随后放开，让本次写盘真的失败。
func TestBlacklistFailedInsertNotRolledBackWhenAlreadyOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "blacklist.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create dir: %v", err)
	}
	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	const ip = "203.0.113.61"

	// 让 AddManual 自己的写盘必然失败：tmp 路径被目录占住。
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("block the tmp path: %v", err)
	}

	bm.saveMu.Lock()
	released := false
	release := func() {
		if !released {
			bm.saveMu.Unlock()
			released = true
		}
	}
	defer release()

	result := make(chan error, 1)
	go func() { result <- bm.AddManual(ip, "concurrent", 0) }()

	deadline := time.Now().Add(5 * time.Second)
	for !bm.IsBlacklisted(ip) {
		if time.Now().After(deadline) {
			release()
			t.Fatal("timed out waiting for the insert to reach memory")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 同窗口另一次成功写盘：把内存里这条原样写进文件。
	bm.mu.RLock()
	installed := *bm.entries[ip]
	bm.mu.RUnlock()
	payload, err := json.MarshalIndent(blacklistFile{Version: blacklistFileVersion, Entries: []BlacklistEntry{installed}}, "", "  ")
	if err != nil {
		release()
		t.Fatalf("encode fixture: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		release()
		t.Fatalf("write the concurrent snapshot: %v", err)
	}
	requireBlacklistFileHasIP(t, path, ip, true)
	release()

	if err := <-result; err != nil {
		t.Fatalf("磁盘已经有这条插入时不能返回失败: %v", err)
	}
	if !bm.IsBlacklisted(ip) {
		t.Fatal("已经落盘的插入不能被回滚")
	}
	requireBlacklistFileHasIP(t, path, ip, true)

	// 收拾掉制造失败的占位目录，确认这条封禁扛得住重启（探针的 after-restart）。
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatalf("remove tmp blocker: %v", err)
	}
	bm.Stop()
	restarted := NewBlacklistManager(1, path)
	defer restarted.Stop()
	if !restarted.IsBlacklisted(ip) {
		t.Fatal("a failed manual ban must not disappear or revive across a restart")
	}
}

// 序号不变量的兜底：这次插入之后已有一次成功落盘的快照（lastDurableSeq 推进），
// 即使回读文件不可用（EIO/权限），也必须按成功处理，不能把已经落盘的插入回滚。
func TestBlacklistFailedInsertKeptWhenDurableSnapshotCoversIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	entry := &BlacklistEntry{
		IP:      "203.0.113.62",
		Reason:  "covered by a concurrent persist",
		Source:  blacklistSourceManual,
		AddedAt: time.Now(),
	}

	// 插入先进内存，另一次 write 成功落盘时快照覆盖了这次插入。
	bm.mu.Lock()
	changeSeq := bm.nextChangeSeqLocked()
	bm.entries[entry.IP] = entry
	bm.mu.Unlock()
	if err := bm.persist(); err != nil {
		t.Fatalf("precondition persist: %v", err)
	}

	// 让回读文件不可用，只剩序号不变量能证明已落盘。
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("make the file unreadable: %v", err)
	}
	defer os.Chmod(path, 0o600)
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("当前环境无法让文件不可读（可能以 root 运行），序号兜底用例不适用")
	}

	err := bm.resolveFailedInsert(insertAttempt{entry: entry, changeSeq: changeSeq}, errors.New("injected write failure"))
	if err != nil {
		t.Fatalf("磁盘已有覆盖这次插入的快照时必须按成功返回: %v", err)
	}
	if !bm.IsBlacklisted(entry.IP) {
		t.Fatal("已经落盘的插入不能被回滚")
	}
}

// 与 persist.go 的 writeState 同一语义：rename 成功即视为落盘成功。此后目录
// fsync 失败只影响「掉电后这次 rename 还在不在」，不算写盘失败——不能回滚内存、
// 不能返回错误，也不该把 lastDurableSeq 落下（回滚判据依赖它）。
func TestBlacklistRenameSuccessSurvivesDirSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "blacklist.json")
	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	if err := bm.AddManual("203.0.113.69", "baseline", 0); err != nil {
		t.Fatalf("baseline add: %v", err)
	}

	previousSyncDir := syncDir
	syncDir = func(*os.File) error { return syscall.EIO }
	t.Cleanup(func() { syncDir = previousSyncDir })

	// persist 层语义：rename 已经生效时目录 fsync 失败必须返回 nil。最后一层
	// 的回滚判据依赖「persist 返回错误 ⇒ 磁盘未更新」这个前提。
	if err := bm.persist(); err != nil {
		t.Fatalf("rename 之后目录 fsync 失败不能让 persist 返回错误: %v", err)
	}

	bm.mu.Lock()
	seqBefore := bm.changeSeq
	bm.mu.Unlock()

	if err := bm.AddManual("203.0.113.70", "dir sync fails", 0); err != nil {
		t.Fatalf("rename 已生效时目录 fsync 失败不能按写盘失败处理: %v", err)
	}
	if !bm.IsBlacklisted("203.0.113.70") {
		t.Fatal("rename 成功的插入不能被回滚")
	}
	requireBlacklistFileHasIP(t, path, "203.0.113.70", true)

	bm.mu.Lock()
	durable := bm.lastDurableSeq
	bm.mu.Unlock()
	if durable <= seqBefore {
		t.Fatalf("rename 成功后必须推进 lastDurableSeq: durable=%d, seqBefore=%d", durable, seqBefore)
	}

	bm.Stop()
	restarted := NewBlacklistManager(1, path)
	defer restarted.Stop()
	if !restarted.IsBlacklisted("203.0.113.70") {
		t.Fatal("rename 成功的手动封禁必须扛住进程重启")
	}
}

// rename 之前的失败必须返回错误、回滚内存，并且不能推进 lastDurableSeq：否则
// 后续回滚会误以为这次变更已经落盘而放弃恢复。
func TestBlacklistPrewriteFailureDoesNotAdvanceDurableSeq(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "blacklist.json")
	bm := NewBlacklistManager(1, path)
	defer bm.Stop()

	if err := bm.AddManual("203.0.113.71", "baseline", 0); err != nil {
		t.Fatalf("baseline add: %v", err)
	}
	bm.mu.Lock()
	baseline := bm.lastDurableSeq
	bm.mu.Unlock()

	// 让下一次写盘在 rename 之前失败：tmp 路径被目录占住。
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("block the tmp path: %v", err)
	}
	if err := bm.AddManual("203.0.113.72", "prewrite fails", 0); err == nil {
		t.Fatal("rename 之前失败必须返回错误")
	}
	if bm.IsBlacklisted("203.0.113.72") {
		t.Fatal("rename 之前失败必须回滚内存")
	}
	bm.mu.Lock()
	after := bm.lastDurableSeq
	bm.mu.Unlock()
	if after != baseline {
		t.Fatalf("rename 之前失败不能推进 lastDurableSeq: %d -> %d", baseline, after)
	}

	// 清理占位目录，让 Stop 的补偿写盘能正常收尾。
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatalf("remove tmp blocker: %v", err)
	}
}
