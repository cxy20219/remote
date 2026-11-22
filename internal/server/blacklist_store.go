package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// 黑名单单独落一个文件，不塞进 server-state.json：后者装着管理员密码 hash、
// 设备清单与 TOTP 密文，每次自动拉黑都去重写它，既放大风险也放大 IO。
const (
	blacklistFileVersion = 1
	blacklistMaxEntries  = 10000
	// 自动拉黑只标 dirty，攒一波再写；手动增删同步写。3 秒与 state 的
	// 落盘周期一致。
	blacklistFlushDelay = stateSyncInterval
)

// blacklistFile 是 blacklist.json 的磁盘格式。
type blacklistFile struct {
	Version int              `json:"version"`
	Entries []BlacklistEntry `json:"entries"`
}

// load 读取磁盘上的黑名单。
//
// 文件不存在 = 空表；损坏 = 隔离成 .corrupt 后从空表开始。任何失败都不能
// 阻止服务启动：黑名单是保护措施，不是启动前置条件。
func (bm *BlacklistManager) load() error {
	if bm.path == "" {
		return nil
	}
	data, err := os.ReadFile(bm.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read blacklist file: %w", err)
	}

	var file blacklistFile
	if err := json.Unmarshal(data, &file); err != nil {
		bm.quarantine(fmt.Errorf("decode blacklist file: %w", err))
		return nil
	}
	if file.Version != blacklistFileVersion {
		bm.quarantine(fmt.Errorf("unsupported blacklist file version %d", file.Version))
		return nil
	}

	expired := 0
	for index := range file.Entries {
		entry := file.Entries[index]
		if entry.IP == "" {
			continue
		}
		// 重启后已经过期的条目没有意义，直接丢，不进内存也不回写。
		if entry.IsExpired() {
			expired++
			continue
		}
		// 兼容旧文件：没有 source 字段时，永久条目是手动封禁，带过期时间
		// 的是自动拉黑（历史版本只有自动拉黑会带 24h 过期）。
		if entry.Source == "" {
			if entry.ExpiresAt.IsZero() {
				entry.Source = blacklistSourceManual
			} else {
				entry.Source = blacklistSourceAuto
			}
		}
		bm.entries[entry.IP] = &entry
	}
	// 文件里可能比上限多：只淘汰最旧的 auto，manual 条目一条都不能丢。
	evicted := bm.evictOldestAutoLocked(blacklistMaxEntries)
	if len(evicted) > 0 {
		slog.Warn("blacklist file exceeded the limit; evicted the oldest auto entries",
			"evicted", len(evicted), "max", blacklistMaxEntries)
	}
	if len(bm.entries) > blacklistMaxEntries {
		slog.Warn("blacklist file holds more manual entries than the limit; keeping them",
			"entries", len(bm.entries), "max", blacklistMaxEntries)
	}
	slog.Info("blacklist loaded", "entries", len(bm.entries), "expired", expired, "path", bm.path)
	return nil
}

// quarantine 把坏文件挪走再继续启动，保留现场供事后排查。
func (bm *BlacklistManager) quarantine(cause error) {
	target := bm.path + ".corrupt"
	if err := os.Rename(bm.path, target); err != nil {
		slog.Error("blacklist file is corrupt and could not be quarantined; starting with an empty list",
			"error", cause, "path", bm.path, "rename_error", err)
		return
	}
	slog.Error("blacklist file is corrupt; starting with an empty list",
		"error", cause, "quarantined", target)
}

// persist 把当前条目原子写盘（写 .tmp 再 rename）。
//
// 调用方不得持有 bm.mu；快照在 saveMu 内取，保证并发写不会用旧快照覆盖新快照。
func (bm *BlacklistManager) persist() error {
	if bm.path == "" {
		bm.mu.Lock()
		bm.dirty = false
		bm.mu.Unlock()
		return nil
	}

	bm.saveMu.Lock()
	defer bm.saveMu.Unlock()

	bm.mu.Lock()
	entries := make([]BlacklistEntry, 0, len(bm.entries))
	for _, entry := range bm.entries {
		if entry.IsExpired() {
			continue
		}
		entries = append(entries, *entry)
	}
	bm.dirty = false
	// 记下这次快照覆盖到的变更序号：写盘成功后，针对更早变更的回滚都会
	// 被拒绝（磁盘已经反映了它们）。
	snapshotSeq := bm.changeSeq
	bm.mu.Unlock()

	// 固定顺序：同样的集合写出同样的字节，便于 diff 与排障。
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].AddedAt.Equal(entries[j].AddedAt) {
			return entries[i].IP < entries[j].IP
		}
		return entries[i].AddedAt.Before(entries[j].AddedAt)
	})
	data, err := json.MarshalIndent(blacklistFile{Version: blacklistFileVersion, Entries: entries}, "", "  ")
	if err != nil {
		bm.restoreDirty()
		return fmt.Errorf("encode blacklist file: %w", err)
	}

	dir := filepath.Dir(bm.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		bm.restoreDirty()
		return fmt.Errorf("create blacklist directory: %w", err)
	}
	tmp := bm.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		bm.restoreDirty()
		return fmt.Errorf("create blacklist file: %w", err)
	}
	discard := func(err error) error {
		file.Close()
		os.Remove(tmp)
		bm.restoreDirty()
		return err
	}
	if _, err := file.Write(data); err != nil {
		return discard(fmt.Errorf("write blacklist file: %w", err))
	}
	// OpenFile 的权限只在创建时生效，残留的 .tmp 可能带着旧权限。
	if err := file.Chmod(0o600); err != nil {
		return discard(fmt.Errorf("set blacklist file mode: %w", err))
	}
	// fsync 之后才 rename：接口返回 200 就表示扛得住进程重启和掉电。
	if err := file.Sync(); err != nil {
		return discard(fmt.Errorf("sync blacklist file: %w", err))
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		bm.restoreDirty()
		return fmt.Errorf("close blacklist file: %w", err)
	}
	if err := os.Rename(tmp, bm.path); err != nil {
		os.Remove(tmp)
		bm.restoreDirty()
		return fmt.Errorf("replace blacklist file: %w", err)
	}
	// rename 成功即视为落盘成功：磁盘上的黑名单已经换成新内容，进程重启一定
	// 读到它。从这里开始推进已持久化序号——之后针对更早变更的回滚都必须放弃。
	// 与 persist.go 的 writeState 保持同一语义：返回错误只可能是 rename 之前
	// 失败，那时磁盘仍是旧内容。
	bm.mu.Lock()
	if snapshotSeq > bm.lastDurableSeq {
		bm.lastDurableSeq = snapshotSeq
	}
	bm.mu.Unlock()
	// 目录 fsync 只影响「掉电后这次 rename 还在不在」；失败只记 WARN，不回滚
	// 内存也不返回错误，否则会出现「接口报错、磁盘却是新内容，重启后又生效」
	// 的自相矛盾。
	dirFile, err := os.Open(dir)
	if err != nil {
		slog.Warn("blacklist file renamed but the directory could not be opened for fsync; durable across process restarts, power loss may roll back",
			"dir", dir, "error", err)
		return nil
	}
	syncErr := syncDir(dirFile)
	dirFile.Close()
	if syncErr != nil {
		slog.Warn("blacklist file renamed but the directory could not be synced; durable across process restarts, power loss may roll back",
			"dir", dir, "error", syncErr)
	}
	return nil
}

// blacklistFileHoldsEntry 直接回读磁盘文件，判断上面是否已经有与 entry 完全相同
// 且未过期的条目。读不出来就返回 false：调用方还有序号不变量兜底。
func (bm *BlacklistManager) blacklistFileHoldsEntry(entry *BlacklistEntry) bool {
	if bm.path == "" || entry == nil {
		return false
	}
	data, err := os.ReadFile(bm.path)
	if err != nil {
		return false
	}
	var file blacklistFile
	if err := json.Unmarshal(data, &file); err != nil {
		return false
	}
	for _, onDisk := range file.Entries {
		if onDisk.IP != entry.IP || onDisk.Source != entry.Source {
			continue
		}
		if onDisk.Reason != entry.Reason || !onDisk.AddedAt.Equal(entry.AddedAt) ||
			!onDisk.ExpiresAt.Equal(entry.ExpiresAt) {
			continue
		}
		return !onDisk.IsExpired()
	}
	return false
}

// restoreDirty 让失败的写入在下一次 flush 时重试，而不是静默丢掉。
func (bm *BlacklistManager) restoreDirty() {
	bm.mu.Lock()
	bm.dirty = true
	bm.mu.Unlock()
}

// flush 只在有未落盘变更时写一次。
func (bm *BlacklistManager) flush() error {
	bm.mu.RLock()
	dirty := bm.dirty
	bm.mu.RUnlock()
	if !dirty {
		return nil
	}
	return bm.persist()
}

// signalFlush 唤醒批量落盘协程；通道满说明已经有人被唤醒，叠加无意义。
func (bm *BlacklistManager) signalFlush() {
	select {
	case bm.wake <- struct{}{}:
	default:
	}
}

// autoFlushLoop 把自动拉黑攒成一批写盘：第一次标记后等 3 秒，期间的新条目
// 合并进同一批。持续攻击下写入频率也被限制在每 3 秒一次。
func (bm *BlacklistManager) autoFlushLoop() {
	defer bm.wg.Done()
	for {
		select {
		case <-bm.stopCh:
			return
		case <-bm.wake:
			timer := time.NewTimer(bm.flushDelay)
			select {
			case <-timer.C:
			case <-bm.stopCh:
				timer.Stop()
				return
			}
			if err := bm.flush(); err != nil {
				slog.Error("failed to persist auto-blacklisted IPs", "error", err)
			}
		}
	}
}

// evictedEntry 记录为腾位置被删掉的条目，落盘失败时要原样放回。
type evictedEntry struct {
	entry     *BlacklistEntry
	violation *violationState
	// changeSeq 是这次淘汰的变更序号：回滚时用它确认淘汰之后没有更晚的
	// 变更成功落盘。
	changeSeq uint64
}

// makeRoomLocked 在插入前腾出至少一个位置：先清已过期条目，再按 AddedAt
// 淘汰最旧的 auto 条目。manual 条目永不淘汰——表里全是 manual 且已满时
// 返回 ok=false，调用方必须放弃这次插入。
//
// 返回的 evicted 供落盘失败时回滚；ok=false 时内存已经恢复原状，调用方
// 不需要也不应该写盘。
func (bm *BlacklistManager) makeRoomLocked() ([]evictedEntry, bool) {
	if len(bm.entries) < blacklistMaxEntries {
		return nil, true
	}
	var evicted []evictedEntry
	for ip, entry := range bm.entries {
		if entry.IsExpired() {
			evicted = append(evicted, evictedEntry{entry: entry, violation: bm.violation[ip], changeSeq: bm.nextChangeSeqLocked()})
			delete(bm.entries, ip)
			delete(bm.violation, ip)
		}
	}
	evicted = append(evicted, bm.evictOldestAutoLocked(blacklistMaxEntries-1)...)
	if len(bm.entries) >= blacklistMaxEntries {
		bm.restoreEvictedLocked(evicted)
		return nil, false
	}
	return evicted, true
}

// evictOldestAutoLocked 按 AddedAt 淘汰最旧的 auto 条目，直到条目数 <= target。
// auto 条目不够时提前停止：manual 条目一条都不会被淘汰。
func (bm *BlacklistManager) evictOldestAutoLocked(target int) []evictedEntry {
	var evicted []evictedEntry
	for len(bm.entries) > target {
		victimIP := ""
		var victim *BlacklistEntry
		for ip, entry := range bm.entries {
			if entry.Source != blacklistSourceAuto {
				continue
			}
			if victim == nil || entry.AddedAt.Before(victim.AddedAt) ||
				(entry.AddedAt.Equal(victim.AddedAt) && ip < victimIP) {
				victimIP, victim = ip, entry
			}
		}
		if victim == nil {
			break
		}
		evicted = append(evicted, evictedEntry{entry: victim, violation: bm.violation[victimIP], changeSeq: bm.nextChangeSeqLocked()})
		delete(bm.entries, victimIP)
		delete(bm.violation, victimIP)
	}
	return evicted
}

// restoreEvictedLocked 把因腾位置被删掉的条目放回去。回滚前必须先确认「当前
// 状态仍是本次淘汰造成的中间态」：
//   - 同名 IP 已被别的操作写入：那是更新的状态，不覆盖；
//   - 本次淘汰之后已有成功落盘的快照：例如并发的 Remove 把 X 删掉并写进了
//     磁盘，此时恢复 X 等于撤销那次成功的删除，而且下次 flush 还会把 X 写回
//     文件（审计探针：remove_err=<nil> 之后 Stop 磁盘上又出现 X）。放弃回滚。
func (bm *BlacklistManager) restoreEvictedLocked(evicted []evictedEntry) {
	for _, item := range evicted {
		if bm.entries[item.entry.IP] != nil || bm.rollbackSupersededLocked(item.changeSeq) {
			continue
		}
		bm.entries[item.entry.IP] = item.entry
		if item.violation != nil {
			bm.violation[item.entry.IP] = item.violation
		}
	}
}
