package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLegacySchemaStateFile 把 v0 fixture 复制到临时目录，模拟升级前写出的
// 状态文件（没有 schema_version 字段）。
func writeLegacySchemaStateFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/state-v0.json")
	if err != nil {
		t.Fatalf("read v0 fixture: %v", err)
	}
	if strings.Contains(string(data), "schema_version") {
		t.Fatal("testdata/state-v0.json must not contain schema_version: it stands for the pre-versioning format")
	}
	path := filepath.Join(t.TempDir(), "server-state.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write v0 state: %v", err)
	}
	return path
}

// readStateSchemaVersion 直接读盘上的明文层，不经过 StateStore。
func readStateSchemaVersion(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var envelope struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("parse state file: %v", err)
	}
	if envelope.SchemaVersion == nil {
		t.Fatal("state file has no schema_version after load")
	}
	return *envelope.SchemaVersion
}

func TestLoadMigratesLegacyStateToCurrentSchema(t *testing.T) {
	path := writeLegacySchemaStateFile(t)

	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("load v0 state: %v", err)
	}

	store.mu.RLock()
	gotSchema := store.state.SchemaVersion
	store.mu.RUnlock()
	if gotSchema != stateSchemaVersion {
		t.Fatalf("in-memory schema_version = %d, want %d", gotSchema, stateSchemaVersion)
	}

	// identity 迁移：v0 的业务字段必须原样保留。
	devices := store.GetAllDevices()
	if len(devices) != 1 || devices[0].ID != "dev-v0" || devices[0].Hostname != "host-v0" {
		t.Fatalf("devices were not preserved by the v0 -> v1 migration: %+v", devices)
	}
	tunnels := store.GetTunnels()
	if len(tunnels) != 1 || tunnels[0].TunnelID != "tun-v0" || tunnels[0].PublicPort != 12022 {
		t.Fatalf("tunnels were not preserved by the v0 -> v1 migration: %+v", tunnels)
	}
	if devices[0].ApprovedAt == nil {
		t.Fatal("approval timestamp was dropped by the v0 -> v1 migration")
	}
}

func TestLoadPersistsSchemaVersion(t *testing.T) {
	path := writeLegacySchemaStateFile(t)

	if err := NewStateStore(path).Load(); err != nil {
		t.Fatalf("load v0 state: %v", err)
	}
	if got := readStateSchemaVersion(t, path); got != stateSchemaVersion {
		t.Fatalf("on-disk schema_version = %d, want %d", got, stateSchemaVersion)
	}
	// 迁移是 identity 的，但必须真的落盘而不是只改内存：再 Load 一次要能读到 v1。
	second := NewStateStore(path)
	if err := second.Load(); err != nil {
		t.Fatalf("reload migrated state: %v", err)
	}
	second.mu.RLock()
	defer second.mu.RUnlock()
	if second.state.SchemaVersion != stateSchemaVersion {
		t.Fatalf("reloaded schema_version = %d, want %d", second.state.SchemaVersion, stateSchemaVersion)
	}
}

func TestRepeatedLoadDoesNotMigrateAgain(t *testing.T) {
	path := writeLegacySchemaStateFile(t)

	if err := NewStateStore(path).Load(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after migration: %v", err)
	}

	// 已经是 v1 的文件不该再触发一次重写。writeState 走 tmp+rename，一旦重写
	// 文件就是一个新 inode——用 os.SameFile 比 mtime 更可靠（不受 FS 精度影响）。
	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("second load: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after second load: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("second load rewrote the state file; an up-to-date schema must not trigger another migration")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.state.SchemaVersion != stateSchemaVersion {
		t.Fatalf("second load schema_version = %d, want %d", store.state.SchemaVersion, stateSchemaVersion)
	}
}

func TestLoadRejectsNewerSchemaVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/state-v0.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// 伪造一份「未来版本」的文件：结构与 v0 相同，只是版本号更新。
	future := strings.Replace(string(data), "{", `{
  "schema_version": 2,`, 1)

	path := filepath.Join(t.TempDir(), "server-state.json")
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatalf("write future state: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat future state: %v", err)
	}

	store := NewStateStore(path)
	err = store.Load()
	if !errors.Is(err, ErrStateTooNew) {
		t.Fatalf("load of a future schema returned %v, want ErrStateTooNew", err)
	}

	// 拒绝必须发生在任何写盘之前：文件字节与 inode 都不能变。
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after rejected load: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("a rejected future-schema file must not be rewritten")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read future state after rejection: %v", err)
	}
	if string(onDisk) != future {
		t.Fatal("state file bytes changed after rejecting a newer schema")
	}
	// 内存里的状态也不能被这份文件替换。
	if devices := store.GetAllDevices(); len(devices) != 0 {
		t.Fatalf("rejected state leaked into memory: %+v", devices)
	}
}

// TestMigrationKeepsEncryptedStateDecryptable 覆盖迁移与加密的交叉：v0 的密文在
// 迁移后必须仍然解得开，且重写出来的仍是加密文件。
func TestMigrationKeepsEncryptedStateDecryptable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	// 32 字节全熵密钥：现网 state.env 就是这种直通形态（kdf "none"）。
	key := "hex:" + strings.Repeat("ab", 32)

	seed := NewStateStore(path)
	if err := seed.SetEncryptionKey(key); err != nil {
		t.Fatalf("set encryption key: %v", err)
	}
	if err := seed.initNew(); err != nil {
		t.Fatalf("init encrypted state: %v", err)
	}
	seed.AddDevice(&DeviceState{ID: "dev-enc", Hostname: "host-enc", Status: deviceStatusAuthorized})
	if err := seed.Save(); err != nil {
		t.Fatalf("save encrypted state: %v", err)
	}

	// 抹掉版本号，把它变成升级前的加密文件。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read encrypted state: %v", err)
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("parse encrypted state: %v", err)
	}
	delete(legacy, "schema_version")
	stripped, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("re-marshal encrypted state: %v", err)
	}
	if err := os.WriteFile(path, stripped, 0o600); err != nil {
		t.Fatalf("write pre-versioning encrypted state: %v", err)
	}

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("set encryption key: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("load pre-versioning encrypted state: %v", err)
	}
	devices := store.GetAllDevices()
	if len(devices) != 1 || devices[0].ID != "dev-enc" {
		t.Fatalf("encrypted devices were lost by migration: %+v", devices)
	}
	if got := readStateSchemaVersion(t, path); got != stateSchemaVersion {
		t.Fatalf("encrypted state schema_version = %d, want %d", got, stateSchemaVersion)
	}
	// 迁移后重新读盘仍是加密文件：明文层不能出现敏感字段。
	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rewritten state: %v", err)
	}
	if !strings.Contains(string(rewritten), `"encrypted"`) {
		t.Fatal("migrated encrypted state lost its encrypted envelope")
	}
	if strings.Contains(string(rewritten), "server_sign_privkey\": \"") &&
		!strings.Contains(string(rewritten), `"server_sign_privkey": ""`) {
		t.Fatal("migrated state leaked the signing key into the plaintext layer")
	}
}
