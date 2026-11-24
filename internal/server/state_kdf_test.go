package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLegacyStateFile 写出升级前的 v1 加密信封：单次 SHA-256 派生、
// 信封只有 version/algorithm/nonce/ciphertext，没有 kdf/salt/params。
func writeLegacyStateFile(t *testing.T, path, rawKey string, state ServerState) {
	t.Helper()

	key, err := deriveLegacyStateEncryptionKey(rawKey)
	if err != nil || len(key) == 0 {
		t.Fatalf("derive legacy key: len=%d err=%v", len(key), err)
	}

	plain := sensitiveStatePlain{
		ServerSignPrivkey:  state.ServerSignPrivkey,
		AdminPasswordHash:  state.AdminPasswordHash,
		DeviceEncKeys:      make(map[string]string),
		TOTPSecret:         state.TOTPSecret,
		TOTPRecoveryHashes: state.TOTPRecoveryHashes,
		TOTPLastStep:       state.TOTPLastStep,
	}
	for _, device := range state.Devices {
		if device.EncKey != "" {
			plain.DeviceEncKeys[device.ID] = device.EncKey
		}
	}
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("marshal legacy plaintext: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plainJSON, []byte(stateEncryptionAAD))

	state.ServerSignPrivkey = ""
	state.AdminPasswordHash = ""
	state.TOTPSecret = ""
	state.TOTPRecoveryHashes = nil
	state.TOTPLastStep = 0
	for i := range state.Devices {
		state.Devices[i].EncKey = ""
	}
	state.Encrypted = &EncryptedState{
		Version:    stateEncryptionVersionLegacy,
		Algorithm:  stateEncryptionAlg,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
}

func readRawState(t *testing.T, path string) ServerState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var raw ServerState
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal state file: %v", err)
	}
	return raw
}

func newLegacyStateFixture(t *testing.T, path, key string) {
	t.Helper()
	writeLegacyStateFile(t, path, key, ServerState{
		ServerSignPrivkey:  hex.EncodeToString(bytes.Repeat([]byte{1}, ed25519.PrivateKeySize)),
		AdminPasswordHash:  "$2a$10$legacy-admin-hash",
		Settings:           defaultSettings(),
		TOTPSecret:         "legacy-totp-secret",
		TOTPRecoveryHashes: []string{"recovery-a", "recovery-b"},
		TOTPLastStep:       42,
		Devices: []DeviceState{{
			ID:     "dev-legacy",
			Status: deviceStatusAuthorized,
			EncKey: "device-secret",
		}},
	})
}

// ① v1 + 口令：迁移成 v2（argon2id），业务字段不丢，二次 Load 一致。
func TestStateKDFMigratesV1PassphraseToArgon2id(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	key := strings.Repeat("k", 32)
	newLegacyStateFixture(t, path, key)

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !store.EncryptionEnabled() {
		t.Fatal("encryption should be enabled after Load")
	}
	device := store.GetDeviceByID("dev-legacy")
	if device == nil || device.EncKey != "device-secret" {
		t.Fatalf("device key lost during migration: %+v", device)
	}
	if len(store.GetServerSignPrivkey()) != ed25519.PrivateKeySize {
		t.Fatal("server signing key lost during migration")
	}
	if cfg := store.TOTPConfig(); cfg.Secret != "legacy-totp-secret" || cfg.LastStep != 42 || len(cfg.RecoveryHashes) != 2 {
		t.Fatalf("TOTP state lost during migration: %+v", cfg)
	}

	raw := readRawState(t, path)
	if raw.Encrypted == nil {
		t.Fatal("state file should carry an encrypted envelope")
	}
	if raw.Encrypted.Version != stateEncryptionVersion {
		t.Fatalf("encrypted version = %d, want %d", raw.Encrypted.Version, stateEncryptionVersion)
	}
	if raw.Encrypted.KDF != stateKDFArgon2id {
		t.Fatalf("kdf = %q, want %q", raw.Encrypted.KDF, stateKDFArgon2id)
	}
	if raw.Encrypted.Salt == "" {
		t.Fatal("argon2id envelope must persist a salt")
	}
	if raw.Encrypted.KDFParams == nil ||
		raw.Encrypted.KDFParams.MemoryKiB != stateKDFArgon2MemoryKiB ||
		raw.Encrypted.KDFParams.Iterations != stateKDFArgon2Iterations ||
		raw.Encrypted.KDFParams.Parallelism != stateKDFArgon2Parallelism {
		t.Fatalf("kdf params = %+v, want the documented defaults", raw.Encrypted.KDFParams)
	}
	if raw.ServerSignPrivkey != "" || raw.AdminPasswordHash != "" || raw.Devices[0].EncKey != "" {
		t.Fatalf("plaintext layer should be cleared after migration: %+v", raw)
	}

	// 二次 Load：同一口令必须能解开迁移后的文件，且 salt 不再变化。
	reloaded := NewStateStore(path)
	if err := reloaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey reloaded: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if got := reloaded.GetDeviceByID("dev-legacy"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("second load device = %+v", got)
	}
	if again := readRawState(t, path); again.Encrypted.Salt != raw.Encrypted.Salt {
		t.Fatal("a plain reload must not rotate the salt")
	}
}

// ② v1 + 全熵密钥（现网 base64 形态）：迁移成 v2 但 kdf=none，不做无意义的 KDF。
func TestStateKDFMigratesV1DirectKeyToNone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	key := "base64:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	newLegacyStateFixture(t, path, key)

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := store.GetDeviceByID("dev-legacy"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("device key lost during migration: %+v", got)
	}

	raw := readRawState(t, path)
	if raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersion {
		t.Fatalf("expected a v2 envelope, got %+v", raw.Encrypted)
	}
	if raw.Encrypted.KDF != stateKDFNone {
		t.Fatalf("kdf = %q, want %q for a raw key", raw.Encrypted.KDF, stateKDFNone)
	}
	if raw.Encrypted.Salt != "" || raw.Encrypted.KDFParams != nil {
		t.Fatalf("kdf=none must not carry salt/params: %+v", raw.Encrypted)
	}

	reloaded := NewStateStore(path)
	if err := reloaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey reloaded: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if got := reloaded.GetDeviceByID("dev-legacy"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("second load device = %+v", got)
	}
}

// ③ v2 + 错误口令：认证失败，文件一个字节都不能变。
func TestStateKDFWrongPassphraseLeavesFileUntouched(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const key = "correct-passphrase-that-is-long-enough"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized, EncKey: "device-secret"})
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	wrong := NewStateStore(path)
	if err := wrong.SetEncryptionKey("wrong-passphrase-that-is-long-enough"); err != nil {
		t.Fatalf("SetEncryptionKey wrong: %v", err)
	}
	if err := wrong.Load(); err == nil {
		t.Fatal("Load with the wrong passphrase must fail")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a failed unlock must not modify the state file")
	}
}

// ④ 迁移写盘失败：Load 仍成功、文件保持 v1、内存可用；下次 Save 补迁到 v2。
func TestStateKDFMigrationFailureKeepsLegacyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	key := strings.Repeat("m", 32)
	newLegacyStateFixture(t, path, key)
	// 这条用例只覆盖「信封迁移写盘失败不阻塞启动」的容忍语义，所以先把 schema
	// 盖成当前版本：否则会同时触发 schema 迁移，而那是必须 fail closed 的
	// （见 TestSchemaAndEnvelopeMigrationFailsClosed）。
	stampStateSchemaVersion(t, path, stateSchemaVersion)

	// 用同名目录占住 .tmp：Load 能读文件，但迁移写盘必然失败。
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatalf("block tmp path: %v", err)
	}

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("a failed migration rewrite must not block startup: %v", err)
	}
	if got := store.GetDeviceByID("dev-legacy"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("decrypted state should be usable: %+v", got)
	}
	if raw := readRawState(t, path); raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersionLegacy {
		t.Fatalf("file should stay v1 after a failed migration: %+v", raw.Encrypted)
	}

	// 释放阻塞后，下一次 Save 必须补迁。
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatalf("unblock tmp path: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save after unblocking: %v", err)
	}
	raw := readRawState(t, path)
	if raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersion || raw.Encrypted.KDF != stateKDFArgon2id {
		t.Fatalf("next Save should complete the migration: %+v", raw.Encrypted)
	}

	reloaded := NewStateStore(path)
	if err := reloaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey reloaded: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload migrated file: %v", err)
	}
	if got := reloaded.GetDeviceByID("dev-legacy"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("migrated file lost the device key: %+v", got)
	}
}

// ⑤ 连续 Save 复用同一 salt/params，只换 nonce（换 salt = 换密钥）。
func TestStateKDFSaveReusesEnvelope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const key = "salt-reuse-passphrase-long-enough"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})
	if err := store.Save(); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	first := readRawState(t, path).Encrypted
	if first == nil || first.Salt == "" {
		t.Fatalf("first envelope = %+v", first)
	}

	store.AddDevice(&DeviceState{ID: "dev-2", Status: deviceStatusAuthorized})
	if err := store.Save(); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	second := readRawState(t, path).Encrypted
	if second == nil {
		t.Fatal("second envelope missing")
	}
	if first.Version != second.Version || first.KDF != second.KDF || first.Salt != second.Salt {
		t.Fatalf("envelope changed between saves: first=%+v second=%+v", first, second)
	}
	if first.KDFParams == nil || second.KDFParams == nil || *first.KDFParams != *second.KDFParams {
		t.Fatalf("kdf params changed between saves: first=%+v second=%+v", first.KDFParams, second.KDFParams)
	}
	if first.Nonce == second.Nonce {
		t.Fatal("nonce must be regenerated on every Save")
	}

	reloaded := NewStateStore(path)
	if err := reloaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey reloaded: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.GetDeviceByID("dev-1") == nil || reloaded.GetDeviceByID("dev-2") == nil {
		t.Fatal("both saves should survive a reload")
	}
}

// ⑥ 篡改 kdf_params 到 1GiB：直接报错，不做派生（否则 1.6GB 小机器会被打爆）。
func TestStateKDFRejectsOversizedParams(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const key = "tamper-test-passphrase-long-enough"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	envelope, ok := doc["encrypted"].(map[string]any)
	if !ok {
		t.Fatalf("encrypted envelope missing: %v", doc)
	}
	params, ok := envelope["kdf_params"].(map[string]any)
	if !ok {
		t.Fatalf("kdf_params missing: %v", envelope)
	}
	params["memory_kib"] = 1024 * 1024
	tampered, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	loaded := NewStateStore(path)
	if err := loaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	err = loaded.Load()
	if err == nil {
		t.Fatal("Load must reject out-of-range kdf parameters")
	}
	if !strings.Contains(err.Error(), "invalid kdf parameters") {
		t.Fatalf("error = %v, want an invalid-kdf-params error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(tampered, after) {
		t.Fatal("a rejected kdf must not rewrite the file")
	}
}

// ⑦ 无密钥 + 明文文件：行为与升级前一致（明文、不生成加密信封）。
func TestStateKDFWithoutKeyStaysPlaintext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")

	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if store.EncryptionEnabled() {
		t.Fatal("encryption must stay disabled without a key")
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized, EncKey: "device-secret"})
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := readRawState(t, path)
	if raw.Encrypted != nil {
		t.Fatalf("plaintext mode must not write an encrypted envelope: %+v", raw.Encrypted)
	}
	if raw.Devices[0].EncKey != "device-secret" {
		t.Fatalf("plaintext state should keep the device key as before: %+v", raw.Devices[0])
	}
}

// ⑧a --state-kdf=legacy：v1 保持 v1，不迁移；仍能读写。
func TestStateKDFLegacyFlagKeepsV1(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	key := strings.Repeat("l", 32)
	newLegacyStateFixture(t, path, key)

	store := NewStateStore(path)
	store.SetStateKDFLegacy(true)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if raw := readRawState(t, path); raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersionLegacy {
		t.Fatalf("legacy flag must keep the file on v1: %+v", raw.Encrypted)
	}

	// 之后的 Save 也只能写 v1。
	store.AddDevice(&DeviceState{ID: "dev-2", Status: deviceStatusAuthorized})
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if raw := readRawState(t, path); raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersionLegacy {
		t.Fatalf("legacy flag must keep writing v1: %+v", raw.Encrypted)
	}

	// 旧格式密钥仍可解：模拟回滚到 v1 进程。
	legacy := NewStateStore(path)
	legacy.SetStateKDFLegacy(true)
	if err := legacy.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey legacy: %v", err)
	}
	if err := legacy.Load(); err != nil {
		t.Fatalf("legacy Load: %v", err)
	}
	if got := legacy.GetDeviceByID("dev-2"); got == nil {
		t.Fatal("device written under legacy format should be readable")
	}
}

// ⑧b --state-kdf=legacy 对已迁移的 v2 文件：降级回 v1，旧二进制能读。
func TestStateKDFLegacyFlagDowngradesV2(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const key = "downgrade-passphrase-long-enough"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized, EncKey: "device-secret"})
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if raw := readRawState(t, path); raw.Encrypted.Version != stateEncryptionVersion {
		t.Fatalf("setup should produce v2, got %+v", raw.Encrypted)
	}

	legacy := NewStateStore(path)
	legacy.SetStateKDFLegacy(true)
	if err := legacy.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey legacy: %v", err)
	}
	if err := legacy.Load(); err != nil {
		t.Fatalf("Load with legacy flag: %v", err)
	}
	raw := readRawState(t, path)
	if raw.Encrypted == nil || raw.Encrypted.Version != stateEncryptionVersionLegacy || raw.Encrypted.KDF != "" {
		t.Fatalf("legacy flag should downgrade the envelope to v1: %+v", raw.Encrypted)
	}
	// 降级后的文件用 v1 派生必须能解开。
	reloaded := NewStateStore(path)
	reloaded.SetStateKDFLegacy(true)
	if err := reloaded.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey reloaded: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload downgraded file: %v", err)
	}
	if got := reloaded.GetDeviceByID("dev-1"); got == nil || got.EncKey != "device-secret" {
		t.Fatalf("downgraded file lost the device key: %+v", got)
	}
}

// 延迟派生后，TOTP 门禁必须在 Load 之前就认为加密已启用。
func TestEncryptionEnabledBeforeLoad(t *testing.T) {
	t.Parallel()
	store := NewStateStore(filepath.Join(t.TempDir(), "server-state.json"))
	if store.EncryptionEnabled() {
		t.Fatal("a store without a key must report encryption disabled")
	}
	if err := store.SetEncryptionKey(strings.Repeat("p", 32)); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if !store.EncryptionEnabled() {
		t.Fatal("a configured key must report encryption enabled before Load")
	}
}

func TestReadStateKeyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.key")
	const key = "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte("  "+key+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := readStateKeyFile(path)
	if err != nil {
		t.Fatalf("read 0600 key file: %v", err)
	}
	if got != key {
		t.Fatalf("key = %q, want %q", got, key)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := readStateKeyFile(path); err == nil {
		t.Fatal("a group-readable key file must be rejected")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("truncate key file: %v", err)
	}
	if _, err := readStateKeyFile(path); err == nil {
		t.Fatal("an empty key file must be rejected")
	}
}

func TestReadStateKeyFileRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.key")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 32)), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	if _, err := readStateKeyFile(link); err == nil {
		t.Fatal("a symlink key file must be rejected")
	}
}

func TestStateKeySourcesConflict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		flagKey  string
		envKey   string
		filePath string
		want     int
	}{
		{name: "none", want: 0},
		{name: "flag only", flagKey: "a", want: 1},
		{name: "env only", envKey: "b", want: 1},
		{name: "file only", filePath: "c", want: 1},
		{name: "flag+env", flagKey: "a", envKey: "b", want: 2},
		{name: "flag+file", flagKey: "a", filePath: "c", want: 2},
		{name: "env+file", envKey: "b", filePath: "c", want: 2},
		{name: "all three", flagKey: "a", envKey: "b", filePath: "c", want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(stateKeySources(tc.flagKey, tc.envKey, tc.filePath)); got != tc.want {
				t.Fatalf("sources = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseStateKDF(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		legacy bool
		wantOK bool
	}{
		{raw: "", legacy: false, wantOK: true},
		{raw: "v2", legacy: false, wantOK: true},
		{raw: "LEGACY", legacy: true, wantOK: true},
		{raw: " legacy ", legacy: true, wantOK: true},
		{raw: "argon2", wantOK: false},
	}
	for _, tc := range cases {
		legacy, err := parseStateKDF(tc.raw)
		if tc.wantOK && err != nil {
			t.Fatalf("parseStateKDF(%q) error: %v", tc.raw, err)
		}
		if !tc.wantOK {
			if err == nil {
				t.Fatalf("parseStateKDF(%q) should fail", tc.raw)
			}
			continue
		}
		if legacy != tc.legacy {
			t.Fatalf("parseStateKDF(%q) legacy = %v, want %v", tc.raw, legacy, tc.legacy)
		}
	}
}

// 信封声明的 kdf 必须与配置的密钥形态匹配：配错时明确报错，不能拿
// “解密失败”去猜是不是口令打错了。
func TestStateKDFRejectsKeyModeMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	const passphrase = "mode-mismatch-passphrase-long-enough"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(passphrase); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// argon2id 文件 + 全熵密钥 → 直接报形态不匹配。
	directKey := "hex:" + hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
	rawKeyStore := NewStateStore(path)
	if err := rawKeyStore.SetEncryptionKey(directKey); err != nil {
		t.Fatalf("SetEncryptionKey direct: %v", err)
	}
	err := rawKeyStore.Load()
	if err == nil || !strings.Contains(err.Error(), "raw 32-byte key was configured") {
		t.Fatalf("Load with a raw key against an argon2id file = %v", err)
	}

	// kdf=none 文件 + 口令 → 同样直接拒绝。
	nonePath := filepath.Join(dir, "none-state.json")
	noneStore := NewStateStore(nonePath)
	if err := noneStore.SetEncryptionKey(directKey); err != nil {
		t.Fatalf("SetEncryptionKey direct: %v", err)
	}
	if err := noneStore.Load(); err != nil {
		t.Fatalf("Load direct: %v", err)
	}
	if raw := readRawState(t, nonePath); raw.Encrypted == nil || raw.Encrypted.KDF != stateKDFNone {
		t.Fatalf("setup should produce kdf=none: %+v", raw.Encrypted)
	}
	passStore := NewStateStore(nonePath)
	if err := passStore.SetEncryptionKey(passphrase); err != nil {
		t.Fatalf("SetEncryptionKey passphrase: %v", err)
	}
	err = passStore.Load()
	if err == nil || !strings.Contains(err.Error(), "a passphrase was configured") {
		t.Fatalf("Load with a passphrase against a kdf=none file = %v", err)
	}
}
