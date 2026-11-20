package server

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goremote/internal/common"
)

func newTestStateStore(settings ServerSettings) *StateStore {
	pub, priv, _ := common.GenerateSignKeypair()
	return &StateStore{
		stopCh: make(chan struct{}),
		state: &ServerState{
			ServerSignPrivkey: hex.EncodeToString(priv),
			ServerSignPubkey:  hex.EncodeToString(pub),
			Settings:          settings,
			Devices:           []DeviceState{},
		},
	}
}

func TestStateStoreGettersReturnDefensiveCopies(t *testing.T) {
	store := newTestStateStore(defaultSettings())
	store.UpdateSettings(func(settings *ServerSettings) {
		settings.GlobalWhitelist = []string{"10.0.0.0/8"}
	})
	approvedAt := time.Now()
	store.AddDevice(&DeviceState{
		ID:          "client-test",
		Hostname:    "original",
		IPWhitelist: []string{"10.0.0.1"},
		ApprovedAt:  &approvedAt,
	})

	devices := store.GetAllDevices()
	devices[0].Hostname = "mutated"
	devices[0].IPWhitelist[0] = "10.0.0.2"
	*devices[0].ApprovedAt = approvedAt.Add(time.Hour)
	settings := store.GetSettings()
	settings.GlobalWhitelist[0] = "0.0.0.0/0"

	device := store.GetDeviceByID("client-test")
	if device == nil {
		t.Fatal("expected device")
	}
	if device.Hostname != "original" {
		t.Fatalf("stored hostname mutated through snapshot copy: %q", device.Hostname)
	}
	if device.IPWhitelist[0] != "10.0.0.1" {
		t.Fatalf("stored whitelist mutated through snapshot copy: %v", device.IPWhitelist)
	}
	if !device.ApprovedAt.Equal(approvedAt) {
		t.Fatal("stored approval time mutated through snapshot copy")
	}
	if got := store.GetSettings().GlobalWhitelist; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("stored settings mutated through snapshot copy: %v", got)
	}
}

func TestStateStoreStopIsIdempotent(t *testing.T) {
	store := newTestStateStore(defaultSettings())
	store.Stop()
	store.Stop()
}

func TestStateStoreLoadBackfillsMissingSettingsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	data := []byte(`{
		"settings": {
			"port_range_start": 12000,
			"port_range_end": 13000,
			"max_conn_per_min": 0
		},
		"devices": []
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	store := NewStateStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	settings := store.GetSettings()
	if settings.PortRangeStart != 12000 || settings.PortRangeEnd != 13000 {
		t.Fatalf("port range not loaded: %d-%d", settings.PortRangeStart, settings.PortRangeEnd)
	}
	if settings.MaxConnPerMin != 0 {
		t.Fatalf("explicit max_conn_per_min=0 should be preserved, got %d", settings.MaxConnPerMin)
	}
	if settings.LoginRateLimit != 5 {
		t.Fatalf("missing login_rate_limit should default to 5, got %d", settings.LoginRateLimit)
	}
	if settings.MaxBodySizeMB != defaultMaxBodySizeMB {
		t.Fatalf("missing max_body_size_mb should default to %d, got %d", defaultMaxBodySizeMB, settings.MaxBodySizeMB)
	}
	if settings.DefaultLocalAddr != "127.0.0.1" {
		t.Fatalf("missing default_local_addr should be backfilled, got %q", settings.DefaultLocalAddr)
	}
}

func TestStateStoreLoadMigratesPlaintextWithoutLosingRuntimeKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	data := []byte(`{
		"admin_password_plain": "legacy-plaintext-password",
		"settings": {"port_range_start": 12000, "port_range_end": 13000},
		"devices": [{"id": "client-1", "status": "authorized", "enc_enabled": true, "device_dh_pubkey": "bb", "enc_key": "secret-device-key"}]
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	store := NewStateStore(path)
	if err := store.SetEncryptionKey("this-is-a-long-enough-state-key-for-tests"); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	device := store.GetDeviceByID("client-1")
	if device == nil || device.EncKey != "secret-device-key" {
		t.Fatalf("runtime device key was lost during migration: %+v", device)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated state: %v", err)
	}
	if strings.Contains(string(persisted), "secret-device-key") {
		t.Fatal("migrated state leaked the device key in plaintext")
	}
	if strings.Contains(string(persisted), "legacy-plaintext-password") {
		t.Fatal("migrated state kept the legacy plaintext admin password")
	}
}

func TestStateStoreEncryptsSensitiveFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	store := NewStateStore(path)
	if err := store.SetEncryptionKey("this-is-a-long-enough-state-key-for-tests"); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "client-1", EncKey: "secret-device-key"})
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if strings.Contains(string(data), "secret-device-key") {
		t.Fatal("sensitive state leaked in persisted JSON")
	}
	var raw ServerState
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw state: %v", err)
	}
	if raw.Encrypted == nil || raw.ServerSignPrivkey != "" || raw.AdminPasswordHash != "" || raw.Devices[0].EncKey != "" {
		t.Fatalf("expected sensitive fields to be encrypted and cleared: %+v", raw)
	}

	loaded := NewStateStore(path)
	if err := loaded.SetEncryptionKey("this-is-a-long-enough-state-key-for-tests"); err != nil {
		t.Fatalf("SetEncryptionKey loaded: %v", err)
	}
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load encrypted: %v", err)
	}
	device := loaded.GetDeviceByID("client-1")
	if device == nil || device.EncKey != "secret-device-key" {
		t.Fatalf("decrypted device key = %+v", device)
	}
}

func TestStateStoreRequiresKeyForEncryptedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	store := NewStateStore(path)
	if err := store.SetEncryptionKey("this-is-a-long-enough-state-key-for-tests"); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	withoutKey := NewStateStore(path)
	if err := withoutKey.Load(); err != ErrStateEncryptionKeyRequired {
		t.Fatalf("Load without key err = %v, want %v", err, ErrStateEncryptionKeyRequired)
	}
}
