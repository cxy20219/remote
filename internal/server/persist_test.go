package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateStoreGetStateReturnsDefensiveCopy(t *testing.T) {
	store := NewStateStoreWithSettings(defaultSettings())
	approvedAt := time.Now()
	store.AddDevice(&DeviceState{
		ID:          "client-test",
		Hostname:    "original",
		IPWhitelist: []string{"10.0.0.1"},
		ApprovedAt:  &approvedAt,
	})

	state := store.GetState()
	state.Devices[0].Hostname = "mutated"
	state.Devices[0].IPWhitelist[0] = "10.0.0.2"
	*state.Devices[0].ApprovedAt = approvedAt.Add(time.Hour)
	state.Settings.GlobalWhitelist = []string{"0.0.0.0/0"}

	device := store.GetDeviceByID("client-test")
	if device == nil {
		t.Fatal("expected device")
	}
	if device.Hostname != "original" {
		t.Fatalf("stored hostname mutated through GetState copy: %q", device.Hostname)
	}
	if device.IPWhitelist[0] != "10.0.0.1" {
		t.Fatalf("stored whitelist mutated through GetState copy: %v", device.IPWhitelist)
	}
	if !device.ApprovedAt.Equal(approvedAt) {
		t.Fatal("stored approval time mutated through GetState copy")
	}
	if got := store.GetSettings().GlobalWhitelist; len(got) != 0 {
		t.Fatalf("stored settings mutated through GetState copy: %v", got)
	}
}

func TestStateStoreStopIsIdempotent(t *testing.T) {
	store := NewStateStoreWithSettings(defaultSettings())
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
