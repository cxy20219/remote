package server

import (
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
