package server

import (
	"testing"

	"goremote/internal/common"
)

func TestSetPortRange_UpdatesPortStatus(t *testing.T) {
	cryptoMgr := common.NewCryptoManager()
	_ = cryptoMgr
	tm := NewTunnelManager(nil, 10000, 20000)

	status := tm.GetPortStatus()
	if status.RangeStart != 10000 || status.RangeEnd != 20000 {
		t.Fatalf("initial range: expected 10000-20000, got %d-%d", status.RangeStart, status.RangeEnd)
	}

	port, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("AllocatePort: %v", err)
	}
	tm.ReleasePort(port)

	tm.SetPortRange(30000, 40000)

	status = tm.GetPortStatus()
	if status.RangeStart != 30000 || status.RangeEnd != 40000 {
		t.Fatalf("after SetPortRange: expected 30000-40000, got %d-%d", status.RangeStart, status.RangeEnd)
	}
}

func TestSetPortRange_PortAllocationInNewRange(t *testing.T) {
	tm := NewTunnelManager(nil, 100, 200)

	p1, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	if p1 < 100 || p1 > 200 {
		t.Fatalf("port %d outside initial range", p1)
	}
	tm.ReleasePort(p1)

	tm.SetPortRange(5000, 6000)

	p2, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("allocate after range change: %v", err)
	}
	if p2 < 5000 || p2 > 6000 {
		t.Fatalf("port %d outside new range 5000-6000", p2)
	}
}

func TestSetPortRange_TracksAllocatedCount(t *testing.T) {
	tm := NewTunnelManager(nil, 1000, 2000)

	p1, _ := tm.AllocatePort()
	p2, _ := tm.AllocatePort()

	status := tm.GetPortStatus()
	if status.Allocated != 2 {
		t.Fatalf("expected 2 allocated, got %d", status.Allocated)
	}

	tm.ReleasePort(p1)
	tm.ReleasePort(p2)

	tm.SetPortRange(3000, 4000)

	status = tm.GetPortStatus()
	if status.Allocated != 0 {
		t.Fatalf("expected 0 allocated after release, got %d", status.Allocated)
	}
}

func TestApproveDevice_ChangesStatus(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, err := dm.RegisterNewClient("aabbccdd00112233445566778899aabb00112233445566778899aabbccdd0011", "00112233445566778899aabbccdd00112233445566778899aabbccdd0011", "test-host", "linux", "10.0.0.1")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	pending := stateStore.GetDevicesByStatus("pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	device, _, _, err := dm.ApproveDevice(deviceID)
	if err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	if device.Status != "authorized" {
		t.Fatalf("expected authorized, got %s", device.Status)
	}
	if !device.EncEnabled {
		t.Fatal("expected enc_enabled after approve")
	}
	if device.EncKey == "" {
		t.Fatal("expected enc_key after approve")
	}

	authorized := stateStore.GetDevicesByStatus("authorized")
	if len(authorized) != 1 {
		t.Fatalf("expected 1 authorized, got %d", len(authorized))
	}

	if !cryptoMgr.HasKey(deviceID) {
		t.Fatal("expected CryptoManager to have key for approved device")
	}
}

func TestDenyDevice_RemovesFromStore(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient("aabbccdd00112233445566778899aabb00112233445566778899aabbccdd0011", "00112233445566778899aabbccdd00112233445566778899aabbccdd0011", "test", "linux", "10.0.0.2")

	if err := dm.DenyDevice(deviceID); err != nil {
		t.Fatalf("DenyDevice: %v", err)
	}

	if stateStore.GetDeviceByID(deviceID) != nil {
		t.Fatal("device should be removed after deny")
	}
}

func TestDeleteDevice_RemovesCryptoKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient("deadbeef00112233445566778899aabb00112233445566778899aabbccdd0011", "cafe0000112233445566778899aabb00112233445566778899aabbccdd0011", "test", "linux", "10.0.0.3")
	dm.ApproveDevice(deviceID)

	if !cryptoMgr.HasKey(deviceID) {
		t.Fatal("expected key after approve")
	}

	if err := dm.DeleteDevice(deviceID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}

	if cryptoMgr.HasKey(deviceID) {
		t.Fatal("key should be removed after delete")
	}
	if stateStore.GetDeviceByID(deviceID) != nil {
		t.Fatal("device should be removed after delete")
	}
}

func TestReauth_VerifiesSignature(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient("1111111111111111111111111111111111111111111111111111111111111111", "2222222222222222222222222222222222222222222222222222222222222222", "test", "linux", "10.0.0.4")
	dm.ApproveDevice(deviceID)

	ok, device, err := dm.ReauthClient(deviceID, "reauth-test-pubkey", 0, "bad-signature")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if ok {
		t.Fatal("reauth should fail with bad signature")
	}
	_ = device

	ok, device, err = dm.ReauthClient(deviceID, "reauth-test-pubkey", 1234567890, "deadbeef")
	if err == nil {
		t.Fatal("expected error for bad timestamp")
	}
	_ = ok
	_ = device

	notFound, _, err := dm.ReauthClient("nonexistent-id", "", 0, "")
	if err == nil {
		t.Fatal("expected error for nonexistent device")
	}
	_ = notFound
}

func TestRegenerateEncKey_ChangesCryptoKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient("3333333333333333333333333333333333333333333333333333333333333333", "4444444444444444444444444444444444444444444444444444444444444444", "test", "linux", "10.0.0.5")
	dm.ApproveDevice(deviceID)

	oldKey := stateStore.GetDeviceByID(deviceID).EncKey

	updated, _, _, err := dm.RegenerateEncKey(deviceID)
	if err != nil {
		t.Fatalf("RegenerateEncKey: %v", err)
	}
	if updated.EncKey == oldKey {
		t.Fatal("enc_key should change after regenerate")
	}
}