package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"goremote/internal/common"
)

func registerPendingTestDevice(t *testing.T, dm *DeviceManager) string {
	t.Helper()
	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "pending-host", "linux", "10.0.0.11")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	return deviceID
}

func agePendingDevice(store *StateStore, deviceID string, age time.Duration) {
	store.UpdateDevice(deviceID, func(d *DeviceState) {
		d.FirstSeen = time.Now().Add(-age)
	})
}

// 超过 24h 的待审批设备被清理，名额与记录一起释放。
func TestPendingDeviceExpiresAfterTTL(t *testing.T) {
	_, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())
	deviceID := registerPendingTestDevice(t, dm)
	agePendingDevice(store, deviceID, pendingDeviceTTL+time.Hour)

	if removed := dm.SweepExpiredPending(time.Now()); removed != 1 {
		t.Fatalf("swept %d devices, want 1", removed)
	}
	if device := store.GetDeviceByID(deviceID); device != nil {
		t.Fatal("expired pending device must be removed")
	}
	if got := store.CountDevicesByStatus(deviceStatusPending); got != 0 {
		t.Fatalf("pending devices = %d, want 0", got)
	}
}

// 未过期的申请不能被清掉：24h 是给「第二天才审批」留的窗口。
func TestFreshPendingDeviceSurvivesSweep(t *testing.T) {
	_, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())
	deviceID := registerPendingTestDevice(t, dm)
	agePendingDevice(store, deviceID, pendingDeviceTTL-time.Hour)

	if removed := dm.SweepExpiredPending(time.Now()); removed != 0 {
		t.Fatalf("swept %d devices, want 0", removed)
	}
	if store.GetDeviceByID(deviceID) == nil {
		t.Fatal("fresh pending device must survive")
	}
}

// FirstSeen 为零的老记录不自动删：不知道它多老，删掉等于凭空丢掉申请。
func TestZeroFirstSeenPendingIsNotSwept(t *testing.T) {
	_, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())
	deviceID := registerPendingTestDevice(t, dm)
	store.UpdateDevice(deviceID, func(d *DeviceState) { d.FirstSeen = time.Time{} })

	if removed := dm.SweepExpiredPending(time.Now()); removed != 0 {
		t.Fatalf("swept %d devices, want 0", removed)
	}
	if store.GetDeviceByID(deviceID) == nil {
		t.Fatal("a device without a first_seen timestamp must not be swept")
	}
}

// 准入表被填满后，清理一条过期申请必须立刻让新设备能进来。
func TestExpiredPendingFreesAdmissionSlot(t *testing.T) {
	_, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())

	for i := 0; i < maxPendingDevices; i++ {
		store.AddDevice(&DeviceState{
			ID:               "client-filler-" + time.Now().Format("150405.000000000") + "-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Status:           deviceStatusPending,
			FirstSeen:        time.Now(),
			IPWhitelist:      []string{},
			DeviceSignPubkey: common.EncodeBytes(make([]byte, 32)),
		})
	}
	if got := store.CountDevicesByStatus(deviceStatusPending); got != maxPendingDevices {
		t.Fatalf("setup: pending devices = %d, want %d", got, maxPendingDevices)
	}
	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	if _, err := dm.RegisterNewClient(common.EncodePublicKey(pub), "", "overflow-host", "linux", "10.0.0.12"); err == nil {
		t.Fatal("setup: registration should be rejected while the admission table is full")
	}

	// 把一条 filler 变成过期，清掉后新设备应当能注册。
	var expiredID string
	for _, device := range store.GetAllDevices() {
		if device.Status == deviceStatusPending {
			expiredID = device.ID
			break
		}
	}
	agePendingDevice(store, expiredID, pendingDeviceTTL+time.Minute)
	if removed := dm.SweepExpiredPending(time.Now()); removed != 1 {
		t.Fatalf("swept %d devices, want 1", removed)
	}
	if _, err := dm.RegisterNewClient(common.EncodePublicKey(pub), "", "overflow-host", "linux", "10.0.0.12"); err != nil {
		t.Fatalf("registration after sweeping an expired device: %v", err)
	}
}

// 过期设备的 pending 连接必须一起关掉，不能留下「设备没了、连接还挂着」。
func TestExpiredPendingClosesConnection(t *testing.T) {
	_, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())
	deviceID := registerPendingTestDevice(t, dm)

	serverConn, agentConn := newTestWebsocketPair(t)
	dm.AddPendingConn(deviceID, &Client{ClientID: deviceID, Conn: serverConn}, "10.0.0.11")
	agePendingDevice(store, deviceID, pendingDeviceTTL+time.Hour)

	if removed := dm.SweepExpiredPending(time.Now()); removed != 1 {
		t.Fatalf("swept %d devices, want 1", removed)
	}
	if _, ok := dm.GetPendingConn(deviceID); ok {
		t.Fatal("expired device must not keep a pending connection")
	}

	agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg struct{}
	err := agentConn.ReadJSON(&msg)
	if err == nil {
		t.Fatal("the pending connection should have been closed")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("connection was not closed; read only timed out")
	}
}

// 清理必须落盘：重启后过期记录不能复活。
func TestExpiredPendingRemovalIsPersisted(t *testing.T) {
	config, store := newTestConfig(t)
	dm := NewDeviceManager(store, common.NewCryptoManager())
	deviceID := registerPendingTestDevice(t, dm)
	agePendingDevice(store, deviceID, pendingDeviceTTL+time.Hour)

	if removed := dm.SweepExpiredPending(time.Now()); removed != 1 {
		t.Fatalf("swept %d devices, want 1", removed)
	}

	reloaded := NewStateStore(filepath.Join(config.DataDir(), "server-state.json"))
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if device := reloaded.GetDeviceByID(deviceID); device != nil {
		t.Fatal("expired device came back after reload: removal was not persisted")
	}
}
