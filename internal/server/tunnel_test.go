package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"goremote/internal/common"
)

type fakePendingConn struct {
	closed bool
}

const (
	testSignPubkeyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDHPubkeyHex   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func (f *fakePendingConn) Close() error {
	f.closed = true
	return nil
}

func TestSetPortRange_UpdatesPortStatus(t *testing.T) {
	cryptoMgr := common.NewCryptoManager()
	_ = cryptoMgr
	tm := NewTunnelManager(nil, 10000, 20000)

	status := tm.GetPortStatus()
	if status.RangeStart != 10000 || status.RangeEnd != 20000 {
		t.Fatalf("initial range: expected 10000-20000, got %d-%d", status.RangeStart, status.RangeEnd)
	}

	port, ln, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("AllocatePort: %v", err)
	}
	if ln != nil {
		ln.Close()
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

	p1, ln1, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	if p1 < 100 || p1 > 200 {
		t.Fatalf("port %d outside initial range", p1)
	}
	if ln1 != nil {
		ln1.Close()
	}
	tm.ReleasePort(p1)

	tm.SetPortRange(5000, 6000)

	p2, ln2, err := tm.AllocatePort()
	if err != nil {
		t.Fatalf("allocate after range change: %v", err)
	}
	if p2 < 5000 || p2 > 6000 {
		t.Fatalf("port %d outside new range 5000-6000", p2)
	}
	if ln2 != nil {
		ln2.Close()
	}
}

func TestSetPortRange_TracksAllocatedCount(t *testing.T) {
	tm := NewTunnelManager(nil, 1000, 2000)

	p1, ln1, _ := tm.AllocatePort()
	p2, ln2, _ := tm.AllocatePort()
	if ln1 != nil {
		ln1.Close()
	}
	if ln2 != nil {
		ln2.Close()
	}

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

func TestNormalizeTunnelExposure(t *testing.T) {
	tests := []struct {
		name      string
		exposure  string
		wantMode  string
		wantBind  string
		wantError bool
	}{
		{name: "empty defaults public", exposure: "", wantMode: TunnelExposurePublic, wantBind: TunnelBindAll},
		{name: "public", exposure: "public", wantMode: TunnelExposurePublic, wantBind: TunnelBindAll},
		{name: "server local", exposure: "server_local", wantMode: TunnelExposureServerLocal, wantBind: TunnelBindServerLocal},
		{name: "reject unknown", exposure: "private", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMode, gotBind, err := normalizeTunnelExposure(tc.exposure)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotMode != tc.wantMode || gotBind != tc.wantBind {
				t.Fatalf("got %q/%q, want %q/%q", gotMode, gotBind, tc.wantMode, tc.wantBind)
			}
		})
	}
}

func TestAllocatePortForExposure_ServerLocalBindsLoopback(t *testing.T) {
	tm := NewTunnelManager(nil, 30000, 30100)

	port, ln, err := tm.AllocatePortForExposure(TunnelExposureServerLocal)
	if err != nil {
		t.Fatalf("AllocatePortForExposure: %v", err)
	}
	defer tm.ReleasePort(port)
	defer ln.Close()

	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("server_local listener = %q, want loopback bind", ln.Addr().String())
	}
}

func TestUpdateTunnel_EmptyExposurePreservesCurrentMode(t *testing.T) {
	tm := NewTunnelManager(nil, 30000, 30100)
	tm.tunnels["t1"] = &Tunnel{
		TunnelID:   "t1",
		ClientID:   "client-1",
		Protocol:   "tcp",
		PublicPort: 30000,
		Exposure:   TunnelExposureServerLocal,
		BindAddr:   TunnelBindServerLocal,
		LocalAddr:  "127.0.0.1",
		LocalPort:  22,
		Status:     "active",
	}
	tm.publicPorts[30000] = "t1"

	tunnel, err := tm.UpdateTunnel("t1", "127.0.0.1", 22, 0, "tcp", "")
	if err != nil {
		t.Fatalf("UpdateTunnel: %v", err)
	}
	if tunnel.Exposure != TunnelExposureServerLocal || tunnel.BindAddr != TunnelBindServerLocal {
		t.Fatalf("exposure changed to %q/%q", tunnel.Exposure, tunnel.BindAddr)
	}
}

func TestApproveDevice_ChangesStatus(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, err := dm.RegisterNewClient(testSignPubkeyHex, testDHPubkeyHex, "test-host", "linux", "10.0.0.1")
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

func TestApproveDeviceRequiresDHPubkey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, err := dm.RegisterNewClient(
		testSignPubkeyHex,
		"",
		"test-host",
		"linux",
		"10.0.0.1",
	)
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	if _, _, _, err := dm.ApproveDevice(deviceID); err == nil {
		t.Fatal("expected approval to fail without device DH public key")
	}

	device := stateStore.GetDeviceByID(deviceID)
	if device == nil {
		t.Fatal("expected device to remain pending")
	}
	if device.Status != "pending" {
		t.Fatalf("expected device to remain pending, got %s", device.Status)
	}
	if cryptoMgr.HasKey(deviceID) {
		t.Fatal("did not expect encryption key for unapproved device")
	}
}

func TestRegisterNewClientRejectsInvalidDHPubkeySize(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	_, err := dm.RegisterNewClient(
		"aabbccdd00112233445566778899aabb00112233445566778899aabbccdd0011",
		"001122",
		"test-host",
		"linux",
		"10.0.0.1",
	)
	if err == nil {
		t.Fatal("expected invalid DH public key size to be rejected")
	}
}

func TestDenyDevice_RemovesFromStore(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient(testSignPubkeyHex, testDHPubkeyHex, "test", "linux", "10.0.0.2")
	fakeConn := &fakePendingConn{}
	dm.pendingConns[deviceID] = &PendingConnInfo{
		Client: &Client{ClientID: deviceID},
		Conn:   fakeConn,
	}

	if err := dm.DenyDevice(deviceID); err != nil {
		t.Fatalf("DenyDevice: %v", err)
	}

	if stateStore.GetDeviceByID(deviceID) != nil {
		t.Fatal("device should be removed after deny")
	}
	if _, ok := dm.GetPendingConn(deviceID); ok {
		t.Fatal("pending connection should be removed after deny")
	}
	if !fakeConn.closed {
		t.Fatal("pending connection should be closed after deny")
	}
}

func TestRegisterNewClient_ReusesExistingPendingDevice(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	pubkey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dhPubkey1 := "1111111111111111111111111111111111111111111111111111111111111111"
	dhPubkey2 := "2222222222222222222222222222222222222222222222222222222222222222"

	firstID, err := dm.RegisterNewClient(pubkey, dhPubkey1, "old-host", "linux", "10.0.0.1")
	if err != nil {
		t.Fatalf("first RegisterNewClient: %v", err)
	}
	secondID, err := dm.RegisterNewClient(pubkey, dhPubkey2, "new-host", "linux", "10.0.0.2")
	if err != nil {
		t.Fatalf("second RegisterNewClient: %v", err)
	}
	if secondID != firstID {
		t.Fatalf("expected pending device to be reused, got %s then %s", firstID, secondID)
	}

	pending := stateStore.GetDevicesByStatus("pending")
	if len(pending) != 1 {
		t.Fatalf("expected one pending device, got %d", len(pending))
	}
	device := stateStore.GetDeviceByID(firstID)
	if device.Hostname != "new-host" {
		t.Fatalf("expected hostname to be refreshed, got %q", device.Hostname)
	}
	if device.DeviceDHPubkey != dhPubkey2 {
		t.Fatal("expected DH pubkey to be refreshed for the pending device")
	}
}

func TestPendingConnReplacementDoesNotLetOldCleanupDeleteNew(t *testing.T) {
	dm := &DeviceManager{
		pendingConns: make(map[string]*PendingConnInfo),
	}

	deviceID := "client-test"
	oldClient := &Client{ClientID: deviceID}
	newClient := &Client{ClientID: deviceID}
	oldConn := &fakePendingConn{}

	dm.pendingConns[deviceID] = &PendingConnInfo{
		Client:   oldClient,
		Conn:     oldConn,
		RemoteIP: "10.0.0.1",
	}

	dm.AddPendingConn(deviceID, newClient, "10.0.0.2")

	if !oldConn.closed {
		t.Fatal("old pending connection should be closed when replaced")
	}

	info, ok := dm.GetPendingConn(deviceID)
	if !ok {
		t.Fatal("expected replacement pending connection to exist")
	}
	if info.Client != newClient {
		t.Fatal("expected replacement pending connection to be stored")
	}
	if info.RemoteIP != "10.0.0.2" {
		t.Fatalf("expected remote IP to be refreshed, got %q", info.RemoteIP)
	}

	dm.RemovePendingConnIfMatch(deviceID, oldClient)
	info, ok = dm.GetPendingConn(deviceID)
	if !ok || info.Client != newClient {
		t.Fatal("old pending cleanup should not remove the replacement connection")
	}

	dm.DetachPendingConnIfMatch(deviceID, newClient)
	if _, ok := dm.GetPendingConn(deviceID); ok {
		t.Fatal("detach should remove matching pending connection")
	}
}

func TestHandleReconnectRefreshesDeviceMetadata(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	pubHex := common.EncodePublicKey(pub)
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	dhPubHex := common.EncodeBytes(dhPub[:])

	deviceID, err := dm.RegisterNewClient(pubHex, dhPubHex, "old-host", "linux", "10.0.0.6")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}

	timestamp := time.Now().Unix()
	signature, err := common.SignTimestamp(priv, deviceID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}

	srv := &Server{
		stateStore: stateStore,
		deviceMgr:  dm,
		clients:    NewClientManager(),
	}
	handler := NewHandler(srv)

	err = handler.handleReconnect(&Client{}, &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       deviceID,
		DevicePubkey:   pubHex,
		DeviceDHPubkey: dhPubHex,
		Timestamp:      timestamp,
		Signature:      common.EncodeBytes(signature),
		Hostname:       "new-host",
		OS:             "android",
	})
	if err == nil {
		t.Fatal("expected nil websocket client to fail only while sending register_ok")
	}

	device := stateStore.GetDeviceByID(deviceID)
	if device.Hostname != "new-host" {
		t.Fatalf("expected hostname to refresh, got %q", device.Hostname)
	}
	if device.Name != "new-host" {
		t.Fatalf("expected name to refresh, got %q", device.Name)
	}
	if device.OS != "android" {
		t.Fatalf("expected OS to refresh, got %q", device.OS)
	}
	if device.DeviceDHPubkey != dhPubHex {
		t.Fatal("expected device DH public key to refresh")
	}
}

func TestHandleReconnectRejectsInvalidStoredDHPubkey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	pubHex := common.EncodePublicKey(pub)
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}

	deviceID, err := dm.RegisterNewClient(pubHex, common.EncodeBytes(dhPub[:]), "test-host", "linux", "10.0.0.6")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	stateStore.UpdateDevice(deviceID, func(d *DeviceState) {
		d.DeviceDHPubkey = "001122"
	})

	timestamp := time.Now().Unix()
	signature, err := common.SignTimestamp(priv, deviceID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}

	srv := &Server{
		stateStore: stateStore,
		deviceMgr:  dm,
		clients:    NewClientManager(),
	}
	handler := NewHandler(srv)

	err = handler.handleReconnect(&Client{}, &common.RegisterPayload{
		ReAuth:       true,
		ClientID:     deviceID,
		DevicePubkey: pubHex,
		Timestamp:    timestamp,
		Signature:    common.EncodeBytes(signature),
		Hostname:     "test-host",
		OS:           "linux",
	})
	if err == nil {
		t.Fatal("expected reconnect to fail when stored DH pubkey is invalid")
	}
	if _, ok := srv.clients.Get(deviceID); ok {
		t.Fatal("client should not be added when register_ok cannot be prepared securely")
	}
}

func TestDeleteDevice_RemovesCryptoKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, _ := dm.RegisterNewClient(testSignPubkeyHex, testDHPubkeyHex, "test", "linux", "10.0.0.3")
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

func TestNewDeviceManagerDoesNotLoadDisabledEncryptionKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	stateStore.AddDevice(&DeviceState{
		ID:         "client-disabled",
		Status:     "authorized",
		EncEnabled: false,
		EncKey:     strings.Repeat("a", 64),
	})

	cryptoMgr := common.NewCryptoManager()
	NewDeviceManager(stateStore, cryptoMgr)

	if cryptoMgr.HasKey("client-disabled") {
		t.Fatal("disabled encryption key should not be loaded")
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

func TestReauthRejectsSignatureReplay(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "test", "linux", "10.0.0.4")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}

	timestamp := time.Now().UnixNano()
	sig, err := common.SignTimestamp(priv, deviceID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}
	signature := common.EncodeBytes(sig)

	if ok, _, err := dm.ReauthClient(deviceID, common.EncodePublicKey(pub), timestamp, signature); err != nil || !ok {
		t.Fatalf("first ReauthClient failed: ok=%v err=%v", ok, err)
	}
	if ok, _, err := dm.ReauthClient(deviceID, common.EncodePublicKey(pub), timestamp, signature); err == nil || ok {
		t.Fatalf("expected replayed ReauthClient to fail: ok=%v err=%v", ok, err)
	}
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

func TestHandleAgentData_MissingExternalConnIsNonFatal(t *testing.T) {
	tm := NewTunnelManager(nil, 10000, 20000)

	if err := tm.HandleAgentData("missing-tunnel", "missing-conn", []byte("late-data"), false); err != nil {
		t.Fatalf("expected late data for closed external connection to be ignored, got %v", err)
	}

	if err := tm.HandleAgentData("missing-tunnel", "missing-conn", nil, true); err != nil {
		t.Fatalf("expected late EOF for closed external connection to be ignored, got %v", err)
	}
}

func TestHandleAgentData_RejectsConnFromDifferentTunnel(t *testing.T) {
	tm := NewTunnelManager(nil, 10000, 20000)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	tm.AddExternalConn("conn-1", "tunnel-a", serverConn)

	if err := tm.HandleAgentData("tunnel-b", "conn-1", nil, true); err == nil {
		t.Fatal("expected mismatched tunnel/conn to be rejected")
	}
	if _, ok := tm.GetExternalConn("conn-1"); !ok {
		t.Fatal("mismatched EOF should not remove another tunnel's connection")
	}
}

func TestHandleAgentData_EOFRemovesMatchingConn(t *testing.T) {
	tm := NewTunnelManager(nil, 10000, 20000)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	tm.AddExternalConn("conn-1", "tunnel-a", serverConn)

	if err := tm.HandleAgentData("tunnel-a", "conn-1", nil, true); err != nil {
		t.Fatalf("expected matching EOF to close connection, got %v", err)
	}
	if _, ok := tm.GetExternalConn("conn-1"); ok {
		t.Fatal("expected matching EOF to remove connection")
	}
}

func TestCloseTunnelsByClient_RemovesOnlyThatClientTunnels(t *testing.T) {
	tm := NewTunnelManager(nil, 10000, 20000)
	tm.tunnels["tunnel-a"] = &Tunnel{TunnelID: "tunnel-a", ClientID: "client-1", PublicPort: 10001, Status: "active"}
	tm.tunnels["tunnel-b"] = &Tunnel{TunnelID: "tunnel-b", ClientID: "client-1", PublicPort: 10002, Status: "active"}
	tm.tunnels["tunnel-c"] = &Tunnel{TunnelID: "tunnel-c", ClientID: "client-2", PublicPort: 10003, Status: "active"}
	tm.publicPorts[10001] = "tunnel-a"
	tm.publicPorts[10002] = "tunnel-b"
	tm.publicPorts[10003] = "tunnel-c"

	tm.CloseTunnelsByClient("client-1")

	if _, ok := tm.GetTunnel("tunnel-a"); ok {
		t.Fatal("expected tunnel-a to be closed")
	}
	if _, ok := tm.GetTunnel("tunnel-b"); ok {
		t.Fatal("expected tunnel-b to be closed")
	}
	if _, ok := tm.GetTunnel("tunnel-c"); !ok {
		t.Fatal("expected other client's tunnel to remain")
	}
	if _, ok := tm.publicPorts[10001]; ok {
		t.Fatal("expected tunnel-a public port to be released")
	}
	if _, ok := tm.publicPorts[10002]; ok {
		t.Fatal("expected tunnel-b public port to be released")
	}
	if got := tm.publicPorts[10003]; got != "tunnel-c" {
		t.Fatalf("expected tunnel-c public port to remain, got %q", got)
	}
}

func TestCreateTunnelUsesRuntimeMaxTunnelsSetting(t *testing.T) {
	settings := defaultSettings()
	settings.MaxTunnelsPerClient = 1
	stateStore := NewStateStoreWithSettings(settings)
	srv := &Server{stateStore: stateStore}
	tm := NewTunnelManager(srv, 10000, 20000)

	if err := tm.CreateTunnel("tunnel-a", "client-1", nil, "tcp", "127.0.0.1", 22, 10001, TunnelExposurePublic); err != nil {
		t.Fatalf("first CreateTunnel: %v", err)
	}
	if err := tm.CreateTunnel("tunnel-b", "client-1", nil, "tcp", "127.0.0.1", 22, 10002, TunnelExposurePublic); err == nil {
		t.Fatal("expected runtime max_tunnels_per_client setting to be enforced")
	}

	srv.UpdateSettings(func(st *ServerSettings) {
		st.MaxTunnelsPerClient = 2
	})
	if err := tm.CreateTunnel("tunnel-b", "client-1", nil, "tcp", "127.0.0.1", 22, 10002, TunnelExposurePublic); err != nil {
		t.Fatalf("second CreateTunnel after runtime update: %v", err)
	}
}

func TestUpdateDeviceConfigTogglesEncryptionRuntimeKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)

	deviceID, err := dm.RegisterNewClient(testSignPubkeyHex, testDHPubkeyHex, "test-host", "linux", "10.0.0.1")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	if !cryptoMgr.HasKey(deviceID) {
		t.Fatal("expected key after approval")
	}

	device, err := dm.UpdateDeviceConfig(deviceID, "", false, nil)
	if err != nil {
		t.Fatalf("UpdateDeviceConfig disable: %v", err)
	}
	if device.EncEnabled {
		t.Fatal("expected encryption disabled")
	}
	if cryptoMgr.HasKey(deviceID) {
		t.Fatal("expected runtime key removed when encryption disabled")
	}

	device, err = dm.UpdateDeviceConfig(deviceID, "", true, nil)
	if err != nil {
		t.Fatalf("UpdateDeviceConfig enable: %v", err)
	}
	if !device.EncEnabled {
		t.Fatal("expected encryption enabled")
	}
	if !cryptoMgr.HasKey(deviceID) {
		t.Fatal("expected runtime key restored when encryption enabled")
	}
}

func TestServerTunnelBytesAllowPlaintextWhenEncryptionDisabled(t *testing.T) {
	settings := defaultSettings()
	stateStore := NewStateStoreWithSettings(settings)
	stateStore.AddDevice(&DeviceState{ID: "client-plain", EncEnabled: false})
	srv := &Server{stateStore: stateStore, cryptoMgr: common.NewCryptoManager()}

	data := []byte("plain")
	encrypted, err := srv.encryptTunnelBytes("client-plain", data)
	if err != nil {
		t.Fatalf("encryptTunnelBytes: %v", err)
	}
	if string(encrypted) != string(data) {
		t.Fatalf("disabled encryption should pass plaintext through, got %q", encrypted)
	}
	decrypted, err := srv.decryptTunnelBytes("client-plain", encrypted)
	if err != nil {
		t.Fatalf("decryptTunnelBytes: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("disabled encryption should decode plaintext, got %q", decrypted)
	}
}
