package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"goremote/internal/common"
)

// reauthFixture 是一台「已审批」设备的全部材料：签到用的签名密钥对，和
// 审批时绑定给它的 DH 密钥对。
type reauthFixture struct {
	id       string
	signPub  string
	signPriv ed25519.PrivateKey
	dhHex    string
	dhPriv   *[32]byte
}

func newReauthFixture(t *testing.T, dm *DeviceManager) reauthFixture {
	t.Helper()
	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	dhPriv, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	dhHex := common.EncodeBytes(dhPub[:])
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), dhHex, "reauth-host", "linux", "10.0.0.7")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	return reauthFixture{
		id:       deviceID,
		signPub:  common.EncodePublicKey(pub),
		signPriv: priv,
		dhHex:    dhHex,
		dhPriv:   dhPriv,
	}
}

func signReauth(t *testing.T, priv ed25519.PrivateKey, clientID string, timestamp int64) string {
	t.Helper()
	signature, err := common.SignTimestamp(priv, clientID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}
	return common.EncodeBytes(signature)
}

// otherDHKeyHex 返回一个合法但不同的 DH 公钥，模拟攻击者替换的密钥。
func otherDHKeyHex(t *testing.T) string {
	t.Helper()
	_, pub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	return common.EncodeBytes(pub[:])
}

// 1. 换了 DH 公钥的 reauth 必须被拒绝。
func TestReauthRejectsChangedDHKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	timestamp := time.Now().Unix()
	ok, device, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		otherDHKeyHex(t),
		timestamp,
		signReauth(t, fixture.signPriv, fixture.id, timestamp),
	)
	if !errors.Is(err, errDeviceDHKeyMismatch) {
		t.Fatalf("err = %v, want errDeviceDHKeyMismatch", err)
	}
	if ok {
		t.Fatal("reauth with a replaced dh pubkey must not succeed")
	}
	if device != nil {
		t.Fatal("reauth with a replaced dh pubkey must not return the device")
	}
}

// 2. 正常重连（DH 未变）必须通过。
func TestReauthAcceptsUnchangedDHKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	timestamp := time.Now().Unix()
	ok, device, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		timestamp,
		signReauth(t, fixture.signPriv, fixture.id, timestamp),
	)
	if err != nil {
		t.Fatalf("ReauthClient: %v", err)
	}
	if !ok || device == nil {
		t.Fatalf("ok=%v device=%v, want success", ok, device)
	}
	if device.DeviceDHPubkey != fixture.dhHex {
		t.Fatalf("device dh pubkey = %q, want %q", device.DeviceDHPubkey, fixture.dhHex)
	}
}

// 3. 记录里有公钥、payload 不带公钥：视为不一致（不能把记录里的公钥当成
// 「无约束」）。
func TestReauthRejectsEmptyDHWhenStoredNonEmpty(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	timestamp := time.Now().Unix()
	ok, _, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		"",
		timestamp,
		signReauth(t, fixture.signPriv, fixture.id, timestamp),
	)
	if !errors.Is(err, errDeviceDHKeyMismatch) {
		t.Fatalf("err = %v, want errDeviceDHKeyMismatch", err)
	}
	if ok {
		t.Fatal("reauth without a dh pubkey must not succeed when one is bound")
	}
}

// 4. 两侧都没有公钥（旧版未加密设备）必须放行，否则老设备会被锁在门外。
func TestReauthAllowsEmptyDHWhenStoredEmpty(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	const legacyID = "client-legacy-no-dh"
	stateStore.AddDevice(&DeviceState{
		ID:               legacyID,
		DeviceSignPubkey: common.EncodePublicKey(pub),
		Status:           deviceStatusAuthorized,
		IPWhitelist:      []string{},
	})

	timestamp := time.Now().Unix()
	ok, device, err := dm.ReauthClient(
		legacyID,
		common.EncodePublicKey(pub),
		"",
		timestamp,
		signReauth(t, priv, legacyID, timestamp),
	)
	if err != nil {
		t.Fatalf("legacy empty-dh reauth must be allowed, got %v", err)
	}
	if !ok || device == nil {
		t.Fatalf("ok=%v device=%v, want success", ok, device)
	}
}

// 5. 记录里的公钥损坏：fail closed，且与 mismatch 分开报，否则日志会把
// 状态损坏说成「设备换了密钥」。
func TestReauthRejectsCorruptStoredDHKey(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	stateStore.UpdateDevice(fixture.id, func(d *DeviceState) { d.DeviceDHPubkey = "001122" })

	timestamp := time.Now().Unix()
	ok, _, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		timestamp,
		signReauth(t, fixture.signPriv, fixture.id, timestamp),
	)
	if !errors.Is(err, errDeviceDHKeyCorrupt) {
		t.Fatalf("err = %v, want errDeviceDHKeyCorrupt", err)
	}
	if errors.Is(err, errDeviceDHKeyMismatch) {
		t.Fatal("corrupt stored key must not be reported as a mismatch")
	}
	if ok {
		t.Fatal("reauth must fail closed when the stored dh pubkey is corrupt")
	}
}

// 6. 被拒绝的 reauth 不能改动设备记录，也不能制造待审批设备。
func TestReauthMismatchDoesNotMutateDevice(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	before := stateStore.GetDeviceByID(fixture.id)
	if before == nil {
		t.Fatal("device disappeared before reauth")
	}
	devicesBefore := len(stateStore.GetAllDevices())

	timestamp := time.Now().Unix()
	if _, _, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		otherDHKeyHex(t),
		timestamp,
		signReauth(t, fixture.signPriv, fixture.id, timestamp),
	); !errors.Is(err, errDeviceDHKeyMismatch) {
		t.Fatalf("err = %v, want errDeviceDHKeyMismatch", err)
	}

	after := stateStore.GetDeviceByID(fixture.id)
	if after == nil {
		t.Fatal("device disappeared after rejected reauth")
	}
	if after.DeviceDHPubkey != before.DeviceDHPubkey {
		t.Fatalf("dh pubkey changed: %q -> %q", before.DeviceDHPubkey, after.DeviceDHPubkey)
	}
	if after.EncKey != before.EncKey {
		t.Fatal("enc key changed on rejected reauth")
	}
	if after.EncEnabled != before.EncEnabled || after.Status != before.Status {
		t.Fatal("device status/encryption changed on rejected reauth")
	}
	if got := stateStore.CountDevicesByStatus(deviceStatusPending); got != 0 {
		t.Fatalf("pending devices = %d, want 0", got)
	}
	if got := len(stateStore.GetAllDevices()); got != devicesBefore {
		t.Fatalf("device count = %d, want %d (rejected reauth must not create a device)", got, devicesBefore)
	}
}

// 7. 走真实 WS 链路：DH 不一致必须回 register_fail，且不写入 register_ok、
// 不动设备记录、不顶掉在线连接。
func TestHandleReconnectRejectsDHMismatchWithoutStateChange(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)
	fixture := newReauthFixture(t, dm)

	existing := &Client{ClientID: fixture.id}
	clients := NewClientManager()
	clients.Add(existing)

	srv := &Server{
		stateStore: stateStore,
		deviceMgr:  dm,
		clients:    clients,
		cryptoMgr:  cryptoMgr,
	}
	handler := NewHandler(srv)

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}

	timestamp := time.Now().Unix()
	err := handler.handleReconnect(client, &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       fixture.id,
		DevicePubkey:   fixture.signPub,
		DeviceDHPubkey: otherDHKeyHex(t),
		Timestamp:      timestamp,
		Signature:      signReauth(t, fixture.signPriv, fixture.id, timestamp),
		Hostname:       "attacker-host",
	})
	if err != nil {
		t.Fatalf("handleReconnect should answer with register_fail, got error %v", err)
	}

	msg := readAgentMessage(t, agentConn, "register_fail", 2*time.Second)
	var failPayload common.RegisterFailPayload
	if err := json.Unmarshal(msg.Payload, &failPayload); err != nil {
		t.Fatalf("unmarshal register_fail: %v", err)
	}
	if failPayload.Reason != registerFailDHKeyMismatch {
		t.Fatalf("register_fail reason = %q, want %q", failPayload.Reason, registerFailDHKeyMismatch)
	}
	expectNoAgentMessage(t, agentConn, 200*time.Millisecond)

	device := stateStore.GetDeviceByID(fixture.id)
	if device == nil {
		t.Fatal("device disappeared after rejected reauth")
	}
	if device.DeviceDHPubkey != fixture.dhHex {
		t.Fatalf("device dh pubkey = %q, want %q", device.DeviceDHPubkey, fixture.dhHex)
	}
	if device.Hostname == "attacker-host" {
		t.Fatal("rejected reauth must not update device metadata")
	}
	if got := stateStore.CountDevicesByStatus(deviceStatusPending); got != 0 {
		t.Fatalf("pending devices = %d, want 0", got)
	}
	if live, ok := clients.Get(fixture.id); !ok || live != existing {
		t.Fatal("rejected reauth must not replace the live connection")
	}
}

// 8. 正常重连下发的 EncKey 必须仍按「记录里的」DH 公钥封装：真设备能解开，
// 换来的公钥解不开。防「只加了拒绝、把正常路径弄坏」。
func TestHandleReconnectSealsEncKeyToStoredDH(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)
	fixture := newReauthFixture(t, dm)

	srv := &Server{
		stateStore: stateStore,
		deviceMgr:  dm,
		clients:    NewClientManager(),
		cryptoMgr:  cryptoMgr,
	}
	handler := NewHandler(srv)

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}

	timestamp := time.Now().Unix()
	if err := handler.handleReconnect(client, &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       fixture.id,
		DevicePubkey:   fixture.signPub,
		DeviceDHPubkey: fixture.dhHex,
		Timestamp:      timestamp,
		Signature:      signReauth(t, fixture.signPriv, fixture.id, timestamp),
		Hostname:       "reconnected-host",
	}); err != nil {
		t.Fatalf("handleReconnect: %v", err)
	}

	msg := readAgentMessage(t, agentConn, "register_ok", 2*time.Second)
	var okPayload common.RegisterOKPayload
	if err := json.Unmarshal(msg.Payload, &okPayload); err != nil {
		t.Fatalf("unmarshal register_ok: %v", err)
	}
	if okPayload.ClientID != fixture.id {
		t.Fatalf("client_id = %q, want %q", okPayload.ClientID, fixture.id)
	}
	if !okPayload.EncEnabled || okPayload.EncKeyEncrypted == "" || okPayload.ServerDHPubkey == "" {
		t.Fatalf("expected encrypted register_ok, got enc_enabled=%v", okPayload.EncEnabled)
	}

	device := stateStore.GetDeviceByID(fixture.id)
	if device == nil {
		t.Fatal("device disappeared after successful reauth")
	}

	serverDHPubBytes, err := hex.DecodeString(okPayload.ServerDHPubkey)
	if err != nil || len(serverDHPubBytes) != 32 {
		t.Fatalf("invalid server dh pubkey in register_ok: %v", err)
	}
	var serverDHPub [32]byte
	copy(serverDHPub[:], serverDHPubBytes)

	shared, err := common.DHSharedSecret(fixture.dhPriv, &serverDHPub)
	if err != nil {
		t.Fatalf("DHSharedSecret: %v", err)
	}
	plain, err := common.DecryptKeyWithSharedSecret(okPayload.EncKeyEncrypted, shared)
	if err != nil {
		t.Fatalf("the approved device must be able to decrypt the tunnel key: %v", err)
	}
	if hex.EncodeToString(plain) != device.EncKey {
		t.Fatal("decrypted key does not match the stored enc_key")
	}

	wrongPriv, _, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	wrongShared, err := common.DHSharedSecret(wrongPriv, &serverDHPub)
	if err != nil {
		t.Fatalf("DHSharedSecret (wrong key): %v", err)
	}
	if _, err := common.DecryptKeyWithSharedSecret(okPayload.EncKeyEncrypted, wrongShared); err == nil {
		t.Fatal("a non-approved dh key must not decrypt the tunnel key")
	}
}

// 9. 待审批期间换 DH 公钥必须仍然允许刷新（Android 重装依赖它），这是本次
// 刻意保留的行为，钉住防止以后被顺手收紧。
func TestPendingDHRefreshStillAllowed(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())

	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, firstDH, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(firstDH[:]), "pending-host", "android", "10.0.0.8")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	secondDHHex := otherDHKeyHex(t)
	sameID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), secondDHHex, "pending-host", "android", "10.0.0.8")
	if err != nil {
		t.Fatalf("re-register pending device: %v", err)
	}
	if sameID != deviceID {
		t.Fatalf("pending re-registration created a new device: %q -> %q", deviceID, sameID)
	}
	device := stateStore.GetDeviceByID(deviceID)
	if device == nil {
		t.Fatal("pending device disappeared")
	}
	if device.DeviceDHPubkey != secondDHHex {
		t.Fatalf("pending dh pubkey = %q, want refreshed %q", device.DeviceDHPubkey, secondDHHex)
	}
	if devices := len(stateStore.GetAllDevices()); devices != 1 {
		t.Fatalf("device count = %d, want 1", devices)
	}
}

// 10. 校验与审批/读取并发：既不能数据竞争，也不能在锁外读到半更新状态。
func TestReauthDHMismatchConcurrentWithApproval(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	// 第二台待审批设备，专门给并发审批用。
	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	pendingID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "pending-concurrent", "linux", "10.0.0.9")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	base := time.Now().Unix()
	var wg sync.WaitGroup

	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				timestamp := base + int64(worker*10+i)
				ok, _, err := dm.ReauthClient(
					fixture.id,
					fixture.signPub,
					otherDHKeyHex(t),
					timestamp,
					signReauth(t, fixture.signPriv, fixture.id, timestamp),
				)
				if !errors.Is(err, errDeviceDHKeyMismatch) || ok {
					t.Errorf("concurrent mismatch reauth: ok=%v err=%v", ok, err)
					return
				}
			}
		}(worker)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, _, _, err := dm.ApproveDevice(pendingID); err != nil {
			t.Errorf("concurrent ApproveDevice: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if d := stateStore.GetDeviceByID(fixture.id); d == nil {
				t.Error("device temporarily invisible to readers")
				return
			}
		}
	}()

	wg.Wait()

	device := stateStore.GetDeviceByID(fixture.id)
	if device == nil || device.DeviceDHPubkey != fixture.dhHex {
		t.Fatal("approved device dh pubkey changed under concurrent reauth")
	}
	if approved := stateStore.GetDeviceByID(pendingID); approved == nil || approved.Status != deviceStatusAuthorized {
		t.Fatal("concurrent approval did not take effect")
	}
}
