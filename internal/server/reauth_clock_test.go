package server

import (
	"embed"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

// startReauthTestServer 起一个真实的 HTTP/WS 服务端（无 TLS），用于验证
// handleConn 的连接关闭与 101 响应头，而不只是 handler 层的返回值。
func startReauthTestServer(t *testing.T) *Server {
	t.Helper()

	config, _ := newTestConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := NewServer(config, embed.FS{})
	srv.Addr = addr
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return srv
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func dialReauthWS(t *testing.T, addr, query string) (*websocket.Conn, *http.Response) {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws"+query, nil)
	if err != nil {
		t.Fatalf("dial %q: %v", query, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, resp
}

func reauthRegisterMessage(t *testing.T, fixture reauthFixture, timestamp int64) common.Message {
	t.Helper()
	payload := common.RegisterPayload{
		ReAuth:         true,
		ClientID:       fixture.id,
		DevicePubkey:   fixture.signPub,
		DeviceDHPubkey: fixture.dhHex,
		Timestamp:      timestamp,
		Signature:      signReauth(t, fixture.signPriv, fixture.id, timestamp),
		Hostname:       "reauth-host",
		OS:             "linux",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	return common.Message{Type: "register", Payload: payloadJSON}
}

// ① 有效签名 + 超窗时间戳：typed error，设备记录零变更、不新增 pending。
func TestReauthClockSkewReturnsTypedError(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)
	devicesBefore := len(stateStore.GetAllDevices())

	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	ok, device, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		oldTimestamp,
		signReauth(t, fixture.signPriv, fixture.id, oldTimestamp),
	)
	if ok || device != nil || err == nil {
		t.Fatalf("skewed reauth = (%v, %v, %v), want a typed error", ok, device, err)
	}

	var skew *errReauthClockSkew
	if !errors.As(err, &skew) {
		t.Fatalf("error = %v, want errReauthClockSkew", err)
	}
	if skew.delta < 9*time.Minute || skew.delta > 11*time.Minute {
		t.Fatalf("delta = %v, want about +10m", skew.delta)
	}
	if got := len(stateStore.GetAllDevices()); got != devicesBefore {
		t.Fatalf("device count = %d, want %d", got, devicesBefore)
	}
	if got := stateStore.CountDevicesByStatus(deviceStatusPending); got != 0 {
		t.Fatalf("pending devices = %d, want 0", got)
	}

	// 线上 agent 发的是 UnixNano：归一化后 delta 仍必须是 +10 分钟量级。
	// 漏了这一步会把每次 reauth 都误判成巨大漂移。
	nanoTimestamp := time.Now().Add(-10 * time.Minute).UnixNano()
	ok, device, err = dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		nanoTimestamp,
		signReauth(t, fixture.signPriv, fixture.id, nanoTimestamp),
	)
	if ok || device != nil || err == nil {
		t.Fatalf("nanosecond skew = (%v, %v, %v), want a typed error", ok, device, err)
	}
	if !errors.As(err, &skew) || skew.delta < 9*time.Minute || skew.delta > 11*time.Minute {
		t.Fatalf("nanosecond delta = %+v (err %v), want about +10m", skew, err)
	}

	// 设备时钟超前（时间戳在未来）时 delta 必须为负，服务端文案才是「设备快」。
	futureTimestamp := time.Now().Add(10 * time.Minute).Unix()
	ok, device, err = dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		futureTimestamp,
		signReauth(t, fixture.signPriv, fixture.id, futureTimestamp),
	)
	if ok || device != nil || err == nil {
		t.Fatalf("future timestamp = (%v, %v, %v), want a typed error", ok, device, err)
	}
	if !errors.As(err, &skew) || skew.delta > -9*time.Minute || skew.delta < -11*time.Minute {
		t.Fatalf("future delta = %+v (err %v), want about -10m", skew, err)
	}
}

// ② 老 agent（未声明 proto）：不发 register_fail，连接被静默关闭，在线 client 不变。
func TestReauthClockSkewLegacyClientGetsSilentClose(t *testing.T) {
	srv := startReauthTestServer(t)
	fixture := newReauthFixture(t, srv.deviceMgr)
	devicesBefore := len(srv.stateStore.GetAllDevices())
	clientsBefore := len(srv.clients.List())

	conn, resp := dialReauthWS(t, srv.Addr, "")
	if got := resp.Header.Get("X-Goremote-Proto"); got != "" {
		t.Fatalf("legacy client must not get a proto header, got %q", got)
	}

	if err := conn.WriteJSON(reauthRegisterMessage(t, fixture, time.Now().Add(-10*time.Minute).Unix())); err != nil {
		t.Fatalf("write reauth: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg common.Message
	err := conn.ReadJSON(&msg)
	if err == nil {
		t.Fatalf("legacy client must not receive %q; the server should close silently", msg.Type)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection stayed open; expected a silent close: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return len(srv.clients.List()) == clientsBefore &&
			len(srv.stateStore.GetAllDevices()) == devicesBefore &&
			srv.stateStore.CountDevicesByStatus(deviceStatusPending) == 0
	}, "a skewed legacy reauth must not change devices or clients")
}

// ③ proto=2 客户端：101 回 X-Goremote-Proto，超窗回 clock_skew:<带符号秒数>。
func TestReauthClockSkewProto2GetsRegisterFail(t *testing.T) {
	srv := startReauthTestServer(t)
	fixture := newReauthFixture(t, srv.deviceMgr)
	devicesBefore := len(srv.stateStore.GetAllDevices())

	conn, resp := dialReauthWS(t, srv.Addr, "?proto=2")
	if got := resp.Header.Get("X-Goremote-Proto"); got != "2" {
		t.Fatalf("proto header = %q, want 2", got)
	}

	if err := conn.WriteJSON(reauthRegisterMessage(t, fixture, time.Now().Add(-10*time.Minute).Unix())); err != nil {
		t.Fatalf("write reauth: %v", err)
	}

	msg := readAgentMessage(t, conn, "register_fail", 3*time.Second)
	var failPayload common.RegisterFailPayload
	if err := json.Unmarshal(msg.Payload, &failPayload); err != nil {
		t.Fatalf("unmarshal register_fail: %v", err)
	}
	if !strings.HasPrefix(failPayload.Reason, common.ClockSkewReasonPrefix) {
		t.Fatalf("reason = %q, want the %q prefix", failPayload.Reason, common.ClockSkewReasonPrefix)
	}
	skewText := strings.TrimPrefix(failPayload.Reason, common.ClockSkewReasonPrefix)
	if !strings.HasPrefix(skewText, "+") {
		t.Fatalf("skew = %q, want a positive server-ahead delta for a 10m-old timestamp", skewText)
	}
	seconds, err := strconv.ParseInt(strings.TrimSuffix(skewText, "s"), 10, 64)
	if err != nil || seconds < 590 || seconds > 610 {
		t.Fatalf("skew seconds = %d (err %v), want about 600", seconds, err)
	}

	if got := len(srv.stateStore.GetAllDevices()); got != devicesBefore {
		t.Fatalf("device count = %d, want %d", got, devicesBefore)
	}
	if got := srv.stateStore.CountDevicesByStatus(deviceStatusPending); got != 0 {
		t.Fatalf("pending devices = %d, want 0", got)
	}
}

// ⑥ 只有声明 proto=2 的升级请求才回响应头；未声明没有。
func TestWebSocketProtoNegotiationHeader(t *testing.T) {
	srv := startReauthTestServer(t)

	_, legacyResp := dialReauthWS(t, srv.Addr, "")
	if got := legacyResp.Header.Get("X-Goremote-Proto"); got != "" {
		t.Fatalf("undeclared client header = %q, want none", got)
	}

	_, protoResp := dialReauthWS(t, srv.Addr, "?proto=2")
	if got := protoResp.Header.Get("X-Goremote-Proto"); got != "2" {
		t.Fatalf("declared client header = %q, want 2", got)
	}
}

// ④ 设备不存在仍降级成新注册（回归）：签名字段合法但 client_id 不存在。
func TestReauthUnknownDeviceFallsBackToNewRegistration(t *testing.T) {
	_, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)
	srv := &Server{
		stateStore: stateStore,
		deviceMgr:  dm,
		clients:    NewClientManager(),
		cryptoMgr:  cryptoMgr,
	}
	handler := NewHandler(srv)

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	timestamp := time.Now().Unix()
	signature, err := common.SignTimestamp(priv, "missing-device", timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}

	if err := handler.handleReconnect(client, &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       "missing-device",
		DevicePubkey:   common.EncodePublicKey(pub),
		DeviceDHPubkey: common.EncodeBytes(dhPub[:]),
		Timestamp:      timestamp,
		Signature:      common.EncodeBytes(signature),
		Hostname:       "new-host",
		OS:             "linux",
	}); err != nil {
		t.Fatalf("unknown device must fall back to new registration, got %v", err)
	}

	msg := readAgentMessage(t, agentConn, "register_pending", 2*time.Second)
	var pending common.RegisterPendingPayload
	if err := json.Unmarshal(msg.Payload, &pending); err != nil {
		t.Fatalf("unmarshal register_pending: %v", err)
	}
	if pending.ClientID == "" || client.ClientID != pending.ClientID {
		t.Fatalf("pending payload = %+v, client id = %q", pending, client.ClientID)
	}
	if got := stateStore.CountDevicesByStatus(deviceStatusPending); got != 1 {
		t.Fatalf("pending devices = %d, want 1", got)
	}
}

// 时间窗必须在验签之后判定：签名无效的过期报文不能被误判成时钟漂移，
// 否则任何人都能用垃圾签名走到「保留身份」的分支。
func TestReauthExpiredTimestampWithBadSignatureIsNotClockSkew(t *testing.T) {
	_, stateStore := newTestConfig(t)
	dm := NewDeviceManager(stateStore, common.NewCryptoManager())
	fixture := newReauthFixture(t, dm)

	_, otherPriv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	signature, err := common.SignTimestamp(otherPriv, fixture.id, oldTimestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}

	ok, device, err := dm.ReauthClient(
		fixture.id,
		fixture.signPub,
		fixture.dhHex,
		oldTimestamp,
		common.EncodeBytes(signature),
	)
	if ok || device != nil || err == nil {
		t.Fatalf("bad signature = (%v, %v, %v), want a generic failure", ok, device, err)
	}
	var skew *errReauthClockSkew
	if errors.As(err, &skew) {
		t.Fatalf("an invalid signature must not be classified as clock skew: %v", err)
	}
}
