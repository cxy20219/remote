package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
	"goremote/internal/server/netplane"
)

type testWGBackend struct {
	mu        sync.Mutex
	failPeers map[string]error
	infraErr  error
	aclErr    error
	linkUp    bool
	linkErr   error
	lastPeers []netplane.Peer
	downs     int
}

func (b *testWGBackend) Probe(context.Context) error                { return nil }
func (b *testWGBackend) Ensure(context.Context, netplane.Hub) error { return nil }
func (b *testWGBackend) Up(context.Context) error                   { return nil }
func (b *testWGBackend) ApplyACL(context.Context, netplane.ACL) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.aclErr
}
func (b *testWGBackend) ACLExists(context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.aclErr != nil {
		return false, nil
	}
	return true, nil
}

func (b *testWGBackend) Apply(_ context.Context, peers []netplane.Peer) (map[string]error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.infraErr != nil {
		return nil, b.infraErr
	}
	b.lastPeers = append([]netplane.Peer(nil), peers...)
	errs := make(map[string]error)
	for id, err := range b.failPeers {
		errs[id] = err
	}
	return errs, nil
}

func (b *testWGBackend) PeerStats(context.Context) (map[string]netplane.PeerStats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := make(map[string]netplane.PeerStats, len(b.lastPeers))
	for _, peer := range b.lastPeers {
		stats[peer.PublicKey] = netplane.PeerStats{HandshakeAge: 5, RXBytes: 1234, TXBytes: 5678}
	}
	return stats, nil
}

func (b *testWGBackend) Down(context.Context) error {
	b.mu.Lock()
	b.downs++
	b.mu.Unlock()
	return nil
}

func (b *testWGBackend) LinkUp(context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.linkErr != nil {
		return false, b.linkErr
	}
	return b.linkUp, nil
}

// setLink 设置下一次只读探测的结果，用来模拟「接口被外部 down」和探测失败。
func (b *testWGBackend) setLink(up bool, err error) {
	b.mu.Lock()
	b.linkUp, b.linkErr = up, err
	b.mu.Unlock()
}

func (b *testWGBackend) fail(deviceID string) {
	b.mu.Lock()
	if b.failPeers == nil {
		b.failPeers = make(map[string]error)
	}
	b.failPeers[deviceID] = errors.New("kernel rejected the peer")
	b.mu.Unlock()
}

func (b *testWGBackend) heal() {
	b.mu.Lock()
	b.failPeers = nil
	b.infraErr = nil
	b.mu.Unlock()
}

// failInfra 让下一轮 reconcile 在接口级失败（Apply 整体返回错误）。
func (b *testWGBackend) failInfra(err error) {
	b.mu.Lock()
	b.infraErr = err
	b.mu.Unlock()
}

// failACL 让 nft 安装失败，用来验证 fail-closed 与 acl_warning。
func (b *testWGBackend) failACL(err error) {
	b.mu.Lock()
	b.aclErr = err
	b.mu.Unlock()
}

func newWGTestServer(t *testing.T) (*Server, *StateStore, *testWGBackend) {
	t.Helper()
	config, store := newTestConfig(t)
	// 启用组网强制要求 state 加密（实现须知 #6）；测试默认满足它，
	// 「没有密钥就拒绝」由 TestPutVPNRequiresStateEncryption 单独覆盖。
	if err := store.SetEncryptionKey(strings.Repeat("test-state-key-", 4)); err != nil {
		t.Fatalf("set state encryption key: %v", err)
	}
	backend := &testWGBackend{}
	plane := netplane.New(netplane.Config{Store: store, Backend: backend, Interval: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	plane.Start(ctx)
	t.Cleanup(plane.Stop)

	server := &Server{
		config:     config,
		stateStore: store,
		adminAuth:  NewAdminAuth(store),
		deviceMgr:  NewDeviceManager(store, common.NewCryptoManager()),
		clients:    NewClientManager(),
		netplane:   plane,
	}
	return server, store, backend
}

func addAuthorizedDevice(t *testing.T, store *StateStore, id string) {
	t.Helper()
	store.AddDevice(&DeviceState{ID: id, Name: id, Status: deviceStatusAuthorized})
}

func callVPNHandler(t *testing.T, handler gin.HandlerFunc, method, body, deviceID string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	engine := gin.New()
	engine.Handle(method, "/api/devices/:id/vpn", handler)
	request := httptest.NewRequest(method, "/api/devices/"+deviceID+"/vpn", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	return recorder
}

func decodeBody[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return value
}

// assertErrorCode 断言 HTTP 状态与响应里的稳定错误码：错误码是 API 契约，
// 只看 4xx/5xx 会把「换了个错误码」漏掉。
func assertErrorCode(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("want status %d, got %d: %s", status, recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response %q: %v", recorder.Body.String(), err)
	}
	if body.Code != code {
		t.Fatalf("want error code %q, got %q: %s", code, body.Code, recorder.Body.String())
	}
}

func putVPN(t *testing.T, server *Server, deviceID, pubkey, role string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(deviceVPNRequest{Pubkey: pubkey, Role: role})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return callVPNHandler(t, server.handleAPIPutDeviceVPN, http.MethodPut, string(body), deviceID)
}

func TestPutVPNBindsAddressAndReturnsTemplate(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	pubkey := randomWGPublicKey(t)

	recorder := putVPN(t, server, "dev-1", pubkey, wgRoleClient)
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("want no-store, got %q", got)
	}
	response := decodeBody[vpnTemplateResponse](t, recorder)
	if response.WGIP != "10.77.0.2" {
		t.Fatalf("first device should get 10.77.0.2, got %q", response.WGIP)
	}
	if !strings.Contains(response.Template, "Address = 10.77.0.2/32") {
		t.Fatalf("template missing address:\n%s", response.Template)
	}
	if strings.Contains(response.Template, "PrivateKey") || strings.Contains(recorder.Body.String(), pubkey) {
		t.Fatal("response must not echo the key or mention a private key")
	}
	device := store.GetDeviceByID("dev-1")
	if device == nil || !device.WGEnabled || device.WGPublicKey != pubkey || device.WGRole != wgRoleClient {
		t.Fatalf("binding not stored: %+v", device)
	}
	if device.WGVersion != 1 {
		t.Fatalf("first binding should be version 1, got %d", device.WGVersion)
	}
}

func TestPutVPNSameKeyIsIdempotent(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	pubkey := randomWGPublicKey(t)

	firstRecorder := putVPN(t, server, "dev-1", pubkey, wgRoleClient)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("first PUT failed: %d %s", firstRecorder.Code, firstRecorder.Body.String())
	}
	secondRecorder := putVPN(t, server, "dev-1", pubkey, wgRoleClient)
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("second PUT failed: %d %s", secondRecorder.Code, secondRecorder.Body.String())
	}
	first := decodeBody[vpnTemplateResponse](t, firstRecorder)
	second := decodeBody[vpnTemplateResponse](t, secondRecorder)
	if first.WGIP != second.WGIP {
		t.Fatalf("re-binding the same key changed the address: %s -> %s", first.WGIP, second.WGIP)
	}
	if store.GetDeviceByID("dev-1").WGVersion != 2 {
		t.Fatal("a repeated PUT should still bump the version")
	}
}

func TestPutVPNRekeysWithoutChangingAddress(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")

	first := decodeBody[vpnTemplateResponse](t, putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient))
	second := decodeBody[vpnTemplateResponse](t, putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient))
	if first.WGIP != second.WGIP {
		t.Fatalf("re-key must keep the address: %s -> %s", first.WGIP, second.WGIP)
	}
	device := store.GetDeviceByID("dev-1")
	if device.WGPublicKey == "" || device.WGVersion != 2 {
		t.Fatalf("re-key not applied: %+v", device)
	}
}

func TestPutVPNRejectsPrivateKeyWithoutWriting(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")

	var privateKey string
	for attempt := 0; attempt < 100; attempt++ {
		key, err := newWGHubPrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		raw, _ := base64.StdEncoding.DecodeString(key)
		raw[0] &= 248
		raw[31] &= 127
		raw[31] |= 64
		privateKey = base64.StdEncoding.EncodeToString(raw)
		break
	}

	recorder := putVPN(t, server, "dev-1", privateKey, wgRoleClient)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", recorder.Code)
	}
	body := decodeBody[map[string]any](t, recorder)
	if body["code"] != "PUBKEY_LOOKS_LIKE_PRIVATE_KEY" {
		t.Fatalf("want PUBKEY_LOOKS_LIKE_PRIVATE_KEY, got %v", body["code"])
	}
	if strings.Contains(recorder.Body.String(), privateKey) {
		t.Fatal("the rejected value must not be echoed")
	}
	device := store.GetDeviceByID("dev-1")
	if device.WGPublicKey != "" || device.WGIP != "" {
		t.Fatalf("rejected key must not reach state: %+v", device)
	}
}

func TestPutVPNRejectsKeyBoundToAnotherDevice(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	addAuthorizedDevice(t, store, "dev-2")
	pubkey := randomWGPublicKey(t)

	if recorder := putVPN(t, server, "dev-1", pubkey, wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("first binding failed: %d %s", recorder.Code, recorder.Body.String())
	}
	bound := store.GetDeviceByID("dev-1")
	recorder := putVPN(t, server, "dev-2", pubkey, wgRoleClient)
	assertErrorCode(t, recorder, http.StatusConflict, "PUBKEY_IN_USE")
	rejected := store.GetDeviceByID("dev-2")
	if rejected == nil {
		t.Fatal("dev-2 must still exist")
	}
	if rejected.WGPublicKey != "" || rejected.WGIP != "" || rejected.WGEnabled || rejected.WGVersion != 0 {
		t.Fatalf("a rejected binding must not touch dev-2: %+v", rejected)
	}
	after := store.GetDeviceByID("dev-1")
	if after.WGPublicKey != bound.WGPublicKey || after.WGIP != bound.WGIP || after.WGVersion != bound.WGVersion {
		t.Fatalf("the accepted binding must stay intact: %+v -> %+v", bound, after)
	}
}

func TestPutVPNRoleIsLockedAfterBinding(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleEndpoint); recorder.Code != http.StatusOK {
		t.Fatalf("first binding failed: %d", recorder.Code)
	}
	before := store.GetDeviceByID("dev-1")
	recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient)
	assertErrorCode(t, recorder, http.StatusConflict, "ROLE_LOCKED")
	after := store.GetDeviceByID("dev-1")
	if after.WGPublicKey != before.WGPublicKey || after.WGRole != wgRoleEndpoint ||
		after.WGIP != before.WGIP || after.WGVersion != before.WGVersion {
		t.Fatalf("a rejected role change must not touch the binding: %+v -> %+v", before, after)
	}
}

func TestPutVPNNeedsAuthorizedDevice(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	store.AddDevice(&DeviceState{ID: "pending-1", Status: deviceStatusPending})
	recorder := putVPN(t, server, "pending-1", randomWGPublicKey(t), wgRoleClient)
	assertErrorCode(t, recorder, http.StatusConflict, "DEVICE_NOT_AUTHORIZED")
	device := store.GetDeviceByID("pending-1")
	if device == nil {
		t.Fatal("a pending device must still exist")
	}
	if device.WGPublicKey != "" || device.WGIP != "" || device.WGEnabled || device.WGVersion != 0 {
		t.Fatalf("a refused pending device must not be touched: %+v", device)
	}
}

func TestPutVPNUnknownDevice(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	recorder := putVPN(t, server, "missing", randomWGPublicKey(t), wgRoleClient)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "device not found") {
		t.Fatalf("unexpected 404 body: %s", recorder.Body.String())
	}
	if store.GetDeviceByID("missing") != nil {
		t.Fatal("the unknown device must not be created")
	}
}

func TestDeleteVPNRevokesThenClearsBinding(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d", recorder.Code)
	}

	recorder := callVPNHandler(t, server.handleAPIDeleteDeviceVPN, http.MethodDelete, "", "dev-1")
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", recorder.Code, recorder.Body.String())
	}
	device := store.GetDeviceByID("dev-1")
	if device == nil {
		t.Fatal("unbind must keep the device record")
	}
	if device.WGPublicKey != "" || device.WGIP != "" || device.WGEnabled {
		t.Fatalf("binding should be cleared: %+v", device)
	}

	again := callVPNHandler(t, server.handleAPIDeleteDeviceVPN, http.MethodDelete, "", "dev-1")
	if again.Code != http.StatusNotFound {
		t.Fatalf("second delete should be 404, got %d", again.Code)
	}
}

func TestDeleteVPNKeepsDisabledRecordWhenRevokeFails(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d", recorder.Code)
	}
	backend.fail("dev-1")

	recorder := callVPNHandler(t, server.handleAPIDeleteDeviceVPN, http.MethodDelete, "", "dev-1")
	// 这是「单设备被内核拒绝」，不是接口级故障：契约是 500 WG_PEER_ERROR，
	// 503 WG_INFRA 留给 Probe/Ensure/Apply 整体失败（见 TestPutVPNReturns503WhenInfraFails）。
	assertErrorCode(t, recorder, http.StatusInternalServerError, "WG_PEER_ERROR")
	device := store.GetDeviceByID("dev-1")
	if device == nil || device.WGPublicKey == "" {
		t.Fatalf("record must survive a failed revoke: %+v", device)
	}
	if device.WGEnabled {
		t.Fatal("the device must already be disabled in state")
	}
}

func TestDeleteVPNUnknownBinding(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	before := store.GetDeviceByID("dev-1")
	recorder := callVPNHandler(t, server.handleAPIDeleteDeviceVPN, http.MethodDelete, "", "dev-1")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "no wireguard binding") {
		t.Fatalf("unexpected 404 body: %s", recorder.Body.String())
	}
	after := store.GetDeviceByID("dev-1")
	if after == nil || after.WGPublicKey != "" || after.WGIP != "" || after.WGEnabled || after.WGVersion != 0 {
		t.Fatalf("unbinding a device without a binding must not touch it: %+v", before)
	}
}

func TestDeleteDeviceRevokesBeforeRemovingRecord(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d", recorder.Code)
	}
	backend.fail("dev-1")

	recorder := callVPNHandler(t, server.handleAPIDeleteDevice, http.MethodDelete, "", "dev-1")
	assertErrorCode(t, recorder, http.StatusInternalServerError, "WG_PEER_ERROR")
	device := store.GetDeviceByID("dev-1")
	if device == nil {
		t.Fatal("a failed revoke must keep the device record")
	}
	if device.WGEnabled {
		t.Fatal("state should already say disabled")
	}

	backend.heal()
	recorder = callVPNHandler(t, server.handleAPIDeleteDevice, http.MethodDelete, "", "dev-1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry should delete the device, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if store.GetDeviceByID("dev-1") != nil {
		t.Fatal("device should be gone after a successful delete")
	}
}

func TestDeleteDeviceWithoutBinding(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	recorder := callVPNHandler(t, server.handleAPIDeleteDevice, http.MethodDelete, "", "dev-1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if store.GetDeviceByID("dev-1") != nil {
		t.Fatal("device should be removed")
	}
}

func TestVPNStatusReportsPeersAndACL(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	pubkey := randomWGPublicKey(t)
	if recorder := putVPN(t, server, "dev-1", pubkey, wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d", recorder.Code)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	engine := gin.New()
	engine.GET("/api/vpn/status", server.handleAPIGetVPNStatus)
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", recorder.Code)
	}

	var status struct {
		Iface      string `json:"iface"`
		CIDR       string `json:"cidr"`
		Listen     int    `json:"listen"`
		ACLReady   bool   `json:"acl_ready"`
		ACLWarning string `json:"acl_warning"`
		InfraErr   string `json:"infra_error"`
		Peers      []struct {
			DeviceID          string `json:"device_id"`
			WGIP              string `json:"wg_ip"`
			Enabled           bool   `json:"enabled"`
			AppliedVersion    uint64 `json:"applied_version"`
			HandshakeAge      int64  `json:"handshake_age"`
			RXBytes           int64  `json:"rx_bytes"`
			TXBytes           int64  `json:"tx_bytes"`
			PubkeyFingerprint string `json:"pubkey_fingerprint"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !status.ACLReady {
		t.Fatal("acl_ready must be true after a successful reconcile with nft installed")
	}
	if status.ACLWarning != "" {
		t.Fatalf("no warning expected when the ACL is active, got %q", status.ACLWarning)
	}
	if status.Iface != wgInterfaceName || status.CIDR != defaultWGCIDR || status.Listen != defaultWGListen {
		t.Fatalf("unexpected status header: %+v", status)
	}
	if len(status.Peers) != 1 || status.Peers[0].WGIP != "10.77.0.2" || !status.Peers[0].Enabled {
		t.Fatalf("unexpected peers: %+v", status.Peers)
	}
	// 前端靠 rx/tx 判断链路是否真的在走数据；fake backend 为每个 peer 返回
	// 1234/5678，解析链路（dump 第 6/7 列 → plane → API）必须原样透出。
	if status.Peers[0].RXBytes != 1234 || status.Peers[0].TXBytes != 5678 {
		t.Fatalf("rx/tx = %d/%d, want 1234/5678", status.Peers[0].RXBytes, status.Peers[0].TXBytes)
	}
	if status.Peers[0].PubkeyFingerprint == "" || strings.Contains(status.Peers[0].PubkeyFingerprint, pubkey) {
		t.Fatal("status must carry a fingerprint, never the raw key")
	}
}

func TestReauthMiddleware(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	_ = store

	next := func(c *gin.Context) {
		// 凭据已经被搬到 context：请求头上必须一个都不剩。
		if c.GetHeader("X-Reauth-Password") != "" || c.GetHeader("X-Reauth-TOTP") != "" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	}
	run := func(headers map[string]string) *httptest.ResponseRecorder {
		gin.SetMode(gin.TestMode)
		recorder := httptest.NewRecorder()
		engine := gin.New()
		engine.Use(reauthHeaderMiddleware())
		engine.PUT("/api/devices/:id/vpn", server.reauthMiddleware(), next)
		request := httptest.NewRequest(http.MethodPut, "/api/devices/x/vpn", nil)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		engine.ServeHTTP(recorder, request)
		return recorder
	}

	if recorder := run(nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("missing password should be 403, got %d", recorder.Code)
	}
	if recorder := run(map[string]string{"X-Reauth-Password": "wrong"}); recorder.Code != http.StatusForbidden {
		t.Fatalf("wrong password should be 403, got %d", recorder.Code)
	}
	// TOTP 未启用：只校验密码。
	if recorder := run(map[string]string{"X-Reauth-Password": "TestPassword123!"}); recorder.Code != http.StatusNoContent {
		t.Fatalf("correct password should pass, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

// callHandler 用一条独立路由调用 handler（不经过 auth/reauth 链）。
func callHandler(t *testing.T, handler gin.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	engine := gin.New()
	engine.Handle(method, target, handler)
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	return recorder
}

func TestPutVPNRequiresStateEncryption(t *testing.T) {
	config, store := newTestConfig(t)
	server := &Server{config: config, stateStore: store}
	addAuthorizedDevice(t, store, "dev-1")

	recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("want 409 without state encryption, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != "STATE_ENCRYPTION_REQUIRED" {
		t.Fatalf("want STATE_ENCRYPTION_REQUIRED, got %q", body.Code)
	}
	if !strings.Contains(body.Error, "GOREMOTE_STATE_KEY") || !strings.Contains(body.Error, "restart") {
		t.Fatalf("the 409 must tell the operator how to fix it, got %q", body.Error)
	}
	if store.WGHubPrivateKey() != "" {
		t.Fatal("no hub key may be generated while state encryption is disabled")
	}
	device := store.GetDeviceByID("dev-1")
	if device.WGPublicKey != "" || device.WGIP != "" || device.WGEnabled {
		t.Fatalf("a rejected enable must not touch state: %+v", device)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if strings.Contains(string(raw), "wg_hub_privkey") {
		t.Fatal("the state file must not contain a wireguard hub private key field")
	}
}

func TestWGErrorStatusMapping(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name string
		err  error
		want int
		code string
	}{
		{"superseded is a conflict", ErrWGSuperseded, http.StatusConflict, "SUPERSEDED"},
		{"encryption is a conflict", ErrWGStateEncryptionRequired, http.StatusConflict, "STATE_ENCRYPTION_REQUIRED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			wgErrorStatus(context, tc.err)
			if recorder.Code != tc.want {
				t.Fatalf("want %d, got %d: %s", tc.want, recorder.Code, recorder.Body.String())
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Code != tc.code {
				t.Fatalf("want code %q, got %q", tc.code, body.Code)
			}
		})
	}
}

func TestPutVPNRejectsListenPortInsideTunnelRange(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	server.UpdateSettings(func(settings *ServerSettings) {
		settings.PortRangeEnd = 60000
	})

	recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("want 409 when the tunnel range covers wg_listen, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != "LISTEN_PORT_CONFLICT" {
		t.Fatalf("want LISTEN_PORT_CONFLICT, got %q", body.Code)
	}
	if device := store.GetDeviceByID("dev-1"); device.WGPublicKey != "" {
		t.Fatalf("the conflicting range must not bind anything: %+v", device)
	}

	server.UpdateSettings(func(settings *ServerSettings) {
		settings.PortRangeEnd = 20000
	})
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding should work once the range no longer covers 51820, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestSettingsRejectPortRangeContainingWGListen(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if err := store.SetWGHubPrivateKey("hub-key-for-settings-test"); err != nil {
		t.Fatalf("seed hub key: %v", err)
	}

	recorder := callHandler(t, server.handleAPIUpdateSettings, http.MethodPut, "/api/settings", `{"port_range_end":60000}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when the range would cover 51820, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "wireguard listen port") {
		t.Fatalf("the error should name the conflict, got %s", recorder.Body.String())
	}
	if got := store.GetSettings().PortRangeEnd; got != 20000 {
		t.Fatalf("the rejected update must not change the port range, got %d", got)
	}

	// 不覆盖 51820 的区间照常允许。
	recorder = callHandler(t, server.handleAPIUpdateSettings, http.MethodPut, "/api/settings", `{"port_range_start":10001,"port_range_end":20000}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("an unrelated range should be accepted, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteDeviceWaitsForPerDeviceLock(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")

	lock := server.wgLock("dev-1")
	lock.Lock()

	done := make(chan int, 1)
	go func() {
		done <- callVPNHandler(t, server.handleAPIDeleteDevice, http.MethodDelete, "", "dev-1").Code
	}()
	select {
	case code := <-done:
		lock.Unlock()
		t.Fatalf("device delete must wait for the same per-device lock as PUT/DELETE /vpn, got %d", code)
	case <-time.After(200 * time.Millisecond):
	}
	lock.Unlock()

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("delete should succeed after the lock is released, got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delete did not finish after the per-device lock was released")
	}
	if store.GetDeviceByID("dev-1") != nil {
		t.Fatal("device should be gone")
	}
}

func TestReauthHeadersNeverReachPanicDump(t *testing.T) {
	// 生产跑在 ReleaseMode（server.go 的 gin.SetMode(gin.ReleaseMode)）。
	// gin v1.12 在这条分支上**不** dump 请求：普通 panic 只有 DebugMode 才会
	// 走 secureRequestDump。真正会把请求头写进 stderr 的是 broken-pipe 分支
	// （客户端断开后 handler 继续写、net/http 抛 ErrAbortHandler，或 EPIPE/
	// ECONNRESET），它不看运行模式，一律请求转储，而只脱敏 Authorization。
	// 所以这里用 panic(http.ErrAbortHandler) 复现生产真实路径。
	previousMode := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	t.Cleanup(func() { gin.SetMode(previousMode) })

	var dump bytes.Buffer
	engine := gin.New()
	engine.Use(gin.RecoveryWithWriter(&dump)) // 与 gin.Recovery() 同一实现，只换 writer
	engine.Use(reauthHeaderMiddleware())
	engine.PUT("/panic", func(*gin.Context) { panic(http.ErrAbortHandler) })

	request := httptest.NewRequest(http.MethodPut, "/panic", nil)
	request.Header.Set("X-Reauth-Password", "SuperSecretPassword-42!")
	request.Header.Set("X-Reauth-TOTP", "TOTP-SECRET-42")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	text := dump.String()
	if text == "" {
		t.Fatal("the broken-pipe branch should have written a request dump")
	}
	// 先证明 dump 确实是请求转储：否则「没泄密」可能只是根本没 dump。
	if !strings.Contains(text, "PUT /panic") {
		t.Fatalf("expected a request dump with the request line, got:\n%s", text)
	}
	for _, secret := range []string{"SuperSecretPassword-42!", "TOTP-SECRET-42"} {
		if strings.Contains(text, secret) {
			t.Fatalf("panic dump leaked a reauth header value %q:\n%s", secret, text)
		}
	}
}

func TestVPNStatusReportsRefusedPlane(t *testing.T) {
	config, store := newTestConfig(t)
	backend := &testWGBackend{}
	plane := netplane.New(netplane.Config{Store: store, Backend: backend, Interval: time.Hour})
	plane.RefuseStart("STATE_ENCRYPTION_REQUIRED", stateEncryptionRequiredMessage)
	server := &Server{config: config, stateStore: store, netplane: plane}

	recorder := callHandler(t, server.handleAPIGetVPNStatus, http.MethodGet, "/api/vpn/status", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", recorder.Code)
	}
	var status struct {
		Blocked    string `json:"blocked"`
		InfraError string `json:"infra_error"`
		Encryption bool   `json:"state_encryption_enabled"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Blocked != "STATE_ENCRYPTION_REQUIRED" {
		t.Fatalf("want the banner code STATE_ENCRYPTION_REQUIRED, got %q", status.Blocked)
	}
	if !strings.Contains(status.InfraError, "state encryption is required") {
		t.Fatalf("infra_error should carry the detail, got %q", status.InfraError)
	}
	if status.Encryption {
		t.Fatal("state encryption should be reported as disabled")
	}

	stopped := make(chan struct{})
	go func() {
		plane.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() must not block on a plane that was refused before Start")
	}
}

func TestVPNEncryptionBlockedPredicate(t *testing.T) {
	_, store := newTestConfig(t)
	server := &Server{stateStore: store}
	if server.vpnEncryptionBlocked() {
		t.Fatal("an empty store must not be blocked")
	}

	addAuthorizedDevice(t, store, "dev-1")
	if err := store.SetWGHubPrivateKey("hub-key"); err != nil {
		t.Fatalf("seed hub key: %v", err)
	}
	if !server.vpnEncryptionBlocked() {
		t.Fatal("a configured VPN without state encryption must be blocked")
	}
	if err := store.SetEncryptionKey(strings.Repeat("k", 32)); err != nil {
		t.Fatalf("set state key: %v", err)
	}
	if server.vpnEncryptionBlocked() {
		t.Fatal("with state encryption enabled the VPN must be allowed to start")
	}
}

// 接口级失败（Probe/Ensure/Apply 整体失败）才是 503 WG_INFRA；
// 单设备被内核拒绝是 500 WG_PEER_ERROR，两者不能混。
func TestPutVPNReturns503WhenInfraFails(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	backend.failInfra(errors.New("wg set wg-grm: operation not permitted"))

	recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient)
	assertErrorCode(t, recorder, http.StatusServiceUnavailable, "WG_INFRA")
}

func callVPNHandlerAtHost(t *testing.T, handler gin.HandlerFunc, method, body, deviceID, host string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	engine := gin.New()
	engine.Handle(method, "/api/devices/:id/vpn", handler)
	request := httptest.NewRequest(method, "/api/devices/"+deviceID+"/vpn", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Host = host
	engine.ServeHTTP(recorder, request)
	return recorder
}

func putVPNAtHost(t *testing.T, server *Server, deviceID, pubkey, role, host string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(deviceVPNRequest{Pubkey: pubkey, Role: role})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return callVPNHandlerAtHost(t, server.handleAPIPutDeviceVPN, http.MethodPut, string(body), deviceID, host)
}

func TestEnsureCIDRFreeRejectsHostNetworkOverlap(t *testing.T) {
	original := hostPrefixes
	hostPrefixes = func() ([]netip.Prefix, error) {
		return []netip.Prefix{
			netip.MustParsePrefix("10.77.0.0/16"), // 模拟 ECS VPC
			netip.MustParsePrefix("192.168.1.0/24"),
		}, nil
	}
	t.Cleanup(func() { hostPrefixes = original })

	if err := ensureCIDRFree("10.77.0.0/24", ""); err == nil {
		t.Fatal("a cidr overlapping a host/VPC network must be rejected")
	} else if !strings.Contains(err.Error(), "10.77.0.0/16") {
		t.Fatalf("the error should name the conflicting network, got %v", err)
	}
	if err := ensureCIDRFree("10.88.0.0/24", ""); err != nil {
		t.Fatalf("a non-overlapping cidr must pass: %v", err)
	}
}

func TestPutVPNRejectsLoopbackEndpointWithoutPublicHost(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	pubkey := randomWGPublicKey(t)

	recorder := putVPNAtHost(t, server, "dev-1", pubkey, wgRoleClient, "127.0.0.1:8080")
	assertErrorCode(t, recorder, http.StatusBadRequest, "PUBLIC_HOST_REQUIRED")
	if device := store.GetDeviceByID("dev-1"); device.WGPublicKey != "" {
		t.Fatalf("a rejected endpoint must not bind anything: %+v", device)
	}

	// 请求 Host 是可用地址时允许绑定，但必须给出 endpoint_warning。
	recorder = putVPNAtHost(t, server, "dev-1", pubkey, wgRoleClient, "vpn.example.com:8080")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	response := decodeBody[vpnTemplateResponse](t, recorder)
	if response.Endpoint != "vpn.example.com:51820" {
		t.Fatalf("endpoint = %q, want vpn.example.com:51820", response.Endpoint)
	}
	if response.EndpointWarning == "" {
		t.Fatal("public_host is empty: the response must warn that the endpoint came from the request host")
	}

	// 配好 public_host 之后不再有 warning。
	server.UpdateSettings(func(settings *ServerSettings) { settings.PublicHost = "203.0.113.10" })
	recorder = putVPNAtHost(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient, "127.0.0.1:8080")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	response = decodeBody[vpnTemplateResponse](t, recorder)
	if response.Endpoint != "203.0.113.10:51820" || response.EndpointWarning != "" {
		t.Fatalf("unexpected endpoint after public_host was set: %+v", response)
	}
}

func TestGetDeviceVPNReturnsSameShapeAsPut(t *testing.T) {
	server, store, _ := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	put := decodeBody[vpnTemplateResponse](t, putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient))

	recorder := callVPNHandler(t, server.handleAPIGetDeviceVPN, http.MethodGet, "", "dev-1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	got := decodeBody[vpnTemplateResponse](t, recorder)
	if got.DeviceID != put.DeviceID || got.WGIP != put.WGIP || got.Role != put.Role {
		t.Fatalf("binding mismatch: put=%+v get=%+v", put, got)
	}
	if got.Endpoint != put.Endpoint || got.Template != put.Template {
		t.Fatalf("endpoint/template mismatch:\nput=%+v\nget=%+v", put, got)
	}
	if len(got.Notes) != len(put.Notes) || got.Applied != put.Applied || !got.ACLReady {
		t.Fatalf("metadata mismatch: put=%+v get=%+v", put, got)
	}

	// 没有绑定：404，且不能伪造一份空模板。
	addAuthorizedDevice(t, store, "dev-2")
	recorder = callVPNHandler(t, server.handleAPIGetDeviceVPN, http.MethodGet, "", "dev-2")
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "no wireguard binding") {
		t.Fatalf("unbound device: want 404 no binding, got %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = callVPNHandler(t, server.handleAPIGetDeviceVPN, http.MethodGet, "", "missing")
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "device not found") {
		t.Fatalf("unknown device: want 404, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestPostVPNReconcileReportsApplied(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder := callHandler(t, server.handleAPIPostVPNReconcile, http.MethodPost, "/api/vpn/reconcile", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Gen      uint64 `json:"gen"`
		Applied  uint64 `json:"applied"`
		ACLReady bool   `json:"acl_ready"`
		InfraErr string `json:"infra_error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode reconcile: %v", err)
	}
	if body.Gen == 0 || body.Applied != body.Gen || !body.ACLReady || body.InfraErr != "" {
		t.Fatalf("unexpected reconcile result: %+v", body)
	}

	// 接口级失败：手动 reconcile 同样 503，不能假装成功。
	backend.failInfra(errors.New("wg set: operation not permitted"))
	recorder = callHandler(t, server.handleAPIPostVPNReconcile, http.MethodPost, "/api/vpn/reconcile", "")
	assertErrorCode(t, recorder, http.StatusServiceUnavailable, "WG_INFRA")
}

func TestVPNStatusWarnsWhenACLFails(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	backend.failACL(errors.New("nft: operation not permitted"))
	addAuthorizedDevice(t, store, "dev-1")

	// ACL 装不上：写接口必须 503（接口会被 down），不能返回 200 让运维以为生效了。
	recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient)
	assertErrorCode(t, recorder, http.StatusServiceUnavailable, "WG_INFRA")

	gin.SetMode(gin.TestMode)
	statusRecorder := httptest.NewRecorder()
	engine := gin.New()
	engine.GET("/api/vpn/status", server.handleAPIGetVPNStatus)
	engine.ServeHTTP(statusRecorder, httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil))
	var status struct {
		ACLReady   bool   `json:"acl_ready"`
		ACLWarning string `json:"acl_warning"`
		InfraErr   string `json:"infra_error"`
	}
	if err := json.Unmarshal(statusRecorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.ACLReady {
		t.Fatal("acl_ready must be false when nft fails")
	}
	if !strings.Contains(status.ACLWarning, "ACL 未生效") || !strings.Contains(status.ACLWarning, "fail-closed") {
		t.Fatalf("acl_warning should explain the fail-closed state, got %q", status.ACLWarning)
	}
	if !strings.Contains(status.InfraErr, "install wireguard nft table") {
		t.Fatalf("infra_error should name the ACL failure, got %q", status.InfraErr)
	}
}

// GET /api/vpn/status 的 link_up 是独立只读探测：接口被外部 down 后必须报
// false（此时 acl_ready/infra_error 仍描述上一轮成功），探测本身失败只影响
// 这两个字段，整条响应仍是 200、别的内容照常。
func TestVPNStatusReportsLinkState(t *testing.T) {
	server, store, backend := newWGTestServer(t)
	addAuthorizedDevice(t, store, "dev-1")
	if recorder := putVPN(t, server, "dev-1", randomWGPublicKey(t), wgRoleClient); recorder.Code != http.StatusOK {
		t.Fatalf("binding failed: %d %s", recorder.Code, recorder.Body.String())
	}

	check := func(wantUp bool, wantDetail string) {
		t.Helper()
		recorder := callHandler(t, server.handleAPIGetVPNStatus, http.MethodGet, "/api/vpn/status", "")
		// 探测失败也必须是 200：link_up 只是观测，不能把状态接口变成 5xx。
		if recorder.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", recorder.Code, recorder.Body.String())
		}
		var body struct {
			LinkUp    bool   `json:"link_up"`
			LinkError string `json:"link_error"`
			ACLReady  bool   `json:"acl_ready"`
			InfraErr  string `json:"infra_error"`
			Peers     []struct {
				DeviceID string `json:"device_id"`
			} `json:"peers"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode status %q: %v", recorder.Body.String(), err)
		}
		if body.LinkUp != wantUp {
			t.Fatalf("link_up = %v, want %v (body %s)", body.LinkUp, wantUp, recorder.Body.String())
		}
		if wantDetail == "" {
			if body.LinkError != "" {
				t.Fatalf("link_error should be empty, got %q", body.LinkError)
			}
		} else if !strings.Contains(body.LinkError, wantDetail) {
			t.Fatalf("link_error = %q, want it to contain %q", body.LinkError, wantDetail)
		}
		// 探测不能改写写路径的状态：ACL 已就绪、设备仍在列表里。
		if !body.ACLReady || body.InfraErr != "" {
			t.Fatalf("probe must not change acl_ready/infra_error, got acl_ready=%v infra_error=%q", body.ACLReady, body.InfraErr)
		}
		if len(body.Peers) != 1 || body.Peers[0].DeviceID != "dev-1" {
			t.Fatalf("peers should survive the probe, got %+v", body.Peers)
		}
	}

	backend.setLink(true, nil)
	check(true, "")

	backend.setLink(false, nil)
	check(false, "")

	backend.setLink(false, errors.New(`ip -o link show dev wg-grm: exit status 1: Device "wg-grm" does not exist.`))
	check(false, "does not exist")
}
