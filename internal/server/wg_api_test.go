package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	downs     int
}

func (b *testWGBackend) Probe(context.Context) error                { return nil }
func (b *testWGBackend) Ensure(context.Context, netplane.Hub) error { return nil }

func (b *testWGBackend) Apply(_ context.Context, peers []netplane.Peer) (map[string]error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.infraErr != nil {
		return nil, b.infraErr
	}
	errs := make(map[string]error)
	for id, err := range b.failPeers {
		errs[id] = err
	}
	return errs, nil
}

func (b *testWGBackend) Handshakes(context.Context) (map[string]int64, error) {
	return map[string]int64{}, nil
}

func (b *testWGBackend) Down(context.Context) error {
	b.mu.Lock()
	b.downs++
	b.mu.Unlock()
	return nil
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
		Iface    string `json:"iface"`
		CIDR     string `json:"cidr"`
		Listen   int    `json:"listen"`
		ACLReady bool   `json:"acl_ready"`
		InfraErr string `json:"infra_error"`
		Peers    []struct {
			DeviceID          string `json:"device_id"`
			WGIP              string `json:"wg_ip"`
			Enabled           bool   `json:"enabled"`
			AppliedVersion    uint64 `json:"applied_version"`
			PubkeyFingerprint string `json:"pubkey_fingerprint"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.ACLReady {
		t.Fatal("acl_ready must be false until the nft batch lands")
	}
	if status.Iface != wgInterfaceName || status.CIDR != defaultWGCIDR || status.Listen != defaultWGListen {
		t.Fatalf("unexpected status header: %+v", status)
	}
	if len(status.Peers) != 1 || status.Peers[0].WGIP != "10.77.0.2" || !status.Peers[0].Enabled {
		t.Fatalf("unexpected peers: %+v", status.Peers)
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
