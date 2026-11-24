package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newObserveTestServer 起一个只注册路由、不监听端口的服务端，用来直接打
// /health 与管理面接口。
func newObserveTestServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	config, _ := newTestConfig(t)
	srv := mustNewServer(t, config, embed.FS{})
	srv.engine = gin.New()
	srv.registerRoutes()
	// 注意：NewServer 会按同一路径再建一个 StateStore，所以测试必须用
	// srv.stateStore，不能拿 newTestConfig 返回的那个对象——两者内存不共享。
	return srv
}

func getHealth(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	srv.engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health returned %d, want 200 (degraded instances must stay 200)", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("health body is not JSON: %v", err)
	}
	return body
}

func TestHealthSummaryCountsTunnelsAndDevices(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	store := srv.stateStore
	tm := NewTunnelManager(srv, 24000, 24100)
	t.Cleanup(tm.CloseAll)
	srv.tunnelManager = tm

	tm.mu.Lock()
	tm.tunnels["tun-active"] = &Tunnel{TunnelID: "tun-active", ClientID: "dev-1", Status: TunnelStatusActive, stats: newTunnelStats()}
	tm.tunnels["tun-waiting"] = &Tunnel{TunnelID: "tun-waiting", ClientID: "dev-2", Status: TunnelStatusWaitingDevice, stats: newTunnelStats()}
	tm.tunnels["tun-failed"] = &Tunnel{TunnelID: "tun-failed", ClientID: "dev-2", Status: TunnelStatusPortConflict, stats: newTunnelStats()}
	tm.rebuildTunnelOwnerLocked()
	tm.mu.Unlock()

	store.AddDevice(&DeviceState{ID: "dev-1", Hostname: "host-1", Status: deviceStatusAuthorized})
	srv.clients.Add(&Client{ClientID: "dev-1"})

	body := getHealth(t, srv)
	if got := body["status"]; got != "degraded" {
		// 有一条 port_conflict，按契约就该是 degraded。
		t.Fatalf("status = %v, want degraded while a tunnel is failed", got)
	}
	if got := body["active_tunnels"]; got != float64(1) {
		t.Fatalf("active_tunnels = %v, want 1", got)
	}
	if got := body["waiting_device_tunnels"]; got != float64(1) {
		t.Fatalf("waiting_device_tunnels = %v, want 1", got)
	}
	if got := body["apply_failed_tunnels"]; got != float64(1) {
		t.Fatalf("apply_failed_tunnels = %v, want 1", got)
	}
	if got := body["online_devices"]; got != float64(1) {
		t.Fatalf("online_devices = %v, want 1", got)
	}
	// /health 免认证，不能暴露版本号（那是唯一能帮攻击者挑 CVE 的字段）。
	if _, leaked := body["version"]; leaked {
		t.Fatal("/health must not expose the build version on an unauthenticated endpoint")
	}
	lastPersist, _ := body["last_persist_ok"].(string)
	if _, err := time.Parse(time.RFC3339, lastPersist); err != nil {
		t.Fatalf("last_persist_ok %q is not RFC3339: %v", lastPersist, err)
	}

	// 故障隧道恢复后应回到 ok。
	tm.mu.Lock()
	tm.tunnels["tun-failed"].Status = TunnelStatusActive
	tm.mu.Unlock()
	if got := getHealth(t, srv)["status"]; got != "ok" {
		t.Fatalf("status = %v, want ok after the failed tunnel recovered", got)
	}
}

func TestHealthDegradedWhenAllDevicesOffline(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	store := srv.stateStore
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})

	if got := getHealth(t, srv)["status"]; got != "degraded" {
		t.Fatalf("status = %v, want degraded while every configured device is offline", got)
	}

	srv.clients.Add(&Client{ClientID: "dev-1"})
	if got := getHealth(t, srv)["status"]; got != "ok" {
		t.Fatalf("status = %v, want ok once the device is online", got)
	}
}

func TestHealthDegradedWhenPersistStalls(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	store := srv.stateStore

	// 造一个「有未落盘改动、且已经卡了 1 分钟」的状态。
	store.mu.Lock()
	store.dirty = true
	store.mu.Unlock()
	store.dirtySince.Store(time.Now().Add(-time.Minute).UnixNano())

	body := getHealth(t, srv)
	if got := body["status"]; got != "degraded" {
		t.Fatalf("status = %v, want degraded while changes stay unpersisted", got)
	}

	// 落盘恢复后立刻回到 ok。
	if err := store.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := getHealth(t, srv)["status"]; got != "ok" {
		t.Fatalf("status = %v, want ok after a successful save", got)
	}
}

func TestRecordDeviceDisconnectKeepsRecentHistory(t *testing.T) {
	t.Parallel()
	store := NewStateStore(t.TempDir() + "/server-state.json")
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})

	now := time.Now()
	for i := 0; i < deviceDisconnectHistoryLimit+5; i++ {
		store.RecordDeviceDisconnect("dev-1", disconnectReasonReadTimeout, now.Add(-time.Duration(i)*time.Minute))
	}

	device := store.GetDeviceByID("dev-1")
	if device == nil {
		t.Fatal("device disappeared")
	}
	if len(device.DisconnectHistory) != deviceDisconnectHistoryLimit {
		t.Fatalf("history length = %d, want %d", len(device.DisconnectHistory), deviceDisconnectHistoryLimit)
	}
	if device.LastDisconnectReason != disconnectReasonReadTimeout {
		t.Fatalf("last reason = %q", device.LastDisconnectReason)
	}
	if device.LastDisconnectAt == nil || device.LastSeen == nil {
		t.Fatal("last_disconnect_at / last_seen must be set")
	}
	if got := countDisconnectsWithin(device.DisconnectHistory, now, deviceDisconnectWindow); got != deviceDisconnectHistoryLimit {
		t.Fatalf("disconnects_24h = %d, want %d", got, deviceDisconnectHistoryLimit)
	}

	// 24 小时窗口外的记录不计数。
	store.RecordDeviceDisconnect("dev-1", disconnectReasonUnknown, now.Add(-48*time.Hour))
	device = store.GetDeviceByID("dev-1")
	if got := countDisconnectsWithin(device.DisconnectHistory, now, deviceDisconnectWindow); got != deviceDisconnectHistoryLimit-1 {
		t.Fatalf("disconnects_24h = %d, want %d after the oldest record aged out", got, deviceDisconnectHistoryLimit-1)
	}

	// 历史满了之后仍然只保留最近 50 条，最后一条是最后写入的那次。
	store.RecordDeviceDisconnect("dev-1", disconnectReasonHeartbeatTimeout, now)
	device = store.GetDeviceByID("dev-1")
	if len(device.DisconnectHistory) != deviceDisconnectHistoryLimit {
		t.Fatalf("history length = %d, want %d", len(device.DisconnectHistory), deviceDisconnectHistoryLimit)
	}
	if got := device.LastDisconnectReason; got != disconnectReasonHeartbeatTimeout {
		t.Fatalf("last reason = %q", got)
	}
}

func TestGracefulShutdownRecordsServerShutdown(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	store := srv.stateStore
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})
	srv.clients.Add(&Client{ClientID: "dev-1"})

	if err := srv.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	device := store.GetDeviceByID("dev-1")
	if device == nil {
		t.Fatal("device disappeared")
	}
	if device.LastDisconnectReason != disconnectReasonServerShutdown {
		t.Fatalf("last reason = %q, want %q", device.LastDisconnectReason, disconnectReasonServerShutdown)
	}
	if len(device.DisconnectHistory) != 1 {
		t.Fatalf("history = %+v, want exactly one server_shutdown record", device.DisconnectHistory)
	}

	// 必须真的落盘：重开一个 store 读文件，仍然能看到这次关闭。
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if !strings.Contains(string(raw), disconnectReasonServerShutdown) {
		t.Fatal("server_shutdown record was not persisted; a restart would look like a crash")
	}
}

func TestTunnelLastDisconnectPersists(t *testing.T) {
	t.Parallel()
	store := NewStateStore(t.TempDir() + "/server-state.json")
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	clients := NewClientManager()
	tm := newTunnelTestManager(t, store, clients, 24000, 24100)

	client := &Client{ClientID: "dev-1"}
	clients.Add(client)
	if err := tm.CreateTunnel("tun-1", "dev-1", client, "tcp", "127.0.0.1", 22, 24001, TunnelExposurePublic); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	// 第二条从来没绑定到设备上（waiting_device）：它的时间戳不能被这次掉线覆盖。
	if err := tm.CreateTunnel("tun-2", "dev-1", nil, "tcp", "127.0.0.1", 22, 24002, TunnelExposurePublic); err != nil {
		t.Fatalf("create unbound tunnel: %v", err)
	}

	tm.DetachClient("dev-1", client)

	definitions := store.GetTunnels()
	if len(definitions) != 2 {
		t.Fatalf("definitions = %+v", definitions)
	}
	byID := map[string]TunnelState{}
	for _, def := range definitions {
		byID[def.TunnelID] = def
	}
	if byID["tun-1"].LastDisconnectAt == nil {
		t.Fatal("bound tunnel lost its last_disconnect_at")
	}
	if byID["tun-2"].LastDisconnectAt != nil {
		t.Fatal("a tunnel that was never bound must not get a last_disconnect_at")
	}
}

func TestDevicesAPIReturnsDisconnectFields(t *testing.T) {
	srv := newObserveTestServer(t)
	store := srv.stateStore
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})
	when := time.Now().Add(-time.Minute)
	store.UpdateDevice("dev-1", func(d *DeviceState) {
		d.LastSeen = &when
		d.LastDisconnectAt = &when
		d.LastDisconnectReason = disconnectReasonHeartbeatTimeout
		d.DisconnectHistory = []DeviceDisconnect{
			{At: when, Reason: disconnectReasonHeartbeatTimeout},
			{At: when.Add(-time.Second), Reason: disconnectReasonServerShutdown},
			{At: when.Add(-25 * time.Hour), Reason: disconnectReasonReadTimeout},
		}
	})

	token, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
	srv.engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("devices API returned %d: %s", recorder.Code, recorder.Body.String())
	}

	var body struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse devices: %v", err)
	}
	if len(body.Devices) != 1 {
		t.Fatalf("devices = %d", len(body.Devices))
	}
	device := body.Devices[0]
	if got := device["disconnects_24h"]; got != float64(1) {
		t.Fatalf("disconnects_24h = %v, want 1 (the 25h-old record must not count)", got)
	}
	if got := device["last_disconnect_reason"]; got != disconnectReasonHeartbeatTimeout {
		t.Fatalf("last_disconnect_reason = %v", got)
	}
	for _, field := range []string{"last_seen", "last_disconnect_at"} {
		value, _ := device[field].(string)
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Fatalf("%s = %q, want RFC3339", field, value)
		}
	}
}

// captureAudit 把全局 slog 输出临时重定向到缓冲区（测试串行执行，恢复靠 defer）。
func captureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buffer
}

// auditLines 返回缓冲里所有 audit=true 的 JSON 行。
func auditLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(buffer.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["audit"] == true {
			entries = append(entries, entry)
		}
	}
	return entries
}

func TestAuditRecordsLoginFailureWithoutSecrets(t *testing.T) {
	srv := newObserveTestServer(t)
	buffer := captureAudit(t)

	const password = "definitely-the-wrong-password"
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"`+password+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	srv.engine.ServeHTTP(recorder, request)

	entries := auditLines(t, buffer)
	if len(entries) == 0 {
		t.Fatal("no audit line was written for a failed login")
	}
	entry := entries[0]
	if entry["event"] != auditEventAdminLoginFailed {
		t.Fatalf("event = %v, want %v", entry["event"], auditEventAdminLoginFailed)
	}
	if entry["result"] != "denied" || entry["reason"] != "bad_password" {
		t.Fatalf("result/reason = %v/%v", entry["result"], entry["reason"])
	}
	if entry["ip"] == "" || entry["ip"] == nil {
		t.Fatal("audit entry must carry the source IP")
	}
	if strings.Contains(buffer.String(), password) {
		t.Fatal("audit log leaked the submitted password")
	}
}

func TestAuditRecordsTunnelDeleteWithSourceIP(t *testing.T) {
	srv := newObserveTestServer(t)
	clients := NewClientManager()
	srv.clients = clients
	tm := NewTunnelManager(srv, 24000, 24100)
	t.Cleanup(tm.CloseAll)
	srv.tunnelManager = tm
	if err := tm.CreateTunnel("tun-audit", "dev-1", nil, "tcp", "127.0.0.1", 22, 24001, TunnelExposurePublic); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	token, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	buffer := captureAudit(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/tunnels/tun-audit", nil)
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
	srv.engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete tunnel returned %d: %s", recorder.Code, recorder.Body.String())
	}

	entries := auditLines(t, buffer)
	if len(entries) == 0 {
		t.Fatal("tunnel delete produced no audit line")
	}
	entry := entries[0]
	if entry["event"] != auditEventTunnelDelete {
		t.Fatalf("event = %v, want %v", entry["event"], auditEventTunnelDelete)
	}
	if entry["object"] != "tunnel:tun-audit" || entry["result"] != "ok" {
		t.Fatalf("object/result = %v/%v", entry["object"], entry["result"])
	}
	if entry["ip"] == nil || entry["ip"] == "" {
		t.Fatal("tunnel delete audit must carry the source IP")
	}
	if entry["session"] == nil || entry["session"] == "" {
		t.Fatal("tunnel delete audit should carry the session fingerprint")
	}
	if strings.Contains(buffer.String(), token) {
		t.Fatal("audit log leaked the session token")
	}
	if len(fmtAuditFingerprint(t, entry["session"].(string))) == 0 {
		t.Fatal("session fingerprint must be 8 hex characters")
	}
}

// fmtAuditFingerprint 校验会话指纹是 8 位十六进制。
func fmtAuditFingerprint(t *testing.T, fingerprint string) string {
	t.Helper()
	if len(fingerprint) != 8 {
		t.Fatalf("session fingerprint %q should be 8 hex chars", fingerprint)
	}
	for _, r := range fingerprint {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("session fingerprint %q is not lowercase hex", fingerprint)
		}
	}
	return fingerprint
}

func TestShutdownDisconnectIsRecordedOnce(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	store := srv.stateStore
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})

	// 模拟 Stop 已经记过 server_shutdown 的那条连接。
	client := &Client{ClientID: "dev-1"}
	client.markDisconnectReason(disconnectReasonServerShutdown)
	client.markShutdownRecorded()

	reason := srv.recordDisconnect(client, nil)
	if reason != disconnectReasonServerShutdown {
		t.Fatalf("reason = %q, want %q", reason, disconnectReasonServerShutdown)
	}
	if device := store.GetDeviceByID("dev-1"); len(device.DisconnectHistory) != 0 {
		t.Fatalf("readLoop recorded a second entry after Stop already did: %+v", device.DisconnectHistory)
	}

	// 没打过标的普通断线仍要记。
	normal := &Client{ClientID: "dev-1"}
	srv.recordDisconnect(normal, nil)
	if device := store.GetDeviceByID("dev-1"); len(device.DisconnectHistory) != 1 {
		t.Fatalf("ordinary disconnect was not recorded: %+v", device.DisconnectHistory)
	}
}

func TestHealthIgnoresPendingDevicesForOfflineCheck(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	// 只有待审批设备：还没接入，不该把新实例判成 degraded。
	srv.stateStore.AddDevice(&DeviceState{ID: "dev-pending", Status: deviceStatusPending})

	if got := getHealth(t, srv)["status"]; got != "ok" {
		t.Fatalf("status = %v, want ok: pending devices are not configured devices yet", got)
	}
}

func TestAuditTruncatesLongClientIDs(t *testing.T) {
	buffer := captureAudit(t)

	longID := strings.Repeat("x", 2000)
	auditAgent(longID, "203.0.113.5", auditEventDeviceReauthReject, "device:"+longID, "reauth", "denied", "not_authorized")

	entries := auditLines(t, buffer)
	if len(entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(entries))
	}
	actor, _ := entries[0]["actor"].(string)
	if !strings.Contains(actor, "…") || len(actor) > 256 {
		t.Fatalf("actor was not truncated: len=%d", len(actor))
	}
}

func TestDisconnects24hExcludesServerShutdown(t *testing.T) {
	t.Parallel()
	store := NewStateStore(t.TempDir() + "/server-state.json")
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})

	now := time.Now()
	store.RecordDeviceDisconnect("dev-1", disconnectReasonReadTimeout, now.Add(-time.Minute))
	store.RecordDeviceDisconnect("dev-1", disconnectReasonHeartbeatTimeout, now.Add(-2*time.Minute))
	store.RecordDeviceDisconnect("dev-1", disconnectReasonServerShutdown, now)

	device := store.GetDeviceByID("dev-1")
	if len(device.DisconnectHistory) != 3 {
		t.Fatalf("server_shutdown must still be kept in history, got %+v", device.DisconnectHistory)
	}
	if got := countDisconnectsWithin(device.DisconnectHistory, now, deviceDisconnectWindow); got != 2 {
		t.Fatalf("disconnects_24h = %d, want 2: deploy restarts must not count as disconnects", got)
	}
	if device.LastDisconnectReason != disconnectReasonServerShutdown {
		t.Fatalf("last_disconnect_reason = %q, want server_shutdown", device.LastDisconnectReason)
	}
}

// TestTouchDeviceSeenThrottlesPersistence 钉住「last_seen 不按心跳频率落盘」：
// 内存里每次都更新，但一分钟内的重复心跳不再标脏。设备一多，逐心跳落盘会把
// 同步循环顶到 3 秒一次的上限。
func TestTouchDeviceSeenThrottlesPersistence(t *testing.T) {
	t.Parallel()
	store := NewStateStore(t.TempDir() + "/server-state.json")
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	store.AddDevice(&DeviceState{ID: "dev-1", Status: deviceStatusAuthorized})

	start := time.Now()
	store.TouchDeviceSeen("dev-1", start)
	if !store.dirty {
		t.Fatal("first last_seen update should mark the state dirty")
	}
	if err := store.flushDirty(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// 30 秒后再来一次心跳：内存更新，但不标脏。
	store.TouchDeviceSeen("dev-1", start.Add(30*time.Second))
	if store.dirty {
		t.Fatal("a heartbeat inside the persistence interval must not mark the state dirty")
	}
	device := store.GetDeviceByID("dev-1")
	if device.LastSeen == nil || !device.LastSeen.Equal(start.Add(30*time.Second)) {
		t.Fatal("in-memory last_seen must be updated even when persistence is throttled")
	}

	// 超过一分钟再更新，重新标脏。
	store.TouchDeviceSeen("dev-1", start.Add(61*time.Second))
	if !store.dirty {
		t.Fatal("a heartbeat past the persistence interval should mark the state dirty again")
	}
}

// TestDetachClientDoesNotPersistSynchronously 钉住断线热路径不做全量落盘：
// 它持着 tm.mu，同步 fsync 会把所有隧道操作一起卡住。
func TestDetachClientDoesNotPersistSynchronously(t *testing.T) {
	t.Parallel()
	store := NewStateStore(t.TempDir() + "/server-state.json")
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	clients := NewClientManager()
	tm := newTunnelTestManager(t, store, clients, 24000, 24100)

	client := &Client{ClientID: "dev-1"}
	clients.Add(client)
	if err := tm.CreateTunnel("tun-1", "dev-1", client, "tcp", "127.0.0.1", 22, 24001, TunnelExposurePublic); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}

	tm.DetachClient("dev-1", client)

	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("DetachClient wrote the state file synchronously; it must only mark dirty and let the sync loop persist")
	}
	if err := store.flushDirty(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	persisted, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if bytes.Equal(before, persisted) {
		t.Fatal("the disconnect timestamp was never persisted by the sync loop")
	}
}

func TestAuditRecordsPasswordChangeFailure(t *testing.T) {
	srv := newObserveTestServer(t)
	token, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	buffer := captureAudit(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/admin/password",
		strings.NewReader(`{"current_password":"wrong-one","new_password":"Another-Passw0rd-2026"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
	srv.engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("password change returned %d, want 401", recorder.Code)
	}

	entries := auditLines(t, buffer)
	if len(entries) == 0 {
		t.Fatal("password change failure produced no audit line")
	}
	entry := entries[0]
	if entry["event"] != auditEventAdminPasswordChange || entry["result"] != "failed" || entry["reason"] != "bad_password" {
		t.Fatalf("audit entry = %v", entry)
	}
	if strings.Contains(buffer.String(), "wrong-one") || strings.Contains(buffer.String(), "Another-Passw0rd-2026") {
		t.Fatal("audit log leaked a password")
	}
}
