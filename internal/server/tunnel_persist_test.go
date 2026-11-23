package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

const (
	testTunnelPortStart = 23000
	testTunnelPortEnd   = 23250
)

// newTunnelTestManager 构造带 stateStore/clients 的管理器，并保证测试结束
// 关掉所有 listener。
func newTunnelTestManager(t *testing.T, store *StateStore, clients *ClientManager, start, end int) *TunnelManager {
	t.Helper()
	srv := &Server{stateStore: store, clients: clients}
	if clients == nil {
		srv.clients = NewClientManager()
	}
	tm := NewTunnelManager(srv, start, end)
	srv.tunnelManager = tm
	t.Cleanup(tm.CloseAll)
	return tm
}

// freeTunnelPort 返回一个当前空闲的端口，用于“端口被占用”类用例。
func freeTunnelPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newTestWebsocketPair 返回一对（服务端, 客户端）websocket 连接：服务端给
// Client.WriteJSON 用，客户端用来读 register_ok / tunnel_open 的顺序。
func newTestWebsocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverConns := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConns <- conn
	}))
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		httpServer.Close()
		t.Fatalf("dial test websocket: %v", err)
	}
	serverConn := <-serverConns
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
		httpServer.Close()
	})
	return serverConn, clientConn
}

func readAgentMessage(t *testing.T, conn *websocket.Conn, wantType string, timeout time.Duration) common.Message {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	var msg common.Message
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read message (want %s): %v", wantType, err)
	}
	if wantType != "" && msg.Type != wantType {
		t.Fatalf("message type = %q, want %q", msg.Type, wantType)
	}
	return msg
}

func expectNoAgentMessage(t *testing.T, conn *websocket.Conn, wait time.Duration) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(wait))
	var msg common.Message
	err := conn.ReadJSON(&msg)
	if err == nil {
		t.Fatalf("unexpected message %q", msg.Type)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout, got %v", err)
	}
}

func callTunnelHandler(t *testing.T, handler gin.HandlerFunc, method, pattern, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	engine := gin.New()
	engine.Handle(method, pattern, handler)
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	return recorder
}

func loadTunnelDefinitions(t *testing.T, store *StateStore, clients *ClientManager) *TunnelManager {
	t.Helper()
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	tm.LoadDefinitions(store.GetTunnels())
	return tm
}

// 判据 1/2/3：定义重启后仍在且 waiting_device、无监听；设备重连后原端口
// active；离线期间新创建拿不到被保留的端口。
func TestTunnelDefinitionsRestoredAfterRestart(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	ports := []int{testTunnelPortStart, testTunnelPortStart + 1, testTunnelPortStart + 2}
	for index, port := range ports {
		id := fmt.Sprintf("tunnel-%d", index)
		if err := tm.CreateTunnel(id, "dev-1", nil, "tcp", "127.0.0.1", 22, port, TunnelExposurePublic); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	// “重启”：用同一个 state 重新加载。
	restarted := loadTunnelDefinitions(t, store, clients)
	tunnels := restarted.ListTunnels()
	if len(tunnels) != 3 {
		t.Fatalf("loaded %d definitions, want 3", len(tunnels))
	}
	for _, tunnel := range tunnels {
		if tunnel.Status != TunnelStatusWaitingDevice {
			t.Fatalf("%s status = %q, want %q", tunnel.TunnelID, tunnel.Status, TunnelStatusWaitingDevice)
		}
		if tunnel.Client != nil {
			t.Fatalf("%s must not be bound before the device connects", tunnel.TunnelID)
		}
	}
	if got := len(restarted.listeners); got != 0 {
		t.Fatalf("no listener should exist before the device connects, got %d", got)
	}
	// 端口确实没有被 bind（而不是只藏了 map 条目）。
	for _, port := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatalf("port %d must be free before the device connects: %v", port, err)
		}
		ln.Close()
	}

	// 判据 3：离线定义占着端口，新分配必须跳过它们。
	nextPort, nextLn, err := restarted.AllocatePortForExposure(TunnelExposurePublic)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	nextLn.Close()
	if nextPort != testTunnelPortStart+3 {
		t.Fatalf("allocated port %d, want %d (reserved ports must be skipped)", nextPort, testTunnelPortStart+3)
	}
	restarted.ReleasePort(nextPort)

	// 判据 2：设备重连后按原端口恢复。
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	restarted.RestoreClient(client)

	for _, port := range ports {
		boundID := ""
		found := false
		for id, tunnel := range restarted.tunnels {
			if tunnel.PublicPort == port {
				boundID = id
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("definition for port %d disappeared", port)
		}
		tunnel, _ := restarted.GetTunnel(boundID)
		if tunnel.Status != TunnelStatusActive {
			t.Fatalf("%s status = %q, want active", boundID, tunnel.Status)
		}
		if _, ok := restarted.listeners[port]; !ok {
			t.Fatalf("port %d should be listening after the device reconnected", port)
		}
	}
	// 三条定义各发一次 tunnel_open，且没有重复。
	seen := make(map[string]bool)
	for i := 0; i < len(ports); i++ {
		msg := readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)
		var payload common.TunnelOpenPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			t.Fatalf("decode tunnel_open: %v", err)
		}
		if seen[payload.TunnelID] {
			t.Fatalf("duplicate tunnel_open for %s", payload.TunnelID)
		}
		seen[payload.TunnelID] = true
	}
	for index := range ports {
		if !seen[fmt.Sprintf("tunnel-%d", index)] {
			t.Fatalf("missing tunnel_open for tunnel-%d", index)
		}
	}
	expectNoAgentMessage(t, agentConn, 150*time.Millisecond)
}

// 判据 4：离线删除后重启不复活、不监听、端口释放。
func TestDeletedOfflineTunnelDoesNotComeBack(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.DeleteTunnel("tunnel-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	restarted := loadTunnelDefinitions(t, store, clients)
	if got := len(restarted.ListTunnels()); got != 0 {
		t.Fatalf("deleted definition came back after restart: %d", got)
	}
	if _, ok := restarted.publicPorts[testTunnelPortStart]; ok {
		t.Fatal("the deleted tunnel must release its public port")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", testTunnelPortStart))
	if err != nil {
		t.Fatalf("the deleted tunnel must not hold a listener: %v", err)
	}
	ln.Close()
}

// 判据 5：端口被占时不换端口、标 port_conflict，其余定义照常 active；
// 释放后自动退避或 POST /retry 都能恢复。
func TestPortConflictKeepsPortAndRetryRecovers(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	blockedPort := testTunnelPortStart + 20
	// 在定义使用的端口上占住监听，模拟端口被别的进程占用。
	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", blockedPort))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("conflicted", "dev-1", nil, "tcp", "127.0.0.1", 22, blockedPort, "public"); err != nil {
		blocker.Close()
		t.Fatalf("create: %v", err)
	}
	if err := tm.CreateTunnel("healthy", "dev-1", nil, "tcp", "127.0.0.1", 23, testTunnelPortStart+10, "public"); err != nil {
		blocker.Close()
		t.Fatalf("create: %v", err)
	}

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	tm.RestoreClient(client)

	conflicted, _ := tm.GetTunnel("conflicted")
	if conflicted.Status != TunnelStatusPortConflict {
		t.Fatalf("conflicted status = %q, want %q", conflicted.Status, TunnelStatusPortConflict)
	}
	if conflicted.PublicPort != blockedPort {
		t.Fatalf("the port must not be changed, got %d want %d", conflicted.PublicPort, blockedPort)
	}
	if conflicted.LastError == "" {
		t.Fatal("port_conflict should carry last_error")
	}
	healthy, _ := tm.GetTunnel("healthy")
	if healthy.Status != TunnelStatusActive {
		t.Fatalf("healthy status = %q, want active", healthy.Status)
	}
	if _, ok := tm.listeners[blockedPort]; ok {
		t.Fatal("a conflicted port must not have a listener")
	}

	// 释放端口后自动退避（1s）应该把它拉回 active。
	blocker.Close()
	waitForCondition(t, 4*time.Second, func() bool {
		tunnel, ok := tm.GetTunnel("conflicted")
		return ok && tunnel.Status == TunnelStatusActive
	}, "the auto retry should recover the tunnel once the port is free")
	if _, ok := tm.listeners[blockedPort]; !ok {
		t.Fatal("the recovered tunnel should be listening on its original port")
	}

	// 重试接口：active 时幂等；设备离线 409。
	recorder := callTunnelHandler(t, tm.server.handleAPIRetryTunnel, http.MethodPost, "/api/tunnels/:tunnel_id/retry", "/api/tunnels/conflicted/retry", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry an active tunnel: status %d body %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := tm.tunnels["missing"]; ok {
		t.Fatal("sanity: missing tunnel should not exist")
	}
	recorder = callTunnelHandler(t, tm.server.handleAPIRetryTunnel, http.MethodPost, "/api/tunnels/:tunnel_id/retry", "/api/tunnels/missing/retry", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("retry a missing tunnel: status %d, want 404", recorder.Code)
	}
	// 设备离线：把当前连接摘掉。
	clients.Remove("dev-1")
	recorder = callTunnelHandler(t, tm.server.handleAPIRetryTunnel, http.MethodPost, "/api/tunnels/:tunnel_id/retry", "/api/tunnels/conflicted/retry", "")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("retry while offline: status %d body %s, want 409", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body.Code != "DEVICE_OFFLINE" {
		t.Fatalf("offline retry code = %q, want DEVICE_OFFLINE", body.Code)
	}
	_ = agentConn
}

// 判据 6：删设备同时删定义，重启后不复活、无监听。
func TestDeleteDeviceRemovesTunnelDefinitions(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(store, cryptoMgr)
	pub, _, _ := common.GenerateSignKeypair()
	_, dhPub, _ := common.GenerateDHKeypair()
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "host", "linux", "10.0.0.9")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: deviceID, Conn: serverConn}
	clients.Add(client)

	srv := &Server{
		config:     config,
		stateStore: store,
		clients:    clients,
		deviceMgr:  dm,
	}
	srv.tunnelManager = newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := srv.tunnelManager.CreateTunnel("tunnel-1", deviceID, client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := srv.tunnelManager.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	readAgentMessage(t, agentConn, "tunnel_open", time.Second)

	recorder := callTunnelHandler(t, srv.handleAPIDeleteDevice, http.MethodDelete, "/api/devices/:id", "/api/devices/"+deviceID, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete device: status %d body %s", recorder.Code, recorder.Body.String())
	}
	if store.GetDeviceByID(deviceID) != nil {
		t.Fatal("the device should be deleted")
	}
	if got := len(srv.tunnelManager.ListTunnels()); got != 0 {
		t.Fatalf("definitions left after device deletion: %d", got)
	}
	if _, ok := srv.tunnelManager.publicPorts[testTunnelPortStart]; ok {
		t.Fatal("the deleted definitions must release their ports")
	}
	if _, ok := srv.tunnelManager.listeners[testTunnelPortStart]; ok {
		t.Fatal("the deleted definitions must close their listeners")
	}
	listRecorder := callTunnelHandler(t, srv.handleAPIListTunnels, http.MethodGet, "/api/tunnels", "/api/tunnels", "")
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list tunnels: status %d", listRecorder.Code)
	}
	var listed struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listed.Total != 0 {
		t.Fatalf("GET /api/tunnels still lists %d definitions after device deletion", listed.Total)
	}

	// 重新加载 state：设备与定义都不应复活。
	reloaded := NewStateStore(store.path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if got := reloaded.GetDeviceByID(deviceID); got != nil {
		t.Fatal("the deleted device came back after restart")
	}
	if got := len(reloaded.GetTunnels()); got != 0 {
		t.Fatalf("definitions came back after restart: %d", got)
	}
}

// 判据 7：同一设备连续断连 5 次，每次只有一个监听、每次重连只发一次
// tunnel_open。
func TestReconnectKeepsSingleListenerAndNoDuplicateOpen(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	for cycle := 0; cycle < 5; cycle++ {
		tm.RestoreClient(client)
		if got := len(tm.listeners); got != 1 {
			t.Fatalf("cycle %d: %d listeners, want 1", cycle, got)
		}
		tunnel, _ := tm.GetTunnel("tunnel-1")
		if tunnel.Status != TunnelStatusActive {
			t.Fatalf("cycle %d: status = %q, want active", cycle, tunnel.Status)
		}
		readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)
		tm.DetachClient("dev-1", client)
		if got := len(tm.listeners); got != 0 {
			t.Fatalf("cycle %d: listener must be closed on detach, got %d", cycle, got)
		}
	}
	// 5 次重连 = 5 条 tunnel_open，没有重复。
	expectNoAgentMessage(t, agentConn, 200*time.Millisecond)
}

// 判据 8：两台设备同时重连，各自端口正确、没有串号。
func TestTwoDevicesRestoreConcurrently(t *testing.T) {
	_, store := newTestConfig(t)
	for _, id := range []string{"dev-1", "dev-2"} {
		store.AddDevice(&DeviceState{ID: id, Name: id, Status: deviceStatusAuthorized})
	}
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	defs := map[string]int{
		"dev-1": testTunnelPortStart,
		"dev-2": testTunnelPortStart + 1,
	}
	for deviceID, port := range defs {
		if err := tm.CreateTunnel("tunnel-"+deviceID, deviceID, nil, "tcp", "127.0.0.1", 22, port, "public"); err != nil {
			t.Fatalf("create %s: %v", deviceID, err)
		}
	}

	conns := make(map[string]*websocket.Conn, 2)
	for _, deviceID := range []string{"dev-1", "dev-2"} {
		serverConn, agentConn := newTestWebsocketPair(t)
		clients.Add(&Client{ClientID: deviceID, Conn: serverConn})
		conns[deviceID] = agentConn
	}

	var wg sync.WaitGroup
	for _, deviceID := range []string{"dev-1", "dev-2"} {
		wg.Add(1)
		go func(deviceID string) {
			defer wg.Done()
			client, _ := clients.Get(deviceID)
			tm.RestoreClient(client)
		}(deviceID)
	}
	wg.Wait()

	for deviceID, port := range defs {
		tunnel, _ := tm.GetTunnel("tunnel-" + deviceID)
		if tunnel.Status != TunnelStatusActive {
			t.Fatalf("%s status = %q, want active", deviceID, tunnel.Status)
		}
		if tunnel.PublicPort != port {
			t.Fatalf("%s port = %d, want %d", deviceID, tunnel.PublicPort, port)
		}
		msg := readAgentMessage(t, conns[deviceID], "tunnel_open", 2*time.Second)
		var payload common.TunnelOpenPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			t.Fatalf("decode tunnel_open for %s: %v", deviceID, err)
		}
		if payload.TunnelID != "tunnel-"+deviceID {
			t.Fatalf("%s received %s, want tunnel-%s", deviceID, payload.TunnelID, deviceID)
		}
	}
}

// 判据 9：state 写失败时创建返回 5xx、内存回滚、端口释放；恢复后可重建。
func TestCreateTunnelFailsWhenStateCannotBePersisted(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, _ := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	srv := &Server{config: config, stateStore: store, clients: clients, tunnelManager: tm}

	// 把数据目录换成一个普通文件：下一次 Save 必然失败。
	dataDir := filepath.Dir(store.path)
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("remove data dir: %v", err)
	}
	if err := os.WriteFile(dataDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("replace data dir: %v", err)
	}

	body := fmt.Sprintf(`{"client_id":"dev-1","local_addr":"127.0.0.1","local_port":22,"exposure":"public"}`)
	recorder := callTunnelHandler(t, srv.handleAPICreateTunnel, http.MethodPost, "/api/tunnels", "/api/tunnels", body)
	if recorder.Code < 500 {
		t.Fatalf("status = %d, want 5xx; body = %s", recorder.Code, recorder.Body.String())
	}
	if got := len(tm.ListTunnels()); got != 0 {
		t.Fatalf("a failed create must roll back the definition, got %d", got)
	}
	for port := range tm.publicPorts {
		t.Fatalf("a failed create must release the allocated port, still reserved: %d", port)
	}

	// 恢复目录后重建成功，且定义真的落盘。
	if err := os.Remove(dataDir); err != nil {
		t.Fatalf("remove blocker: %v", err)
	}
	recorder = callTunnelHandler(t, srv.handleAPICreateTunnel, http.MethodPost, "/api/tunnels", "/api/tunnels", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", recorder.Code, recorder.Body.String())
	}
	var created struct {
		TunnelID string `json:"tunnel_id"`
		Status   string `json:"status"`
		Port     int    `json:"public_port"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active", created.Status)
	}
	if got := len(store.GetTunnels()); got != 1 {
		t.Fatalf("persisted definitions = %d, want 1", got)
	}
	if created.Port < testTunnelPortStart || created.Port > testTunnelPortEnd {
		t.Fatalf("allocated port %d outside the range", created.Port)
	}
}

// 判据 10：range 改小后未绑定定义 out_of_range、无监听；PUT 新端口后
// active。已在服务的 listener 不受 range 变化影响。
func TestPortRangeChangeMarksUnboundDefinitionOutOfRange(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	tm.SetPortRange(testTunnelPortStart+100, testTunnelPortEnd)
	tunnel, _ := tm.GetTunnel("tunnel-1")
	if tunnel.Status != TunnelStatusOutOfRange {
		t.Fatalf("status = %q, want %q", tunnel.Status, TunnelStatusOutOfRange)
	}
	if tunnel.LastError == "" {
		t.Fatal("out_of_range should carry last_error")
	}
	if got := len(tm.listeners); got != 0 {
		t.Fatalf("an out-of-range definition must not have a listener, got %d", got)
	}

	// 设备上线后通过 PUT 改到范围内的新端口 → active。
	serverConn, _ := newTestWebsocketPair(t)
	clients.Add(&Client{ClientID: "dev-1", Conn: serverConn})
	body := fmt.Sprintf(`{"local_addr":"127.0.0.1","local_port":22,"public_port":%d,"exposure":"public"}`, testTunnelPortStart+120)
	recorder := callTunnelHandler(t, tm.server.handleAPIUpdateTunnel, http.MethodPut, "/api/tunnels/:tunnel_id", "/api/tunnels/tunnel-1", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update: status %d body %s", recorder.Code, recorder.Body.String())
	}
	var updated Tunnel
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active", updated.Status)
	}
	if updated.PublicPort != testTunnelPortStart+120 {
		t.Fatalf("port = %d, want %d", updated.PublicPort, testTunnelPortStart+120)
	}
	if _, ok := tm.listeners[testTunnelPortStart+120]; !ok {
		t.Fatal("the updated tunnel should listen on the new port")
	}

	// 正在服务的 listener 不受 range 改小影响。
	tm.SetPortRange(testTunnelPortStart+200, testTunnelPortEnd)
	stillBound, _ := tm.GetTunnel("tunnel-1")
	if stillBound.Status != TunnelStatusActive {
		t.Fatalf("a bound tunnel must keep working after a range change, status = %q", stillBound.Status)
	}
	if _, ok := tm.listeners[testTunnelPortStart+120]; !ok {
		t.Fatal("a bound listener must not be closed by a range change")
	}
}

// 判据 11/12：启动时丢弃孤儿定义和结构非法的定义（不 panic、不 bind）。
func TestLoadDropsOrphanAndInvalidDefinitions(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	now := time.Now()
	if err := store.ReplaceTunnels([]TunnelState{
		{TunnelID: "orphan", ClientID: "missing-device", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart, Exposure: "public", CreatedAt: now},
		{TunnelID: "bad-exposure", ClientID: "dev-1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart + 1, Exposure: "garbage", CreatedAt: now},
		{TunnelID: "bad-protocol", ClientID: "dev-1", Protocol: "udp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart + 2, Exposure: "public", CreatedAt: now},
		{TunnelID: "valid", ClientID: "dev-1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart + 3, Exposure: "public", CreatedAt: now},
		// 同端口重复定义：保留 CreatedAt 最早的一条，后来的丢弃。
		{TunnelID: "duplicate-port", ClientID: "dev-1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart + 3, Exposure: "public", CreatedAt: now.Add(time.Second)},
	}); err != nil {
		t.Fatalf("persist definitions: %v", err)
	}

	srv := NewServer(config, embed.FS{})
	tunnels := srv.tunnelManager.ListTunnels()
	if len(tunnels) != 1 || tunnels[0].TunnelID != "valid" {
		t.Fatalf("loaded tunnels = %+v, want only the valid one", tunnels)
	}
	if got := len(srv.tunnelManager.listeners); got != 0 {
		t.Fatalf("startup must not bind listeners, got %d", got)
	}
}

// 判据 13：tunnel_open 必须晚于 register_ok —— agent 在注册期间会直接丢弃
// 未知消息，顺序反了就变成“握手成功、隧道也在、一用就不通”。
func TestTunnelOpenIsSentAfterRegisterOK(t *testing.T) {
	config, stateStore := newTestConfig(t)
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
	pubHex := common.EncodePublicKey(pub)
	dhPubHex := common.EncodeBytes(dhPub[:])
	deviceID, err := dm.RegisterNewClient(pubHex, dhPubHex, "host", "linux", "10.0.0.9")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}

	clients := NewClientManager()
	clients.SetStore(stateStore)
	srv := &Server{
		config:     config,
		stateStore: stateStore,
		clients:    clients,
		deviceMgr:  dm,
		cryptoMgr:  cryptoMgr,
	}
	srv.handler = NewHandler(srv)
	srv.tunnelManager = newTunnelTestManager(t, stateStore, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := srv.tunnelManager.CreateTunnel("tunnel-1", deviceID, nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{Conn: serverConn}
	timestamp := time.Now().Unix()
	signature, err := common.SignTimestamp(priv, deviceID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}
	payload := &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       deviceID,
		DevicePubkey:   pubHex,
		DeviceDHPubkey: dhPubHex,
		Timestamp:      timestamp,
		Signature:      common.EncodeBytes(signature),
	}
	if err := srv.handler.handleReconnect(client, payload); err != nil {
		t.Fatalf("handleReconnect: %v", err)
	}
	if !client.tunnelRestoreScheduled.Load() {
		t.Fatal("restore must be scheduled after register_ok was written")
	}

	// 第一条必须是 register_ok；tunnel_open 只能在它之后。
	first := readAgentMessage(t, agentConn, "", 2*time.Second)
	if first.Type != "register_ok" {
		t.Fatalf("first message = %q, want register_ok (tunnel_open must never precede it)", first.Type)
	}
	second := readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)
	var open common.TunnelOpenPayload
	if err := json.Unmarshal(second.Payload, &open); err != nil {
		t.Fatalf("decode tunnel_open: %v", err)
	}
	if open.TunnelID != "tunnel-1" {
		t.Fatalf("tunnel_open = %s, want tunnel-1", open.TunnelID)
	}
}

// GET /api/tunnels 必须包含离线定义，并带 status（last_error 仅非空时出现）。
func TestListTunnelsIncludesOfflineDefinitions(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	srv := &Server{config: config, stateStore: store, clients: clients, tunnelManager: tm}

	recorder := callTunnelHandler(t, srv.handleAPIListTunnels, http.MethodGet, "/api/tunnels", "/api/tunnels", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Total   int      `json:"total"`
		Tunnels []Tunnel `json:"tunnels"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if body.Total != 1 || len(body.Tunnels) != 1 {
		t.Fatalf("list = %+v, want one offline definition", body)
	}
	if body.Tunnels[0].Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want %q", body.Tunnels[0].Status, TunnelStatusWaitingDevice)
	}
	if body.Tunnels[0].PublicPort != testTunnelPortStart {
		t.Fatalf("public_port = %d, want %d", body.Tunnels[0].PublicPort, testTunnelPortStart)
	}
}

// 更新定义也要同步落盘：重启后新目标/新端口仍在。
func TestUpdateTunnelPersistsDefinition(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.UpdateTunnel("tunnel-1", "127.0.0.1", 8080, testTunnelPortStart+5, "tcp", TunnelExposureServerLocal); err != nil {
		t.Fatalf("update: %v", err)
	}

	restarted := loadTunnelDefinitions(t, store, clients)
	tunnel, ok := restarted.GetTunnel("tunnel-1")
	if !ok {
		t.Fatal("updated definition disappeared after restart")
	}
	if tunnel.LocalPort != 8080 || tunnel.PublicPort != testTunnelPortStart+5 || tunnel.Exposure != TunnelExposureServerLocal {
		t.Fatalf("restored definition = %+v, want the updated target/port/exposure", tunnel)
	}
	if tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device", tunnel.Status)
	}
}

// 设计 §9：RemoveDevice 必须同步落盘，删设备后 3 秒内崩溃不能复活。
func TestRemoveDeviceIsPersistedSynchronously(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-sync", Name: "dev-sync", Status: deviceStatusAuthorized})
	if err := store.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	removed, err := store.RemoveDevice("dev-sync")
	if err != nil || !removed {
		t.Fatalf("remove device: removed=%v err=%v", removed, err)
	}

	// 不经过任何 flush：直接读盘。（3 秒同步循环还没跑过。）
	reloaded := NewStateStore(store.path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.GetDeviceByID("dev-sync") != nil {
		t.Fatal("a removed device must not come back after an immediate crash")
	}
}

// state 落盘要原子且权限收紧：不留下 .tmp，0600。
func TestWriteStateIsAtomic(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-atomic", Name: "dev-atomic", Status: deviceStatusAuthorized})
	if err := store.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode = %o, want 600", perm)
	}
	if _, err := os.Stat(store.path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the temp file must be gone after a successful save, stat err=%v", err)
	}
}

// 同一个连接上 scheduleTunnelRestore 只生效一次（审批接口与 pending 循环
// 可能同时到达）；否则重放会重复下发 tunnel_open。
func TestScheduleTunnelRestoreRunsOncePerConnection(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	client.markRegisterOKWritten()

	tm.server.scheduleTunnelRestore(client)
	tm.server.scheduleTunnelRestore(client)
	tm.server.scheduleTunnelRestore(client)

	readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)
	expectNoAgentMessage(t, agentConn, 200*time.Millisecond)

	tunnel, _ := tm.GetTunnel("tunnel-1")
	if tunnel.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active", tunnel.Status)
	}
}

// 结构性判据：register_ok 还没写成功时，scheduleTunnelRestore 必须拒绝
// 重放——这道闸门让“先调度后写”的时序错误在 10/10 次运行里都能抓住。
func TestScheduleTunnelRestoreRequiresRegisterOK(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	// 没写 register_ok：调度必须被拒绝，既不下发 tunnel_open 也不建立绑定。
	tm.server.scheduleTunnelRestore(client)
	expectNoAgentMessage(t, agentConn, 200*time.Millisecond)
	tunnel, _ := tm.GetTunnel("tunnel-1")
	if tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device (nothing may be restored yet)", tunnel.Status)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("no listener may be opened before register_ok is written")
	}
}

// register_ok 写失败时必须不调度重放：agent 没收到注册确认，任何
// tunnel_open 都会被当作未知消息丢掉。
func TestTunnelRestoreNotScheduledWhenRegisterOKFails(t *testing.T) {
	config, stateStore := newTestConfig(t)
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
	pubHex := common.EncodePublicKey(pub)
	dhPubHex := common.EncodeBytes(dhPub[:])
	deviceID, err := dm.RegisterNewClient(pubHex, dhPubHex, "host", "linux", "10.0.0.10")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}
	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}

	clients := NewClientManager()
	clients.SetStore(stateStore)
	srv := &Server{config: config, stateStore: stateStore, clients: clients, deviceMgr: dm, cryptoMgr: cryptoMgr}
	srv.handler = NewHandler(srv)
	srv.tunnelManager = newTunnelTestManager(t, stateStore, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := srv.tunnelManager.CreateTunnel("tunnel-1", deviceID, nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Conn 为 nil：register_ok 写失败。
	client := &Client{}
	timestamp := time.Now().Unix()
	signature, err := common.SignTimestamp(priv, deviceID, timestamp)
	if err != nil {
		t.Fatalf("SignTimestamp: %v", err)
	}
	payload := &common.RegisterPayload{
		ReAuth:         true,
		ClientID:       deviceID,
		DevicePubkey:   pubHex,
		DeviceDHPubkey: dhPubHex,
		Timestamp:      timestamp,
		Signature:      common.EncodeBytes(signature),
	}
	if err := srv.handler.handleReconnect(client, payload); err == nil {
		t.Fatal("handleReconnect must fail when register_ok cannot be written")
	}
	if client.tunnelRestoreScheduled.Load() {
		t.Fatal("no restore may be scheduled after a failed register_ok")
	}
	tunnel, _ := srv.tunnelManager.GetTunnel("tunnel-1")
	if tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device", tunnel.Status)
	}
}

// 裁决 1：定义落盘成功即 200，apply 失败只把状态标成 apply_failed。
func TestCreateTunnelReturnsOKWhenApplyFails(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	// 连接为 nil：tunnel_open 写失败，但定义应该已经落盘。
	clients.Add(&Client{ClientID: "dev-1"})
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	srv := &Server{config: config, stateStore: store, clients: clients, tunnelManager: tm}

	recorder := callTunnelHandler(t, srv.handleAPICreateTunnel, http.MethodPost, "/api/tunnels", "/api/tunnels",
		`{"client_id":"dev-1","local_addr":"127.0.0.1","local_port":22,"exposure":"public"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		TunnelID  string `json:"tunnel_id"`
		Status    string `json:"status"`
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != TunnelStatusApplyFailed {
		t.Fatalf("status = %q, want %q", response.Status, TunnelStatusApplyFailed)
	}
	if response.LastError == "" {
		t.Fatal("apply_failed should carry last_error")
	}
	if got := len(store.GetTunnels()); got != 1 {
		t.Fatalf("the definition must stay persisted, got %d", got)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("apply_failed must close the listener (a black hole otherwise)")
	}
}

// 阻塞 2：Save 失败的回滚不能用删除时记下的下标。并发删除会把切片改短，
// 旧实现往更短的切片里插回原下标会 panic，panic 发生在持锁区间里还会把
// s.mu 永久带走。
func TestRemoveDeviceRollbackSurvivesConcurrentDeletes(t *testing.T) {
	ids := []string{"dev-1", "dev-2", "dev-3", "dev-4"}
	for round := 0; round < 50; round++ {
		_, store := newTestConfig(t)
		for _, id := range ids {
			store.AddDevice(&DeviceState{ID: id, Name: id, Status: deviceStatusAuthorized})
		}
		// 把数据目录换成一个普通文件：两次删除的 Save 都必然失败。
		dataDir := filepath.Dir(store.path)
		if err := os.RemoveAll(dataDir); err != nil {
			t.Fatalf("remove data dir: %v", err)
		}
		if err := os.WriteFile(dataDir, []byte("x"), 0o600); err != nil {
			t.Fatalf("replace data dir: %v", err)
		}

		var wg sync.WaitGroup
		done := make(chan struct{})
		go func() {
			defer close(done)
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = store.RemoveDevice("dev-1")
			}()
			go func() {
				defer wg.Done()
				_, _ = store.RemoveDevice("dev-4")
			}()
			wg.Wait()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: RemoveDevice deadlocked (the rollback kept s.mu)", round)
		}

		// Save 失败 = 内存回滚：四台设备都必须在，且后续查询不能挂死。
		for _, id := range ids {
			if store.GetDeviceByID(id) == nil {
				t.Fatalf("round %d: device %s lost after a failed removal rollback", round, id)
			}
		}
		if got := len(store.GetAllDevices()); got != len(ids) {
			t.Fatalf("round %d: devices = %d, want %d", round, got, len(ids))
		}
	}
}

// 阻塞 1：handleExternalConn 在公网连接路径上读 tunnel.Client，本次改动
// 让同一字段在 6 处运行时写。外部连接与 DetachClient 并发时必须是同步的。
func TestExternalConnectionDoesNotRaceWithDetach(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	tm.retryDelays = []time.Duration{200 * time.Millisecond}
	if err := tm.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// 排掉 tunnel_open，避免 apply/detach 循环把写缓冲塞满。
	go func() {
		for {
			if _, _, err := agentConn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", testTunnelPortStart)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tm.DetachClient("dev-1", client)
			if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
				return
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// readAgentMessageUntil 读消息直到出现目标类型（期间允许 pong 等噪声），
// 用于“重放由异步 goroutine 完成”的场景。
func readAgentMessageUntil(t *testing.T, conn *websocket.Conn, wantType string, timeout time.Duration) common.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	for {
		var msg common.Message
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read message (want %s): %v", wantType, err)
		}
		if msg.Type == wantType {
			return msg
		}
	}
}

// newPendingTunnelServer 构造一台待审批设备 + 一条定义，返回服务端与
// 待审批连接（尚未登记到 clients）。
func newPendingTunnelServer(t *testing.T, tunnelID string) (*Server, *DeviceManager, *Client, *websocket.Conn, string) {
	t.Helper()
	config, stateStore := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(stateStore, cryptoMgr)
	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "host", "linux", "10.0.0.11")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	clients := NewClientManager()
	clients.SetStore(stateStore)
	srv := &Server{config: config, stateStore: stateStore, clients: clients, deviceMgr: dm, cryptoMgr: cryptoMgr}
	srv.handler = NewHandler(srv)
	srv.tunnelManager = newTunnelTestManager(t, stateStore, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := srv.tunnelManager.CreateTunnel(tunnelID, deviceID, nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: deviceID, Conn: serverConn}
	dm.AddPendingConn(deviceID, client, "10.0.0.11")
	return srv, dm, client, agentConn, deviceID
}

// 非阻塞 1：审批接口先拿走 register_ok 的发送权，pending 循环看到 CAS 失败、
// 而写标记还没置位时，调度闸门会拒绝。设备在线但定义永远不恢复——
// 下一条心跳必须补上这次重放。
func TestTunnelRestoreRecoversWhenApprovalWinsTheRegisterOKRace(t *testing.T) {
	srv, dm, client, agentConn, deviceID := newPendingTunnelServer(t, "tunnel-1")

	// 审批接口已经拿走发送权，但 register_ok 还没写完。
	client.markRegisterOKSent()

	go srv.pendingLoop(client)

	if _, _, _, err := dm.ApproveDevice(deviceID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	if err := agentConn.WriteJSON(common.Message{Type: "ping"}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	readAgentMessage(t, agentConn, "pong", 2*time.Second)
	waitForCondition(t, 2*time.Second, func() bool {
		return srv.clients.IsCurrent(deviceID, client)
	}, "pending loop should promote the approved connection")

	// 这正是审计探针观察到的状态：没调度、定义 waiting、没有监听。
	if client.tunnelRestoreScheduled.Load() {
		t.Fatal("nothing may be scheduled before register_ok was actually written")
	}
	tunnel, _ := srv.tunnelManager.GetTunnel("tunnel-1")
	if tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device", tunnel.Status)
	}
	if got := len(srv.tunnelManager.listeners); got != 0 {
		t.Fatalf("listeners = %d, want 0 before restore", got)
	}

	// 审批接口的写现在才落地：没有单独调度，只能靠心跳补。
	client.markRegisterOKWritten()
	if err := agentConn.WriteJSON(common.Message{Type: "ping"}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	msg := readAgentMessageUntil(t, agentConn, "tunnel_open", 2*time.Second)
	var payload common.TunnelOpenPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatalf("decode tunnel_open: %v", err)
	}
	if payload.TunnelID != "tunnel-1" {
		t.Fatalf("tunnel_open = %s, want tunnel-1", payload.TunnelID)
	}
	waitForCondition(t, 2*time.Second, func() bool {
		tunnel, _ := srv.tunnelManager.GetTunnel("tunnel-1")
		return tunnel.Status == TunnelStatusActive
	}, "the heartbeat retry must restore the tunnel")
	if _, ok := srv.tunnelManager.listeners[testTunnelPortStart]; !ok {
		t.Fatal("the restored tunnel must have a listener")
	}
}

// 同一件事的正常路径：审批接口先写完 register_ok，pending 循环随后接上时
// 必须按“写标记”调度，而不是按 sendRegisterOK 的返回值（CAS 失败返回 nil）。
func TestApprovalPathRestoresTunnelsAfterRegisterOK(t *testing.T) {
	srv, _, client, agentConn, deviceID := newPendingTunnelServer(t, "tunnel-1")

	go srv.pendingLoop(client)

	recorder := callTunnelHandler(t, srv.handleAPIApproveDevice, http.MethodPost,
		"/api/devices/:id/approve", "/api/devices/"+deviceID+"/approve", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("approve: status %d body %s", recorder.Code, recorder.Body.String())
	}
	readAgentMessage(t, agentConn, "register_ok", 2*time.Second)

	if err := agentConn.WriteJSON(common.Message{Type: "ping"}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	readAgentMessageUntil(t, agentConn, "tunnel_open", 2*time.Second)
	waitForCondition(t, 2*time.Second, func() bool {
		tunnel, _ := srv.tunnelManager.GetTunnel("tunnel-1")
		return tunnel.Status == TunnelStatusActive
	}, "the approved device must get its tunnel back after register_ok")
	if !client.tunnelRestoreScheduled.Load() {
		t.Fatal("the approval path must schedule exactly one restore")
	}
}

// 设计 §7：更新到被占用的端口 → 200 + port_conflict，定义保留新端口；
// 端口释放后自动退避恢复。创建侧已有用例，更新侧原来没有。
func TestUpdateTunnelToOccupiedPortReportsPortConflict(t *testing.T) {
	config, store := newTestConfig(t)
	config.Tunnel.Enabled = true
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)

	targetPort := testTunnelPortStart + 1
	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", targetPort))
	if err != nil {
		t.Fatalf("occupy target port: %v", err)
	}

	srv := &Server{config: config, stateStore: store, clients: clients, tunnelManager: tm}
	body := fmt.Sprintf(`{"local_addr":"127.0.0.1","local_port":22,"public_port":%d,"exposure":"public"}`, targetPort)
	recorder := callTunnelHandler(t, srv.handleAPIUpdateTunnel, http.MethodPut, "/api/tunnels/:tunnel_id", "/api/tunnels/tunnel-1", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update to an occupied port: status %d, want 200; body = %s", recorder.Code, recorder.Body.String())
	}
	var updated Tunnel
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Status != TunnelStatusPortConflict {
		t.Fatalf("status = %q, want %q", updated.Status, TunnelStatusPortConflict)
	}
	if updated.LastError == "" {
		t.Fatal("port_conflict should carry last_error")
	}
	if updated.PublicPort != targetPort {
		t.Fatalf("public_port = %d, want %d (the port must not be swapped)", updated.PublicPort, targetPort)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("the old listener must be closed once the definition moved to another port")
	}
	if got := tm.publicPorts[targetPort]; got != "tunnel-1" {
		t.Fatalf("port reservation = %q, want tunnel-1", got)
	}

	// 释放被外部占用的端口：自动退避应该按新端口恢复。
	blocker.Close()
	waitForCondition(t, 3*time.Second, func() bool {
		tunnel, _ := tm.GetTunnel("tunnel-1")
		return tunnel.Status == TunnelStatusActive
	}, "the retry chain should recover the tunnel on the updated port")
	if _, ok := tm.listeners[targetPort]; !ok {
		t.Fatal("the recovered tunnel must listen on the updated port")
	}
}

// 非阻塞 3 的配套：端口冲突退避链必须是完整的 1s/3s/9s/30s/60s；序列用尽后
// 按最后一个间隔继续探测，直到重试窗口到期才停下等人。
func TestPortConflictRetryChainIsComplete(t *testing.T) {
	want := []time.Duration{time.Second, 3 * time.Second, 9 * time.Second, 30 * time.Second, 60 * time.Second}
	if !reflect.DeepEqual(defaultPortConflictRetryDelays, want) {
		t.Fatalf("defaultPortConflictRetryDelays = %v, want %v", defaultPortConflictRetryDelays, want)
	}
	if defaultPortConflictRetryWindow != 10*time.Minute {
		t.Fatalf("defaultPortConflictRetryWindow = %v, want 10m", defaultPortConflictRetryWindow)
	}

	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)

	// 场景 1：前两次重试仍被占用，第二次之后放开端口——只有第三次（最后
	// 一条延时）才会成功；少一条延时这条会红。
	port1 := testTunnelPortStart + 30
	blocker1, err := net.Listen("tcp", fmt.Sprintf(":%d", port1))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	if err := tm.CreateTunnel("chain-1", "dev-1", client, "tcp", "127.0.0.1", 22, port1, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	tm.retryDelays = []time.Duration{30 * time.Millisecond, 30 * time.Millisecond, 800 * time.Millisecond}
	if _, err := tm.ApplyTunnel("chain-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // 前两次重试（~30ms/~60ms）已撞在占用上
	blocker1.Close()
	waitForCondition(t, 3*time.Second, func() bool {
		tunnel, _ := tm.GetTunnel("chain-1")
		return tunnel.Status == TunnelStatusActive
	}, "the last retry in the chain must still be attempted")

	// 场景 2：窗口用尽后必须停下，不再自动重试；手动 retry 才恢复。
	port2 := testTunnelPortStart + 31
	blocker2, err := net.Listen("tcp", fmt.Sprintf(":%d", port2))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer blocker2.Close()
	if err := tm.CreateTunnel("chain-2", "dev-1", client, "tcp", "127.0.0.1", 22, port2, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	tm.retryDelays = []time.Duration{30 * time.Millisecond, 30 * time.Millisecond, 80 * time.Millisecond}
	tm.retryWindow = 200 * time.Millisecond
	if _, err := tm.ApplyTunnel("chain-2"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	tunnel, _ := tm.GetTunnel("chain-2")
	if tunnel.Status != TunnelStatusPortConflict {
		t.Fatalf("status = %q, want port_conflict after the chain gives up", tunnel.Status)
	}
	tm.mu.RLock()
	retrying := tm.tunnels["chain-2"].retrying
	tm.mu.RUnlock()
	if retrying {
		t.Fatal("the retry chain must stop after the last delay")
	}
	blocker2.Close()
	time.Sleep(300 * time.Millisecond)
	if tunnel, _ := tm.GetTunnel("chain-2"); tunnel.Status != TunnelStatusPortConflict {
		t.Fatalf("a finished chain must not retry on its own, status = %q", tunnel.Status)
	}
	if _, err := tm.RetryTunnel("chain-2"); err != nil {
		t.Fatalf("manual retry: %v", err)
	}
	if tunnel, _ := tm.GetTunnel("chain-2"); tunnel.Status != TunnelStatusActive {
		t.Fatalf("manual retry should activate the tunnel, got %q", tunnel.Status)
	}
	_ = agentConn
}

// 非阻塞 2：断开必须先摘连接再解绑。连接摘掉之后，迟到的 restore 找不到
// “当前连接”，不允许再绑出没有主人的 listener。
func TestLateRestoreAfterDisconnectDoesNotBind(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, _ := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; !ok {
		t.Fatal("sanity: the tunnel should be listening")
	}

	// readLoop 的收尾顺序：先摘连接，再解绑。
	if !clients.RemoveIfMatch("dev-1", client) {
		t.Fatal("the connection should have been removed")
	}
	tm.DetachClient("dev-1", client)
	if got := len(tm.listeners); got != 0 {
		t.Fatalf("listeners = %d, want 0 after detach", got)
	}

	// 迟到的重放（断开窗口里已经启动的 goroutine）必须什么都绑不了。
	tm.RestoreClient(client)
	if got := len(tm.listeners); got != 0 {
		t.Fatalf("a late restore bound %d listener(s) for a removed connection", got)
	}
	if tunnel, _ := tm.GetTunnel("tunnel-1"); tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device", tunnel.Status)
	}

	// 反向窗口：设备已经重连并重新绑定，旧连接的收尾（带旧连接身份）晚到，
	// 不能拆掉新连接刚恢复的 listener。
	freshConn, _ := newTestWebsocketPair(t)
	fresh := &Client{ClientID: "dev-1", Conn: freshConn}
	clients.Add(fresh)
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply after reconnect: %v", err)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; !ok {
		t.Fatal("sanity: the new connection should be listening")
	}
	tm.DetachClient("dev-1", client)
	if _, ok := tm.listeners[testTunnelPortStart]; !ok {
		t.Fatal("a late detach from a superseded connection must not close the new binding")
	}
	if tunnel, _ := tm.GetTunnel("tunnel-1"); tunnel.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active after the skipped late detach", tunnel.Status)
	}
}

// 非阻塞 5：拒绝设备时落盘失败是服务端故障（设备还在、拒绝没生效），
// 必须返回 500 而不是 400。
func TestDenyDeviceReturns500WhenStateCannotBePersisted(t *testing.T) {
	config, store := newTestConfig(t)
	cryptoMgr := common.NewCryptoManager()
	dm := NewDeviceManager(store, cryptoMgr)
	pub, _, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	_, dhPub, err := common.GenerateDHKeypair()
	if err != nil {
		t.Fatalf("GenerateDHKeypair: %v", err)
	}
	deviceID, err := dm.RegisterNewClient(common.EncodePublicKey(pub), common.EncodeBytes(dhPub[:]), "host", "linux", "10.0.0.12")
	if err != nil {
		t.Fatalf("RegisterNewClient: %v", err)
	}

	srv := &Server{config: config, stateStore: store, deviceMgr: dm, cryptoMgr: cryptoMgr, clients: NewClientManager()}

	// 把数据目录换成一个普通文件：RemoveDevice 的 Save 必然失败。
	dataDir := filepath.Dir(store.path)
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("remove data dir: %v", err)
	}
	if err := os.WriteFile(dataDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("replace data dir: %v", err)
	}

	recorder := callTunnelHandler(t, srv.handleAPIDenyDevice, http.MethodPost,
		"/api/devices/:id/deny", "/api/devices/"+deviceID+"/deny", "")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("deny with a broken state file: status %d, want 500; body = %s", recorder.Code, recorder.Body.String())
	}
	if store.GetDeviceByID(deviceID) == nil {
		t.Fatal("the device must still be there when the denial could not be persisted")
	}
}

// 非阻塞 3：旧连接那次 apply 的 tunnel_open 迟到失败时，不能关掉新一次
// apply 已经建好的 listener，也不能把新尝试标成 apply_failed——否则会出现
// “agent 收到 tunnel_open、服务端没监听”。
func TestStaleApplyFailureDoesNotCloseTheNewApplyListener(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	// 旧连接没有真实 Conn：写 tunnel_open 必然失败。
	stale := &Client{ClientID: "dev-1"}
	clients.Add(stale)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", stale, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	tm.DetachClient("dev-1", stale)

	// 卡住旧连接的写入：这次 apply 会在 bind 之后停在 SendTunnelOpen 上。
	stale.writeMu.Lock()
	staleDone := make(chan struct{})
	go func() {
		defer close(staleDone)
		_, _ = tm.applyTunnel("tunnel-1", stale)
	}()
	waitForCondition(t, time.Second, func() bool {
		tm.mu.RLock()
		defer tm.mu.RUnlock()
		_, bound := tm.listeners[testTunnelPortStart]
		return bound
	}, "the stale apply should have bound its listener before writing")

	// 设备重连：新连接接管，新一次 apply 也卡在写 tunnel_open 上。
	serverConn, agentConn := newTestWebsocketPair(t)
	fresh := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(fresh)
	tm.DetachClient("dev-1", fresh)

	fresh.writeMu.Lock()
	freshDone := make(chan Tunnel, 1)
	go func() {
		updated, _ := tm.applyTunnel("tunnel-1", fresh)
		freshDone <- updated
	}()
	waitForCondition(t, time.Second, func() bool {
		tm.mu.RLock()
		defer tm.mu.RUnlock()
		_, bound := tm.listeners[testTunnelPortStart]
		return bound
	}, "the new apply should have bound its listener before writing")

	// 让旧 apply 的写失败：它只能清理自己那一次。
	stale.writeMu.Unlock()
	<-staleDone

	tm.mu.RLock()
	_, stillBound := tm.listeners[testTunnelPortStart]
	current := tm.tunnels["tunnel-1"]
	stillApplying := current.applying
	staleSeq := current.applySeq
	tm.mu.RUnlock()
	if !stillBound {
		t.Fatal("a stale apply failure closed the listener of the new attempt")
	}
	if !stillApplying {
		t.Fatal("a stale apply failure cleared the new attempt's applying flag")
	}

	// 新 apply 写成功后必须变成 active，listener 还在。
	fresh.writeMu.Unlock()
	updated := <-freshDone
	if updated.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active", updated.Status)
	}
	readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)
	tm.mu.RLock()
	_, boundAfter := tm.listeners[testTunnelPortStart]
	seqAfter := tm.tunnels["tunnel-1"].applySeq
	tm.mu.RUnlock()
	if !boundAfter {
		t.Fatal("the new attempt must keep its listener once active")
	}
	if seqAfter != staleSeq {
		t.Fatalf("applySeq changed from %d to %d, want it stable per attempt", staleSeq, seqAfter)
	}
}

// blockingDetachHandler 只在“隧道解绑完成”这条日志上停住调用方：解绑把
// listener 关掉、定义标回 waiting_device 之后，收尾还没走到“摘连接”。
// 这一段正是收尾顺序的差别所在，用它把窗口拉长到可确定断言。
type blockingDetachHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingDetachHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *blockingDetachHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "tunnel definitions detached from device" {
		return nil
	}
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	return nil
}

func (h *blockingDetachHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingDetachHandler) WithGroup(string) slog.Handler      { return h }

// 回归保护：readLoop 的收尾必须是「先摘连接、再解绑」。顺序反过来时，
// 解绑完成到摘连接之间“设备仍算在线”，迟到的重放会重新绑上 listener，
// 而收尾不会再去关它——设备已离线却留着监听。
//
// 这里用真实的 readLoop 跑完整流程，并在解绑日志处把收尾停住，确定性地
// 在窗口内触发一次重放。旧顺序下这个重放会绑定成功，用例变红。
func TestReadLoopTeardownRemovesConnectionBeforeDetach(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	srv := &Server{stateStore: store, clients: clients}
	tm := NewTunnelManager(srv, testTunnelPortStart, testTunnelPortEnd)
	srv.tunnelManager = tm
	t.Cleanup(tm.CloseAll)

	if err := tm.CreateTunnel("tunnel-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	serverConn, _ := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := tm.listeners[testTunnelPortStart]; !ok {
		t.Fatal("sanity: the tunnel should be listening before the disconnect")
	}

	handler := &blockingDetachHandler{entered: make(chan struct{}, 1), release: make(chan struct{})}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(handler.release) }) }
	t.Cleanup(func() {
		release()
		slog.SetDefault(previous)
	})

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		srv.readLoop(client)
	}()

	// 半关读方向：readLoop 立刻读到 EOF 进入收尾，但写方向还能成功——
	// 这样旧顺序下迟到的 tunnel_open 才写得出去，才会真的留下 listener。
	tcp, ok := serverConn.UnderlyingConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("test websocket is not plain TCP: %T", serverConn.UnderlyingConn())
	}
	if err := tcp.CloseRead(); err != nil {
		t.Fatalf("half close: %v", err)
	}

	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the teardown never reached its detach log line")
	}

	// 此刻解绑已经做完（listener 已关、定义 waiting_device）。两种顺序的
	// 全部区别就在这一行：正确顺序下连接已经摘掉，旧顺序下还算“在线”。
	if clients.IsCurrent("dev-1", client) {
		t.Fatal("the connection must already be removed when the detach runs")
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("sanity: the detach should have closed the listener")
	}
	tm.RestoreClient(client)
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("a restore between detach and remove bound a listener for an offline device")
	}

	release()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not finish its teardown")
	}

	// 收尾之后：连接已摘、定义仍 waiting_device、没有 listener。
	if clients.IsCurrent("dev-1", client) {
		t.Fatal("the connection must be removed by the teardown")
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("the teardown must not leave a listener behind")
	}
	if tunnel, _ := tm.GetTunnel("tunnel-1"); tunnel.Status != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want waiting_device", tunnel.Status)
	}
}

// UpdateTunnel 与 apply 交错：apply 已经 bind、卡在 sendTunnelOpen 时改端口，
// 更新流程会关掉旧 listener；这次 apply 必须在定义变更时被作废，否则它写成功
// 之后会把状态改回 active——面板显示“已连接”，实际一条监听都没有。
//
// 这里用 writeMu 把在途的 apply 确定性地停在写 tunnel_open 之前，再让更新
// 流程走完定义改写，断言最终状态自洽（active 就一定有监听）。
func TestUpdateTunnelDuringApplyKeepsStatusHonest(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := tm.ApplyTunnel("tunnel-1"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	readAgentMessage(t, agentConn, "tunnel_open", 2*time.Second)

	oldPort := testTunnelPortStart
	newPort := testTunnelPortStart + 1

	// 制造“apply 已 bind、卡在 sendTunnelOpen”的在途状态：先解绑，再让
	// 重放去绑定，并卡住它的写。
	client.writeMu.Lock()
	tm.DetachClient("dev-1", client)
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		_, _ = tm.applyTunnel("tunnel-1", client)
	}()
	waitForCondition(t, 2*time.Second, func() bool {
		tm.mu.RLock()
		defer tm.mu.RUnlock()
		_, bound := tm.listeners[oldPort]
		return bound
	}, "the in-flight apply should have bound its listener")

	tm.mu.RLock()
	staleSeq := tm.tunnels["tunnel-1"].applySeq
	inFlight := tm.tunnels["tunnel-1"].applying
	tm.mu.RUnlock()
	if !inFlight {
		t.Fatal("sanity: the apply should still be in flight")
	}

	// 管理员在这次 apply 卡住的窗口里改端口。
	type updateResult struct {
		tunnel *Tunnel
		err    error
	}
	updated := make(chan updateResult, 1)
	go func() {
		tunnel, err := tm.UpdateTunnel("tunnel-1", "127.0.0.1", 22, newPort, "tcp", "public")
		updated <- updateResult{tunnel, err}
	}()
	waitForCondition(t, 2*time.Second, func() bool {
		tunnel, ok := tm.GetTunnel("tunnel-1")
		return ok && tunnel.PublicPort == newPort
	}, "the update should have rewritten the definition")

	// 关键断言：定义变了，在途的那次 apply 必须立刻作废。
	tm.mu.RLock()
	stillApplying := tm.tunnels["tunnel-1"].applying
	seqNow := tm.tunnels["tunnel-1"].applySeq
	tm.mu.RUnlock()
	if stillApplying {
		t.Fatal("the in-flight apply must be invalidated when the definition changes")
	}
	if seqNow == staleSeq {
		t.Fatalf("applySeq = %d, want a new attempt id (stale apply must not win)", seqNow)
	}

	client.writeMu.Unlock()
	<-applyDone
	res := <-updated
	if res.err != nil {
		t.Fatalf("update: %v", res.err)
	}

	// 最终状态必须自洽：active 一定对应新端口上的真实监听。
	if res.tunnel.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active (last_error=%q)", res.tunnel.Status, res.tunnel.LastError)
	}
	tm.mu.RLock()
	_, newBound := tm.listeners[newPort]
	_, oldBound := tm.listeners[oldPort]
	tm.mu.RUnlock()
	if !newBound {
		t.Fatal("an active tunnel must have a listener on its port")
	}
	if oldBound {
		t.Fatal("the old port must not keep a listener after the update")
	}
}

// apply 在「已 bind、还没写 tunnel_open」时定义被改掉：这次 apply 必须放弃
// 写 tunnel_open，否则 agent 会收到一条基于旧定义的消息，而服务端已经按新
// 定义在监听。
//
// 窗口只有两条指令（解锁 → 再校验），没有可观测状态，所以用 tunnelOpenHook
// 把第一次 apply 停在窗口中，再由更新流程改写定义，然后放行它。
func TestApplyDoesNotSendStaleTunnelOpenAfterUpdate(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)
	serverConn, agentConn := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if err := tm.CreateTunnel("tunnel-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, "public"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// 只停住第一次 apply；更新流程自己的那次必须放行。
	first := make(chan struct{}, 1)
	first <- struct{}{}
	entered := make(chan struct{})
	release := make(chan struct{})
	previousHook := tunnelOpenHook
	tunnelOpenHook = func(string) {
		select {
		case <-first:
			close(entered)
			<-release
		default:
		}
	}
	t.Cleanup(func() { tunnelOpenHook = previousHook })

	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		_, _ = tm.applyTunnel("tunnel-1", client)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the apply never reached the tunnel_open window")
	}

	// 窗口内改定义：本地端口也改，才能区分新旧两条 tunnel_open。
	newPort := testTunnelPortStart + 1
	updated, err := tm.UpdateTunnel("tunnel-1", "127.0.0.1", 2200, newPort, "tcp", "public")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Status != TunnelStatusActive {
		t.Fatalf("status = %q, want active (last_error=%q)", updated.Status, updated.LastError)
	}

	// 更新流程发的是新定义。
	msg := readAgentMessageUntil(t, agentConn, "tunnel_open", 2*time.Second)
	var open common.TunnelOpenPayload
	if err := json.Unmarshal(msg.Payload, &open); err != nil {
		t.Fatalf("decode tunnel_open: %v", err)
	}
	if open.LocalPort != 2200 {
		t.Fatalf("tunnel_open local_port = %d, want the new definition (2200)", open.LocalPort)
	}

	// 放行在途的那次 apply：它不能再发一条基于旧定义（22）的 tunnel_open。
	close(release)
	<-applyDone
	agentConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var stale common.Message
	if err := agentConn.ReadJSON(&stale); err == nil {
		var staleOpen common.TunnelOpenPayload
		_ = json.Unmarshal(stale.Payload, &staleOpen)
		t.Fatalf("a tunnel_open was sent after the definition changed: type=%q local_port=%d (want no message)",
			stale.Type, staleOpen.LocalPort)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout, got %v", err)
	}

	if _, ok := tm.listeners[newPort]; !ok {
		t.Fatal("the updated definition must still be listening on its new port")
	}
	if _, ok := tm.listeners[testTunnelPortStart]; ok {
		t.Fatal("the stale apply must not leave a listener on the old port")
	}
}
