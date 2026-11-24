package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func mustTunnel(t *testing.T, tm *TunnelManager, tunnelID string) Tunnel {
	t.Helper()
	tunnel, ok := tm.GetTunnel(tunnelID)
	if !ok {
		t.Fatalf("tunnel %s not found", tunnelID)
	}
	return tunnel
}

func newRateTestManager(t *testing.T) (*TunnelManager, Tunnel) {
	t.Helper()
	_, store := newTestConfig(t)
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)
	client := &Client{ClientID: "dev-1"}
	if err := tm.CreateTunnel("t-1", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, ""); err != nil {
		t.Fatalf("CreateTunnel: %v", err)
	}
	return tm, mustTunnel(t, tm, "t-1")
}

// ① 真实转发路径：外部→agent 记 rx，agent→外部 记 tx，计数等于字节数。
func TestTunnelByteCountersFollowForwarding(t *testing.T) {
	tm, tunnel := newRateTestManager(t)

	serverWS, agentWS := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverWS}
	client.SetEncryptionEnabled(false)

	extServer, extClient := net.Pipe()
	t.Cleanup(func() {
		extClient.Close()
		extServer.Close()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		tm.handleExternalConn("conn-1", &tunnel, client, extServer)
	}()

	// rx：外部连接 → agent
	rxData := bytes.Repeat([]byte{'r'}, 300)
	go func() { _, _ = extClient.Write(rxData) }()
	agentWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := agentWS.ReadMessage(); err != nil {
		t.Fatalf("agent should receive the forwarded frame: %v", err)
	}

	// tx：agent → 外部连接
	txData := bytes.Repeat([]byte{'t'}, 200)
	if err := tm.HandleAgentData("t-1", "conn-1", txData, false); err != nil {
		t.Fatalf("HandleAgentData: %v", err)
	}
	got := make([]byte, len(txData))
	extClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(extClient, got); err != nil {
		t.Fatalf("external side should receive the payload: %v", err)
	}
	if !bytes.Equal(got, txData) {
		t.Fatalf("forwarded payload mismatch: %x", got)
	}

	// tx 在 writer 协程里、写成功之后才累加：读者可能先拿到字节，轮询等计数。
	waitForCondition(t, 2*time.Second, func() bool {
		_, txBytes, _, _ := tunnel.statsSnapshot()
		return txBytes == uint64(len(txData))
	}, "tx_bytes should reach the forwarded byte count")
	if rxBytes, _, _, _ := tunnel.statsSnapshot(); rxBytes != uint64(len(rxData)) {
		t.Fatalf("rx_bytes = %d, want %d", rxBytes, len(rxData))
	}

	extClient.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleExternalConn did not exit after the external side closed")
	}
}

// ② 采样：有流量时速率等于本周期字节数，无流量归零，累计值保留。
func TestTunnelRateSampling(t *testing.T) {
	tm, tunnel := newRateTestManager(t)

	tunnel.stats.addRX(1000)
	tunnel.stats.addTX(2000)
	tm.sampleRates()

	rxBytes, txBytes, rxRate, txRate := tunnel.statsSnapshot()
	if rxBytes != 1000 || txBytes != 2000 {
		t.Fatalf("totals = (%d, %d), want (1000, 2000)", rxBytes, txBytes)
	}
	if rxRate != 1000 || txRate != 2000 {
		t.Fatalf("rates = (%d, %d), want (1000, 2000)", rxRate, txRate)
	}

	// 一个周期没有新流量：速率归零，累计不变。
	tm.sampleRates()
	rxBytes, txBytes, rxRate, txRate = tunnel.statsSnapshot()
	if rxBytes != 1000 || txBytes != 2000 {
		t.Fatalf("totals after idle = (%d, %d), want unchanged", rxBytes, txBytes)
	}
	if rxRate != 0 || txRate != 0 {
		t.Fatalf("idle rates = (%d, %d), want (0, 0)", rxRate, txRate)
	}

	// 再来一个周期：只算新增字节。
	tunnel.stats.addRX(300)
	tm.sampleRates()
	_, _, rxRate, txRate = tunnel.statsSnapshot()
	if rxRate != 300 || txRate != 0 {
		t.Fatalf("delta rates = (%d, %d), want (300, 0)", rxRate, txRate)
	}
}

// ② 真实 ticker：1 秒后发布非零速率，无流量后回到 0。
func TestRateTrackerTicks(t *testing.T) {
	tm, tunnel := newRateTestManager(t)
	tm.StartRateTracker()
	t.Cleanup(tm.StopRateTracker)

	tunnel.stats.addRX(4096)

	waitForCondition(t, 3*time.Second, func() bool {
		_, _, rxRate, _ := tunnel.statsSnapshot()
		return rxRate > 0
	}, "rate tracker should publish a non-zero rate within one tick")

	waitForCondition(t, 3*time.Second, func() bool {
		_, _, rxRate, _ := tunnel.statsSnapshot()
		return rxRate == 0
	}, "rate should fall back to zero when there is no traffic")
}

// ③ 并发累加、采样与 API 视图读取，交给 -race。
func TestTunnelRateConcurrentAccess(t *testing.T) {
	tm, tunnel := newRateTestManager(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tunnel.stats.addRX(64)
				tunnel.stats.addTX(32)
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
				tm.sampleRates()
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
				view := newTunnelView(tunnel)
				if view.TunnelID != "t-1" {
					return
				}
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ④ API JSON：新增字段存在、是数字、值正确；既有字段语义不变。
func TestTunnelRateAPIFields(t *testing.T) {
	tm, tunnel := newRateTestManager(t)
	tunnel.stats.addRX(1234)
	tunnel.stats.addTX(4321)
	tm.sampleRates()

	srv := &Server{tunnelManager: tm}
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/api/tunnels", srv.handleAPIListTunnels)
	engine.GET("/api/tunnels/:tunnel_id", srv.handleAPIGetTunnel)

	decode := func(path string) map[string]any {
		t.Helper()
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, recorder.Code, recorder.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return body
	}

	requireNumber := func(entry map[string]any, field string, want float64) {
		t.Helper()
		value, ok := entry[field]
		if !ok {
			t.Fatalf("field %q missing from the tunnel JSON: %v", field, entry)
		}
		number, ok := value.(float64)
		if !ok {
			t.Fatalf("field %q = %T, want a JSON number", field, value)
		}
		if number != want {
			t.Fatalf("field %q = %v, want %v", field, number, want)
		}
	}

	listBody := decode("/api/tunnels")
	if total, _ := listBody["total"].(float64); total != 1 {
		t.Fatalf("total = %v, want 1", listBody["total"])
	}
	tunnels, ok := listBody["tunnels"].([]any)
	if !ok || len(tunnels) != 1 {
		t.Fatalf("tunnels = %v, want one entry", listBody["tunnels"])
	}
	entry, ok := tunnels[0].(map[string]any)
	if !ok {
		t.Fatalf("tunnel entry = %T", tunnels[0])
	}
	requireNumber(entry, "rx_bytes", 1234)
	requireNumber(entry, "tx_bytes", 4321)
	requireNumber(entry, "rx_rate", 1234)
	requireNumber(entry, "tx_rate", 4321)
	if got, _ := entry["tunnel_id"].(string); got != "t-1" {
		t.Fatalf("tunnel_id = %q, want t-1", got)
	}
	if got, _ := entry["status"].(string); got != TunnelStatusWaitingDevice {
		t.Fatalf("status = %q, want %q (existing field semantics must not change)", got, TunnelStatusWaitingDevice)
	}

	single := decode("/api/tunnels/t-1")
	requireNumber(single, "rx_bytes", 1234)
	requireNumber(single, "tx_bytes", 4321)
	requireNumber(single, "rx_rate", 1234)
	requireNumber(single, "tx_rate", 4321)
}

// 从持久化定义恢复的隧道也必须带运行时统计（不能只在 CreateTunnel 初始化）。
func TestLoadedTunnelHasRuntimeStats(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)

	tm.LoadDefinitions([]TunnelState{{
		TunnelID:   "t-loaded",
		ClientID:   "dev-1",
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1",
		LocalPort:  22,
		PublicPort: testTunnelPortStart,
		Exposure:   "public",
		CreatedAt:  time.Now(),
	}})
	tunnel := mustTunnel(t, tm, "t-loaded")
	if tunnel.stats == nil {
		t.Fatal("a tunnel restored from state must carry runtime stats")
	}

	tunnel.stats.addRX(512)
	tm.sampleRates()
	if _, _, rxRate, _ := tunnel.statsSnapshot(); rxRate != 512 {
		t.Fatalf("loaded tunnel rx_rate = %d, want 512", rxRate)
	}
}
