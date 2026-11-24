package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// trafficBase 是所有桶边界用例的时间基准：整分钟，30s/600s 桶都对齐。
var trafficBase = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func atOffset(seconds int) time.Time {
	return trafficBase.Add(time.Duration(seconds) * time.Second)
}

// ① 桶平均：sum/count，未满的当前桶按已采样秒数折算——除整段会把它说慢 15 倍。
func TestTrafficRingAveragesBuckets(t *testing.T) {
	t.Parallel()
	ring := newTrafficRing(trafficShortInterval, trafficShortPoints)

	ring.record(atOffset(1), 100, 1000)
	ring.record(atOffset(2), 300, 3000)

	rx, tx := ring.snapshot(atOffset(5), trafficShortPoints)
	last := trafficShortPoints - 1
	if rx[last] != 200 || tx[last] != 2000 {
		t.Fatalf("current bucket = (%d, %d) B/s, want (200, 2000): sum/count, not sum/interval", rx[last], tx[last])
	}
	for i := 0; i < last; i++ {
		if rx[i] != 0 || tx[i] != 0 {
			t.Fatalf("bucket %d has data before any sample: (%d, %d)", i, rx[i], tx[i])
		}
	}

	// 跨桶：上一桶的平均必须留在原处，新桶从 0 开始重新算。
	ring.record(atOffset(31), 900, 900)
	rx, tx = ring.snapshot(atOffset(32), trafficShortPoints)
	if rx[last] != 900 || tx[last] != 900 {
		t.Fatalf("new bucket = (%d, %d), want (900, 900)", rx[last], tx[last])
	}
	if rx[last-1] != 200 || tx[last-1] != 2000 {
		t.Fatalf("previous bucket = (%d, %d), want (200, 2000) unchanged", rx[last-1], tx[last-1])
	}
}

// ② 环形覆盖：写满后回绕，只留最近 points 个桶，且顺序仍是时间升序。
func TestTrafficRingWrapKeepsLastPoints(t *testing.T) {
	t.Parallel()
	const points = 4
	ring := newTrafficRing(trafficShortInterval, points)

	for k := 0; k < 6; k++ {
		ring.record(atOffset(k*30), uint64(10*(k+1)), 0)
	}

	rx, _ := ring.snapshot(atOffset(5*30), points)
	want := []uint64{30, 40, 50, 60} // k=2,3,4,5；k=0,1 已被回绕覆盖
	if len(rx) != points {
		t.Fatalf("snapshot length = %d, want %d (fixed length is part of the contract)", len(rx), points)
	}
	for i := range want {
		if rx[i] != want[i] {
			t.Fatalf("after wrap rx = %v, want %v", rx, want)
		}
	}
}

// ③ 空桶必须清零：跨越多个桶后，中间没采样的区间是 0，不是上一轮的旧值。
func TestTrafficRingGapAndClockRollback(t *testing.T) {
	t.Parallel()
	ring := newTrafficRing(trafficShortInterval, 4)

	// 小缺口：k=0 有数据，k=1 没采样，k=2 有数据。
	ring.record(atOffset(0), 100, 0)
	ring.record(atOffset(60), 300, 0)
	rx, _ := ring.snapshot(atOffset(60), 4) // 窗口 k=-1,0,1,2
	want := []uint64{0, 100, 0, 300}
	if len(rx) != 4 || rx[0] != want[0] || rx[1] != want[1] || rx[2] != want[2] || rx[3] != want[3] {
		t.Fatalf("gap buckets = %v, want %v (missing samples must be 0, never stale)", rx, want)
	}

	// 大缺口：超过整圈容量，旧数据必须全部作废。
	big := newTrafficRing(trafficShortInterval, 4)
	big.record(atOffset(0), 100, 0)
	big.record(atOffset(130), 200, 0) // 间隔 4 个桶 = 整圈
	rx, _ = big.snapshot(atOffset(130), 4)
	want = []uint64{0, 0, 0, 200}
	for i := range want {
		if rx[i] != want[i] {
			t.Fatalf("after a full-ring gap rx = %v, want %v", rx, want)
		}
	}

	// 回绕 + 缺口复用旧槽位：推进过期桶时必须把 sum/count 清零，否则上一圈
	// 的字节会被算进新桶（平均值被旧数据污染）。
	reuse := newTrafficRing(trafficShortInterval, 4)
	for k := 0; k < 4; k++ {
		reuse.record(atOffset(k*30), uint64(100*(k+1)), 0) // 100/200/300/400
	}
	reuse.record(atOffset(6*30), 1000, 0) // 跳 3 个桶，槽位 0/1/2 会被复用
	rx, _ = reuse.snapshot(atOffset(6*30), 4)
	want = []uint64{400, 0, 0, 1000}
	for i := range want {
		if rx[i] != want[i] {
			t.Fatalf("stale buckets survived the wrap: rx = %v, want %v", rx, want)
		}
	}

	// 时钟回拨：不覆盖已经画出来的历史。
	rollback := newTrafficRing(trafficShortInterval, 4)
	rollback.record(atOffset(30), 100, 0)
	rollback.record(atOffset(0), 500, 0)
	rx, _ = rollback.snapshot(atOffset(30), 2)
	if rx[0] != 0 || rx[1] != 100 {
		t.Fatalf("clock rollback overwrote history: %v, want [0 100]", rx)
	}
}

// ④ 窗口形状：1h=30s×120，24h=600s×144；未知窗口返回 false。
func TestTunnelTrafficWindowShape(t *testing.T) {
	t.Parallel()
	tunnel := Tunnel{TunnelID: "t-1", stats: newTunnelStats()}

	cases := []struct {
		window   string
		interval int
		points   int
	}{
		{trafficWindow1h, 30, 120},
		{trafficWindow24h, 600, 144},
	}
	for _, tc := range cases {
		response, ok := tunnel.TunnelTraffic(tc.window, trafficBase)
		if !ok {
			t.Fatalf("window %q rejected", tc.window)
		}
		if response.Window != tc.window || response.IntervalSeconds != tc.interval || response.Points != tc.points {
			t.Fatalf("window %q = {%s %d %d}, want {%s %d %d}", tc.window,
				response.Window, response.IntervalSeconds, response.Points, tc.window, tc.interval, tc.points)
		}
		if len(response.RX) != tc.points || len(response.TX) != tc.points {
			t.Fatalf("window %q arrays = (%d, %d), want %d", tc.window, len(response.RX), len(response.TX), tc.points)
		}
		for i := range response.RX {
			if response.RX[i] != 0 || response.TX[i] != 0 {
				t.Fatalf("fresh tunnel must report zeros, bucket %d = (%d, %d)", i, response.RX[i], response.TX[i])
			}
		}
	}

	if _, ok := tunnel.TunnelTraffic("7d", trafficBase); ok {
		t.Fatal("an unknown window must be rejected, not silently defaulted")
	}
	// 没有 stats 的隧道（测试夹具或历史中构造的对象）同样是全长全 0，不能 panic。
	bare := Tunnel{TunnelID: "t-2"}
	for _, window := range []string{trafficWindow1h, trafficWindow24h} {
		response, ok := bare.TunnelTraffic(window, trafficBase)
		if !ok || len(response.RX) != response.Points {
			t.Fatalf("window %q on a stats-less tunnel = %v len=%d", window, ok, len(response.RX))
		}
	}
}

// ⑤ 采样进历史：速率采样协程算出的差值必须同时折进两条环。
func TestTrafficHistoryFollowsSampling(t *testing.T) {
	t.Parallel()
	tm, tunnel := newRateTestManager(t)

	tunnel.stats.addRX(120)
	tunnel.stats.addTX(240)
	tm.sampleRatesAt(atOffset(1))
	tunnel.stats.addRX(80)
	tm.sampleRatesAt(atOffset(2))

	response, ok := tunnel.TunnelTraffic(trafficWindow1h, atOffset(3))
	if !ok {
		t.Fatal("1h window rejected")
	}
	last := response.Points - 1
	// rx: (120+80)/2 = 100；tx: (240+0)/2 = 120 —— 第二个周期没有 tx 流量。
	if response.RX[last] != 100 || response.TX[last] != 120 {
		t.Fatalf("current bucket = (%d, %d) B/s, want (100, 120)", response.RX[last], response.TX[last])
	}

	// 24h 环用同一个 600s 桶，两个样本都落在桶开头。
	response24, ok := tunnel.TunnelTraffic(trafficWindow24h, atOffset(3))
	if !ok {
		t.Fatal("24h window rejected")
	}
	last24 := response24.Points - 1
	if response24.RX[last24] != 100 || response24.TX[last24] != 120 {
		t.Fatalf("24h current bucket = (%d, %d), want (100, 120)", response24.RX[last24], response24.TX[last24])
	}
}

// ⑥ 重启归零：历史是内存态，新进程造出来的隧道没有任何桶数据。
func TestTrafficHistoryStartsEmptyAfterRestart(t *testing.T) {
	t.Parallel()
	tm, tunnel := newRateTestManager(t)
	tunnel.stats.addRX(4096)
	tm.sampleRatesAt(atOffset(1))
	if response, _ := tunnel.TunnelTraffic(trafficWindow1h, atOffset(2)); response.RX[response.Points-1] == 0 {
		t.Fatal("sampling did not reach the history, so this test would prove nothing")
	}

	// 重启后的对象：同一 tunnel_id，全新的运行时统计（不进 state schema）。
	restarted := Tunnel{TunnelID: tunnel.TunnelID, stats: newTunnelStats()}
	for _, window := range []string{trafficWindow1h, trafficWindow24h} {
		response, ok := restarted.TunnelTraffic(window, atOffset(2))
		if !ok {
			t.Fatalf("window %q rejected", window)
		}
		for i := range response.RX {
			if response.RX[i] != 0 || response.TX[i] != 0 {
				t.Fatalf("window %q bucket %d survived a restart: (%d, %d)", window, i, response.RX[i], response.TX[i])
			}
		}
	}
}

// ⑦ HTTP 形状：字段名、默认窗口、400/404 与「存在但没数据」的区别。
func TestTunnelTrafficAPI(t *testing.T) {
	t.Parallel()
	tm, tunnel := newRateTestManager(t)
	tunnel.stats.addRX(600)
	tm.sampleRatesAt(atOffset(1))

	srv := &Server{tunnelManager: tm}
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/api/tunnels/:tunnel_id/traffic", srv.handleAPITunnelTraffic)

	get := func(t *testing.T, target string) (int, map[string]any) {
		t.Helper()
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		var body map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		return recorder.Code, body
	}

	code, body := get(t, "/api/tunnels/t-1/traffic")
	if code != http.StatusOK {
		t.Fatalf("default window = %d, want 200: %v", code, body)
	}
	for _, field := range []string{"window", "interval_seconds", "points", "rx", "tx"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("field %q missing from the traffic response: %v", field, body)
		}
	}
	if body["window"] != trafficWindow1h || body["interval_seconds"] != float64(30) || body["points"] != float64(120) {
		t.Fatalf("default window body = %v", body)
	}
	rx, ok := body["rx"].([]any)
	if !ok || len(rx) != 120 {
		t.Fatalf("rx = %T len=%d, want 120 numbers", body["rx"], len(rx))
	}
	if _, ok := rx[119].(float64); !ok {
		t.Fatalf("rx entries must be JSON numbers, got %T", rx[119])
	}

	if code, body = get(t, "/api/tunnels/t-1/traffic?window=24h"); code != http.StatusOK {
		t.Fatalf("24h window = %d: %v", code, body)
	}
	if body["interval_seconds"] != float64(600) || body["points"] != float64(144) {
		t.Fatalf("24h body = %v", body)
	}

	if code, _ = get(t, "/api/tunnels/t-1/traffic?window=7d"); code != http.StatusBadRequest {
		t.Fatalf("unknown window = %d, want 400", code)
	}
	if code, _ = get(t, "/api/tunnels/missing/traffic"); code != http.StatusNotFound {
		t.Fatalf("unknown tunnel = %d, want 404", code)
	}
	if code, _ = get(t, "/api/tunnels/missing/traffic?window=7d"); code != http.StatusNotFound {
		t.Fatalf("unknown tunnel with a bad window = %d, want 404 (tunnel first)", code)
	}
}

// ⑧ 路由在认证组里：未登录 401，登录后能拿到数据；历史不混进 /api/tunnels 列表。
func TestTunnelTrafficRouteIsAuthenticated(t *testing.T) {
	t.Parallel()
	srv := newObserveTestServer(t)
	tm := NewTunnelManager(srv, 24000, 24100)
	t.Cleanup(tm.CloseAll)
	tm.mu.Lock()
	tm.tunnels["tun-1"] = &Tunnel{TunnelID: "tun-1", ClientID: "dev-1", Status: TunnelStatusActive, stats: newTunnelStats()}
	tm.rebuildTunnelOwnerLocked()
	tm.mu.Unlock()
	srv.tunnelManager = tm

	routeFound := false
	for _, route := range srv.engine.Routes() {
		if route.Method == http.MethodGet && route.Path == "/api/tunnels/:tunnel_id/traffic" {
			routeFound = true
		}
	}
	if !routeFound {
		t.Fatal("/api/tunnels/:tunnel_id/traffic is not registered")
	}

	do := func(target string, cookie *http.Cookie) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if cookie != nil {
			request.AddCookie(cookie)
		}
		recorder := httptest.NewRecorder()
		srv.engine.ServeHTTP(recorder, request)
		return recorder
	}

	if code := do("/api/tunnels/tun-1/traffic", nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated traffic = %d, want 401", code)
	}

	token, err := srv.adminAuth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	recorder := do("/api/tunnels/tun-1/traffic", &http.Cookie{Name: "go_remote_token", Value: token})
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated traffic = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response TunnelTrafficResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode traffic: %v", err)
	}
	if response.Points != 120 || len(response.RX) != 120 || len(response.TX) != 120 {
		t.Fatalf("traffic response = %+v", response)
	}

	// 列表接口只带累计值与速率，不背历史数组（2 秒轮询会扛不住）。
	list := do("/api/tunnels", &http.Cookie{Name: "go_remote_token", Value: token})
	var listBody struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode tunnel list: %v", err)
	}
	if len(listBody.Tunnels) != 1 {
		t.Fatalf("tunnel list = %d entries, want 1", len(listBody.Tunnels))
	}
	for _, field := range []string{"rx", "tx"} {
		if _, ok := listBody.Tunnels[0][field]; ok {
			t.Fatalf("the tunnel list must not carry %q history", field)
		}
	}
}

// ⑨ 并发读写：采样协程写、HTTP 读，-race 下必须干净（各用各的锁）。
func TestTrafficHistoryConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	tm, tunnel := newRateTestManager(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			tunnel.stats.addRX(64)
			tunnel.stats.addTX(32)
			tm.sampleRatesAt(atOffset(i))
		}
	}()

	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if response, ok := tunnel.TunnelTraffic(trafficWindow1h, atOffset(j)); !ok || len(response.RX) != 120 {
					t.Errorf("1h read = %v len=%d", ok, len(response.RX))
					return
				}
				if response, ok := tunnel.TunnelTraffic(trafficWindow24h, atOffset(j)); !ok || len(response.TX) != 144 {
					t.Errorf("24h read = %v len=%d", ok, len(response.TX))
					return
				}
			}
		}()
	}

	close(stop)
	wg.Wait()
}
