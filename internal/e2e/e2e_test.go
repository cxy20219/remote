package e2e

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"goremote/internal/agent"
	"goremote/internal/buildinfo"
	"goremote/internal/server"
)

const adminPassword = "TestPassword123!"

// tunnelPortRange 刻意避开其它包用到的端口段：go test ./... 会并行跑多个包，
// 端口撞上会变成「偶发失败」，比测试失败更难查。
const (
	tunnelPortStart = 31000
	tunnelPortEnd   = 31100
)

// harness 把一次 E2E 需要的三样东西放一起：真 server、带会话 cookie 的 HTTP
// 客户端、以及已经被测试接管的后台进程。
type harness struct {
	t        *testing.T
	baseURL  string
	dataDir  string
	client   *http.Client
	srv      *server.Server
	agents   []*agent.Agent
	identity string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dataDir := t.TempDir()
	statePath := filepath.Join(dataDir, "server-state.json")
	store := server.NewStateStore(statePath)
	if err := store.Load(); err != nil {
		t.Fatalf("create the initial state: %v", err)
	}
	if _, err := store.SetInitialAdminPassword(adminPassword); err != nil {
		t.Fatalf("set the admin password: %v", err)
	}
	store.UpdateSettings(func(settings *server.ServerSettings) {
		settings.PortRangeStart = tunnelPortStart
		settings.PortRangeEnd = tunnelPortEnd
	})
	if err := store.Save(); err != nil {
		t.Fatalf("persist the settings: %v", err)
	}

	port := freePort(t)
	config := &server.Config{
		Server: server.ServerConfig{Host: "127.0.0.1", Port: port},
		// AAD 打开：proto=2 路径真的走 v2 帧（AAD 绑定帧头），老 agent 仍走 v1。
		Tunnel: server.TunnelConfig{Enabled: true, AAD: true},
	}
	config.SetDataDir(dataDir)
	srv, err := server.NewServer(config, embed.FS{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	h := &harness{
		t:        t,
		baseURL:  "http://127.0.0.1:" + strconv.Itoa(port),
		dataDir:  dataDir,
		srv:      srv,
		identity: filepath.Join(t.TempDir(), "identity"),
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second}

	go func() { _ = srv.Start() }()
	// LIFO：先注册 server 的清理，后注册 agent 的，这样 agent 先停、server 后停。
	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Logf("server stop: %v", err)
		}
	})

	h.waitFor("server /health", 15*time.Second, func() (bool, string) {
		status, _, err := h.request(http.MethodGet, "/health", nil)
		if err != nil {
			return false, err.Error()
		}
		return status == http.StatusOK, fmt.Sprintf("status=%d", status)
	})

	status, body, err := h.request(http.MethodPost, "/api/login", map[string]string{"password": adminPassword})
	if err != nil || status != http.StatusOK {
		t.Fatalf("admin login: status=%d err=%v body=%s", status, err, body)
	}
	return h
}

// startAgent 起一个真 agent 并等它连上服务端。
func (h *harness) startAgent(legacy bool) *agent.Agent {
	h.t.Helper()

	identity, err := agent.LoadIdentity(h.identity)
	if err != nil {
		h.t.Fatalf("load identity: %v", err)
	}
	if identity == nil {
		identity, err = agent.CreateIdentity(h.identity, h.baseURL[len("http://"):])
		if err != nil {
			h.t.Fatalf("create identity: %v", err)
		}
	}

	config := agent.DefaultConfig()
	config.Server.Address = h.baseURL[len("http://"):]
	config.IdentityDir = h.identity
	config.Agent.Hostname = "e2e-agent"
	config.Agent.OS = "linux"
	// 默认重连间隔 5s：断线重连用例里会让测试白等，压到 1s 仍在真实路径上。
	config.Reconnect.Interval = 1
	config.Reconnect.MaxInterval = 2
	config.Heartbeat.Interval = 2
	config.Server.LegacyHandshake = legacy

	instance := agent.NewAgent(config, identity)
	go func() { _ = instance.Run() }()
	h.agents = append(h.agents, instance)
	h.t.Cleanup(func() { instance.Stop() })
	return instance
}

// stopAgent 主动断开，模拟网络中断/进程被杀。
func (h *harness) stopAgent(instance *agent.Agent) {
	instance.Stop()
}

func (h *harness) request(method, path string, payload any) (int, string, error) {
	h.t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return 0, "", err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, h.baseURL+path, body)
	if err != nil {
		return 0, "", err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := h.client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, "", err
	}
	return response.StatusCode, string(raw), nil
}

// waitFor 轮询到条件成立；失败时把最后观察到的东西带出来，免得只看到 timeout。
func (h *harness) waitFor(step string, timeout time.Duration, check func() (bool, string)) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	last := "no attempt"
	for time.Now().Before(deadline) {
		ok, detail := check()
		if ok {
			return
		}
		last = detail
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("%s: timed out after %s (last observed: %s)", step, timeout, last)
}

// waitForPendingDevice 等 agent 的注册申请出现在待审批列表里。
func (h *harness) waitForPendingDevice() string {
	h.t.Helper()
	deviceID := ""
	h.waitFor("device shows up as pending", 20*time.Second, func() (bool, string) {
		status, body, err := h.request(http.MethodGet, "/api/devices/pending", nil)
		if err != nil || status != http.StatusOK {
			return false, fmt.Sprintf("status=%d err=%v", status, err)
		}
		var payload struct {
			Devices []struct {
				ID string `json:"id"`
			} `json:"devices"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			return false, "decode pending list: " + err.Error()
		}
		if payload.Total == 0 {
			return false, "no pending device yet"
		}
		deviceID = payload.Devices[0].ID
		return true, ""
	})
	return deviceID
}

func (h *harness) approve(deviceID string) {
	h.t.Helper()
	status, body, err := h.request(http.MethodPost, "/api/devices/pending/"+deviceID+"/approve", nil)
	if err != nil || status != http.StatusOK {
		h.t.Fatalf("approve %s: status=%d err=%v body=%s", deviceID, status, err, body)
	}
}

// createTunnel 建一条隧道。审批通过后 agent 才被登记成正式 client，这里用 404
// 当作「还没就绪」重试——404 发生在占用端口之前，重试不会留下半条定义。
func (h *harness) createTunnel(clientID string, localPort int) (tunnelID string, publicPort int) {
	h.t.Helper()
	h.waitFor("device is registered as an online client", 20*time.Second, func() (bool, string) {
		status, body, err := h.request(http.MethodPost, "/api/tunnels", map[string]any{
			"client_id":  clientID,
			"local_addr": "127.0.0.1",
			"local_port": localPort,
			"protocol":   "tcp",
			"exposure":   "public",
		})
		if err != nil {
			return false, err.Error()
		}
		if status == http.StatusNotFound {
			return false, "client not online yet"
		}
		if status != http.StatusOK {
			return false, fmt.Sprintf("status=%d body=%s", status, body)
		}
		var payload struct {
			TunnelID   string `json:"tunnel_id"`
			PublicPort int    `json:"public_port"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			return false, "decode create response: " + err.Error()
		}
		tunnelID, publicPort = payload.TunnelID, payload.PublicPort
		return true, ""
	})
	return tunnelID, publicPort
}

// waitForTunnelStatus 等某条隧道进入期望状态。
func (h *harness) waitForTunnelStatus(tunnelID, want string) {
	h.t.Helper()
	last := ""
	h.waitFor("tunnel "+tunnelID+" becomes "+want, 20*time.Second, func() (bool, string) {
		status, body, err := h.request(http.MethodGet, "/api/tunnels", nil)
		if err != nil || status != http.StatusOK {
			return false, fmt.Sprintf("status=%d err=%v", status, err)
		}
		var payload struct {
			Tunnels []struct {
				TunnelID string `json:"tunnel_id"`
				Status   string `json:"status"`
				LastErr  string `json:"last_error"`
			} `json:"tunnels"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			return false, "decode tunnel list: " + err.Error()
		}
		for _, tunnel := range payload.Tunnels {
			if tunnel.TunnelID != tunnelID {
				continue
			}
			last = tunnel.Status + " " + tunnel.LastErr
			return tunnel.Status == want, last
		}
		last = "tunnel not in the list"
		return false, last
	})
}

// echoRoundTrip 经公网隧道端口把 payload 打到本地 echo 服务，再读回同样的字节。
// 这一步同时覆盖了 server→agent 的 tunnel_open、agent 连本地服务、双向数据帧、
// 以及 server 把响应写回公网连接。
func (h *harness) echoRoundTrip(publicPort int, payload string) {
	h.t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		h.t.Fatalf("dial the public tunnel port %s: %v", address, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		h.t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		h.t.Fatalf("write through the tunnel: %v", err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		h.t.Fatalf("read the echoed bytes back: %v", err)
	}
	if string(buffer) != payload {
		h.t.Fatalf("echo mismatch: sent %q, got %q", payload, string(buffer))
	}
}

// startEchoServer 起一个回显的本地服务，agent 侧把它当 tunnel 的 local_port。
func startEchoServer(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the echo service: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// TestAgentLifecycleEndToEnd 是阶段四的 E2E 验收：注册 → 审批 → 建隧道 →
// 数据往返 → 断线 → 用同一身份重连 → 隧道恢复 → 再往返一次。
func runLifecycle(t *testing.T, legacy bool, wantVersion string) {
	t.Helper()
	h := newHarness(t)
	echoPort := startEchoServer(t)

	t.Log("step 1: agent registers and shows up as pending")
	first := h.startAgent(legacy)
	deviceID := h.waitForPendingDevice()

	t.Log("step 2: admin approves the device")
	h.approve(deviceID)

	t.Log("step 3: admin creates a tunnel to the local echo service")
	tunnelID, publicPort := h.createTunnel(deviceID, echoPort)
	if publicPort < tunnelPortStart || publicPort > tunnelPortEnd {
		t.Fatalf("public port %d is outside the configured range %d-%d", publicPort, tunnelPortStart, tunnelPortEnd)
	}

	t.Log("step 4: the tunnel becomes active and carries data")
	h.waitForTunnelStatus(tunnelID, server.TunnelStatusActive)
	h.echoRoundTrip(publicPort, "hello-through-the-tunnel")

	t.Log("step 5: the agent drops; the tunnel must leave the active state")
	h.stopAgent(first)
	h.waitForTunnelStatus(tunnelID, server.TunnelStatusWaitingDevice)

	t.Log("step 6: a new agent process reuses the same identity and reconnects")
	h.startAgent(legacy)
	h.waitForTunnelStatus(tunnelID, server.TunnelStatusActive)

	t.Log("step 7: data flows again after the reconnect")
	h.echoRoundTrip(publicPort, "hello-again-after-reconnect")

	// 版本可见性：新 agent 上报的版本入库、不标落后；老 agent 不带参数 → 空，
	// 且绝不能被标成「落后」（未知不等于旧）。
	device := h.device(deviceID)
	if device.AgentVersion != wantVersion {
		t.Fatalf("agent_version = %q, want %q (handshake legacy=%t)", device.AgentVersion, wantVersion, legacy)
	}
	if device.AgentOutdated {
		t.Fatalf("agent_outdated must be false for agent_version %q", device.AgentVersion)
	}

	// 重连用的是 reauth 路径，设备不能被当成新设备再审批一次。
	status, body, err := h.request(http.MethodGet, "/api/devices/pending", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("list pending devices: status=%d err=%v", status, err)
	}
	var pending struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &pending); err != nil {
		t.Fatalf("decode pending devices: %v", err)
	}
	if pending.Total != 0 {
		t.Fatalf("a reconnecting device must not become pending again, total=%d body=%s", pending.Total, body)
	}
}

// device 读取 /api/devices 里的一台设备（契约字段见 api.go 的 deviceInfo）。
func (h *harness) device(id string) struct {
	AgentVersion  string `json:"agent_version"`
	AgentOutdated bool   `json:"agent_outdated"`
} {
	h.t.Helper()
	status, body, err := h.request(http.MethodGet, "/api/devices", nil)
	if err != nil || status != http.StatusOK {
		h.t.Fatalf("list devices: status=%d err=%v body=%s", status, err, body)
	}
	var payload struct {
		Devices []struct {
			ID            string `json:"id"`
			AgentVersion  string `json:"agent_version"`
			AgentOutdated bool   `json:"agent_outdated"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		h.t.Fatalf("decode device list: %v", err)
	}
	for _, entry := range payload.Devices {
		if entry.ID == id {
			return struct {
				AgentVersion  string `json:"agent_version"`
				AgentOutdated bool   `json:"agent_outdated"`
			}{AgentVersion: entry.AgentVersion, AgentOutdated: entry.AgentOutdated}
		}
	}
	h.t.Fatalf("device %s is not in the list: %s", id, body)
	return struct {
		AgentVersion  string `json:"agent_version"`
		AgentOutdated bool   `json:"agent_outdated"`
	}{}
}

// TestAgentLifecycleEndToEnd 是阶段四的 E2E 硬门：proto=2 与 proto=1 各跑一遍
// 完整链路（注册→审批→建隧道→数据往返→断线重连→再往返）。
func TestAgentLifecycleEndToEnd(t *testing.T) {
	// 注入一个发布版本，让新 agent 真的上报 ver=；跑完还原，别影响同包其它用例。
	previous := buildinfo.Version
	buildinfo.Version = "v2.8.0"
	t.Cleanup(func() { buildinfo.Version = previous })

	cases := []struct {
		name        string
		legacy      bool
		wantVersion string
	}{
		{name: "proto2_new_agent_new_server", legacy: false, wantVersion: "v2.8.0"},
		{name: "proto1_old_agent_new_server", legacy: true, wantVersion: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			runLifecycle(t, testCase.legacy, testCase.wantVersion)
		})
	}
}

// TestHandshakeHeaders 直接盯协议契约：带 ?proto=2 才回协商头，老 agent
// 什么头都收不到（这正是「老 agent 天然忽略」的实现方式）。
func TestHandshakeHeaders(t *testing.T) {
	h := newHarness(t)
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}

	cases := []struct {
		name      string
		query     string
		wantProto string
		wantAAD   string
		wantCaps  string
	}{
		{name: "modern agent", query: "?proto=2", wantProto: "2", wantAAD: "1", wantCaps: "obs"},
		{name: "old agent (no query)", query: "", wantProto: "", wantAAD: "", wantCaps: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			url := "ws://" + strings.TrimPrefix(h.baseURL, "http://") + "/ws" + testCase.query
			conn, resp, err := dialer.Dial(url, nil)
			if err != nil {
				t.Fatalf("dial %s: %v", url, err)
			}
			defer conn.Close()
			if resp == nil {
				t.Fatal("no handshake response")
			}
			for header, want := range map[string]string{
				"X-Goremote-Proto": testCase.wantProto,
				"X-Goremote-AAD":   testCase.wantAAD,
				"X-Goremote-Caps":  testCase.wantCaps,
			} {
				if got := resp.Header.Get(header); got != want {
					t.Fatalf("%s = %q, want %q (query %q)", header, got, want, testCase.query)
				}
			}
		})
	}
}
