package agent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/buildinfo"
)

// captureHandshake 起一个假服务端：记录 agent 带来的整组 query，按 headers 回 101。
func captureHandshake(t *testing.T, headers http.Header) (string, <-chan url.Values) {
	t.Helper()
	captured := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- r.URL.Query()
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, headers)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(50 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://"), captured
}

// TestHandshakeCarriesBuildIdentity 钉住 agent→server 的握手参数：ver/commit
// 来自构建信息，caps 来自能力位。它们走 query 而不是 JSON，正是为了不碰
// 严格解码的注册报文。
func TestHandshakeCarriesBuildIdentity(t *testing.T) {
	previous := buildinfo.Version
	buildinfo.Version = "v2.8.0"
	t.Cleanup(func() { buildinfo.Version = previous })

	headers := http.Header{}
	headers.Set("X-Goremote-Proto", "2")
	headers.Set("X-Goremote-Caps", "obs,aad,obs")
	addr, captured := captureHandshake(t, headers)

	connector := NewConnector(addr, false, "", false, nil)
	if err := connector.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer connector.Close()

	query := <-captured
	if got := query.Get("proto"); got != "2" {
		t.Fatalf("proto = %q, want 2", got)
	}
	if got := query.Get("ver"); got != "v2.8.0" {
		t.Fatalf("ver = %q, want v2.8.0", got)
	}
	if got := query.Get("commit"); got == "" || got == "dev" {
		// 从源码目录构建时一定有 vcs.revision；从临时目录构建才回落 dev。
		t.Logf("commit = %q (dev build, acceptable)", got)
	}

	// 服务端能力位：去重排序后读回。
	if got := connector.ServerCaps(); !reflect.DeepEqual(got, []string{"aad", "obs"}) {
		t.Fatalf("ServerCaps = %v, want [aad obs]", got)
	}
	if got := connector.ServerProto(); got != 2 {
		t.Fatalf("ServerProto = %d, want 2", got)
	}
}

// TestHandshakeLegacyAgentSendsNothing 是兼容矩阵里「老 agent × 新服务端」那一格：
// 不带任何参数时，agent 必须确认自己按 v1 工作，不能猜、不能回退尝试。
func TestHandshakeLegacyAgentSendsNothing(t *testing.T) {
	// 假服务端什么都不回：等价于 v2.8.0 之前的服务端。
	addr, captured := captureHandshake(t, http.Header{})

	connector := NewConnector(addr, false, "", false, nil)
	connector.legacyHandshake = true
	if err := connector.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer connector.Close()

	query := <-captured
	if len(query) != 0 {
		t.Fatalf("a legacy handshake must send no params, got %v", query)
	}
	if got := connector.ServerProto(); got != 1 {
		t.Fatalf("ServerProto = %d, want 1 (no proto header)", got)
	}
	if connector.AADEnabled() {
		t.Fatal("AAD must stay disabled when the server does not negotiate it")
	}
	if got := connector.ServerCaps(); len(got) != 0 {
		t.Fatalf("ServerCaps = %v, want none", got)
	}
}

// TestHandshakeVersionIsSanitized 保证启用了注入的怪版本也按协议上界被清洗。
func TestHandshakeVersionIsSanitized(t *testing.T) {
	previous := buildinfo.Version
	buildinfo.Version = "v2.8.0\x00; rm -rf /"
	t.Cleanup(func() { buildinfo.Version = previous })

	addr, captured := captureHandshake(t, http.Header{})
	connector := NewConnector(addr, false, "", false, nil)
	if err := connector.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer connector.Close()

	query := <-captured
	version := query.Get("ver")
	if strings.ContainsAny(version, " \x00;/") {
		t.Fatalf("ver = %q, sanitization did not run", version)
	}
	if len(version) > buildinfo.MaxVersionLen {
		t.Fatalf("ver = %q, longer than %d", version, buildinfo.MaxVersionLen)
	}
}
