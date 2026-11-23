package server

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newTimeoutTestClient(t *testing.T, clientID string, lastPing time.Time) (*Client, *websocket.Conn) {
	t.Helper()
	serverConn, agentConn := newTestWebsocketPair(t)
	return &Client{ClientID: clientID, Conn: serverConn, LastPing: lastPing}, agentConn
}

// 只关超时的那一条，且日志/关闭都在锁外做（行为层面：干净地只影响 stale）。
func TestCheckClientsTimeoutClosesOnlyStaleClients(t *testing.T) {
	srv := &Server{clients: NewClientManager()}

	stale, staleAgent := newTimeoutTestClient(t, "client-stale", time.Time{})
	fresh, freshAgent := newTimeoutTestClient(t, "client-fresh", time.Time{})
	srv.clients.Add(stale)
	srv.clients.Add(fresh)

	// Add 会把 LastPing 重置为当前时间，所以过期时间必须在注册之后再改。
	srv.clients.mu.Lock()
	srv.clients.clients["client-stale"].LastPing = time.Now().Add(-2 * time.Minute)
	srv.clients.mu.Unlock()

	srv.checkClientsTimeout(30 * time.Second)

	// stale 连接必须被关闭：关掉会得到 close/EOF，而不是读超时。
	staleAgent.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := staleAgent.ReadMessage()
	if err == nil {
		t.Fatal("stale client connection should have been closed")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("stale connection was not closed; the read merely timed out")
	}

	// fresh 连接必须仍然可用。
	if err := fresh.Conn.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
		t.Fatalf("fresh client connection must stay open: %v", err)
	}
	freshAgent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, payload, err := freshAgent.ReadMessage(); err != nil || string(payload) != "pong" {
		t.Fatalf("fresh client read = %q, %v", payload, err)
	}

	// 锁内只做收集：清理后两个 client 都还在表里（由 readLoop 负责摘除），
	// 这里只确认没有在锁内做额外状态修改导致意外删除。
	if _, ok := srv.clients.Get("client-fresh"); !ok {
		t.Fatal("fresh client must remain registered")
	}
}

// 心跳 Touch 与超时清理并发：-race 下不得有告警。
func TestCheckClientsTimeoutConcurrentWithHeartbeat(t *testing.T) {
	srv := &Server{clients: NewClientManager()}
	client, _ := newTimeoutTestClient(t, "client-race", time.Now())
	srv.clients.Add(client)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			srv.checkClientsTimeout(time.Hour)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if !srv.clients.TouchIfMatch("client-race", client) {
				t.Error("registered client should be touchable")
				return
			}
		}
	}()
	wg.Wait()

	if _, ok := srv.clients.Get("client-race"); !ok {
		t.Fatal("client disappeared during concurrent heartbeat")
	}
}

// blockingHandler 在收到心跳超时日志时停在 Handle 里，用来检测这条日志
// 是不是在 clients.mu 内写的：如果持锁，TouchIfMatch 会跟着卡住。
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *blockingHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "client heartbeat timeout" {
		select {
		case h.entered <- struct{}{}:
		default:
		}
		<-h.release
	}
	return nil
}

func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingHandler) WithGroup(string) slog.Handler      { return h }

func TestHeartbeatTimeoutLoggingHappensOutsideClientsLock(t *testing.T) {
	original := slog.Default()
	handler := &blockingHandler{entered: make(chan struct{}, 1), release: make(chan struct{})}
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(original)

	srv := &Server{clients: NewClientManager()}
	stale, _ := newTimeoutTestClient(t, "client-stale", time.Time{})
	srv.clients.Add(stale)
	srv.clients.mu.Lock()
	srv.clients.clients["client-stale"].LastPing = time.Now().Add(-2 * time.Minute)
	srv.clients.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.checkClientsTimeout(30 * time.Second)
	}()

	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat timeout log was never emitted")
	}

	// 日志已经停在 Handle 里；此刻 clients.mu 必须可被 Touch 抢占。
	touched := make(chan bool, 1)
	go func() { touched <- srv.clients.TouchIfMatch("client-stale", stale) }()
	select {
	case ok := <-touched:
		if !ok {
			t.Fatal("TouchIfMatch could not find the registered client")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("clients.mu was held while writing the heartbeat timeout log; log outside the lock")
	}

	close(handler.release)
	<-done
}
