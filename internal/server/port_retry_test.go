package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// captureHandler 收集日志文本，用来断言「窗口耗尽」那条 WARN 确实打出来了。
type captureHandler struct {
	mu       sync.Mutex
	messages []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	h.messages = append(h.messages, record.Message)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) contains(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, message := range h.messages {
		if len(substr) <= len(message) && stringContains(message, substr) {
			return true
		}
	}
	return false
}

func stringContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// setupPortConflictTunnel 造一条端口被外部占用的定义，并触发一次 apply，
// 使隧道进入 port_conflict 且自动重试协程已经启动。
func setupPortConflictTunnel(t *testing.T, configure func(*TunnelManager)) (*TunnelManager, *Client, net.Listener) {
	t.Helper()
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	clients := NewClientManager()
	clients.SetStore(store)

	port := testTunnelPortStart + 40
	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	t.Cleanup(func() { blocker.Close() })

	tm := newTunnelTestManager(t, store, clients, testTunnelPortStart, testTunnelPortEnd)
	if configure != nil {
		configure(tm)
	}
	if err := tm.CreateTunnel("conflicted", "dev-1", nil, "tcp", "127.0.0.1", 22, port, "public"); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	serverConn, _ := newTestWebsocketPair(t)
	client := &Client{ClientID: "dev-1", Conn: serverConn}
	clients.Add(client)
	tm.RestoreClient(client)
	waitForCondition(t, 2*time.Second, func() bool {
		tunnel, ok := tm.GetTunnel("conflicted")
		return ok && tunnel.Status == TunnelStatusPortConflict
	}, "the tunnel should report port_conflict while the port is occupied")
	return tm, client, blocker
}

// 窗口用尽后停止自动重试，并打出可执行的 WARN。
func TestPortConflictRetryStopsAfterWindow(t *testing.T) {
	exit := make(chan string, 1)
	configure := func(tm *TunnelManager) {
		tm.retryDelays = []time.Duration{10 * time.Millisecond}
		tm.retryWindow = 30 * time.Millisecond
		tm.retryExitHook = func(tunnelID, reason string) {
			if tunnelID == "conflicted" {
				select {
				case exit <- reason:
				default:
				}
			}
		}
	}

	originalLogger := slog.Default()
	handler := &captureHandler{}
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(originalLogger)

	tm, _, blocker := setupPortConflictTunnel(t, configure)

	select {
	case reason := <-exit:
		if reason != "window exhausted" {
			t.Fatalf("retry goroutine exited with %q, want window exhausted", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the automatic retry goroutine never gave up")
	}

	tunnel, ok := tm.GetTunnel("conflicted")
	if !ok {
		t.Fatal("the definition must be kept after retries give up")
	}
	if tunnel.Status != TunnelStatusPortConflict {
		t.Fatalf("status = %q, want port_conflict", tunnel.Status)
	}
	tm.mu.RLock()
	retrying := tm.tunnels["conflicted"].retrying
	tm.mu.RUnlock()
	if retrying {
		t.Fatal("retrying flag must be cleared once the window is exhausted")
	}
	if !handler.contains("stopped automatic retries, retry manually") {
		t.Fatal("the exhaustion WARN with manual-retry guidance was not logged")
	}

	// 端口之后释放，也不该再被自动绑上（自动重试已经停手）。
	blocker.Close()
	time.Sleep(100 * time.Millisecond)
	if tunnel, _ := tm.GetTunnel("conflicted"); tunnel.Status == TunnelStatusActive {
		t.Fatal("automatic retries must not resume after the window is exhausted")
	}
}

// 自动重试还在退避时，人工重试必须能立刻生效。
func TestManualRetryWorksWhileAutoRetryPending(t *testing.T) {
	exit := make(chan string, 1)
	tm, _, blocker := setupPortConflictTunnel(t, func(tm *TunnelManager) {
		tm.retryDelays = []time.Duration{300 * time.Millisecond}
		tm.retryExitHook = func(tunnelID, reason string) {
			if tunnelID == "conflicted" {
				select {
				case exit <- reason:
				default:
				}
			}
		}
	})

	// 自动重试协程此时还在退避；释放端口后立刻人工重试。
	blocker.Close()
	updated, err := tm.RetryTunnel("conflicted")
	if err != nil {
		t.Fatalf("manual retry: %v", err)
	}
	if updated.Status != TunnelStatusActive {
		t.Fatalf("manual retry status = %q, want active", updated.Status)
	}

	// 自动重试醒来后必须发现已经绑好并退出（不会重复 bind 或覆盖状态）。
	select {
	case reason := <-exit:
		if reason != "tunnel resolved or removed" {
			t.Fatalf("auto retry exited with %q, want tunnel resolved or removed", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the auto retry goroutine did not exit after the tunnel became active")
	}
	if tunnel, _ := tm.GetTunnel("conflicted"); tunnel.Status != TunnelStatusActive {
		t.Fatalf("status after exit = %q, want active", tunnel.Status)
	}
}

// 隧道被删除后，自动重试协程必须退出（不泄漏）。
func TestPortConflictRetryExitsWhenTunnelDeleted(t *testing.T) {
	exit := make(chan string, 1)
	tm, _, _ := setupPortConflictTunnel(t, func(tm *TunnelManager) {
		tm.retryDelays = []time.Duration{50 * time.Millisecond}
		tm.retryExitHook = func(tunnelID, reason string) {
			if tunnelID == "conflicted" {
				select {
				case exit <- reason:
				default:
				}
			}
		}
	})

	if _, err := tm.DeleteTunnel("conflicted"); err != nil {
		t.Fatalf("DeleteTunnel: %v", err)
	}

	select {
	case reason := <-exit:
		if reason != "tunnel resolved or removed" {
			t.Fatalf("retry goroutine exited with %q, want tunnel resolved or removed", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the retry goroutine kept running after the tunnel was deleted")
	}
}
