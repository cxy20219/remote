package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
)

// IPv6 同一 /64 内的不同地址必须共用一份违规预算：换地址不能把计数清零。
func TestBlacklistAggregatesIPv6ViolationsPer64(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(3, "")
	defer bm.Stop()

	if bm.AddViolation("2001:db8::1") {
		t.Fatal("first violation must not blacklist yet")
	}
	if bm.AddViolation("2001:db8::2") {
		t.Fatal("second violation must not blacklist yet")
	}
	if !bm.AddViolation("2001:db8::3") {
		t.Fatal("third violation in the same /64 must trip the threshold")
	}

	if !bm.IsBlacklisted("2001:db8::4") {
		t.Fatal("a different address in the blacklisted /64 must be blocked")
	}
	if bm.IsBlacklisted("2001:db9::1") {
		t.Fatal("a different /64 must not be blocked")
	}
	if got := bm.AllViolations()["2001:db8::/64"]; got != 0 {
		t.Fatalf("violation counter for the /64 should be cleared after blacklisting, got %d", got)
	}
}

// 手动封禁按单个地址记账，不能被 /64 聚合放大成整段封禁。
func TestBlacklistManualEntryStaysSingleAddress(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(10, "")
	defer bm.Stop()

	if err := bm.AddManual("2001:db8::5", "manual", time.Hour); err != nil {
		t.Fatalf("AddManual: %v", err)
	}
	if !bm.IsBlacklisted("2001:db8::5") {
		t.Fatal("the manually banned address must be blocked")
	}
	if bm.IsBlacklisted("2001:db8::6") {
		t.Fatal("manual bans must not spread to the rest of the /64")
	}
}

// IPv4 行为不能变：地址本身就是一个键。
func TestBlacklistIPv4AggregationUnchanged(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(2, "")
	defer bm.Stop()

	bm.AddViolation("192.0.2.9")
	if !bm.AddViolation("192.0.2.9") {
		t.Fatal("second IPv4 violation must trip the threshold")
	}
	if !bm.IsBlacklisted("192.0.2.9") {
		t.Fatal("the IPv4 address must be blocked")
	}
	if bm.IsBlacklisted("192.0.2.10") {
		t.Fatal("IPv4 bans must stay per-address")
	}
}

// 公网 accept 路径：同一 /64 换地址也要共用限流预算。
func TestExternalConnAllowedAggregatesIPv6Per64(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(1000, "")
	defer bm.Stop()
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	srv := &Server{blacklist: bm, clients: NewClientManager(), portLimiter: rl}
	tm := &TunnelManager{server: srv}
	tunnel := &Tunnel{TunnelID: "tunnel-1"}

	if !tm.externalConnAllowed(tunnel, "2001:db8::1") {
		t.Fatal("first address in the /64 should be allowed")
	}
	if !tm.externalConnAllowed(tunnel, "2001:db8::2") {
		t.Fatal("second address in the /64 should be allowed (within the budget)")
	}
	if tm.externalConnAllowed(tunnel, "2001:db8::3") {
		t.Fatal("third address in the same /64 must be rejected: the budget is per /64")
	}
	if !tm.externalConnAllowed(tunnel, "2001:db9::1") {
		t.Fatal("a different /64 must get its own budget")
	}
}

// 黑名单条目是 /64 聚合键时，accept 路径要按整段拒绝。
func TestExternalConnAllowedRejectsAggregatedBlacklist(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(2, "")
	defer bm.Stop()
	bm.AddViolation("2001:db8::1")
	if !bm.AddViolation("2001:db8::2") {
		t.Fatal("setup: expected the /64 to be blacklisted")
	}

	srv := &Server{blacklist: bm, clients: NewClientManager()}
	tm := &TunnelManager{server: srv}
	tunnel := &Tunnel{TunnelID: "tunnel-1"}

	if tm.externalConnAllowed(tunnel, "2001:db8::99") {
		t.Fatal("any address in the blacklisted /64 must be rejected")
	}
	if !tm.externalConnAllowed(tunnel, "2001:db9::1") {
		t.Fatal("a different /64 must not be affected")
	}
}

// 全局白名单与设备白名单继续免限流（反扫描策略），这是本项必须回归的行为。
func TestExternalConnAllowedKeepsWhitelistBypass(t *testing.T) {
	t.Parallel()
	bm := NewBlacklistManager(1000, "")
	defer bm.Stop()
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	srv := &Server{blacklist: bm, clients: NewClientManager(), portLimiter: rl}
	srv.globalWhitelist.Store(newIPMatcher([]string{"2001:db8::1"}))
	tm := &TunnelManager{server: srv}
	tunnel := &Tunnel{TunnelID: "tunnel-1"}

	if !tm.externalConnAllowed(tunnel, "2001:db8::1") {
		t.Fatal("global whitelist bypass failed")
	}
	if !tm.externalConnAllowed(tunnel, "2001:db8::1") {
		t.Fatal("global whitelisted address must not be rate limited")
	}

	// 设备白名单：设备在线且有白名单条目时，来源地址免限流。
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{
		ID:          "dev-whitelist",
		Status:      deviceStatusAuthorized,
		IPWhitelist: []string{"2001:db8:1::7"},
	})
	clients := NewClientManager()
	clients.SetStore(store)
	clients.Add(&Client{ClientID: "dev-whitelist"})
	srv.clients = clients
	srv.deviceMgr = NewDeviceManager(store, common.NewCryptoManager())
	tunnel.ClientID = "dev-whitelist"

	if !tm.externalConnAllowed(tunnel, "2001:db8:1::7") {
		t.Fatal("device whitelist bypass failed")
	}
	// 白名单地址不消耗预算：同 /64 的非白名单地址先花掉那一次，再被拒。
	if !tm.externalConnAllowed(tunnel, "2001:db8:1::8") {
		t.Fatal("first non-whitelisted address should still be within budget")
	}
	if tm.externalConnAllowed(tunnel, "2001:db8:1::9") {
		t.Fatal("a non-whitelisted address must still be rate limited")
	}
}

// 自动拉黑的键含 "/"（IPv6 /64），删除接口必须能处理，
// 否则管理员从面板解除不了聚合封禁。
func TestRemoveBlacklistAcceptsAggregatedKey(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	bm := NewBlacklistManager(1, "")
	defer bm.Stop()
	if !bm.AddViolation("2001:db8::5") {
		t.Fatalf("setup: expected the /64 to be blacklisted")
	}
	if !bm.IsBlacklisted("2001:db8::6") {
		t.Fatal("setup: /64 should be blocked")
	}

	srv := &Server{blacklist: bm}
	engine := gin.New()
	engine.DELETE("/api/security/blacklist/*ip", srv.handleAPIRemoveBlacklist)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/security/blacklist/2001:db8::/64", nil)
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE aggregated key = %d (%s), want 200", recorder.Code, recorder.Body.String())
	}
	if bm.IsBlacklisted("2001:db8::6") {
		t.Fatal("the /64 must be released after removal")
	}
}
