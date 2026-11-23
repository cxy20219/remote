package server

import (
	"sync"
	"testing"

	"goremote/internal/common"
)

func newWhitelistCacheFixture(t *testing.T) (*DeviceManager, *StateStore) {
	t.Helper()
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{
		ID:          "dev-1",
		Status:      deviceStatusAuthorized,
		IPWhitelist: []string{"203.0.113.0/24"},
	})
	return NewDeviceManager(store, common.NewCryptoManager()), store
}

// 缓存命中时不得重建 matcher：命中/未命中计数直接反映在可观测计数上。
func TestDeviceWhitelistMatcherIsCached(t *testing.T) {
	dm, _ := newWhitelistCacheFixture(t)

	first := dm.IPWhitelistMatcher("dev-1")
	if first == nil || !first.Match("203.0.113.9") {
		t.Fatal("compiled matcher should match an address inside the whitelisted CIDR")
	}
	hits, misses := dm.WhitelistCacheStats()
	if hits != 0 || misses != 1 {
		t.Fatalf("after the first lookup hits=%d misses=%d, want 0/1", hits, misses)
	}

	second := dm.IPWhitelistMatcher("dev-1")
	if second != first {
		t.Fatal("the second lookup must return the cached matcher")
	}
	hits, misses = dm.WhitelistCacheStats()
	if hits != 1 || misses != 1 {
		t.Fatalf("after the second lookup hits=%d misses=%d, want 1/1", hits, misses)
	}
}

// 白名单变更后的下一次查询必须立即使用新规则。
func TestDeviceWhitelistMatcherInvalidatedOnChange(t *testing.T) {
	dm, store := newWhitelistCacheFixture(t)

	before := dm.IPWhitelistMatcher("dev-1")
	if before == nil || before.Match("198.51.100.9") {
		t.Fatal("setup: the new address must not match the old whitelist")
	}

	store.UpdateDevice("dev-1", func(d *DeviceState) {
		d.IPWhitelist = []string{"198.51.100.9"}
	})

	after := dm.IPWhitelistMatcher("dev-1")
	if after == nil {
		t.Fatal("a device with a whitelist must return a matcher")
	}
	if !after.Match("198.51.100.9") {
		t.Fatal("the matcher must be rebuilt from the updated whitelist")
	}
	if after.Match("203.0.113.9") {
		t.Fatal("the old whitelist entry must no longer match")
	}
}

// 设备删除后缓存不能残留：再查必须返回 nil。
func TestDeviceWhitelistMatcherInvalidatedOnDelete(t *testing.T) {
	dm, _ := newWhitelistCacheFixture(t)

	if matcher := dm.IPWhitelistMatcher("dev-1"); matcher == nil {
		t.Fatal("setup: expected a matcher before deleting the device")
	}
	if err := dm.DeleteDevice("dev-1"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if matcher := dm.IPWhitelistMatcher("dev-1"); matcher != nil {
		t.Fatal("a deleted device must not leave a cached matcher behind")
	}
}

// 并发 accept 与设备变更：-race 下干净，且任何时刻拿到的 matcher 都是完整可用的。
func TestDeviceWhitelistMatcherConcurrentWithUpdates(t *testing.T) {
	dm, store := newWhitelistCacheFixture(t)

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				matcher := dm.IPWhitelistMatcher("dev-1")
				if matcher == nil {
					t.Error("matcher disappeared while the device still exists")
					return
				}
				_ = matcher.Match("203.0.113.9")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			store.UpdateDevice("dev-1", func(d *DeviceState) {
				d.IPWhitelist = []string{"203.0.113.0/24"}
			})
		}
	}()
	wg.Wait()
}

// 空白名单与不存在的设备都返回 nil，不缓存错误结果。
func TestDeviceWhitelistMatcherEmptyCases(t *testing.T) {
	dm, store := newWhitelistCacheFixture(t)
	store.AddDevice(&DeviceState{ID: "dev-empty", Status: deviceStatusAuthorized})

	if matcher := dm.IPWhitelistMatcher("dev-empty"); matcher != nil {
		t.Fatal("a device without a whitelist must not produce a matcher")
	}
	if matcher := dm.IPWhitelistMatcher(""); matcher != nil {
		t.Fatal("empty device id must not produce a matcher")
	}
	if matcher := dm.IPWhitelistMatcher("missing"); matcher != nil {
		t.Fatal("missing device must not produce a matcher")
	}
}
