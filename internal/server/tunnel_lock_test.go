package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// assertOwnerIndexMatches 断言数据面索引与 tm.tunnels 双向一致：
// 每条定义都能查到正确归属，索引里也没有已删除的残留条目。
func assertOwnerIndexMatches(t *testing.T, tm *TunnelManager) {
	t.Helper()

	tm.mu.RLock()
	expected := make(map[string]string, len(tm.tunnels))
	for tunnelID, tunnel := range tm.tunnels {
		expected[tunnelID] = tunnel.ClientID
	}
	tm.mu.RUnlock()

	for tunnelID, clientID := range expected {
		got, ok := tm.TunnelOwner(tunnelID)
		if !ok || got != clientID {
			t.Fatalf("owner index[%s] = (%q, %v), want %q", tunnelID, got, ok, clientID)
		}
	}
	index := tm.tunnelOwner.Load()
	if index == nil {
		t.Fatal("owner index is not initialized")
	}
	for tunnelID := range *index {
		if _, ok := expected[tunnelID]; !ok {
			t.Fatalf("owner index still contains deleted tunnel %s", tunnelID)
		}
	}
}

func assertTunnelOwner(t *testing.T, tm *TunnelManager, tunnelID, wantClientID string) {
	t.Helper()
	got, ok := tm.TunnelOwner(tunnelID)
	if !ok || got != wantClientID {
		t.Fatalf("owner[%s] = (%q, %v), want %q", tunnelID, got, ok, wantClientID)
	}
}

func assertNoTunnelOwner(t *testing.T, tm *TunnelManager, tunnelID string) {
	t.Helper()
	if got, ok := tm.TunnelOwner(tunnelID); ok {
		t.Fatalf("owner[%s] = %q, want no entry", tunnelID, got)
	}
}

func tunnelExternalConnCount(tm *TunnelManager) int {
	tm.extMu.RLock()
	defer tm.extMu.RUnlock()
	return len(tm.extConns)
}

// ① 建隧道的落盘（fsync）卡在 tm.mu 里时，数据面必须立即返回。
// 修复前 HandleAgentData 取 tm.mu.RLock，会一直等到 CreateTunnel 的
// syncDir 返回。
func TestHandleAgentDataNotBlockedByPersistLock(t *testing.T) {
	_, store := newTestConfig(t)
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)
	client := &Client{ClientID: "dev-1"}

	if err := tm.CreateTunnel("t-a", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, ""); err != nil {
		t.Fatalf("CreateTunnel t-a: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		serverSide.Close()
		clientSide.Close()
	})
	if err := tm.AddExternalConn("conn-1", "t-a", serverSide); err != nil {
		t.Fatalf("AddExternalConn: %v", err)
	}
	go io.Copy(io.Discard, clientSide)

	// 让下一次目录 fsync 停住：CreateTunnel 会持 tm.mu 卡在 syncDir 里。
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	previousSyncDir := syncDir
	syncDir = func(*os.File) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-block
		return nil
	}
	t.Cleanup(func() { syncDir = previousSyncDir })

	createErr := make(chan error, 1)
	go func() {
		createErr <- tm.CreateTunnel("t-b", "dev-2", nil, "tcp", "127.0.0.1", 23, testTunnelPortStart+1, "")
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("CreateTunnel did not reach the blocked syncDir")
	}

	start := time.Now()
	if err := tm.HandleAgentData("t-a", "conn-1", []byte("payload"), false); err != nil {
		t.Fatalf("HandleAgentData: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("HandleAgentData blocked for %v behind the persist lock", elapsed)
	}

	close(block)
	select {
	case err := <-createErr:
		if err != nil {
			t.Fatalf("CreateTunnel t-b: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CreateTunnel did not finish after releasing syncDir")
	}
}

// ② Create / Update / Delete / RemoveClientTunnels 之后索引与定义一致。
func TestTunnelOwnerIndexFollowsMutations(t *testing.T) {
	_, store := newTestConfig(t)
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)

	if err := tm.CreateTunnel("t-1", "dev-1", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart, ""); err != nil {
		t.Fatalf("CreateTunnel t-1: %v", err)
	}
	if err := tm.CreateTunnel("t-2", "dev-2", nil, "tcp", "127.0.0.1", 22, testTunnelPortStart+1, ""); err != nil {
		t.Fatalf("CreateTunnel t-2: %v", err)
	}
	assertOwnerIndexMatches(t, tm)
	assertTunnelOwner(t, tm, "t-1", "dev-1")
	assertTunnelOwner(t, tm, "t-2", "dev-2")

	// Update 不改归属，但走同一条重建路径，索引必须继续一致。
	if _, err := tm.UpdateTunnel("t-1", "127.0.0.1", 2222, testTunnelPortStart+2, "", ""); err != nil {
		t.Fatalf("UpdateTunnel t-1: %v", err)
	}
	assertOwnerIndexMatches(t, tm)
	assertTunnelOwner(t, tm, "t-1", "dev-1")

	if _, err := tm.DeleteTunnel("t-2"); err != nil {
		t.Fatalf("DeleteTunnel t-2: %v", err)
	}
	assertOwnerIndexMatches(t, tm)
	assertNoTunnelOwner(t, tm, "t-2")

	if err := tm.RemoveClientTunnels("dev-1"); err != nil {
		t.Fatalf("RemoveClientTunnels dev-1: %v", err)
	}
	assertOwnerIndexMatches(t, tm)
	assertNoTunnelOwner(t, tm, "t-1")
}

// ② LoadDefinitions / CloseAll 也必须重建；④ CloseAll 后无残留 extConns。
func TestTunnelOwnerIndexAfterLoadAndCloseAll(t *testing.T) {
	_, store := newTestConfig(t)
	store.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	store.AddDevice(&DeviceState{ID: "dev-2", Name: "dev-2", Status: deviceStatusAuthorized})
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)

	now := time.Now()
	tm.LoadDefinitions([]TunnelState{
		{TunnelID: "t-1", ClientID: "dev-1", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart, Exposure: "public", CreatedAt: now},
		{TunnelID: "t-2", ClientID: "dev-2", Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: 22, PublicPort: testTunnelPortStart + 1, Exposure: "public", CreatedAt: now.Add(time.Second)},
	})
	assertOwnerIndexMatches(t, tm)
	assertTunnelOwner(t, tm, "t-1", "dev-1")
	assertTunnelOwner(t, tm, "t-2", "dev-2")

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		serverSide.Close()
		clientSide.Close()
	})
	if err := tm.AddExternalConn("conn-1", "t-1", serverSide); err != nil {
		t.Fatalf("AddExternalConn: %v", err)
	}
	if got := tunnelExternalConnCount(tm); got != 1 {
		t.Fatalf("external conns = %d, want 1", got)
	}

	tm.CloseAll()

	if got := tunnelExternalConnCount(tm); got != 0 {
		t.Fatalf("external conns after CloseAll = %d, want 0", got)
	}
	assertOwnerIndexMatches(t, tm)
	assertNoTunnelOwner(t, tm, "t-1")
	assertNoTunnelOwner(t, tm, "t-2")
	if err := tm.HandleAgentData("t-1", "conn-1", []byte("late"), false); err != nil {
		t.Fatalf("data after CloseAll should be dropped quietly, got %v", err)
	}
}

// ③ 并发 create/delete 与数据帧、索引读取同时进行，交给 -race 检查。
func TestTunnelOwnerIndexConcurrentDataPlane(t *testing.T) {
	_, store := newTestConfig(t)
	tm := newTunnelTestManager(t, store, NewClientManager(), testTunnelPortStart, testTunnelPortEnd)
	client := &Client{ClientID: "dev-1"}

	if err := tm.CreateTunnel("stable", "dev-1", client, "tcp", "127.0.0.1", 22, testTunnelPortStart, ""); err != nil {
		t.Fatalf("CreateTunnel stable: %v", err)
	}
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		serverSide.Close()
		clientSide.Close()
	})
	if err := tm.AddExternalConn("conn-1", "stable", serverSide); err != nil {
		t.Fatalf("AddExternalConn: %v", err)
	}
	go io.Copy(io.Discard, clientSide)

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
				_ = tm.HandleAgentData("stable", "conn-1", []byte("chunk"), false)
			}
		}
	}()
	// 并发增删外部连接：extConns 的所有读写都必须走 extMu，少了任何一处
	// -race 都会在这里暴露。
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			connID := fmt.Sprintf("churn-%d", i)
			serverSide, clientSide := net.Pipe()
			if err := tm.AddExternalConn(connID, "stable", serverSide); err != nil {
				serverSide.Close()
				clientSide.Close()
				continue
			}
			tm.RemoveExternalConn(connID)
			clientSide.Close()
		}
	}()

	for i := 0; i < 30; i++ {
		tunnelID := fmt.Sprintf("tmp-%d", i)
		if err := tm.CreateTunnel(tunnelID, "dev-2", nil, "tcp", "127.0.0.1", 23, testTunnelPortStart+1+i, ""); err != nil {
			t.Fatalf("CreateTunnel %s: %v", tunnelID, err)
		}
		if _, err := tm.DeleteTunnel(tunnelID); err != nil {
			t.Fatalf("DeleteTunnel %s: %v", tunnelID, err)
		}
		assertTunnelOwner(t, tm, "stable", "dev-1")
	}

	close(stop)
	wg.Wait()
	assertOwnerIndexMatches(t, tm)
}
