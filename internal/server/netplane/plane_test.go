package netplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeStore struct {
	mu       sync.Mutex
	snapshot Snapshot
	err      error
}

func (f *fakeStore) NetplaneSnapshot() (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Snapshot{}, f.err
	}
	snapshot := f.snapshot
	snapshot.Peers = append([]Peer(nil), f.snapshot.Peers...)
	return snapshot, nil
}

func (f *fakeStore) set(snapshot Snapshot) {
	f.mu.Lock()
	f.snapshot = snapshot
	f.mu.Unlock()
}

type fakeBackend struct {
	mu        sync.Mutex
	probeErr  error
	ensureErr error
	applyErr  error
	perPeer   map[string]error
	applied   [][]Peer
	downs     int
	probes    int
}

func (f *fakeBackend) Probe(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.probeErr
}

func (f *fakeBackend) Ensure(context.Context, Hub) error { return f.ensureErr }

func (f *fakeBackend) Apply(_ context.Context, peers []Peer) (map[string]error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, append([]Peer(nil), peers...))
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	errs := make(map[string]error)
	for id, err := range f.perPeer {
		errs[id] = err
	}
	return errs, nil
}

func (f *fakeBackend) Handshakes(context.Context) (map[string]int64, error) {
	return map[string]int64{"peer-key": 12}, nil
}

func (f *fakeBackend) Down(context.Context) error {
	f.mu.Lock()
	f.downs++
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) appliedRounds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func testSnapshot(version uint64, enabled bool) Snapshot {
	return Snapshot{
		Hub: Hub{Interface: "wg-grm", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820, Endpoint: "1.2.3.4:51820"},
		Peers: []Peer{{
			DeviceID: "dev-1", PublicKey: "peer-key", Address: "10.77.0.2", Role: "client",
			Enabled: enabled, Version: version,
		}},
	}
}

func startPlane(t *testing.T, store Store, backend Backend) *Plane {
	t.Helper()
	plane := New(Config{Store: store, Backend: backend, Interval: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	plane.Start(ctx)
	t.Cleanup(plane.Stop)
	return plane
}

func TestReconcileAppliesPeersAndAdvancesVersion(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(3, true))
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)

	if err := plane.Wait(context.Background(), "dev-1", 3, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}
	status := plane.Status()
	if status.Gen != status.Applied {
		t.Fatalf("gen %d != applied %d", status.Gen, status.Applied)
	}
	if status.ACLReady {
		t.Fatal("ACL must report false in stage 1: nft rules land in the second batch")
	}
	if len(status.Peers) != 1 || status.Peers[0].AppliedVersion != 3 {
		t.Fatalf("unexpected peers: %+v", status.Peers)
	}
	if status.Peers[0].HandshakeAge != 12 {
		t.Fatalf("handshake age not joined: %+v", status.Peers[0])
	}
}

func TestNoPeersSkipsKernel(t *testing.T) {
	store := &fakeStore{}
	store.set(Snapshot{Hub: Hub{Interface: "wg-grm", CIDR: "10.77.0.0/24"}})
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)
	plane.Bump()
	deadline := time.Now().Add(time.Second)
	for plane.Status().Applied == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	backend.mu.Lock()
	probes := backend.probes
	backend.mu.Unlock()
	if probes != 0 {
		t.Fatalf("kernel must not be touched without peers, probes=%d", probes)
	}
}

func TestInfraFailureIsReportedAndFailsWrites(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{ensureErr: errors.New("kernel module missing")}
	plane := startPlane(t, store, backend)

	err := plane.Wait(context.Background(), "dev-1", 1, 300*time.Millisecond)
	if !errors.Is(err, ErrInfra) {
		t.Fatalf("want ErrInfra, got %v", err)
	}
	if plane.InfraError() == "" {
		t.Fatal("InfraError should be set")
	}
}

func TestDeviceErrorDoesNotBlockOtherDevices(t *testing.T) {
	store := &fakeStore{}
	store.set(Snapshot{
		Hub: Hub{Interface: "wg-grm", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820},
		Peers: []Peer{
			{DeviceID: "bad", PublicKey: "bad-key", Address: "10.77.0.2", Enabled: true, Version: 1},
			{DeviceID: "good", PublicKey: "good-key", Address: "10.77.0.3", Enabled: true, Version: 1},
		},
	})
	backend := &fakeBackend{perPeer: map[string]error{"bad": errors.New("peer rejected")}}
	plane := startPlane(t, store, backend)

	if err := plane.Wait(context.Background(), "bad", 1, 300*time.Millisecond); !errors.Is(err, ErrDevice) {
		t.Fatalf("bad device should fail with ErrDevice, got %v", err)
	}
	if err := plane.Wait(context.Background(), "good", 1, time.Second); err != nil {
		t.Fatalf("good device must still apply: %v", err)
	}
	status := plane.Status()
	if status.InfraError != "" {
		t.Fatalf("a single bad peer must not become an infra error: %q", status.InfraError)
	}
	var badError string
	for _, peer := range status.Peers {
		if peer.DeviceID == "bad" {
			badError = peer.Error
		}
	}
	if badError == "" {
		t.Fatal("bad device should carry wg_error")
	}
}

func TestBumpReappliesWhenDesiredChanges(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 1, time.Second); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	store.set(testSnapshot(2, true))
	plane.Bump()
	if err := plane.Wait(context.Background(), "dev-1", 2, 2*time.Second); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if backend.appliedRounds() < 2 {
		t.Fatal("expected a second reconcile round")
	}
}

func TestWaitTimesOut(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(9, true))
	plane := New(Config{Store: store, Backend: &fakeBackend{}, Interval: time.Hour})
	// 不启动 goroutine：appliedVersion 永远追不上。
	err := plane.Wait(context.Background(), "dev-1", 9, 60*time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestStopBringsInterfaceDown(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{}
	plane := New(Config{Store: store, Backend: backend, Interval: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plane.Start(ctx)
	plane.Stop()
	backend.mu.Lock()
	downs := backend.downs
	backend.mu.Unlock()
	if downs == 0 {
		t.Fatal("Stop should ask the backend to bring the interface down")
	}
}

func stopPlane(t *testing.T, plane *Plane) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		plane.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Plane.Stop must return even when Start was refused")
	}
}

func TestRefusedPlaneFailsClosed(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{}
	plane := New(Config{Store: store, Backend: backend, Interval: time.Hour})

	plane.RefuseStart("STATE_ENCRYPTION_REQUIRED", "state encryption is required to enable wireguard networking")
	status := plane.Status()
	if status.Blocked != "STATE_ENCRYPTION_REQUIRED" {
		t.Fatalf("want blocked code STATE_ENCRYPTION_REQUIRED, got %q", status.Blocked)
	}
	if !strings.Contains(status.InfraError, "state encryption is required") {
		t.Fatalf("the detail must reach the status API, got %q", status.InfraError)
	}
	if backend.downs == 0 {
		t.Fatal("refusing to start must bring the interface down (fail closed)")
	}

	// 拒绝之后 Start 必须是空操作：不能起 goroutine，也不能碰内核。
	plane.Start(context.Background())
	if backend.probes != 0 || backend.appliedRounds() != 0 {
		t.Fatalf("Start after RefuseStart touched the kernel: probes=%d applies=%d", backend.probes, backend.appliedRounds())
	}

	plane.Bump()
	started := time.Now()
	err := plane.Wait(context.Background(), "dev-1", 1, 5*time.Second)
	if !errors.Is(err, ErrInfra) {
		t.Fatalf("want ErrInfra from a refused plane, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Wait must fail fast on a refused plane, took %s", elapsed)
	}

	stopPlane(t, plane)
}
