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
	mu         sync.Mutex
	probeErr   error
	ensureErr  error
	upErr      error
	downErr    error
	applyErr   error
	aclErr     error
	aclMissing bool
	aclExists  bool
	aclCalls   int
	aclTables  []ACL
	perPeer    map[string]error
	applied    [][]Peer
	events     []string
	downs      int
	probes     int
	linkUp     bool
	linkErr    error
	linkBlock  bool
	linkCalls  int
}

func (f *fakeBackend) Probe(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return f.probeErr
}

func (f *fakeBackend) Ensure(context.Context, Hub) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "ensure-config")
	return f.ensureErr
}

func (f *fakeBackend) Up(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "up")
	return f.upErr
}

func (f *fakeBackend) ApplyACL(_ context.Context, acl ACL) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aclCalls++
	if f.aclErr != nil {
		f.events = append(f.events, "acl-failed")
		return f.aclErr
	}
	f.aclExists = true
	f.aclMissing = false
	f.aclTables = append(f.aclTables, acl)
	f.events = append(f.events, "acl")
	return nil
}

func (f *fakeBackend) ACLExists(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.aclExists && !f.aclMissing, nil
}

func (f *fakeBackend) Apply(_ context.Context, peers []Peer) (map[string]error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "peers")
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

func (f *fakeBackend) PeerStats(context.Context) (map[string]PeerStats, error) {
	return map[string]PeerStats{"peer-key": {HandshakeAge: 12, RXBytes: 111, TXBytes: 222}}, nil
}

func (f *fakeBackend) Down(context.Context) error {
	f.mu.Lock()
	f.downs++
	err := f.downErr
	f.mu.Unlock()
	return err
}

// LinkUp 模拟 `ip -o link show dev wg-grm`：linkBlock 时一直等到预算用完，
// 用来验证探测的超时语义。
func (f *fakeBackend) LinkUp(ctx context.Context) (bool, error) {
	f.mu.Lock()
	f.linkCalls++
	up, err, block := f.linkUp, f.linkErr, f.linkBlock
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if err != nil {
		return false, err
	}
	return up, nil
}

func (f *fakeBackend) setLink(up bool, err error) {
	f.mu.Lock()
	f.linkUp = up
	f.linkErr = err
	f.mu.Unlock()
}

func (f *fakeBackend) appliedRounds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeBackend) aclRounds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.aclCalls
}

func (f *fakeBackend) lastACL() ACL {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.aclTables) == 0 {
		return ACL{}
	}
	return f.aclTables[len(f.aclTables)-1]
}

func (f *fakeBackend) markACLMissing() {
	f.mu.Lock()
	f.aclMissing = true
	f.mu.Unlock()
}

func (f *fakeBackend) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeBackend) downCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downs
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
	if !status.ACLReady {
		t.Fatal("ACL must report ready after a successful reconcile")
	}
	if len(status.Peers) != 1 || status.Peers[0].AppliedVersion != 3 {
		t.Fatalf("unexpected peers: %+v", status.Peers)
	}
	if status.Peers[0].HandshakeAge != 12 || status.Peers[0].RXBytes != 111 || status.Peers[0].TXBytes != 222 {
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
	if got := backend.aclRounds(); got != 0 {
		t.Fatalf("no peers means no ACL to install, got %d installs", got)
	}
	if !plane.Status().ACLReady {
		t.Fatal("with no peers there is nothing to isolate; acl_ready should be true")
	}
}

// Ensure 失败必须整轮 fail-closed：不装 ACL、不下发 peer、接口被 down，
// status 里 infra_error 非空且 acl_ready=false——不能出现「进程以为接口已起」
// 的假活状态（例如 51820 被阶段 0 的 wgt0 占用时 ip link set up 返回 rc=2）。
func TestEnsureFailureFailsClosedAndSkipsACL(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{ensureErr: errors.New("bring wg-grm up: RTNETLINK answers: Address already in use")}
	plane := startPlane(t, store, backend)

	if err := plane.Wait(context.Background(), "dev-1", 1, 300*time.Millisecond); !errors.Is(err, ErrInfra) {
		t.Fatalf("want ErrInfra, got %v", err)
	}
	status := plane.Status()
	if !strings.Contains(status.InfraError, "Address already in use") {
		t.Fatalf("infra_error must carry the up failure, got %q", status.InfraError)
	}
	if status.ACLReady {
		t.Fatal("acl_ready must be false when the interface never came up")
	}
	if got := backend.aclRounds(); got != 0 {
		t.Fatalf("an Ensure failure must not install the nft table, got %d installs", got)
	}
	if got := backend.appliedRounds(); got != 0 {
		t.Fatalf("an Ensure failure must not push peers, got %d rounds", got)
	}
	if got := backend.downCount(); got == 0 {
		t.Fatal("an Ensure failure must bring the interface down")
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

// M1 回归：顺序必须是 [ensure-config → acl → peers → up]。接口在 ACL 与
// peer 就位前一直 down，iifname 不匹配任何包，所以不存在「peer 可达但没 ACL」
// 的 fail-open 窗口；up 同时是端口冲突唯一会暴露的一步。
func TestReconcileOrdersConfigACLPeersThenUp(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(3, true))
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)

	if err := plane.Wait(context.Background(), "dev-1", 3, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}
	const wantOrder = "ensure-config,acl,peers,up"
	if got := strings.Join(backend.eventLog(), ","); got != wantOrder {
		t.Fatalf("reconcile order = %s, want %s (up must be the last step)", got, wantOrder)
	}
	acl := backend.lastACL()
	if acl.Interface != "wg-grm" {
		t.Fatalf("ACL interface = %q", acl.Interface)
	}
	if len(acl.Clients) != 1 || acl.Clients[0] != "10.77.0.2/32" || len(acl.Endpoints) != 0 {
		t.Fatalf("unexpected ACL sets: %+v", acl)
	}
	if !plane.Status().ACLReady {
		t.Fatal("a successful reconcile must report acl_ready=true")
	}

	// 复现 M1 的真实路径：表被外部 flush、peer 仍在。下一轮必须先重装表、
	// 再下发 peer、最后 up；表在 up 之前必须已经存在。
	backend.markACLMissing()
	gen := plane.Bump()
	if err := plane.WaitApplied(context.Background(), gen, time.Second); err != nil {
		t.Fatalf("wait applied: %v", err)
	}
	events := backend.eventLog()
	if len(events) != 8 || strings.Join(events[4:], ",") != wantOrder {
		t.Fatalf("reconcile after an external table flush = %v, want a second %s", events, wantOrder)
	}
	exists, err := backend.ACLExists(context.Background())
	if err != nil {
		t.Fatalf("acl exists: %v", err)
	}
	if !exists {
		t.Fatal("the nft table must exist once the interface is up")
	}
}

// Down 失败不能被吞掉：状态里必须能看出「我们以为已经断了、其实没有」。
func TestDownFailureIsSurfacedInInfraError(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{
		ensureErr: errors.New("bring wg-grm up: Address already in use"),
		downErr:   errors.New("ip link set wg-grm down: operation not permitted"),
	}
	plane := startPlane(t, store, backend)

	status := plane.Status()
	if !strings.Contains(status.InfraError, "Address already in use") {
		t.Fatalf("the original failure must stay in infra_error, got %q", status.InfraError)
	}
	if !strings.Contains(status.InfraError, "bringing the interface down also failed") {
		t.Fatalf("a failed Down must be surfaced too, got %q", status.InfraError)
	}
	if backend.downCount() == 0 {
		t.Fatal("Down must have been attempted")
	}
}

func TestACLIsNotReloadedWhenUnchanged(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(3, true))
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 3, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got := backend.aclRounds(); got != 1 {
		t.Fatalf("first reconcile should install the ACL once, got %d", got)
	}

	// 没有任何期望变化：再跑一轮不能重载表，否则每次 Bump 都会清零计数器。
	gen := plane.Bump()
	if err := plane.WaitApplied(context.Background(), gen, time.Second); err != nil {
		t.Fatalf("wait applied: %v", err)
	}
	if got := backend.aclRounds(); got != 1 {
		t.Fatalf("an unchanged ACL must not be reloaded, got %d installs", got)
	}
	if backend.appliedRounds() < 2 {
		t.Fatalf("peers should still be reconciled every round, got %d", backend.appliedRounds())
	}
}

func TestACLRebuildsWhenTableDisappears(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(3, true))
	backend := &fakeBackend{}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 3, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}

	// 模拟 `nft flush ruleset` / 别的防火墙工具把表删掉。
	backend.markACLMissing()
	gen := plane.Bump()
	if err := plane.WaitApplied(context.Background(), gen, time.Second); err != nil {
		t.Fatalf("wait applied: %v", err)
	}
	if got := backend.aclRounds(); got != 2 {
		t.Fatalf("a missing table must be reinstalled, got %d installs", got)
	}
	if !plane.Status().ACLReady {
		t.Fatal("ACL should be ready again after the reinstall")
	}
}

func TestACLFailureFailsClosed(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{aclErr: errors.New("nft: operation not permitted")}
	plane := startPlane(t, store, backend)

	status := plane.Status()
	if status.ACLReady {
		t.Fatal("acl_ready must be false when nft fails")
	}
	if !strings.Contains(status.InfraError, "install wireguard nft table") {
		t.Fatalf("infra_error should name the ACL failure, got %q", status.InfraError)
	}
	if got := backend.appliedRounds(); got != 0 {
		t.Fatalf("peers must not be applied without an ACL, got %d rounds", got)
	}
	if got := backend.downCount(); got == 0 {
		t.Fatal("an ACL failure must bring the interface down (fail-closed)")
	}
}

// link_up 是只读探测：exec 成功时按标志位报 up/down，exec 失败时必须保守
// 报 false 并带上原因（宁可报不健康，也不能把已被外部 down 的接口说成健康）。
func TestLinkStateReportsInterfaceFlags(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{linkUp: true}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 1, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}

	if up, detail := plane.LinkState(context.Background()); !up || detail != "" {
		t.Fatalf("link up = %v, link_error = %q; want true, \"\"", up, detail)
	}

	// 外部 `ip link set wg-grm down` 后 flags 里没有 UP，但 acl_ready 和
	// infra_error 仍然描述上一次成功，此时 link_up 必须说真话。
	backend.setLink(false, nil)
	if up, detail := plane.LinkState(context.Background()); up || detail != "" {
		t.Fatalf("link up = %v, link_error = %q; want false, \"\"", up, detail)
	}

	backend.setLink(false, errors.New(`ip -o link show dev wg-grm: exit status 1: Device "wg-grm" does not exist.`))
	up, detail := plane.LinkState(context.Background())
	if up {
		t.Fatal("a failed probe must report the link as down")
	}
	if !strings.Contains(detail, "does not exist") {
		t.Fatalf("link_error should carry the exec failure, got %q", detail)
	}
}

// 探测 1s 内没回来就报 timeout，不能把状态接口一直挂住。
func TestLinkStateTimesOut(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{linkBlock: true}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 1, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}

	start := time.Now()
	up, detail := plane.LinkState(context.Background())
	elapsed := time.Since(start)
	if up || detail != "timeout" {
		t.Fatalf("link up = %v, link_error = %q; want false, \"timeout\"", up, detail)
	}
	if elapsed > 2*linkProbeTimeout {
		t.Fatalf("the probe must give up after %v, took %v", linkProbeTimeout, elapsed)
	}
}

// 观测不是控制：探测不得触发 reconcile、不得改 gen/applied、不得写内核。
func TestLinkStateDoesNotTouchReconcileState(t *testing.T) {
	store := &fakeStore{}
	store.set(testSnapshot(1, true))
	backend := &fakeBackend{linkUp: true}
	plane := startPlane(t, store, backend)
	if err := plane.Wait(context.Background(), "dev-1", 1, time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}

	before := plane.Status()
	events := strings.Join(backend.eventLog(), ",")
	downs := backend.downCount()
	for i := 0; i < 3; i++ {
		plane.LinkState(context.Background())
	}
	after := plane.Status()

	if after.Gen != before.Gen || after.Applied != before.Applied {
		t.Fatalf("probe changed gen/applied: %d/%d -> %d/%d", before.Gen, before.Applied, after.Gen, after.Applied)
	}
	if got := strings.Join(backend.eventLog(), ","); got != events {
		t.Fatalf("probe issued kernel writes: events %q -> %q", events, got)
	}
	if got := backend.downCount(); got != downs {
		t.Fatalf("probe brought the interface down: downs %d -> %d", downs, got)
	}
	if after.Peers[0].AppliedVersion != before.Peers[0].AppliedVersion {
		t.Fatalf("probe changed the applied version: %d -> %d", before.Peers[0].AppliedVersion, after.Peers[0].AppliedVersion)
	}
}
