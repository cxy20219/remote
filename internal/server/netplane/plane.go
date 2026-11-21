// Package netplane keeps the kernel's WireGuard state equal to the manager's
// desired state.
//
// It is the only writer of kernel peers. It knows nothing about tunnels or the
// WebSocket control channel: callers write state, call Bump, and wait for the
// device's applied version. One goroutine serialises every reconcile, so two
// writers never race on netlink.
package netplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// 阶段 1 的默认值；与服务端的 state 保持一致，但不导入它（netplane 不依赖 server）。
const (
	DefaultInterface = "wg-grm"
	defaultMTU       = 1420
)

var (
	// ErrTimeout 表示在预算内没有等到内核应用。
	ErrTimeout = errors.New("wireguard reconcile did not finish in time")
	// ErrInfra 表示接口/驱动级失败，所有 VPN 写接口都该 503。
	ErrInfra = errors.New("wireguard infrastructure error")
	// ErrDevice 表示单台设备的内核错误；只影响该设备的写。
	ErrDevice = errors.New("wireguard peer error")
)

// Peer 是一台设备的期望状态。
type Peer struct {
	DeviceID  string
	PublicKey string
	Address   string
	Role      string
	Enabled   bool
	Version   uint64
}

// Hub 是服务器自己的接口参数。
type Hub struct {
	Interface  string
	PrivateKey string
	CIDR       string
	Address    string
	Listen     int
	MTU        int
	// Endpoint 是模板里给设备的 host:port（来自 public_host + listen）。
	Endpoint string
}

// Snapshot 是某一瞬间的期望状态。Peers 只包含启用绑定的设备。
type Snapshot struct {
	Hub   Hub
	Peers []Peer
}

// ACL 是 table inet goremote 的期望内容。
//
// Clients / Endpoints 是 hub 侧看到的对端 /32 地址（如 10.77.0.2/32），
// 按 role 分开是因为 allow 规则只放 client→endpoint；如果把整个
// 10.77.0.0/24 当成一个集合，endpoint→client 也会命中 allow。
type ACL struct {
	Interface string
	Clients   []string
	Endpoints []string
}

// Store 提供期望状态；由服务端实现，读取必须是锁内的克隆。
type Store interface {
	NetplaneSnapshot() (Snapshot, error)
}

// PeerStatus 是给状态接口看的一台设备。
type PeerStatus struct {
	DeviceID       string `json:"device_id"`
	Address        string `json:"wg_ip"`
	TrueAddress    string `json:"-"`
	Role           string `json:"role"`
	Enabled        bool   `json:"enabled"`
	Version        uint64 `json:"wg_version"`
	AppliedVersion uint64 `json:"applied_version"`
	Error          string `json:"error,omitempty"`
	HandshakeAge   int64  `json:"handshake_age,omitempty"` // 秒；0 表示未知/从未握手
	RXBytes        int64  `json:"rx_bytes"`                // hub 收到的字节数
	TXBytes        int64  `json:"tx_bytes"`                // hub 发出的字节数
}

// PeerStats 是 `wg show <iface> dump` 里每台设备的运行状态。
type PeerStats struct {
	HandshakeAge int64 // 距最近握手的秒数；0 表示从未握手
	RXBytes      int64
	TXBytes      int64
}

// Status 是 GET /api/vpn/status 的数据源。
type Status struct {
	Interface  string
	Endpoint   string
	CIDR       string
	Listen     int
	Gen        uint64
	Applied    uint64
	InfraError string
	// Blocked 是拒绝启动的稳定原因码（例如 STATE_ENCRYPTION_REQUIRED），
	// 空串表示没有被拒绝；面板据此显示 banner。
	Blocked  string
	ACLReady bool
	Peers    []PeerStatus
}

// Backend 是唯一碰内核的一层；测试注入假实现。
type Backend interface {
	// Probe 报告内核与工具是否可用（wireguard 模块 + ip/wg）。
	Probe(ctx context.Context) error
	// Ensure 建/改 hub 接口并配置私钥/地址/MTU/redirects，但**不把接口 up**。
	// 接口保持 down 直到 ACL 与 peer 都就位（见 Up）。
	Ensure(ctx context.Context, hub Hub) error
	// Up 把接口置为 up。必须是 reconcile 的最后一步：接口 down 时 ACL 的
	// iifname 不匹配任何包，冷启动从建接口到表就绪全程没有无 ACL 窗口。
	Up(ctx context.Context) error
	// ApplyACL 用 `nft -f` 原子替换 table inet goremote。失败时不得留下半套
	// 规则；调用方会 fail-closed（接口 down）。
	ApplyACL(ctx context.Context, acl ACL) error
	// ACLExists 报告 table inet goremote 是否存在（运行期看门狗用；表被外部
	// flush 掉时要能发现并重装）。
	ACLExists(ctx context.Context) (bool, error)
	// Apply 把 peer 集合对齐到 desired；返回按 device_id 的失败（不影响其它设备），
	// 第二个返回值是接口级错误（此时整轮作废）。
	Apply(ctx context.Context, peers []Peer) (map[string]error, error)
	// PeerStats 返回公钥 → 最近握手年龄与收发字节数。
	PeerStats(ctx context.Context) (map[string]PeerStats, error)
	// Down 把接口拉下来（fail-closed 用）。
	Down(ctx context.Context) error
	// LinkUp 只读地报告接口的管理状态（IFF_UP）。只用于状态接口的观测，
	// 不能改变任何内核状态；任何错误都按「不健康」处理。
	LinkUp(ctx context.Context) (bool, error)
}

// Config 是 New 的参数。
type Config struct {
	Store   Store
	Backend Backend
	// Interval 是自愈周期（外部删表/删接口时兜底），默认 30s。
	Interval time.Duration
}

// Plane 是状态机的拥有者。
type Plane struct {
	store    Store
	backend  Backend
	interval time.Duration

	mu             sync.Mutex
	gen            uint64
	applied        uint64
	infraErr       string
	blocked        string
	refused        bool
	started        bool
	aclReady       bool
	aclSignature   string
	appliedVersion map[string]uint64
	deviceErr      map[string]string
	peerStats      map[string]PeerStats
	peers          []Peer
	hubEndpoint    string
	hubCIDR        string
	hubListen      int

	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	startOne sync.Once
	stopOne  sync.Once
	running  bool
}

// New 构造 Plane；Backend 为 nil 时所有写都 503（errDisabled）。
func New(cfg Config) *Plane {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Plane{
		store:          cfg.Store,
		backend:        cfg.Backend,
		interval:       interval,
		appliedVersion: make(map[string]uint64),
		deviceErr:      make(map[string]string),
		peerStats:      make(map[string]PeerStats),
		wake:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// RefuseStart 让 Plane 保持未启动（fail closed），并把原因暴露给状态接口。
//
// 用于「满足启动条件才允许碰内核」的场合：例如组网已配置但 state 未加密，
// 此时绝不能把 hub 私钥写进内核、也不能让旧 peer 继续生效，所以顺手把接口
// 拉下来。调用后 Start 是空操作，写接口通过 InfraError 快速失败。
func (p *Plane) RefuseStart(code, detail string) {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.refused = true
	p.blocked = code
	p.infraErr = detail
	p.mu.Unlock()
	if p.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := p.backend.Down(ctx); err != nil {
			slog.Error("wireguard interface could not be brought down while refusing to start", "error", err)
		}
		cancel()
	}
}

// Start 起后台 goroutine，并同步跑首轮 reconcile。调用方的 ctx 决定首轮预算
// （服务端给 10s）。首轮失败不返回错误给启动路径：fail closed 由 infraErr
// 表达，面板继续服务。
func (p *Plane) Start(ctx context.Context) {
	p.startOne.Do(func() {
		p.mu.Lock()
		if p.refused {
			p.mu.Unlock()
			return
		}
		p.started = true
		p.running = true
		p.mu.Unlock()
		go p.loop()
	})
	p.mu.Lock()
	refused := p.refused
	started := p.started
	p.mu.Unlock()
	if refused || !started {
		return
	}
	p.reconcile(ctx)
}

// Stop 停止 goroutine 并尽力把接口拉下来（失败只记录，不阻塞退出）。
func (p *Plane) Stop() {
	p.stopOne.Do(func() {
		p.mu.Lock()
		started := p.started
		p.mu.Unlock()
		if started {
			close(p.stop)
			<-p.done
		}
		if p.backend != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err := p.backend.Down(ctx); err != nil {
				slog.Error("wireguard interface could not be brought down on shutdown", "error", err)
			}
			cancel()
		}
	})
}

// Bump 记录一次期望变更并唤醒 reconcile，返回新的 gen。
func (p *Plane) Bump() uint64 {
	p.mu.Lock()
	p.gen++
	gen := p.gen
	p.mu.Unlock()
	p.signal()
	return gen
}

func (p *Plane) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Wait 等某台设备的 appliedVersion 追上 version。infraErr 或该设备的
// wg_error 会立刻返回，不空等到超时。
func (p *Plane) Wait(ctx context.Context, deviceID string, version uint64, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		p.mu.Lock()
		blocked := p.blocked
		// 只有后台已经追上当前 gen 时，错误才是这次写的结果。刚 Bump 完、
		// 新一轮还没跑时读到的是上一轮的错误，此时必须继续等，不能立刻失败
		// （否则一次内核抖动会把后续所有重试都判死）。
		caughtUp := p.applied >= p.gen
		infra := p.infraErr
		deviceErr := p.deviceErr[deviceID]
		applied := p.appliedVersion[deviceID]
		p.mu.Unlock()
		// 被拒绝启动时 loop 根本不会跑，等 applied 追平只会白等到超时。
		if blocked != "" {
			if infra == "" {
				infra = blocked
			}
			return fmt.Errorf("%w: %s", ErrInfra, infra)
		}
		if caughtUp {
			if infra != "" {
				return fmt.Errorf("%w: %s", ErrInfra, infra)
			}
			if deviceErr != "" {
				return fmt.Errorf("%w: %s", ErrDevice, deviceErr)
			}
		}
		if applied >= version {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// WaitApplied 等后台把**全局**期望状态应用到一个 gen（手动 reconcile 用）。
// 语义与 Wait 一致：只有后台已经追上当前 gen 时才采信错误。
func (p *Plane) WaitApplied(ctx context.Context, gen uint64, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		p.mu.Lock()
		blocked := p.blocked
		caughtUp := p.applied >= p.gen
		infra := p.infraErr
		applied := p.applied
		p.mu.Unlock()

		if blocked != "" {
			if infra == "" {
				infra = blocked
			}
			return fmt.Errorf("%w: %s", ErrInfra, infra)
		}
		if infra != "" && caughtUp {
			return fmt.Errorf("%w: %s", ErrInfra, infra)
		}
		if applied >= gen {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// InfraError 返回当前接口级错误，空串表示正常。
func (p *Plane) InfraError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.infraErr
}

// linkProbeTimeout 是链路状态探测的预算。状态接口宁可把接口报成不健康，
// 也不能因为一次内核卡顿被拖住：1 秒内没回来就报 timeout。
const linkProbeTimeout = time.Second

// LinkState 只读地探测接口此刻是否 up，返回 (link_up, link_error)。
//
// 这是观测，不是控制：不触发 reconcile、不改 gen/applied、不写内核；30s
// ticker 仍然只负责恢复。它解决的问题是「接口被外部 down、acl_ready 与
// infra_error 仍然说自己健康」的假绿窗口——那两个字段描述的是上一轮
// reconcile 的结果，而 link_up 描述的是此刻。
func (p *Plane) LinkState(ctx context.Context) (bool, string) {
	// backend 在 New 里定下之后不再变，读它不需要 p.mu：探测最长 1s，
	// 不能因为等锁把状态接口拖住。
	backend := p.backend
	if backend == nil {
		return false, "wireguard backend is not configured"
	}
	probeCtx, cancel := context.WithTimeout(ctx, linkProbeTimeout)
	defer cancel()
	up, err := backend.LinkUp(probeCtx)
	// 先看预算：exec 被 ctx 杀掉时返回的是 "signal: killed"，从错误文本
	// 分辨不出是超时还是权限问题。
	switch {
	case errors.Is(probeCtx.Err(), context.DeadlineExceeded):
		return false, "timeout"
	case probeCtx.Err() != nil:
		return false, "canceled"
	case err != nil:
		return false, err.Error()
	}
	return up, ""
}

// Enabled 报告这个 Plane 是否被接进了服务端。
func (p *Plane) Enabled() bool { return p != nil }

// Status 组装状态接口需要的快照。
func (p *Plane) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()

	status := Status{
		Interface:  DefaultInterface,
		Endpoint:   p.hubEndpoint,
		CIDR:       p.hubCIDR,
		Listen:     p.hubListen,
		Gen:        p.gen,
		Applied:    p.applied,
		InfraError: p.infraErr,
		Blocked:    p.blocked,
		ACLReady:   p.aclReady,
	}
	for _, peer := range p.peers {
		stats := p.peerStats[peer.PublicKey]
		status.Peers = append(status.Peers, PeerStatus{
			DeviceID:       peer.DeviceID,
			Address:        peer.Address,
			Role:           peer.Role,
			Enabled:        peer.Enabled,
			Version:        peer.Version,
			AppliedVersion: p.appliedVersion[peer.DeviceID],
			Error:          p.deviceErr[peer.DeviceID],
			HandshakeAge:   stats.HandshakeAge,
			RXBytes:        stats.RXBytes,
			TXBytes:        stats.TXBytes,
		})
	}
	return status
}

func (p *Plane) loop() {
	defer close(p.done)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-p.wake:
		case <-ticker.C:
		}
		for {
			p.mu.Lock()
			before := p.gen
			p.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			p.reconcile(ctx)
			cancel()
			p.mu.Lock()
			after := p.gen
			p.mu.Unlock()
			if after == before {
				break
			}
		}
	}
}

// reconcile 跑一轮。单设备失败只记该设备，其余设备照常推进。
func (p *Plane) reconcile(ctx context.Context) {
	p.mu.Lock()
	gen := p.gen
	p.mu.Unlock()

	snapshot, err := p.store.NetplaneSnapshot()
	if err != nil {
		p.fail(gen, err)
		return
	}
	p.mu.Lock()
	p.peers = append([]Peer(nil), snapshot.Peers...)
	p.hubEndpoint = snapshot.Hub.Endpoint
	p.hubCIDR = snapshot.Hub.CIDR
	p.hubListen = snapshot.Hub.Listen
	p.mu.Unlock()

	// 没有任何设备绑定：不去碰内核，避免在没用到组网的部署上要求权限。
	// 没有 peer 就没有需要隔离的流量，acl_ready 报 true 是诚实的。
	if len(snapshot.Peers) == 0 {
		p.mu.Lock()
		p.aclReady = true
		p.aclSignature = ""
		p.mu.Unlock()
		p.finish(gen, snapshot.Peers, nil, nil)
		return
	}
	if p.backend == nil {
		p.invalidateACL()
		p.fail(gen, errors.New("wireguard backend is not configured"))
		return
	}
	// 顺序是 [ensure-config → acl → peers → up]：接口在整个配置/装表/下发
	// peer 期间保持 down，iifname 不匹配任何包；只有 ACL 与 peer 都就位后
	// 才 up。`ip link set up` 也是端口冲突（EADDRINUSE）唯一会暴露的地方，
	// 所以它必须是最后一道闸门。
	if err := p.backend.Probe(ctx); err != nil {
		p.invalidateACL()
		p.failClosed(gen, err)
		return
	}
	if err := p.backend.Ensure(ctx, snapshot.Hub); err != nil {
		p.invalidateACL()
		p.failClosed(gen, err)
		return
	}
	acl := buildACL(snapshot)
	if err := p.ensureACL(ctx, acl); err != nil {
		p.invalidateACL()
		p.failClosed(gen, err)
		return
	}
	deviceErrs, err := p.backend.Apply(ctx, snapshot.Peers)
	if err != nil {
		p.invalidateACL()
		p.failClosed(gen, err)
		return
	}
	if err := p.backend.Up(ctx); err != nil {
		// 失败时接口保持 down；failClosed 再兜一次，防止之前某一轮它已经是 up。
		p.failClosed(gen, err)
		return
	}
	stats, err := p.backend.PeerStats(ctx)
	if err != nil {
		// 读状态失败不影响“已应用”的判定，但要把错误暴露出来。
		p.fail(gen, err)
		return
	}
	p.finish(gen, snapshot.Peers, deviceErrs, stats)
}

// failClosed 把接口拉下来并把 Down 的失败也写进 infra_error。
//
// 不能 `_ = Down(ctx)`：如果 down 也失败，状态里必须能看出来「我们以为已经
// 断了，其实没有」。Down 用独立的 3 秒 ctx，避免本轮 ctx 已经超时导致清理
// 直接失败。
func (p *Plane) failClosed(gen uint64, cause error) {
	downCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.backend.Down(downCtx); err != nil {
		slog.Error("wireguard interface could not be brought down after a reconcile failure", "error", err)
		cause = fmt.Errorf("%w; bringing the interface down also failed: %v", cause, err)
	}
	p.fail(gen, cause)
}

func (p *Plane) invalidateACL() {
	p.mu.Lock()
	p.aclReady = false
	p.aclSignature = ""
	p.mu.Unlock()
}

// ensureACL 只在期望集合变化或表被外部删掉时重载整表。
//
// 每次 peer 变更都重建表会清零 nft 计数器（排障时看不到 drop 有没有增长），
// 所以签名没变时先用 `nft list tables` 确认表还在，在就跳过。
func (p *Plane) ensureACL(ctx context.Context, acl ACL) error {
	signature := acl.signature()
	p.mu.Lock()
	ready := p.aclReady
	previous := p.aclSignature
	p.mu.Unlock()

	if ready && previous == signature {
		exists, err := p.backend.ACLExists(ctx)
		if err != nil {
			return fmt.Errorf("check wireguard nft table: %w", err)
		}
		if exists {
			return nil
		}
	}
	if err := p.backend.ApplyACL(ctx, acl); err != nil {
		return fmt.Errorf("install wireguard nft table: %w", err)
	}
	p.mu.Lock()
	p.aclReady = true
	p.aclSignature = signature
	p.mu.Unlock()
	return nil
}

func (p *Plane) fail(gen uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infraErr = err.Error()
	p.applied = gen // 本轮尝试已经结束；等待者靠 infraErr 立刻失败
}

func (p *Plane) finish(gen uint64, peers []Peer, deviceErrs map[string]error, stats map[string]PeerStats) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infraErr = ""
	appliedVersion := make(map[string]uint64, len(peers))
	deviceErr := make(map[string]string, len(peers))
	for _, peer := range peers {
		if err, ok := deviceErrs[peer.DeviceID]; ok && err != nil {
			deviceErr[peer.DeviceID] = err.Error()
			// 失败的设备不推进 appliedVersion：等待者会拿到该设备的 error。
			continue
		}
		appliedVersion[peer.DeviceID] = peer.Version
	}
	p.appliedVersion = appliedVersion
	p.deviceErr = deviceErr
	p.peers = append([]Peer(nil), peers...)
	if stats != nil {
		p.peerStats = stats
	}
	p.applied = gen
}
