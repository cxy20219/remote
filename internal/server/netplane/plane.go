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
	// Ensure 建/改 hub 接口并置为 up。
	Ensure(ctx context.Context, hub Hub) error
	// Apply 把 peer 集合对齐到 desired；返回按 device_id 的失败（不影响其它设备），
	// 第二个返回值是接口级错误（此时整轮作废）。
	Apply(ctx context.Context, peers []Peer) (map[string]error, error)
	// Handshakes 返回公钥 → 最近握手距今秒数（0 表示从未握手）。
	Handshakes(ctx context.Context) (map[string]int64, error)
	// Down 把接口拉下来（fail-closed 用）。
	Down(ctx context.Context) error
}

// Config 是 New 的参数。
type Config struct {
	Store   Store
	Backend Backend
	// ACLReady 在阶段 1 恒为 false：nft 规则要到第二批才落地，状态接口必须
	// 如实报告，而不是让人以为转发已经被限制。
	ACLReady bool
	// Interval 是自愈周期（外部删表/删接口时兜底），默认 30s。
	Interval time.Duration
}

// Plane 是状态机的拥有者。
type Plane struct {
	store    Store
	backend  Backend
	aclReady bool
	interval time.Duration

	mu             sync.Mutex
	gen            uint64
	applied        uint64
	infraErr       string
	blocked        string
	refused        bool
	started        bool
	appliedVersion map[string]uint64
	deviceErr      map[string]string
	handshakes     map[string]int64
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
		aclReady:       cfg.ACLReady,
		interval:       interval,
		appliedVersion: make(map[string]uint64),
		deviceErr:      make(map[string]string),
		handshakes:     make(map[string]int64),
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
		_ = p.backend.Down(ctx)
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
			_ = p.backend.Down(ctx)
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

// InfraError 返回当前接口级错误，空串表示正常。
func (p *Plane) InfraError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.infraErr
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
		status.Peers = append(status.Peers, PeerStatus{
			DeviceID:       peer.DeviceID,
			Address:        peer.Address,
			Role:           peer.Role,
			Enabled:        peer.Enabled,
			Version:        peer.Version,
			AppliedVersion: p.appliedVersion[peer.DeviceID],
			Error:          p.deviceErr[peer.DeviceID],
			HandshakeAge:   p.handshakes[peer.PublicKey],
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
	if len(snapshot.Peers) == 0 {
		p.finish(gen, snapshot.Peers, nil, nil)
		return
	}
	if p.backend == nil {
		p.fail(gen, errors.New("wireguard backend is not configured"))
		return
	}
	if err := p.backend.Probe(ctx); err != nil {
		p.fail(gen, err)
		_ = p.backend.Down(ctx)
		return
	}
	if err := p.backend.Ensure(ctx, snapshot.Hub); err != nil {
		p.fail(gen, err)
		_ = p.backend.Down(ctx)
		return
	}
	deviceErrs, err := p.backend.Apply(ctx, snapshot.Peers)
	if err != nil {
		p.fail(gen, err)
		_ = p.backend.Down(ctx)
		return
	}
	handshakes, err := p.backend.Handshakes(ctx)
	if err != nil {
		// 读状态失败不影响“已应用”的判定，但要把错误暴露出来。
		p.fail(gen, err)
		return
	}
	p.finish(gen, snapshot.Peers, deviceErrs, handshakes)
}

func (p *Plane) fail(gen uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infraErr = err.Error()
	p.applied = gen // 本轮尝试已经结束；等待者靠 infraErr 立刻失败
}

func (p *Plane) finish(gen uint64, peers []Peer, deviceErrs map[string]error, handshakes map[string]int64) {
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
	if handshakes != nil {
		p.handshakes = handshakes
	}
	p.applied = gen
}
