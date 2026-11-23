package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

const (
	TunnelExposurePublic      = "public"
	TunnelExposureServerLocal = "server_local"

	// 派生状态：不落盘，按定义 + 当前连接计算。
	TunnelStatusWaitingDevice = "waiting_device" // 定义在，设备不在线
	TunnelStatusActive        = "active"         // 已绑定且 tunnel_open 已写入当前连接
	TunnelStatusPortConflict  = "port_conflict"  // bind 失败（EADDRINUSE/EACCES）
	TunnelStatusOutOfRange    = "out_of_range"   // public_port 不在当前端口段
	TunnelStatusApplyFailed   = "apply_failed"   // bind 成功但 tunnel_open 写失败等

	TunnelBindAll         = "0.0.0.0"
	TunnelBindServerLocal = "127.0.0.1"

	externalConnQueueSize  = 32
	externalQueueWaitLimit = 15 * time.Second
	externalWriteTimeout   = 30 * time.Second

	// 公网侧并发连接硬上限：超限直接关闭新连接，不排队——扫描器不该拿到
	// 「等一会儿就能连上」的保证，也不该让每个试探连接都占住一份读缓冲。
	maxExternalConnsPerTunnel = 64
	maxExternalConnsTotal     = 1024

	// 公网读缓冲。转发帧本身是变长的（读多少发多少），缓冲大小不影响帧
	// 边界语义；32KB 让单连接常驻从 256KB 降到 32KB，1024 并发约 32MB。
	externalConnBufSize = 32 * 1024

	// 公网连接的空闲读超时默认值；可用 --external-idle-timeout 覆盖。
	// 15 分钟对扫描器太宽容：一条不发数据的连接能白占端口与缓冲。
	defaultExternalIdleTimeout = 10 * time.Minute
)

var (
	errTunnelNotFound = errors.New("tunnel not found")
	errTunnelOffline  = errors.New("tunnel device is offline")
	errTunnelPersist  = errors.New("tunnel definitions could not be persisted")

	// 公网连接数上限。超限直接关闭，不排队也不能挤掉已有连接。
	errExternalConnPerTunnelLimit = errors.New("per-tunnel external connection limit reached")
	errExternalConnGlobalLimit    = errors.New("global external connection limit reached")
)

// portConflictRetryDelays 覆盖「旧进程端口还没退干净」的瞬态冲突：1s/3s/9s
// 三次后停下等人处理（不换端口）。
var portConflictRetryDelays = []time.Duration{time.Second, 3 * time.Second, 9 * time.Second}

// tunnelOpenHook 只给测试用：apply 已经 bind、还没写 tunnel_open 时被调用
// （此时不持有 tm.mu），用来把“写前再校验”的窗口停下来。生产路径为 nil。
var tunnelOpenHook func(tunnelID string)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, externalConnBufSize)
		return &b
	},
}

// Tunnel 隧道信息：定义字段可持久化，运行时字段（Client/listener/status）
// 只存在于内存。BindAddr 由 exposure 派生，不落盘。
type Tunnel struct {
	TunnelID   string    `json:"tunnel_id"`
	ClientID   string    `json:"client_id"`
	Client     *Client   `json:"-"` // WebSocket 连接 (not serialized)
	Protocol   string    `json:"protocol"`
	PublicPort int       `json:"public_port"`
	Exposure   string    `json:"exposure"`
	BindAddr   string    `json:"bind_addr"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  int       `json:"local_port"`
	CreatedAt  time.Time `json:"created_at"`

	// Status/LastError 是派生值，不落盘也不参与 dirty。
	Status    string `json:"status"`
	LastError string `json:"last_error,omitempty"`

	// applying/retrying 防同一条定义被并发 apply / 重复排重试链（tm.mu 保护）。
	// applySeq 标识“当前这一次 apply”：旧连接迟到的失败分支只能清理自己
	// 那一次，不能关掉新一次 apply 已经建好的 listener。
	applying bool
	retrying bool
	applySeq uint64
}

// lessTunnelOrder 定义重放/落盘的稳定顺序：创建时间优先，相同时间用
// tunnel_id 兜底，保证重启前后顺序一致。
func lessTunnelOrder(aCreated time.Time, aID string, bCreated time.Time, bID string) bool {
	if aCreated.Equal(bCreated) {
		return aID < bID
	}
	return aCreated.Before(bCreated)
}

// definition 返回可持久化的定义视图。
func (t *Tunnel) definition() TunnelState {
	return TunnelState{
		TunnelID:   t.TunnelID,
		ClientID:   t.ClientID,
		Protocol:   t.Protocol,
		LocalAddr:  t.LocalAddr,
		LocalPort:  t.LocalPort,
		PublicPort: t.PublicPort,
		Exposure:   t.Exposure,
		CreatedAt:  t.CreatedAt,
	}
}

func tunnelFromDefinition(def TunnelState) *Tunnel {
	exposure, bindAddr, err := normalizeTunnelExposure(def.Exposure)
	if err != nil {
		exposure, bindAddr = def.Exposure, TunnelBindAll
	}
	return &Tunnel{
		TunnelID:   def.TunnelID,
		ClientID:   def.ClientID,
		Protocol:   def.Protocol,
		PublicPort: def.PublicPort,
		Exposure:   exposure,
		BindAddr:   bindAddr,
		LocalAddr:  def.LocalAddr,
		LocalPort:  def.LocalPort,
		CreatedAt:  def.CreatedAt,
		Status:     TunnelStatusWaitingDevice,
	}
}

type extChunk struct {
	data []byte
	eof  bool
}

// ExternalConn tracks one public-side TCP connection. A dedicated writer
// goroutine drains the queue so transient slow writes do not stall the shared
// WebSocket receive loop; sustained backpressure is bounded by queue wait.
type ExternalConn struct {
	ConnID   string
	TunnelID string
	Conn     net.Conn

	queue     chan extChunk
	done      chan struct{}
	closeOnce sync.Once
}

func newExternalConn(connID, tunnelID string, conn net.Conn) *ExternalConn {
	return &ExternalConn{
		ConnID:   connID,
		TunnelID: tunnelID,
		Conn:     conn,
		queue:    make(chan extChunk, externalConnQueueSize),
		done:     make(chan struct{}),
	}
}

func (ec *ExternalConn) push(chunk extChunk) bool {
	select {
	case <-ec.done:
		return false
	default:
	}
	select {
	case <-ec.done:
		return false
	case ec.queue <- chunk:
		return true
	default:
	}

	// The queue is a burst buffer. When it fills, apply backpressure to the
	// shared WebSocket for a bounded time instead of dropping live TCP data.
	timer := time.NewTimer(externalQueueWaitLimit)
	defer timer.Stop()
	select {
	case <-ec.done:
		return false
	case ec.queue <- chunk:
		return true
	case <-timer.C:
		return false
	}
}

func (ec *ExternalConn) stop() {
	ec.closeOnce.Do(func() {
		close(ec.done)
		_ = ec.Conn.Close()
	})
}

// TunnelManager 隧道管理器
type TunnelManager struct {
	mu               sync.RWMutex
	tunnels          map[string]*Tunnel       // tunnelID -> Tunnel
	publicPorts      map[int]string           // listenPort -> tunnelID
	extConns         map[string]*ExternalConn // connID -> ExternalConn
	unavailablePorts map[int]struct{}         // 系统占用的端口（惰性检测）
	portStart        int
	portEnd          int
	listeners        map[int]net.Listener // publicPort -> 监听器
	server           *Server
	closed           bool
}

// NewTunnelManager creates a new TunnelManager
func NewTunnelManager(server *Server, portStart, portEnd int) *TunnelManager {
	return &TunnelManager{
		tunnels:          make(map[string]*Tunnel),
		publicPorts:      make(map[int]string),
		extConns:         make(map[string]*ExternalConn),
		unavailablePorts: make(map[int]struct{}),
		portStart:        portStart,
		portEnd:          portEnd,
		listeners:        make(map[int]net.Listener),
		server:           server,
	}
}

func normalizeTunnelExposure(exposure string) (string, string, error) {
	exposure = strings.ToLower(strings.TrimSpace(exposure))
	if exposure == "" {
		exposure = TunnelExposurePublic
	}

	switch exposure {
	case TunnelExposurePublic:
		return TunnelExposurePublic, TunnelBindAll, nil
	case TunnelExposureServerLocal:
		return TunnelExposureServerLocal, TunnelBindServerLocal, nil
	default:
		return "", "", fmt.Errorf("unsupported exposure %q: use public or server_local", exposure)
	}
}

func listenAddrForBind(bindAddr string, port int) string {
	bindAddr = strings.TrimSpace(bindAddr)
	if bindAddr == "" || bindAddr == TunnelBindAll {
		return fmt.Sprintf(":%d", port)
	}
	return net.JoinHostPort(bindAddr, fmt.Sprintf("%d", port))
}

// AllocatePortForExposure 按入口类型分配端口并创建监听器。
func (tm *TunnelManager) AllocatePortForExposure(exposure string) (int, net.Listener, error) {
	_, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return 0, nil, err
	}
	return tm.allocatePortForBind(bindAddr)
}

func (tm *TunnelManager) allocatePortForBind(bindAddr string) (int, net.Listener, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return 0, nil, fmt.Errorf("tunnel manager is shutting down")
	}
	for port := tm.portStart; port <= tm.portEnd; port++ {
		if _, used := tm.publicPorts[port]; used {
			continue
		}
		if _, unavailable := tm.unavailablePorts[port]; unavailable {
			continue
		}
		ln, err := net.Listen("tcp", listenAddrForBind(bindAddr, port))
		if err != nil {
			tm.unavailablePorts[port] = struct{}{}
			slog.Warn("port occupied by system, skipping", "port", port, "bind_addr", bindAddr, "error", err)
			continue
		}
		tm.publicPorts[port] = "" // 标记为已用
		return port, ln, nil
	}
	return 0, nil, fmt.Errorf("no available ports in range %d-%d", tm.portStart, tm.portEnd)
}

// ReleasePort 释放一次「已分配但还没归属任何定义」的端口占位。端口已经被
// 别的定义认领时什么都不做：创建失败的回滚只能撤掉自己那次占位，否则会把
// 并发“改到同一端口”的那条定义刚认领的端口放掉。
func (tm *TunnelManager) ReleasePort(port int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if owner, used := tm.publicPorts[port]; used && owner != "" {
		slog.Debug("releasePort: port is owned by a tunnel, keeping it",
			"public_port", port, "tunnel_id", owner)
		return
	}
	delete(tm.publicPorts, port)
	delete(tm.unavailablePorts, port)
}

// CreateTunnel 创建隧道
func (tm *TunnelManager) CreateTunnel(tunnelID, clientID string, client *Client, protocol, localAddr string, localPort, publicPort int, exposure string) error {
	normalizedExposure, bindAddr, err := normalizeTunnelExposure(exposure)
	if err != nil {
		return err
	}
	maxTunnels := tm.maxTunnelsPerClient()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return fmt.Errorf("tunnel manager is shutting down")
	}
	if _, exists := tm.tunnels[tunnelID]; exists {
		return fmt.Errorf("tunnel already exists: %s", tunnelID)
	}
	if maxTunnels > 0 {
		count := 0
		for _, t := range tm.tunnels {
			if t.ClientID == clientID {
				count++
			}
		}
		if count >= maxTunnels {
			return fmt.Errorf("max tunnels per client reached: %d", maxTunnels)
		}
	}
	if existingID, used := tm.publicPorts[publicPort]; used && existingID != "" {
		return fmt.Errorf("public port %d already in use", publicPort)
	}

	tunnel := &Tunnel{
		TunnelID:   tunnelID,
		ClientID:   clientID,
		Client:     client,
		Protocol:   protocol,
		PublicPort: publicPort,
		Exposure:   normalizedExposure,
		BindAddr:   bindAddr,
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		CreatedAt:  time.Now(),
		Status:     TunnelStatusWaitingDevice,
	}
	if publicPort < tm.portStart || publicPort > tm.portEnd {
		tunnel.Status = TunnelStatusOutOfRange
		tunnel.LastError = fmt.Sprintf("public port %d is outside the configured range %d-%d", publicPort, tm.portStart, tm.portEnd)
	}

	tm.tunnels[tunnelID] = tunnel
	tm.publicPorts[publicPort] = tunnelID

	// 定义先落盘，绑定是它的投影：Save 失败就回滚内存并让 API 返回 5xx。
	if err := tm.persistDefinitionsLocked(); err != nil {
		delete(tm.tunnels, tunnelID)
		if tm.publicPorts[publicPort] == tunnelID {
			delete(tm.publicPorts, publicPort)
		}
		return fmt.Errorf("%w: %v", errTunnelPersist, err)
	}

	slog.Info("tunnel definition created",
		"tunnel_id", tunnelID,
		"client_id", clientID,
		"public_port", publicPort,
		"exposure", normalizedExposure,
		"bind_addr", bindAddr,
		"local_addr", localAddr,
		"local_port", localPort)

	return nil
}

func (tm *TunnelManager) GetTunnel(tunnelID string) (Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		return Tunnel{}, false
	}
	return *tunnel, true
}

// ListTunnels 返回所有隧道
func (tm *TunnelManager) ListTunnels() []Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tunnels := make([]Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, *t)
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
	})
	return tunnels
}

// ListTunnelsByClient 返回指定客户端的隧道
func (tm *TunnelManager) ListTunnelsByClient(clientID string) []Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var tunnels []Tunnel
	for _, t := range tm.tunnels {
		if t.ClientID == clientID {
			tunnels = append(tunnels, *t)
		}
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
	})
	return tunnels
}

// DeleteTunnel 删除定义：先删定义并同步落盘（失败则原样恢复），再关
// listener、断外部连接、释放端口。离线定义也能删。
func (tm *TunnelManager) DeleteTunnel(tunnelID string) (*Tunnel, error) {
	tm.mu.Lock()
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		tm.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", errTunnelNotFound, tunnelID)
	}
	delete(tm.tunnels, tunnelID)
	if err := tm.persistDefinitionsLocked(); err != nil {
		tm.tunnels[tunnelID] = tunnel
		tm.mu.Unlock()
		return nil, fmt.Errorf("persist tunnel definition removal: %w", err)
	}
	tm.closeListenerLocked(tunnel.PublicPort)
	tm.closeTunnelConnectionsLocked(tunnelID)
	delete(tm.publicPorts, tunnel.PublicPort)
	client := tunnel.Client
	out := *tunnel
	tm.mu.Unlock()

	// 定义已经不存在；通知失败只影响 agent 侧残留，不影响定义。
	if client != nil {
		if err := sendTunnelClose(client, tunnelID); err != nil {
			slog.Warn("failed to notify agent about tunnel deletion", "tunnel_id", tunnelID, "error", err)
		}
	}
	slog.Info("tunnel definition deleted", "tunnel_id", tunnelID)
	return &out, nil
}

// closeListenerLocked 关掉并移除某端口的 listener。调用方必须持有 tm.mu。
func (tm *TunnelManager) closeListenerLocked(port int) {
	if listener, ok := tm.listeners[port]; ok {
		listener.Close()
		delete(tm.listeners, port)
	}
}

func (tm *TunnelManager) maxTunnelsPerClient() int {
	if tm.server == nil || tm.server.stateStore == nil {
		return 0
	}
	return tm.server.stateStore.GetSettings().MaxTunnelsPerClient
}

// DetachClient 断开设备时调用：关掉该设备所有 listener 与外部连接，但保留
// 定义和端口。定义留下才能在下一次 register_ok 之后原端口重放。
//
// client 是正在断开的那个连接，nil 表示不做身份校验（单测直接驱动）。设备
// 已经有新连接时直接跳过：旧连接的收尾晚到时，不能拆掉新连接刚恢复的绑定。
func (tm *TunnelManager) DetachClient(clientID string, client *Client) {
	tm.mu.Lock()
	// 身份校验放在锁内：检查与解绑之间不能有注册新连接的窗口。锁序是
	// tm.mu → clients.mu，与 applyTunnel 的 isCurrentClient 一致。
	if client != nil && tm.server != nil && tm.server.clients != nil {
		if current, ok := tm.server.clients.Get(clientID); ok && current != client {
			tm.mu.Unlock()
			slog.Debug("skip detach: the device already reconnected",
				"client_id", clientID)
			return
		}
	}
	detached := 0
	for tunnelID, tunnel := range tm.tunnels {
		if tunnel.ClientID != clientID {
			continue
		}
		tm.closeListenerLocked(tunnel.PublicPort)
		tm.closeTunnelConnectionsLocked(tunnelID)
		tunnel.Client = nil
		tunnel.applying = false
		tunnel.retrying = false
		if tunnel.Status != TunnelStatusOutOfRange {
			tunnel.Status = TunnelStatusWaitingDevice
			tunnel.LastError = ""
		}
		detached++
	}
	tm.mu.Unlock()
	if detached > 0 {
		slog.Info("tunnel definitions detached from device", "client_id", clientID, "count", detached)
	}
}

// RemoveClientTunnels 删除设备时调用：先删定义并同步落盘，再关 listener、
// 断外部连接、释放端口。落盘失败时定义原样保留。
func (tm *TunnelManager) RemoveClientTunnels(clientID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var removed []*Tunnel
	for tunnelID, tunnel := range tm.tunnels {
		if tunnel.ClientID == clientID {
			delete(tm.tunnels, tunnelID)
			removed = append(removed, tunnel)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if err := tm.persistDefinitionsLocked(); err != nil {
		for _, tunnel := range removed {
			tm.tunnels[tunnel.TunnelID] = tunnel
		}
		return fmt.Errorf("%w: %v", errTunnelPersist, err)
	}
	for _, tunnel := range removed {
		tm.closeListenerLocked(tunnel.PublicPort)
		tm.closeTunnelConnectionsLocked(tunnel.TunnelID)
		delete(tm.publicPorts, tunnel.PublicPort)
	}
	slog.Info("tunnel definitions removed for device", "client_id", clientID, "count", len(removed))
	return nil
}

func (tm *TunnelManager) CloseAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.closed = true

	for _, ec := range tm.extConns {
		ec.stop()
	}
	for _, listener := range tm.listeners {
		listener.Close()
	}

	tm.extConns = make(map[string]*ExternalConn)
	tm.listeners = make(map[int]net.Listener)
	tm.tunnels = make(map[string]*Tunnel)
	tm.publicPorts = make(map[int]string)

	slog.Info("all tunnels closed")
}

// UpdateTunnel 修改定义并同步落盘；落盘成功后，若设备在线则重绑并重放
// tunnel_open。apply 失败只改 status/last_error，不回滚定义（与创建一致）。
func (tm *TunnelManager) UpdateTunnel(tunnelID string, localAddr string, localPort int, newPublicPort int, protocol string, exposure string) (*Tunnel, error) {
	tm.mu.Lock()
	if tm.closed {
		tm.mu.Unlock()
		return nil, fmt.Errorf("tunnel manager is shutting down")
	}
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		tm.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", errTunnelNotFound, tunnelID)
	}

	effectiveExposure := exposure
	if strings.TrimSpace(effectiveExposure) == "" {
		effectiveExposure = tunnel.Exposure
	}
	normalizedExposure, bindAddr, err := normalizeTunnelExposure(effectiveExposure)
	if err != nil {
		tm.mu.Unlock()
		return nil, err
	}
	targetPort := tunnel.PublicPort
	if newPublicPort > 0 {
		targetPort = newPublicPort
	}
	if targetPort < tm.portStart || targetPort > tm.portEnd {
		tm.mu.Unlock()
		return nil, fmt.Errorf("public port %d out of range [%d, %d]", targetPort, tm.portStart, tm.portEnd)
	}
	if existingID, used := tm.publicPorts[targetPort]; used && existingID != "" && existingID != tunnelID {
		tm.mu.Unlock()
		return nil, fmt.Errorf("public port %d already in use", targetPort)
	}

	previous := *tunnel
	client := tunnel.Client
	oldPort := tunnel.PublicPort
	portChanged := targetPort != oldPort
	bindChanged := bindAddr != tunnel.BindAddr
	targetChanged := localAddr != tunnel.LocalAddr || localPort != tunnel.LocalPort || protocol != tunnel.Protocol
	if !portChanged && !bindChanged && !targetChanged {
		out := *tunnel
		tm.mu.Unlock()
		return &out, nil
	}

	tunnel.PublicPort = targetPort
	tunnel.Exposure = normalizedExposure
	tunnel.BindAddr = bindAddr
	tunnel.LocalAddr = localAddr
	tunnel.LocalPort = localPort
	tunnel.Protocol = protocol
	tunnel.Client = nil
	tunnel.Status = TunnelStatusWaitingDevice
	tunnel.LastError = ""
	if portChanged {
		delete(tm.publicPorts, oldPort)
		tm.publicPorts[targetPort] = tunnelID
	}

	// 定义先落盘：失败就整体回滚，连 listener 都不动。
	if err := tm.persistDefinitionsLocked(); err != nil {
		*tunnel = previous
		if portChanged {
			delete(tm.publicPorts, targetPort)
			tm.publicPorts[oldPort] = tunnelID
		}
		tm.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", errTunnelPersist, err)
	}

	// 定义已经换了：正在途中的那次 apply 是旧定义的投影，必须作废。否则
	// 它在 tunnel_open 写成功之后会把状态改回 active，而它对应的 listener
	// 刚在这里被关掉——面板显示“已连接”，实际没有任何监听。
	if tunnel.applying {
		tunnel.applying = false
		tunnel.applySeq++
	}

	// 落盘成功后才动绑定：旧 listener 不再属于这条定义。
	if portChanged || bindChanged {
		tm.closeListenerLocked(oldPort)
		if portChanged {
			delete(tm.publicPorts, oldPort)
		}
	}
	if targetChanged || portChanged || bindChanged {
		tm.closeTunnelConnectionsLocked(tunnelID)
	}
	out := *tunnel
	tm.mu.Unlock()

	// 设备在线才重绑；离线时定义已经保存，等下次重连。
	if client == nil {
		client = tm.currentClient(out.ClientID)
	}
	if client == nil {
		return &out, nil
	}
	if targetChanged || portChanged || bindChanged {
		if err := sendTunnelClose(client, tunnelID); err != nil {
			slog.Warn("failed to notify agent about tunnel update", "tunnel_id", tunnelID, "error", err)
		}
	}
	updated, err := tm.applyTunnel(tunnelID, client)
	if err != nil {
		return &out, err
	}
	slog.Info("tunnel updated",
		"tunnel_id", tunnelID,
		"public_port", updated.PublicPort,
		"exposure", updated.Exposure,
		"local_addr", updated.LocalAddr,
		"local_port", updated.LocalPort)
	return &updated, nil
}

// closeTunnelConnectionsLocked closes all external connections of a tunnel.
// The caller must hold tm.mu.
func (tm *TunnelManager) closeTunnelConnectionsLocked(tunnelID string) {
	var connIDs []string
	for connID, ec := range tm.extConns {
		if ec.TunnelID == tunnelID {
			ec.stop()
			connIDs = append(connIDs, connID)
		}
	}
	for _, connID := range connIDs {
		delete(tm.extConns, connID)
	}
}

// AddExternalConn registers a public-side connection. It fails when the
// tunnel disappeared between accept and registration, or when the per-tunnel /
// global external connection cap is reached.
//
// 上限在这里（锁内）判定：先通过再登记会留出「两个 accept 同时挤过」的
// 窗口。计数直接数 extConns——端口限流已经把 accept 速率压到每分钟个位数，
// 遍历这点开销可以忽略，不值得再维护一份容易失同步的计数。
func (tm *TunnelManager) AddExternalConn(connID, tunnelID string, conn net.Conn) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.tunnels[tunnelID]; !ok {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	perTunnel := 0
	for _, ec := range tm.extConns {
		if ec.TunnelID == tunnelID {
			perTunnel++
		}
	}
	if perTunnel >= maxExternalConnsPerTunnel {
		return fmt.Errorf("%w: tunnel %s has %d", errExternalConnPerTunnelLimit, tunnelID, perTunnel)
	}
	if len(tm.extConns) >= maxExternalConnsTotal {
		return fmt.Errorf("%w: %d active", errExternalConnGlobalLimit, len(tm.extConns))
	}
	ec := newExternalConn(connID, tunnelID, conn)
	tm.extConns[connID] = ec
	go tm.runExternalWriter(connID, ec)
	return nil
}

// externalConnAllowed 判定公网侧的新连接能不能接入：黑名单直接拒；全局
// 白名单与设备白名单免限流（它们服务的是隧道反扫描，不是管理面信任域）；
// 其余按 clientIPKey 聚合限流——IPv6 按 /64 记账，换地址不能重置扫描预算。
// loopback 的放行留在 accept 循环里，它判断的是部署形态而不是安全策略。
func (tm *TunnelManager) externalConnAllowed(tunnel *Tunnel, remoteIP string) bool {
	if tm.server == nil {
		return true
	}
	if tm.server.blacklist != nil && tm.server.blacklist.IsBlacklisted(remoteIP) {
		slog.Warn("external connection from blacklisted IP, rejecting",
			"remote_ip", remoteIP, "tunnel_id", tunnel.TunnelID)
		return false
	}
	if tm.server.IsGloballyWhitelisted(remoteIP) {
		return true
	}
	if tm.server.clients != nil && tunnel.ClientID != "" {
		if whitelist := tm.server.clients.GetIPWhitelist(tunnel.ClientID); isIPWhitelisted(remoteIP, whitelist) {
			slog.Debug("external connection whitelisted, bypassing rate limit",
				"remote_ip", remoteIP, "tunnel_id", tunnel.TunnelID, "client_id", tunnel.ClientID)
			return true
		}
	}
	if tm.server.portLimiter == nil {
		return true
	}
	if tm.server.portLimiter.Allow(clientIPKey(remoteIP)) {
		return true
	}
	slog.Warn("external connection rate limited (anti-scanning)",
		"remote_ip", remoteIP, "key", clientIPKey(remoteIP), "tunnel_id", tunnel.TunnelID)
	tm.server.blacklist.AddViolation(remoteIP)
	return false
}

// externalIdleTimeout 返回公网连接的空闲读超时。未配置时用默认值，测试里
// 直接构造的 Server（没有 config）也走默认，不会退化成 0 导致立即超时。
func (tm *TunnelManager) externalIdleTimeout() time.Duration {
	if tm.server != nil && tm.server.config != nil {
		if configured := tm.server.config.Tunnel.ExternalIdleTimeout; configured > 0 {
			return configured
		}
	}
	return defaultExternalIdleTimeout
}

// RemoveExternalConn removes and closes an external connection.
func (tm *TunnelManager) RemoveExternalConn(connID string) {
	tm.mu.Lock()
	ec := tm.extConns[connID]
	delete(tm.extConns, connID)
	tm.mu.Unlock()
	if ec != nil {
		ec.stop()
	}
}

func (tm *TunnelManager) removeExternalConnIfMatch(connID string, ec *ExternalConn) {
	tm.mu.Lock()
	if tm.extConns[connID] == ec {
		delete(tm.extConns, connID)
	}
	tm.mu.Unlock()
}

func (tm *TunnelManager) runExternalWriter(connID string, ec *ExternalConn) {
	for {
		select {
		case <-ec.done:
			return
		case chunk := <-ec.queue:
			if len(chunk.data) > 0 {
				ec.Conn.SetWriteDeadline(time.Now().Add(externalWriteTimeout))
				err := writeFull(ec.Conn, chunk.data)
				ec.Conn.SetWriteDeadline(time.Time{})
				if err != nil {
					slog.Debug("external connection write failed", "conn_id", connID, "error", err)
					ec.stop()
					tm.removeExternalConnIfMatch(connID, ec)
					tm.sendTunnelEOFToTunnel(ec.TunnelID, connID)
					return
				}
			}
			if chunk.eof {
				ec.stop()
				tm.removeExternalConnIfMatch(connID, ec)
				return
			}
		}
	}
}

// acceptLoop 接受外部连接
func (tm *TunnelManager) acceptLoop(publicPort int, tunnelID string) {
	tm.mu.RLock()
	listener, ok := tm.listeners[publicPort]
	tunnel, tunnelOk := tm.tunnels[tunnelID]
	tm.mu.RUnlock()

	if !ok || !tunnelOk {
		slog.Error("acceptLoop: listener or tunnel not found",
			"public_port", publicPort,
			"tunnel_id", tunnelID)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			tm.mu.RLock()
			currentListener, stillOk := tm.listeners[publicPort]
			tm.mu.RUnlock()
			if !stillOk || currentListener != listener {
				return
			}
			slog.Warn("accept error", "public_port", publicPort, "error", err)
			continue
		}

		remoteIP := extractIP(conn.RemoteAddr().String())

		if isLoopbackIP(remoteIP) {
			slog.Debug("external connection from localhost, bypassing rate limit",
				"tunnel_id", tunnelID)
		} else if !tm.externalConnAllowed(tunnel, remoteIP) {
			conn.Close()
			continue
		}

		connID := tunnelID + "-" + uuid.NewString()
		// Client 是运行时字段，detach/重连都会在锁内改写它。公网连接路径
		// 上必须取快照再交给 goroutine，不能无锁读。
		tm.mu.RLock()
		activeClient := tunnel.Client
		tm.mu.RUnlock()
		go tm.handleExternalConn(connID, tunnel, activeClient, conn)
	}
}

// handleExternalConn reads from the public connection and forwards frames to
// the agent. client 是 accept 那一刻的连接快照。
func (tm *TunnelManager) handleExternalConn(connID string, tunnel *Tunnel, client *Client, extConn net.Conn) {
	common.TuneTCPConn(extConn)

	tunnelID := tunnel.TunnelID
	if client == nil || tm.server == nil {
		extConn.Close()
		return
	}
	if err := tm.AddExternalConn(connID, tunnelID, extConn); err != nil {
		if errors.Is(err, errExternalConnPerTunnelLimit) || errors.Is(err, errExternalConnGlobalLimit) {
			slog.Warn("external connection rejected: connection limit reached",
				"tunnel_id", tunnelID,
				"remote", extConn.RemoteAddr(),
				"error", err)
		}
		extConn.Close()
		return
	}
	defer func() {
		tm.RemoveExternalConn(connID)
		tm.sendTunnelEOF(tunnelID, connID, client)
	}()

	slog.Debug("external connection accepted",
		"conn_id", connID,
		"tunnel_id", tunnelID,
		"remote", extConn.RemoteAddr())

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	idleTimeout := tm.externalIdleTimeout()
	for {
		extConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := extConn.Read(buf)
		if n > 0 {
			frame, frameErr := tm.server.encodeTunnelFrame(client, tunnelID, connID, buf[:n], false)
			if frameErr != nil {
				slog.Error("failed to encode tunnel data frame", "conn_id", connID, "error", frameErr)
				return
			}
			if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				slog.Warn("failed to send tunnel_data_bin to agent", "conn_id", connID, "error", err)
				return
			}
		}
		if err != nil {
			var netErr net.Error
			switch {
			case errors.As(err, &netErr) && netErr.Timeout():
				// 空闲超时现在是常规事件（默认 10 分钟），不该按错误刷 WARN。
				slog.Debug("external conn idle timeout", "conn_id", connID, "idle_timeout", idleTimeout)
			case err == io.EOF || strings.Contains(err.Error(), "use of closed network connection"):
				slog.Debug("external conn closed", "conn_id", connID, "error", err)
			default:
				slog.Warn("external conn read error", "conn_id", connID, "error", err)
			}
			return
		}
	}
}

func (tm *TunnelManager) sendTunnelEOF(tunnelID, connID string, client *Client) {
	if client == nil {
		return
	}
	frame, err := common.EncodeBinaryTunnelDataFrame(tunnelID, connID, nil, true)
	if err != nil {
		return
	}
	if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		slog.Debug("failed to send tunnel EOF frame", "tunnel_id", tunnelID, "conn_id", connID, "error", err)
	}
}

func (tm *TunnelManager) sendTunnelEOFToTunnel(tunnelID, connID string) {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	var client *Client
	if ok {
		client = tunnel.Client
	}
	tm.mu.RUnlock()
	tm.sendTunnelEOF(tunnelID, connID, client)
}

// encodeTunnelFrame encrypts (when enabled) and encodes one tunnel data frame
// without copying the ciphertext a second time.
func (s *Server) encodeTunnelFrame(client *Client, tunnelID, connID string, data []byte, isEOF bool) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("tunnel client is not connected")
	}
	if !client.EncryptionEnabled() {
		return common.EncodeBinaryTunnelDataFrame(tunnelID, connID, data, isEOF)
	}
	if s.cryptoMgr == nil {
		return nil, fmt.Errorf("encryption manager is not initialized")
	}

	frame, payload, err := common.NewBinaryTunnelDataFrame(tunnelID, connID, len(data)+common.TunnelEncryptionOverhead, isEOF)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.cryptoMgr.EncryptTo(client.ClientID, payload, data)
	if err != nil {
		return nil, err
	}
	return frame[:len(frame)+len(encrypted)], nil
}

// PortStatus 端口范围状态摘要
type PortStatus struct {
	RangeStart     int   `json:"range_start"`
	RangeEnd       int   `json:"range_end"`
	TotalPorts     int   `json:"total_ports"`
	Allocated      int   `json:"allocated"`
	Unavailable    []int `json:"unavailable"`
	AvailableCount int   `json:"available_count"`
}

// SetPortRange 热更新端口范围。已在服务的 listener 不动（不切断在用的
// SSH）；未绑定的定义在新范围外标记 out_of_range，范围恢复后回到
// waiting_device。
func (tm *TunnelManager) SetPortRange(start, end int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.portStart = start
	tm.portEnd = end
	for _, tunnel := range tm.tunnels {
		if _, bound := tm.listeners[tunnel.PublicPort]; bound {
			continue
		}
		if tunnel.PublicPort < start || tunnel.PublicPort > end {
			if tunnel.Status != TunnelStatusOutOfRange {
				tunnel.Status = TunnelStatusOutOfRange
				tunnel.LastError = fmt.Sprintf("public port %d is outside the configured range %d-%d", tunnel.PublicPort, start, end)
			}
			continue
		}
		if tunnel.Status == TunnelStatusOutOfRange {
			tunnel.Status = TunnelStatusWaitingDevice
			tunnel.LastError = ""
		}
	}
}

// GetPortStatus 返回端口范围使用状况
func (tm *TunnelManager) GetPortStatus() PortStatus {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	total := tm.portEnd - tm.portStart + 1
	if total < 0 {
		total = 0
	}
	unavailable := make([]int, 0, len(tm.unavailablePorts))
	for port := range tm.unavailablePorts {
		if port >= tm.portStart && port <= tm.portEnd {
			unavailable = append(unavailable, port)
		}
	}
	sort.Ints(unavailable)

	allocated := 0
	for port := range tm.publicPorts {
		if port >= tm.portStart && port <= tm.portEnd {
			allocated++
		}
	}
	available := total - allocated - len(unavailable)
	if available < 0 {
		available = 0
	}

	return PortStatus{
		RangeStart:     tm.portStart,
		RangeEnd:       tm.portEnd,
		TotalPorts:     total,
		Allocated:      allocated,
		Unavailable:    unavailable,
		AvailableCount: available,
	}
}

// HandleAgentData enqueues data from the agent for the public connection. The
// per-connection writer drains the queue asynchronously so a slow external
// client cannot stall the shared WebSocket receive loop.
func (tm *TunnelManager) HandleAgentData(tunnelID, connID string, data []byte, isEOF bool) error {
	tm.mu.RLock()
	ec, ok := tm.extConns[connID]
	tm.mu.RUnlock()

	if !ok {
		slog.Debug("external connection already closed, dropping tunnel data",
			"tunnel_id", tunnelID,
			"conn_id", connID,
			"is_eof", isEOF,
			"bytes", len(data))
		return nil
	}
	if ec.TunnelID != tunnelID {
		return fmt.Errorf("conn %s does not belong to tunnel %s", connID, tunnelID)
	}

	if !ec.push(extChunk{data: data, eof: isEOF}) {
		slog.Warn("external connection queue stalled, closing connection",
			"tunnel_id", tunnelID,
			"conn_id", connID)
		tm.RemoveExternalConn(connID)
		tm.sendTunnelEOFToTunnel(tunnelID, connID)
	}
	return nil
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func sendTunnelOpen(client *Client, tunnelID, localAddr string, localPort int, protocol string) error {
	if client == nil {
		return fmt.Errorf("tunnel client is not connected")
	}
	payloadJSON, err := json.Marshal(common.TunnelOpenPayload{
		TunnelID:  tunnelID,
		LocalAddr: localAddr,
		LocalPort: localPort,
		Protocol:  protocol,
	})
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{Type: "tunnel_open", Payload: payloadJSON})
}

func sendTunnelClose(client *Client, tunnelID string) error {
	if client == nil {
		return fmt.Errorf("tunnel client is not connected")
	}
	payloadJSON, err := json.Marshal(common.TunnelClosePayload{TunnelID: tunnelID})
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{Type: "tunnel_close", Payload: payloadJSON})
}

// LoadDefinitions 把持久化的定义装入管理器：只占端口，不 bind。启动时调用。
//
// 校验不过的定义直接丢弃并记 ERROR：设备不存在（孤儿外键）、设备未授权、
// exposure/protocol/local_port 非法、端口非法或重复。端口不在当前 range 的
// 定义保留，标记 out_of_range（可能只是临时改小了范围）。
func (tm *TunnelManager) LoadDefinitions(definitions []TunnelState) {
	if len(definitions) == 0 {
		return
	}
	sorted := append([]TunnelState(nil), definitions...)
	sort.Slice(sorted, func(i, j int) bool {
		return lessTunnelOrder(sorted[i].CreatedAt, sorted[i].TunnelID, sorted[j].CreatedAt, sorted[j].TunnelID)
	})

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.closed {
		return
	}

	reserved := make(map[int]string, len(sorted))
	loaded := 0
	for _, def := range sorted {
		if def.TunnelID == "" || def.ClientID == "" {
			slog.Error("dropping tunnel definition without tunnel_id/client_id", "definition", def)
			continue
		}
		if _, exists := tm.tunnels[def.TunnelID]; exists {
			slog.Error("dropping duplicate tunnel definition", "tunnel_id", def.TunnelID)
			continue
		}
		if def.PublicPort < 1 || def.PublicPort > 65535 {
			slog.Error("dropping tunnel definition with an invalid public port", "tunnel_id", def.TunnelID, "public_port", def.PublicPort)
			continue
		}
		if existingID, used := reserved[def.PublicPort]; used {
			slog.Error("dropping tunnel definition with a duplicate public port",
				"tunnel_id", def.TunnelID, "kept_tunnel_id", existingID, "public_port", def.PublicPort)
			continue
		}
		if !tm.definitionAllowed(def) {
			continue
		}
		tunnel := tunnelFromDefinition(def)
		if def.PublicPort < tm.portStart || def.PublicPort > tm.portEnd {
			tunnel.Status = TunnelStatusOutOfRange
			tunnel.LastError = fmt.Sprintf("public port %d is outside the configured range %d-%d", def.PublicPort, tm.portStart, tm.portEnd)
		}
		tm.tunnels[def.TunnelID] = tunnel
		// 端口必须在加载时就占住，否则下一个创建会把 10000 分走。
		tm.publicPorts[def.PublicPort] = def.TunnelID
		reserved[def.PublicPort] = def.TunnelID
		loaded++
	}
	slog.Info("tunnel definitions loaded", "loaded", loaded, "submitted", len(sorted))
}

// definitionAllowed 校验一条定义能否自动恢复（设备身份 + 结构完整性）。
func (tm *TunnelManager) definitionAllowed(def TunnelState) bool {
	if tm.server != nil && tm.server.stateStore != nil {
		device := tm.server.stateStore.GetDeviceByID(def.ClientID)
		if device == nil {
			slog.Error("dropping tunnel definition for a device that no longer exists",
				"tunnel_id", def.TunnelID, "client_id", def.ClientID)
			return false
		}
		if device.Status != deviceStatusAuthorized {
			slog.Error("dropping tunnel definition for an unauthorized device",
				"tunnel_id", def.TunnelID, "client_id", def.ClientID, "status", device.Status)
			return false
		}
	}
	if def.Protocol != "tcp" {
		slog.Error("dropping tunnel definition with an unsupported protocol",
			"tunnel_id", def.TunnelID, "protocol", def.Protocol)
		return false
	}
	if _, _, err := normalizeTunnelExposure(def.Exposure); err != nil {
		slog.Error("dropping tunnel definition with an invalid exposure",
			"tunnel_id", def.TunnelID, "exposure", def.Exposure, "error", err)
		return false
	}
	if def.LocalPort < 1 || def.LocalPort > 65535 || strings.TrimSpace(def.LocalAddr) == "" {
		slog.Error("dropping tunnel definition with an invalid target",
			"tunnel_id", def.TunnelID, "local_addr", def.LocalAddr, "local_port", def.LocalPort)
		return false
	}
	return true
}

// definitionsLocked 返回按创建时间排序的定义快照。调用方必须持有 tm.mu。
func (tm *TunnelManager) definitionsLocked() []TunnelState {
	definitions := make([]TunnelState, 0, len(tm.tunnels))
	for _, tunnel := range tm.tunnels {
		definitions = append(definitions, tunnel.definition())
	}
	sort.Slice(definitions, func(i, j int) bool {
		return lessTunnelOrder(definitions[i].CreatedAt, definitions[i].TunnelID, definitions[j].CreatedAt, definitions[j].TunnelID)
	})
	return definitions
}

// persistDefinitionsLocked 把当前定义同步写进 state。调用方必须持有 tm.mu；
// 保存失败时 state 里的定义恢复原样，调用方负责回滚自己的内存变更。
func (tm *TunnelManager) persistDefinitionsLocked() error {
	if tm.server == nil || tm.server.stateStore == nil {
		return nil
	}
	return tm.server.stateStore.ReplaceTunnels(tm.definitionsLocked())
}

// ApplyTunnel 把一条定义绑定到它的当前连接：必要时 bind，再写 tunnel_open。
// 返回最新的定义视图；绑定失败不会删除定义或改变端口。
func (tm *TunnelManager) ApplyTunnel(tunnelID string) (Tunnel, error) {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	var client *Client
	var clientID string
	var snapshot Tunnel
	if ok {
		client = tunnel.Client
		clientID = tunnel.ClientID
		snapshot = *tunnel
	}
	tm.mu.RUnlock()
	if !ok {
		return Tunnel{}, fmt.Errorf("%w: %s", errTunnelNotFound, tunnelID)
	}
	if client == nil {
		client = tm.currentClient(clientID)
	}
	if client == nil {
		return snapshot, nil
	}
	return tm.applyTunnel(tunnelID, client)
}

// RetryTunnel 手动重试一次绑定（排障入口）。已 active 时幂等返回当前状态；
// 设备离线返回 errTunnelOffline。
func (tm *TunnelManager) RetryTunnel(tunnelID string) (Tunnel, error) {
	tm.mu.RLock()
	tunnel, ok := tm.tunnels[tunnelID]
	var snapshot Tunnel
	var client *Client
	if ok {
		snapshot = *tunnel
		client = tunnel.Client
	}
	tm.mu.RUnlock()
	if !ok {
		return Tunnel{}, fmt.Errorf("%w: %s", errTunnelNotFound, tunnelID)
	}
	if client != nil && !tm.isCurrentClient(client) {
		// 连接指针是旧的（设备已断开或已重连），按离线处理。
		client = nil
	}
	if snapshot.Status == TunnelStatusActive && client != nil {
		return snapshot, nil
	}
	if client == nil {
		client = tm.currentClient(snapshot.ClientID)
	}
	if client == nil {
		return snapshot, errTunnelOffline
	}
	return tm.applyTunnel(tunnelID, client)
}

// RestoreClient 在 register_ok 写成功之后重放该设备的全部定义。按创建时间
// 顺序逐条 apply，失败互不影响；旧连接上的迟到 restore 会因 IsCurrent 失败
// 而自行终止。
func (tm *TunnelManager) RestoreClient(client *Client) {
	if client == nil || client.ClientID == "" {
		return
	}
	tm.mu.RLock()
	tunnels := make([]Tunnel, 0)
	for _, tunnel := range tm.tunnels {
		if tunnel.ClientID == client.ClientID {
			tunnels = append(tunnels, *tunnel)
		}
	}
	tm.mu.RUnlock()
	sort.Slice(tunnels, func(i, j int) bool {
		return lessTunnelOrder(tunnels[i].CreatedAt, tunnels[i].TunnelID, tunnels[j].CreatedAt, tunnels[j].TunnelID)
	})

	for _, tunnel := range tunnels {
		if !tm.isCurrentClient(client) {
			return
		}
		if _, err := tm.applyTunnel(tunnel.TunnelID, client); err != nil {
			slog.Warn("failed to restore tunnel definition", "tunnel_id", tunnel.TunnelID, "client_id", client.ClientID, "error", err)
		}
	}
}

// applyTunnel 是唯一的绑定入口：range 检查 → bind → 锁外写 tunnel_open →
// 标记 active。applying/retrying 保证同一条定义不会被并发重复绑定。
func (tm *TunnelManager) applyTunnel(tunnelID string, client *Client) (Tunnel, error) {
	tm.mu.Lock()
	tunnel, ok := tm.tunnels[tunnelID]
	if !ok {
		tm.mu.Unlock()
		return Tunnel{}, fmt.Errorf("%w: %s", errTunnelNotFound, tunnelID)
	}
	if tm.closed {
		out := *tunnel
		tm.mu.Unlock()
		return out, nil
	}
	if client == nil || client.ClientID != tunnel.ClientID {
		out := *tunnel
		tm.mu.Unlock()
		return out, errTunnelOffline
	}
	if tunnel.applying || !tm.isCurrentClient(client) {
		out := *tunnel
		tm.mu.Unlock()
		return out, nil
	}
	if tunnel.Client == client && tunnel.Status == TunnelStatusActive {
		out := *tunnel
		tm.mu.Unlock()
		return out, nil
	}
	if tunnel.PublicPort < tm.portStart || tunnel.PublicPort > tm.portEnd {
		tunnel.Status = TunnelStatusOutOfRange
		tunnel.LastError = fmt.Sprintf("public port %d is outside the configured range %d-%d", tunnel.PublicPort, tm.portStart, tm.portEnd)
		tunnel.Client = nil
		tm.closeListenerLocked(tunnel.PublicPort)
		out := *tunnel
		tm.mu.Unlock()
		return out, nil
	}

	tunnel.applying = true
	tunnel.applySeq++
	seq := tunnel.applySeq
	if _, bound := tm.listeners[tunnel.PublicPort]; !bound {
		ln, err := net.Listen("tcp", listenAddrForBind(tunnel.BindAddr, tunnel.PublicPort))
		if err != nil {
			tunnel.Status = TunnelStatusPortConflict
			tunnel.LastError = err.Error()
			tunnel.Client = nil
			tunnel.applying = false
			startRetry := !tunnel.retrying
			if startRetry {
				tunnel.retrying = true
			}
			out := *tunnel
			tm.mu.Unlock()
			slog.Warn("tunnel port is occupied; keeping the reserved port",
				"tunnel_id", tunnelID, "public_port", out.PublicPort, "bind_addr", out.BindAddr, "error", err)
			if startRetry {
				go tm.retryPortConflict(tunnelID, client)
			}
			return out, nil
		}
		tm.listeners[tunnel.PublicPort] = ln
		go tm.acceptLoop(tunnel.PublicPort, tunnelID)
	}
	out := *tunnel
	tm.mu.Unlock()

	if tunnelOpenHook != nil {
		tunnelOpenHook(tunnelID)
	}

	// bind 之后、写 tunnel_open 之前定义可能又被改掉（UpdateTunnel 会作废
	// 这次 apply）：再确认一次，别把基于旧定义的 tunnel_open 发出去。
	tm.mu.RLock()
	current, exists := tm.tunnels[tunnelID]
	stale := !exists || !current.applying || current.applySeq != seq
	tm.mu.RUnlock()
	if stale {
		return out, nil
	}

	// WS 写在锁外：慢连接不能卡住其他隧道管理。
	if err := sendTunnelOpen(client, tunnelID, out.LocalAddr, out.LocalPort, out.Protocol); err != nil {
		tm.mu.Lock()
		// 只有“还是我这一次 apply”才允许清理：applying 被断开/删除清掉，
		// 或新一次 apply 已经接手（applySeq 变了）时，这次写入已经过期。
		if current, ok := tm.tunnels[tunnelID]; ok && current.applying && current.applySeq == seq {
			current.Status = TunnelStatusApplyFailed
			current.LastError = err.Error()
			current.Client = nil
			current.applying = false
			// 没告诉 agent，留着 listener 就是黑洞。
			tm.closeListenerLocked(current.PublicPort)
			out = *current
		}
		tm.mu.Unlock()
		slog.Warn("failed to send tunnel_open; the definition is kept and the listener is closed",
			"tunnel_id", tunnelID, "error", err)
		return out, nil
	}

	tm.mu.Lock()
	if current, ok := tm.tunnels[tunnelID]; ok && current.applying && current.applySeq == seq {
		current.Client = client
		current.Status = TunnelStatusActive
		current.LastError = ""
		current.applying = false
		current.retrying = false
		out = *current
	}
	tm.mu.Unlock()
	return out, nil
}

// retryPortConflict 用 1s/3s/9s 退避重试瞬态端口冲突；三次后停下等人。
func (tm *TunnelManager) retryPortConflict(tunnelID string, client *Client) {
	for _, delay := range portConflictRetryDelays {
		if !tm.sleepForRetry(delay) {
			tm.finishRetry(tunnelID)
			return
		}
		if !tm.isCurrentClient(client) {
			tm.finishRetry(tunnelID)
			return
		}
		tm.mu.Lock()
		tunnel, ok := tm.tunnels[tunnelID]
		stop := !ok || tunnel.ClientID != client.ClientID || tunnel.Client != nil ||
			tunnel.Status != TunnelStatusPortConflict
		tm.mu.Unlock()
		if stop {
			tm.finishRetry(tunnelID)
			return
		}
		updated, err := tm.applyTunnel(tunnelID, client)
		if err != nil {
			tm.finishRetry(tunnelID)
			return
		}
		if updated.Status == TunnelStatusActive {
			tm.finishRetry(tunnelID)
			return
		}
	}
	tm.finishRetry(tunnelID)
}

func (tm *TunnelManager) finishRetry(tunnelID string) {
	tm.mu.Lock()
	if tunnel, ok := tm.tunnels[tunnelID]; ok {
		tunnel.retrying = false
	}
	tm.mu.Unlock()
}

// sleepForRetry 等待一次退避；服务停止时返回 false。
func (tm *TunnelManager) sleepForRetry(delay time.Duration) bool {
	if tm.server == nil || tm.server.stopCh == nil {
		time.Sleep(delay)
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-tm.server.stopCh:
		return false
	}
}

// currentClient 返回该设备当前的连接（离线为 nil）。
func (tm *TunnelManager) currentClient(clientID string) *Client {
	if tm.server == nil || tm.server.clients == nil {
		return nil
	}
	client, _ := tm.server.clients.Get(clientID)
	return client
}

// isCurrentClient 判断连接是否仍是该设备的最新连接；没有客户端注册表
// （单元测试）时视为当前。
func (tm *TunnelManager) isCurrentClient(client *Client) bool {
	if tm.server == nil || tm.server.clients == nil || client == nil {
		return true
	}
	return tm.server.clients.IsCurrent(client.ClientID, client)
}
