package server

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type DeviceQuerier interface {
	GetDeviceByID(id string) *DeviceState
}

type Client struct {
	ClientID string
	Hostname string
	OS       string
	Conn     *websocket.Conn
	// RemoteAddr 是带端口的原始地址（日志与调试用）；RemoteIP 是升级时按
	// trusted-proxies 规则解析出的裸 IP，审计必须用它——否则同一来源每次端口
	// 不同，反代后面还会记成代理地址。
	RemoteAddr string
	RemoteIP   string
	RegTime    time.Time
	LastPing   time.Time

	// encEnabled mirrors DeviceState.EncEnabled for the current connection so
	// the tunnel data path never has to hit the state store.
	encEnabled     atomic.Bool
	registerOKSent atomic.Bool
	// registerOKWritten 只在 register_ok 真正写成功之后置位：隧道重放必须
	// 严格晚于它，否则 agent 会把 tunnel_open 当未知消息丢掉。
	registerOKWritten atomic.Bool
	// tunnelRestoreScheduled 保证一个连接只调度一次定义重放（审批接口与
	// pending 循环可能同时到达 register_ok 成功的时刻）。
	tunnelRestoreScheduled atomic.Bool
	writeMu                sync.Mutex

	// protoVersion 是本连接协商到的协议版本，来自 WS 升级请求的 ?proto=2。
	// 老 agent 不声明 → 按 v1 行为处理。
	protoVersion int
	// agentVersion / agentCommit 来自握手参数 ?ver= / ?commit=，已清洗过；
	// 老 agent 不带 → 空。它们只在注册成功后落进设备记录（见 recordAgentBuild），
	// 不参与任何行为门控：版本串只是元数据，proto/caps 才是能力位。
	agentVersion string
	agentCommit  string
	// caps 是 agent 在握手时声明的能力位（?caps=a,b），本阶段还没有任何
	// 按 cap 门控的可选字段，先存下来供排障与后续能力使用。
	caps []string
	// aadEnabled 表示升级时协商了 v2 帧 AAD（proto=2 且服务端开关打开）。
	// 建连后不再变化。
	aadEnabled bool

	// disconnectReason 由主动关闭方先写（心跳超时 / 服务端关闭）；写不进去说明
	// 是读循环自己先结束的，由 readLoop 按读错误分类。只有 disconnectReason()
	// 的读取者会看到它。
	disconnectReason atomic.Value // string
	// shutdownRecorded 表示 Stop 已经为这条连接记过 server_shutdown：readLoop 的
	// defer 随后会看到连接被关闭（RemoveIfMatch 仍可能成功），必须跳过第二次记录，
	// 否则每次发版 24h 断连次数都会 +2。
	shutdownRecorded atomic.Bool
}

// markShutdownRecorded 标记 Stop 已经记过 server_shutdown。
func (c *Client) markShutdownRecorded() { c.shutdownRecorded.Store(true) }

// shutdownAlreadyRecorded 返回 Stop 是否已经替这条连接记过断开。
func (c *Client) shutdownAlreadyRecorded() bool { return c.shutdownRecorded.Load() }

// markDisconnectReason 记录主动关闭本连接的原因；先写者优先。
func (c *Client) markDisconnectReason(reason string) {
	if c.disconnectReason.Load() != nil {
		return
	}
	c.disconnectReason.CompareAndSwap(nil, reason)
}

// disconnectReasonValue 返回主动关闭原因；空表示由读循环自行结束。
func (c *Client) disconnectReasonValue() string {
	if reason, ok := c.disconnectReason.Load().(string); ok {
		return reason
	}
	return ""
}

// Proto 返回本连接的协议版本；未声明时按 v1 处理。
func (c *Client) Proto() int {
	if c.protoVersion < 1 {
		return 1
	}
	return c.protoVersion
}

// AADEnabled 返回本连接是否协商了 v2 帧 AAD。
func (c *Client) AADEnabled() bool {
	return c != nil && c.aadEnabled
}

// parseClientProto 解析 WS 升级请求里的 proto 协商位。服务端当前支持 v1
// （无声明）与 v2；声明更高的版本时协商到 2。非法值按 v1 处理。
func parseClientProto(raw string) int {
	version, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || version < 2 {
		return 1
	}
	return 2
}

// ClientInfo is an immutable snapshot exposed by the admin API.
type ClientInfo struct {
	ClientID   string    `json:"client_id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	RemoteAddr string    `json:"remote_addr"`
	RegTime    time.Time `json:"reg_time"`
	LastPing   time.Time `json:"last_ping"`
	Online     bool      `json:"online"`
}

func (c *Client) SetEncryptionEnabled(enabled bool) {
	c.encEnabled.Store(enabled)
}

func (c *Client) EncryptionEnabled() bool {
	return c.encEnabled.Load()
}

// markRegisterOKSent ensures that only one of the approval handler and the
// pending-loop transition sends register_ok to a given connection.
func (c *Client) markRegisterOKSent() bool {
	return c.registerOKSent.CompareAndSwap(false, true)
}

// markRegisterOKWritten 记录 register_ok 已成功写入连接。
func (c *Client) markRegisterOKWritten() {
	c.registerOKWritten.Store(true)
}

// markTunnelRestoreScheduled 保证每个连接只调度一次 tunnel 定义重放。
func (c *Client) markTunnelRestoreScheduled() bool {
	return c.tunnelRestoreScheduled.CompareAndSwap(false, true)
}

type ClientManager struct {
	mu      sync.RWMutex
	clients map[string]*Client
	store   DeviceQuerier
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients: make(map[string]*Client),
	}
}

func (m *ClientManager) SetStore(store DeviceQuerier) {
	m.store = store
}

func (m *ClientManager) Add(client *Client) {
	now := time.Now()
	m.mu.Lock()
	var old *Client
	if existing, ok := m.clients[client.ClientID]; ok && existing != client {
		old = existing
	}
	client.RegTime = now
	client.LastPing = now
	m.clients[client.ClientID] = client
	m.mu.Unlock()

	if old != nil && old.Conn != nil {
		old.Conn.Close()
	}
}

func (m *ClientManager) Remove(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID)
}

func (m *ClientManager) RemoveAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients = make(map[string]*Client)
}

func (m *ClientManager) RemoveIfMatch(clientID string, client *Client) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.clients[clientID]; ok && current == client {
		delete(m.clients, clientID)
		return true
	}
	return false
}

func (m *ClientManager) IsCurrent(clientID string, client *Client) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	current, ok := m.clients[clientID]
	return ok && current == client
}

func (m *ClientManager) Get(clientID string) (*Client, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[clientID]
	return client, ok
}

// List returns the live client pointers. Callers must not mutate fields that
// are protected by the manager lock; use Snapshot for API responses.
func (m *ClientManager) List() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clients := make([]*Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients
}

func (m *ClientManager) Snapshot() []ClientInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ClientInfo, 0, len(m.clients))
	for _, client := range m.clients {
		result = append(result, clientInfoLocked(client))
	}
	return result
}

func (m *ClientManager) SnapshotByID(clientID string) (ClientInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[clientID]
	if !ok {
		return ClientInfo{}, false
	}
	return clientInfoLocked(client), true
}

func clientInfoLocked(client *Client) ClientInfo {
	return ClientInfo{
		ClientID:   client.ClientID,
		Hostname:   client.Hostname,
		OS:         client.OS,
		RemoteAddr: client.RemoteAddr,
		RegTime:    client.RegTime,
		LastPing:   client.LastPing,
		Online:     true,
	}
}

func (m *ClientManager) TouchIfMatch(clientID string, client *Client) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.clients[clientID]; ok && current == client {
		current.LastPing = time.Now()
		return true
	}
	return false
}

func (c *Client) WriteJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("client connection is nil")
	}

	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetWriteDeadline(time.Time{})
	return c.Conn.WriteJSON(v)
}

func (c *Client) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("client connection is nil")
	}

	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetWriteDeadline(time.Time{})
	return c.Conn.WriteMessage(messageType, data)
}
