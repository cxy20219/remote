package server

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type DeviceQuerier interface {
	GetDeviceByID(id string) *DeviceState
}

type Client struct {
	ClientID   string
	Hostname   string
	OS         string
	Conn       *websocket.Conn
	RemoteAddr string
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
