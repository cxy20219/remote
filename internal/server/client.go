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
	AnyDeviceMatches(match func(*DeviceState) bool) bool
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
	writeMu        sync.Mutex
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

func (m *ClientManager) IsIPWhitelisted(ip string) bool {
	if m.store == nil {
		return false
	}
	// Scan the store in place instead of cloning every device. Device
	// whitelists apply even while the device is offline.
	return m.store.AnyDeviceMatches(func(device *DeviceState) bool {
		return isIPWhitelisted(ip, device.IPWhitelist)
	})
}

func (m *ClientManager) GetIPWhitelist(clientID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[clientID]
	if !ok || m.store == nil {
		return nil
	}
	device := m.store.GetDeviceByID(client.ClientID)
	if device == nil {
		return nil
	}
	return device.IPWhitelist
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
