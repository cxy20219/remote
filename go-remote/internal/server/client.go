package server

import (
	"fmt"
	"sync"
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

	writeMu sync.Mutex
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
	m.mu.Lock()
	var old *Client
	if existing, ok := m.clients[client.ClientID]; ok && existing != client {
		old = existing
	}
	client.RegTime = time.Now()
	client.LastPing = time.Now()
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

func (m *ClientManager) List() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clients := make([]*Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients
}

func (m *ClientManager) UpdateActivityIfMatch(clientID string, client *Client) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.clients[clientID]; ok && current == client {
		current.LastPing = time.Now()
		return true
	}
	return false
}

func (m *ClientManager) UpdatePingIfMatch(clientID string, client *Client) bool {
	return m.UpdateActivityIfMatch(clientID, client)
}

func (m *ClientManager) IsIPWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, client := range m.clients {
		device := m.getDeviceStateForClient(client)
		if device != nil && isIPWhitelisted(ip, device.IPWhitelist) {
			return true
		}
	}
	return false
}

func (m *ClientManager) getDeviceStateForClient(client *Client) *DeviceState {
	if m.store == nil || client == nil || client.ClientID == "" {
		return nil
	}
	return m.store.GetDeviceByID(client.ClientID)
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

func (c *Client) WriteJSON(v interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in WriteJSON: %v", r)
		}
	}()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("client connection is nil")
	}

	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetWriteDeadline(time.Time{})
	err = c.Conn.WriteJSON(v)
	return err
}

func (c *Client) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("client connection is nil")
	}

	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetWriteDeadline(time.Time{})
	err := c.Conn.WriteMessage(messageType, data)
	return err
}
