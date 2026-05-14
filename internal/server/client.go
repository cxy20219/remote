package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients: make(map[string]*Client),
	}
}

func (m *ClientManager) Add(client *Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client.RegTime = time.Now()
	client.LastPing = time.Now()
	m.clients[client.ClientID] = client
}

func (m *ClientManager) Remove(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID)
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

func (m *ClientManager) UpdatePing(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if client, ok := m.clients[clientID]; ok {
		client.LastPing = time.Now()
	}
}

func (m *ClientManager) IsIPWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, client := range m.clients {
		device := getDeviceStateForClient(client)
		if device != nil && isIPWhitelisted(ip, device.IPWhitelist) {
			return true
		}
	}
	return false
}

func getDeviceStateForClient(client *Client) *DeviceState {
	return nil
}

func (m *ClientManager) GetIPWhitelist(clientID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[clientID]
	if !ok {
		return nil
	}
	_ = client
	return nil
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

	return c.Conn.WriteJSON(v)
}

func (c *Client) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("client connection is nil")
	}

	return c.Conn.WriteMessage(messageType, data)
}