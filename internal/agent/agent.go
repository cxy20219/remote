package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"goremote/internal/common"
)

type Agent struct {
	config        *Config
	connector     *Connector
	handler       *Handler
	reconnect     *Reconnect
	tunnelManager *TunnelManager
	crypto        *common.CryptoContext
	hostname      string
	os            string
	clientID      string
	mu            sync.RWMutex
	stopped       bool
}

func NewAgent(config *Config) *Agent {
	hostname := config.Agent.Hostname
	if hostname == "" {
		hostname = common.GetHostname()
	}

	os := config.Agent.OS
	if os == "" {
		os = common.GetOS()
	}

	connector := NewConnector(
		config.Server.Address,
		config.Server.TLS.Enabled,
		config.Server.TLS.CA,
		config.Auth.Key,
		config.Server.TLS.InsecureSkipVerify,
	)

	agent := &Agent{
		config:    config,
		connector: connector,
		handler:   nil,
		reconnect: NewReconnect(
			config.Reconnect.Interval,
			config.Reconnect.MaxAttempts,
			config.Reconnect.MaxInterval,
		),
		tunnelManager: NewTunnelManager(nil),
		hostname:      hostname,
		os:            os,
	}

	agent.tunnelManager.agent = agent

	if config.Auth.Key != "" {
		crypto, err := common.NewCryptoContext(config.Auth.Key)
		if err != nil {
			slog.Error("failed to initialize encryption", "error", err)
		} else {
			agent.crypto = crypto
			slog.Info("tunnel data encryption enabled (AES-256-GCM)")
		}
	} else {
		slog.Warn("auth.key is empty, tunnel data encryption disabled")
	}

	agent.handler = NewHandler(agent)

	return agent
}

func (a *Agent) Run() error {
	slog.Info("agent starting",
		"server", a.config.Server.Address,
		"hostname", a.hostname,
		"os", a.os)

	for {
		if a.isStopped() {
			return nil
		}

		if err := a.connect(); err != nil {
			slog.Warn("connection failed", "error", err)

			if !a.reconnect.shouldRetry() {
				slog.Error("max reconnect attempts reached")
				return fmt.Errorf("max reconnect attempts reached")
			}

			a.reconnect.beforeRetry()
			continue
		}

		a.reconnect.reset()

		if err := a.handleConnection(); err != nil {
			slog.Warn("connection error", "error", err)
		}

		a.connector.Close()
		a.tunnelManager.Cleanup()
		a.reconnect.beforeRetry()

		if a.isStopped() {
			return nil
		}
	}
}

func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	a.connector.Close()
}

func (a *Agent) isStopped() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stopped
}

func (a *Agent) connect() error {
	if err := a.connector.Connect(); err != nil {
		return err
	}

	if err := a.connector.Register(a.hostname, a.os); err != nil {
		a.connector.Close()
		return err
	}

	for {
		msg, err := a.connector.Receive()
		if err != nil {
			a.connector.Close()
			return err
		}

		if msg.Type == "register_ok" {
			var payload common.RegisterOKPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.SetClientID(payload.ClientID)
			slog.Info("registered successfully", "client_id", payload.ClientID)
			return nil
		}

		if msg.Type == "register_fail" {
			var payload common.RegisterFailPayload
			json.Unmarshal(msg.Payload, &payload)
			a.connector.Close()
			return fmt.Errorf("registration failed: %s", payload.Reason)
		}
	}
}

func (a *Agent) handleConnection() error {
	hbDone := make(chan struct{})
	go a.startHeartbeat(hbDone)

	for {
		msg, err := a.connector.Receive()
		if err != nil {
			close(hbDone)
			return err
		}

		if err := a.handler.Handle(msg); err != nil {
			slog.Error("failed to handle message", "type", msg.Type, "error", err)
		}
	}
}

func (a *Agent) startHeartbeat(done chan struct{}) {
	interval := time.Duration(a.config.Heartbeat.Interval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.connector.SendPing(); err != nil {
				slog.Warn("heartbeat failed", "error", err)
				return
			}
		case <-done:
			return
		}
	}
}

func (a *Agent) SetClientID(clientID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clientID = clientID
}

func (a *Agent) GetClientID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.clientID
}
