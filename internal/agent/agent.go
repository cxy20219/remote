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
	config          *Config
	connector       *Connector
	handler         *Handler
	reconnect       *Reconnect
	tunnelManager   *TunnelManager
	cryptoMgr       *common.CryptoManager
	hostname        string
	os              string
	clientID        string
	identity        *AgentIdentity
	mu              sync.RWMutex
	stopped         bool
	pendingApproval bool
}

func NewAgent(config *Config, identity *AgentIdentity) *Agent {
	hostname := config.Agent.Hostname
	if hostname == "" {
		hostname = common.GetHostname()
	}

	osName := config.Agent.OS
	if osName == "" {
		osName = common.GetOS()
	}

	cryptoMgr := common.NewCryptoManager()

	connector := NewConnector(
		config.Server.Address,
		config.Server.TLS.Enabled,
		config.Server.TLS.CA,
		config.Server.TLS.InsecureSkipVerify,
		identity,
	)

	agent := &Agent{
		config:        config,
		connector:     connector,
		handler:       nil,
		reconnect:     NewReconnect(config.Reconnect.Interval, config.Reconnect.MaxAttempts, config.Reconnect.MaxInterval),
		tunnelManager: NewTunnelManager(nil),
		cryptoMgr:     cryptoMgr,
		hostname:      hostname,
		os:            osName,
		identity:      identity,
	}

	agent.tunnelManager.agent = agent
	agent.handler = NewHandler(agent)

	if identity != nil && identity.EncKey != "" {
		encKeyBytes, err := common.DecodeBytes(identity.EncKey)
		if err != nil {
			slog.Error("failed to decode enc_key from identity", "error", err)
		} else if len(encKeyBytes) > 0 {
			err = cryptoMgr.SetKey(identity.ClientID, encKeyBytes)
			if err != nil {
				slog.Error("failed to set enc_key", "error", err)
			} else {
				slog.Info("tunnel data encryption enabled (AES-256-GCM)")
			}
		}
	}

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

	identity := a.identity
	if identity != nil && identity.ClientID != "" {
		timestamp := time.Now().Unix()
		if err := a.connector.RegisterReauth(identity.ClientID, timestamp, a.hostname, a.os); err != nil {
			a.connector.Close()
			return err
		}
		slog.Info("reconnecting with existing identity", "client_id", identity.ClientID)
	} else {
		if err := a.connector.RegisterNew(a.hostname, a.os); err != nil {
			a.connector.Close()
			return err
		}
		slog.Info("registering with new identity")
	}

	for {
		msg, err := a.connector.Receive()
		if err != nil {
			a.connector.Close()
			return err
		}

		switch msg.Type {
		case "register_ok":
			var payload common.RegisterOKPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.SetClientID(payload.ClientID)
			a.processRegisterOK(&payload)
			slog.Info("registered successfully", "client_id", payload.ClientID)
			return nil

		case "register_pending":
			var payload common.RegisterPendingPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.SetClientID(payload.ClientID)
			if a.identity != nil {
				a.identity.ClientID = payload.ClientID
				a.identity.Save(a.config.IdentityDir)
			}
			a.setPendingApproval(true)
			slog.Info("waiting for admin approval", "client_id", payload.ClientID)
			return nil

		case "register_fail":
			var payload common.RegisterFailPayload
			json.Unmarshal(msg.Payload, &payload)

			if a.identity != nil && a.identity.ClientID != "" {
				slog.Warn("reauth failed, clearing identity for re-registration", "reason", payload.Reason)
				a.identity.ClientID = ""
				a.identity.EncKey = ""
				a.identity.Save(a.config.IdentityDir)
			}

			a.connector.Close()
			return fmt.Errorf("registration failed: %s", payload.Reason)

		case "ping":
			// Continue waiting while pending
			continue

		default:
			slog.Debug("unexpected message during registration", "type", msg.Type)
		}
	}
}

func (a *Agent) processRegisterOK(payload *common.RegisterOKPayload) {
	identity := a.identity
	if identity == nil {
		return
	}

	identity.ClientID = payload.ClientID

	if payload.EncKeyEncrypted != "" && payload.ServerDHPubkey != "" && identity.DeviceDHPrivkey != "" {
		encKey, err := identity.DecryptEncKey(payload.EncKeyEncrypted, payload.ServerDHPubkey)
		if err != nil {
			slog.Error("failed to decrypt enc_key", "error", err)
			identity.EncEnabled = false
		} else {
			identity.EncKey = common.EncodeBytes(encKey)
			identity.EncEnabled = payload.EncEnabled

			if err := a.cryptoMgr.SetKey(payload.ClientID, encKey); err != nil {
				slog.Error("failed to set encryption key", "error", err)
			} else {
				slog.Info("tunnel data encryption enabled (AES-256-GCM)")
			}
		}
	} else {
		identity.EncEnabled = payload.EncEnabled
	}

	if err := identity.Save(a.config.IdentityDir); err != nil {
		slog.Error("failed to save identity", "error", err)
	}
}

func (a *Agent) handleConnection() error {
	if a.isPendingApproval() {
		if err := a.handlePending(); err != nil {
			return err
		}
	}

	hbDone := make(chan struct{})
	go a.startHeartbeat(hbDone)
	defer close(hbDone)

	for {
		msg, err := a.connector.Receive()
		if err != nil {
			return err
		}

		if err := a.handler.Handle(msg); err != nil {
			switch msg.Type {
			case "register_ok", "register_fail", "register_update", "device_deleted":
				slog.Error("fatal message error, reconnecting", "type", msg.Type, "error", err)
				return err
			default:
				slog.Warn("non-fatal message error, continuing", "type", msg.Type, "error", err)
			}
		}
	}
}

func (a *Agent) handlePending() error {
	hbDone := make(chan struct{})
	go a.startHeartbeat(hbDone)
	defer close(hbDone)

	for {
		msg, err := a.connector.Receive()
		if err != nil {
			return err
		}

		switch msg.Type {
		case "register_ok":
			var payload common.RegisterOKPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				return err
			}
			a.SetClientID(payload.ClientID)
			a.processRegisterOK(&payload)
			a.setPendingApproval(false)
			slog.Info("approved, entering work state", "client_id", payload.ClientID)
			if err := a.connector.SendPing(); err != nil {
				slog.Warn("failed to notify server after approval", "client_id", payload.ClientID, "error", err)
			}
			return nil

		case "register_fail":
			var payload common.RegisterFailPayload
			json.Unmarshal(msg.Payload, &payload)

			if a.identity != nil {
				a.identity.ClientID = ""
				a.identity.EncKey = ""
				a.identity.Save(a.config.IdentityDir)
			}

			a.connector.Close()
			return fmt.Errorf("registration denied: %s", payload.Reason)

		case "device_deleted":
			if a.identity != nil {
				a.identity.ClientID = ""
				a.identity.EncKey = ""
				a.identity.Save(a.config.IdentityDir)
			}
			a.connector.Close()
			return fmt.Errorf("device deleted by admin")

		case "ping":
			continue

		default:
			slog.Debug("unexpected message while pending", "type", msg.Type)
		}
	}
}

func (a *Agent) isPendingApproval() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pendingApproval
}

func (a *Agent) setPendingApproval(pending bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingApproval = pending
}

func (a *Agent) startHeartbeat(done chan struct{}) {
	interval := time.Duration(a.config.Heartbeat.Interval) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
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
