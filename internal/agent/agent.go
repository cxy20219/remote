package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goremote/internal/common"
)

var errAgentStopped = errors.New("agent stopped")

type Agent struct {
	config        *Config
	connector     *Connector
	handler       *Handler
	reconnect     *Reconnect
	tunnelManager *TunnelManager
	cryptoMgr     *common.CryptoManager
	hostname      string
	os            string
	identity      *AgentIdentity

	stopped         atomic.Bool
	pendingApproval atomic.Bool
	encEnabled      atomic.Bool
	clientID        atomic.Value // string
	stopCh          chan struct{}
	stopOnce        sync.Once
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
		reconnect:     NewReconnect(config.Reconnect.Interval, config.Reconnect.MaxAttempts, config.Reconnect.MaxInterval),
		tunnelManager: NewTunnelManager(nil),
		cryptoMgr:     cryptoMgr,
		hostname:      hostname,
		os:            osName,
		identity:      identity,
		stopCh:        make(chan struct{}),
	}

	agent.clientID.Store("")
	agent.tunnelManager.agent = agent
	agent.handler = NewHandler(agent)

	if identity != nil && identity.EncEnabled && identity.EncKey != "" {
		encKeyBytes, err := common.DecodeBytes(identity.EncKey)
		if err != nil {
			slog.Error("failed to decode enc_key from identity", "error", err)
		} else if err := cryptoMgr.SetKey(identity.ClientID, encKeyBytes); err != nil {
			slog.Error("failed to set enc_key", "error", err)
		} else {
			agent.encEnabled.Store(true)
			slog.Info("tunnel data encryption enabled (AES-256-GCM)")
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
			if errors.Is(err, errAgentStopped) || a.isStopped() {
				return nil
			}
			slog.Warn("connection failed", "error", err)

			if !a.reconnect.shouldRetry() {
				slog.Error("max reconnect attempts reached")
				return fmt.Errorf("max reconnect attempts reached")
			}
			if !a.reconnect.wait(a.stopCh) {
				return nil
			}
			continue
		}

		a.reconnect.reset()

		if err := a.handleConnection(); err != nil && !a.isStopped() {
			slog.Warn("connection error", "error", err)
		}

		a.connector.Close()
		a.tunnelManager.Cleanup()

		if a.isStopped() {
			return nil
		}
		if !a.reconnect.wait(a.stopCh) {
			return nil
		}
	}
}

func (a *Agent) Stop() {
	a.stopOnce.Do(func() {
		a.stopped.Store(true)
		close(a.stopCh)
		a.connector.Close()
		a.tunnelManager.Cleanup()
	})
}

func (a *Agent) isStopped() bool {
	return a.stopped.Load()
}

func (a *Agent) connect() error {
	if err := a.connector.Connect(); err != nil {
		return err
	}
	if a.isStopped() {
		a.connector.Close()
		return errAgentStopped
	}

	identity := a.identity
	if identity != nil && identity.ClientID != "" {
		if err := a.connector.RegisterReauth(identity.ClientID, time.Now().UnixNano(), a.hostname, a.os); err != nil {
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
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			if err := a.processRegisterOK(&payload); err != nil {
				a.connector.Close()
				return err
			}
			a.SetClientID(payload.ClientID)
			slog.Info("registered successfully", "client_id", payload.ClientID)
			return nil

		case "register_pending":
			var payload common.RegisterPendingPayload
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.SetClientID(payload.ClientID)
			if a.identity != nil {
				a.identity.ClientID = payload.ClientID
				a.identity.Save(a.config.IdentityDir)
			}
			a.pendingApproval.Store(true)
			slog.Info("waiting for admin approval", "client_id", payload.ClientID)
			return nil

		case "register_fail":
			var payload common.RegisterFailPayload
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.connector.Close()
			return a.handleRegisterFail(payload.Reason)

		case "ping":
			continue

		default:
			slog.Debug("unexpected message during registration", "type", msg.Type)
		}
	}
}

// handleRegisterFail 处理服务端的 register_fail。时钟漂移是唯一可以保留本地
// 身份的错误：服务端已经验签成功，只是时间戳超出允许窗口，此时清掉 ClientID
// 只会把设备退化成需要重新审批的新设备。其他原因（DH 公钥不一致、记录损坏）
// 仍然清身份重注册，由管理员重新审批。
func (a *Agent) handleRegisterFail(reason string) error {
	if strings.HasPrefix(reason, common.ClockSkewReasonPrefix) {
		skew := strings.TrimPrefix(reason, common.ClockSkewReasonPrefix)
		slog.Error("server rejected reauthentication because this device clock is out of sync with the server; keeping the device identity",
			"skew", skew,
			"hint", "sync this device clock (enable NTP) and the agent will retry automatically")
		return fmt.Errorf("registration failed: device clock is out of sync with the server (%s); enable NTP and the agent will retry", skew)
	}
	if a.identity != nil && a.identity.ClientID != "" {
		slog.Warn("reauth failed, clearing identity for re-registration", "reason", reason)
		a.clearRegistration()
	}
	return fmt.Errorf("registration failed: %s", reason)
}

// clearRegistration forgets the server-side device identity while keeping the
// local key pairs and the pinned server signing key.
func (a *Agent) clearRegistration() {
	clientID := a.GetClientID()
	if a.identity != nil && a.identity.ClientID != "" {
		clientID = a.identity.ClientID
	}
	if clientID != "" {
		a.cryptoMgr.RemoveKey(clientID)
	}
	a.encEnabled.Store(false)
	a.SetClientID("")
	a.pendingApproval.Store(false)
	if a.identity != nil {
		a.identity.ClientID = ""
		a.identity.EncKey = ""
		a.identity.EncEnabled = false
		if err := a.identity.Save(a.config.IdentityDir); err != nil {
			slog.Error("failed to save identity", "error", err)
		}
	}
}

func (a *Agent) processRegisterOK(payload *common.RegisterOKPayload) error {
	identity := a.identity
	if identity == nil {
		return nil
	}
	if err := a.verifyServerKeySignature(payload.ClientID, payload.EncEnabled, payload.ServerDHPubkey, payload.EncKeyEncrypted, payload.ServerSignPubkey, payload.ServerSignature); err != nil {
		return err
	}
	if identity.ClientID != "" && identity.ClientID != payload.ClientID {
		return fmt.Errorf("register_ok client_id mismatch: got %q, expected %q", payload.ClientID, identity.ClientID)
	}

	identity.ClientID = payload.ClientID

	if !payload.EncEnabled {
		identity.EncEnabled = false
		identity.EncKey = ""
		a.cryptoMgr.RemoveKey(payload.ClientID)
		a.encEnabled.Store(false)
	} else if payload.EncKeyEncrypted != "" && payload.ServerDHPubkey != "" && identity.DeviceDHPrivkey != "" {
		encKey, err := identity.DecryptEncKey(payload.EncKeyEncrypted, payload.ServerDHPubkey)
		if err != nil {
			return fmt.Errorf("decrypt enc_key: %w", err)
		}
		identity.EncKey = common.EncodeBytes(encKey)
		identity.EncEnabled = true
		if err := a.cryptoMgr.SetKey(payload.ClientID, encKey); err != nil {
			return fmt.Errorf("set encryption key: %w", err)
		}
		a.encEnabled.Store(true)
		slog.Info("tunnel data encryption enabled (AES-256-GCM)")
	} else if payload.EncKeyEncrypted != "" || payload.ServerDHPubkey != "" {
		return fmt.Errorf("cannot decrypt enc_key: missing device DH private key")
	} else if a.cryptoMgr.HasKey(payload.ClientID) {
		identity.EncEnabled = true
		a.encEnabled.Store(true)
	} else {
		return fmt.Errorf("server enabled encryption but sent no key")
	}

	if err := identity.Save(a.config.IdentityDir); err != nil {
		slog.Error("failed to save identity", "error", err)
	}
	return nil
}

func (a *Agent) verifyServerKeySignature(clientID string, encEnabled bool, serverDHPubkey, encKeyEncrypted, serverSignPubkey, serverSignature string) error {
	identity := a.identity
	if identity == nil {
		return nil
	}

	if serverSignPubkey == "" || serverSignature == "" {
		if identity.ServerSignPubkey != "" {
			return fmt.Errorf("missing server signature")
		}
		return nil
	}
	if clientID == "" {
		return fmt.Errorf("missing client_id in signed server key payload")
	}
	if identity.ServerSignPubkey != "" && identity.ServerSignPubkey != serverSignPubkey {
		return fmt.Errorf("server sign key changed")
	}

	pub, err := common.DecodePublicKey(serverSignPubkey)
	if err != nil {
		return fmt.Errorf("decode server sign pubkey: %w", err)
	}
	signature, err := common.DecodeBytes(serverSignature)
	if err != nil {
		return fmt.Errorf("decode server signature: %w", err)
	}
	if !common.VerifyServerKeyPayload(pub, clientID, encEnabled, serverDHPubkey, encKeyEncrypted, signature) {
		return fmt.Errorf("invalid server signature")
	}

	if identity.ServerSignPubkey == "" {
		identity.ServerSignPubkey = serverSignPubkey
	}
	return nil
}

func (a *Agent) handleConnection() error {
	if a.pendingApproval.Load() {
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
			if errors.Is(err, common.ErrTunnelAADRequired) || errors.Is(err, common.ErrTunnelAADUnexpected) {
				// 帧版本与协商不一致：断开重连，让下一轮重新握手。
				slog.Error("tunnel frame AAD negotiation violated, reconnecting",
					"type", msg.Type, "error", err)
				return err
			}
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
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
				return err
			}
			if err := a.processRegisterOK(&payload); err != nil {
				return err
			}
			a.SetClientID(payload.ClientID)
			a.pendingApproval.Store(false)
			slog.Info("approved, entering work state", "client_id", payload.ClientID)
			if err := a.connector.SendPing(); err != nil {
				slog.Warn("failed to notify server after approval", "client_id", payload.ClientID, "error", err)
			}
			return nil

		case "register_fail":
			var payload common.RegisterFailPayload
			if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
				a.connector.Close()
				return err
			}
			a.clearRegistration()
			a.connector.Close()
			return fmt.Errorf("registration denied: %s", payload.Reason)

		case "device_deleted":
			a.clearRegistration()
			a.connector.Close()
			return fmt.Errorf("device deleted by admin")

		case "ping", "pong":
			continue

		default:
			slog.Debug("unexpected message while pending", "type", msg.Type)
		}
	}
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
		case <-a.stopCh:
			return
		}
	}
}

func (a *Agent) SetClientID(clientID string) {
	a.clientID.Store(clientID)
}

func (a *Agent) GetClientID() string {
	value := a.clientID.Load()
	if value == nil {
		return ""
	}
	return value.(string)
}

func (a *Agent) isEncryptionEnabled() bool {
	return a != nil && a.encEnabled.Load()
}

// aadEnabled 表示本次连接是否协商了 v2 帧 AAD。
func (a *Agent) aadEnabled() bool {
	return a != nil && a.connector != nil && a.connector.AADEnabled()
}

// decryptTunnelBytes 解密一帧；aad 为 nil 表示 v1 帧。
func (a *Agent) decryptTunnelBytes(data, aad []byte) ([]byte, error) {
	if !a.isEncryptionEnabled() {
		return data, nil
	}
	if len(aad) > 0 {
		return a.cryptoMgr.DecryptBytesAAD(a.GetClientID(), data, aad)
	}
	return a.cryptoMgr.DecryptBytes(a.GetClientID(), data)
}
