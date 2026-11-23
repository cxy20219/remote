package agent

import (
	"fmt"
	"log/slog"

	"goremote/internal/common"
)

type Handler struct {
	agent *Agent
}

func NewHandler(agent *Agent) *Handler {
	return &Handler{agent: agent}
}

func (h *Handler) Handle(msg *common.Message) error {
	switch msg.Type {
	case "register_ok":
		return h.handleRegisterOK(msg)
	case "register_fail":
		return h.handleRegisterFail(msg)
	case "register_update":
		return h.handleRegisterUpdate(msg)
	case "device_deleted":
		return h.handleDeviceDeleted(msg)
	case "pong":
		return nil
	case "tunnel_open":
		return h.handleTunnelOpen(msg)
	case "tunnel_close":
		return h.handleTunnelClose(msg)
	case "tunnel_data_bin":
		return h.handleTunnelDataBinary(msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (h *Handler) handleRegisterOK(msg *common.Message) error {
	var payload common.RegisterOKPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	h.agent.SetClientID(payload.ClientID)
	if err := h.agent.processRegisterOK(&payload); err != nil {
		return err
	}
	slog.Info("registered successfully", "client_id", payload.ClientID)
	return nil
}

func (h *Handler) handleRegisterFail(msg *common.Message) error {
	var payload common.RegisterFailPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Error("registration failed", "reason", payload.Reason)
	return fmt.Errorf("registration failed: %s", payload.Reason)
}

func (h *Handler) handleRegisterUpdate(msg *common.Message) error {
	var payload common.RegisterUpdatePayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	identity := h.agent.identity
	if identity == nil {
		return nil
	}
	clientID := payload.ClientID
	if clientID == "" {
		clientID = identity.ClientID
	}
	if err := h.agent.verifyServerKeySignature(clientID, payload.EncEnabled, payload.ServerDHPubkey, payload.EncKeyEncrypted, payload.ServerSignPubkey, payload.ServerSignature); err != nil {
		return err
	}
	if clientID != "" && identity.ClientID != "" && clientID != identity.ClientID {
		return fmt.Errorf("register_update client_id mismatch: got %q, expected %q", clientID, identity.ClientID)
	}

	if !payload.EncEnabled {
		identity.EncEnabled = false
		identity.EncKey = ""
		h.agent.cryptoMgr.RemoveKey(clientID)
		h.agent.encEnabled.Store(false)
		if err := identity.Save(h.agent.config.IdentityDir); err != nil {
			slog.Error("failed to save identity after update", "error", err)
		}
		return nil
	}

	if payload.EncKeyEncrypted != "" && payload.ServerDHPubkey != "" && identity.DeviceDHPrivkey != "" {
		encKey, err := identity.DecryptEncKey(payload.EncKeyEncrypted, payload.ServerDHPubkey)
		if err != nil {
			return fmt.Errorf("decrypt updated enc_key: %w", err)
		}
		identity.EncKey = common.EncodeBytes(encKey)
		identity.EncEnabled = true
		if err := h.agent.cryptoMgr.SetKey(clientID, encKey); err != nil {
			return fmt.Errorf("update encryption key: %w", err)
		}
		h.agent.encEnabled.Store(true)
		slog.Info("encryption key updated")
	} else if payload.EncKeyEncrypted != "" || payload.ServerDHPubkey != "" {
		return fmt.Errorf("cannot decrypt updated enc_key: missing device DH private key")
	} else if h.agent.cryptoMgr.HasKey(clientID) {
		identity.EncEnabled = true
		h.agent.encEnabled.Store(true)
	} else {
		return fmt.Errorf("server enabled encryption but sent no key")
	}

	if err := identity.Save(h.agent.config.IdentityDir); err != nil {
		slog.Error("failed to save identity after update", "error", err)
	}

	return nil
}

func (h *Handler) handleDeviceDeleted(msg *common.Message) error {
	h.agent.clearRegistration()
	slog.Warn("device deleted by admin, will need to re-register")
	return fmt.Errorf("device deleted by admin")
}

func (h *Handler) handleTunnelOpen(msg *common.Message) error {
	var payload common.TunnelOpenPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("tunnel open request",
		"tunnel_id", payload.TunnelID,
		"local_addr", payload.LocalAddr,
		"local_port", payload.LocalPort,
		"protocol", payload.Protocol)

	h.agent.tunnelManager.CreateTunnel(
		payload.TunnelID,
		payload.LocalAddr,
		payload.LocalPort,
		payload.Protocol,
	)
	return nil
}

func (h *Handler) handleTunnelClose(msg *common.Message) error {
	var payload common.TunnelClosePayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("tunnel close request", "tunnel_id", payload.TunnelID)
	return h.agent.tunnelManager.CloseTunnel(payload.TunnelID)
}

func (h *Handler) handleTunnelDataBinary(msg *common.Message) error {
	payload := msg.BinaryData
	if payload == nil {
		return fmt.Errorf("missing binary tunnel payload")
	}
	if len(payload.Data) > common.TunnelChunkSize+common.TunnelEncryptionOverhead {
		return fmt.Errorf("tunnel payload too large: %d bytes", len(payload.Data))
	}

	// v2 协商防降级：加密隧道协商了 AAD 后只接受 v2 数据帧；未协商的
	// 连接收到 v2 帧同样拒收。EOF 帧沿用 v1 明文，所以 v1 EOF 放行。
	if h.agent.isEncryptionEnabled() && h.agent.aadEnabled() {
		if payload.Version != common.TunnelFrameVersionAAD && !(payload.IsEOF && len(payload.Data) == 0) {
			return common.ErrTunnelAADRequired
		}
	} else if payload.Version == common.TunnelFrameVersionAAD {
		return common.ErrTunnelAADUnexpected
	}

	if payload.IsEOF && len(payload.Data) == 0 {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
		return nil
	}

	data, err := h.agent.decryptTunnelBytes(payload.Data, payload.AAD())
	if err != nil {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
		return fmt.Errorf("decrypt failed: %w", err)
	}

	h.agent.tunnelManager.Dispatch(payload.ConnID, payload.TunnelID, data, payload.IsEOF)
	return nil
}
