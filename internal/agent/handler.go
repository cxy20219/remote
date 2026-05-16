package agent

import (
	"fmt"
	"log/slog"
	"time"

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
	case "tunnel_open_ack":
		return h.handleTunnelOpenAck(msg)
	case "tunnel_close":
		return h.handleTunnelClose(msg)
	case "tunnel_data_bin":
		return h.handleTunnelDataBinary(msg)
	case "tunnel_error":
		return h.handleTunnelError(msg)
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
	h.agent.processRegisterOK(&payload)
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

	if payload.EncKeyEncrypted != "" && payload.ServerDHPubkey != "" && identity.DeviceDHPrivkey != "" {
		encKey, err := identity.DecryptEncKey(payload.EncKeyEncrypted, payload.ServerDHPubkey)
		if err != nil {
			slog.Error("failed to decrypt updated enc_key", "error", err)
			return err
		}

		identity.EncKey = common.EncodeBytes(encKey)
		identity.EncEnabled = payload.EncEnabled

		if err := h.agent.cryptoMgr.SetKey(identity.ClientID, encKey); err != nil {
			slog.Error("failed to update encryption key", "error", err)
			return err
		}

		slog.Info("encryption key updated")
	}

	identity.EncEnabled = payload.EncEnabled
	if err := identity.Save(h.agent.config.IdentityDir); err != nil {
		slog.Error("failed to save identity after update", "error", err)
	}

	return nil
}

func (h *Handler) handleDeviceDeleted(msg *common.Message) error {
	identity := h.agent.identity
	if identity != nil {
		identity.ClientID = ""
		identity.EncKey = ""
		identity.Save(h.agent.config.IdentityDir)
	}
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
		0,
	)

	return nil
}

func (h *Handler) handleTunnelOpenAck(msg *common.Message) error {
	var payload common.TunnelOpenAckPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	if !payload.Success {
		slog.Warn("tunnel open failed",
			"tunnel_id", payload.TunnelID,
			"error", payload.Error)
		h.agent.tunnelManager.CloseTunnel(payload.TunnelID)
		return nil
	}

	tunnel, ok := h.agent.tunnelManager.GetTunnel(payload.TunnelID)
	if ok {
		tunnel.PublicPort = payload.PublicPort
	}

	slog.Info("tunnel open ack",
		"tunnel_id", payload.TunnelID,
		"public_port", payload.PublicPort)

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

	if payload.IsEOF && len(payload.Data) == 0 {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
		return nil
	}

	clientID := h.agent.GetClientID()
	data, err := h.agent.cryptoMgr.DecryptBytes(clientID, payload.Data)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	conn, err := h.agent.tunnelManager.GetOrCreateLocalConn(payload.ConnID, payload.TunnelID)
	if err != nil {
		h.agent.tunnelManager.SendError(payload.TunnelID, payload.ConnID, err.Error())
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Write(data)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
		h.agent.tunnelManager.SendError(payload.TunnelID, payload.ConnID, err.Error())
		return err
	}

	h.agent.tunnelManager.StartReadLoop(payload.ConnID, payload.TunnelID)

	if payload.IsEOF {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
	}

	return nil
}

func (h *Handler) handleTunnelError(msg *common.Message) error {
	var payload common.TunnelErrorPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Warn("tunnel error from server",
		"tunnel_id", payload.TunnelID,
		"conn_id", payload.ConnID,
		"error", payload.Error)

	if payload.ConnID != "" {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
	}

	return nil
}
