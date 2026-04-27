package agent

import (
	"encoding/base64"
	"encoding/json"
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
	case "pong":
		return nil
	case "tunnel_open":
		return h.handleTunnelOpen(msg)
	case "tunnel_open_ack":
		return h.handleTunnelOpenAck(msg)
	case "tunnel_close":
		return h.handleTunnelClose(msg)
	case "tunnel_data":
		return h.handleTunnelData(msg)
	case "tunnel_error":
		return h.handleTunnelError(msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (h *Handler) handleRegisterOK(msg *common.Message) error {
	var payload common.RegisterOKPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	h.agent.SetClientID(payload.ClientID)
	slog.Info("registered successfully", "client_id", payload.ClientID)
	return nil
}

func (h *Handler) handleRegisterFail(msg *common.Message) error {
	var payload common.RegisterFailPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Error("registration failed", "reason", payload.Reason)
	return fmt.Errorf("registration failed: %s", payload.Reason)
}

func (h *Handler) handleTunnelOpen(msg *common.Message) error {
	var payload common.TunnelOpenPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("tunnel close request", "tunnel_id", payload.TunnelID)
	return h.agent.tunnelManager.CloseTunnel(payload.TunnelID)
}

func (h *Handler) handleTunnelData(msg *common.Message) error {
	var payload common.TunnelDataPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return err
	}

	conn, err := h.agent.tunnelManager.GetOrCreateLocalConn(payload.ConnID, payload.TunnelID)
	if err != nil {
		h.agent.tunnelManager.SendError(payload.TunnelID, payload.ConnID, err.Error())
		return err
	}

	if _, err := conn.Write(data); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
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
