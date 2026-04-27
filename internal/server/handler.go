package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"goremote/internal/common"
)

type Handler struct {
	server *Server
}

func NewHandler(server *Server) *Handler {
	return &Handler{server: server}
}

func (h *Handler) Handle(client *Client, msg *common.Message) error {
	switch msg.Type {
	case "register":
		return h.handleRegister(client, msg)
	case "ping":
		return h.handlePing(client, msg)
	case "tunnel_open":
		return h.handleTunnelOpen(client, msg)
	case "tunnel_close":
		return h.handleTunnelClose(client, msg)
	case "tunnel_data":
		return h.handleTunnelData(client, msg)
	case "tunnel_error":
		return h.handleTunnelError(client, msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (h *Handler) handleRegister(client *Client, msg *common.Message) error {
	var payload common.RegisterPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return h.sendRegisterFail(client, "invalid payload")
	}

	if payload.Key != h.server.config.Auth.Key {
		return h.sendRegisterFail(client, "invalid key")
	}

	client.Hostname = payload.Hostname
	client.OS = payload.OS

	client.ClientID = fmt.Sprintf("client-%s", generateUUID())

	h.server.clients.Add(client)

	slog.Info("client registered",
		"client_id", client.ClientID,
		"hostname", client.Hostname,
		"os", client.OS)

	return h.sendRegisterOK(client)
}

func (h *Handler) handlePing(client *Client, msg *common.Message) error {
	h.server.clients.UpdatePing(client.ClientID)
	return client.WriteJSON(common.Message{Type: "pong"})
}

func (h *Handler) handleTunnelOpen(client *Client, msg *common.Message) error {
	var payload common.TunnelOpenPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	publicPort, err := h.server.tunnelManager.AllocatePort()
	if err != nil {
		ackPayload := common.TunnelOpenAckPayload{
			TunnelID: payload.TunnelID,
			Success:  false,
			Error:    err.Error(),
		}
		payloadJSON, _ := json.Marshal(ackPayload)
		return client.WriteJSON(common.Message{
			Type:    "tunnel_open_ack",
			Payload: payloadJSON,
		})
	}

	if err := h.server.tunnelManager.CreateTunnel(
		payload.TunnelID,
		client.ClientID,
		client,
		payload.Protocol,
		payload.LocalAddr,
		payload.LocalPort,
		publicPort,
	); err != nil {
		h.server.tunnelManager.ReleasePort(publicPort)
		ackPayload := common.TunnelOpenAckPayload{
			TunnelID: payload.TunnelID,
			Success:  false,
			Error:    err.Error(),
		}
		payloadJSON, _ := json.Marshal(ackPayload)
		return client.WriteJSON(common.Message{
			Type:    "tunnel_open_ack",
			Payload: payloadJSON,
		})
	}

	if err := h.server.tunnelManager.Listen(publicPort, payload.TunnelID); err != nil {
		h.server.tunnelManager.CloseTunnel(payload.TunnelID)
		ackPayload := common.TunnelOpenAckPayload{
			TunnelID: payload.TunnelID,
			Success:  false,
			Error:    err.Error(),
		}
		payloadJSON, _ := json.Marshal(ackPayload)
		return client.WriteJSON(common.Message{
			Type:    "tunnel_open_ack",
			Payload: payloadJSON,
		})
	}

	ackPayload := common.TunnelOpenAckPayload{
		TunnelID:   payload.TunnelID,
		PublicPort: publicPort,
		Success:    true,
	}
	payloadJSON, _ := json.Marshal(ackPayload)
	return client.WriteJSON(common.Message{
		Type:    "tunnel_open_ack",
		Payload: payloadJSON,
	})
}

func (h *Handler) handleTunnelClose(client *Client, msg *common.Message) error {
	var payload common.TunnelClosePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	tunnel, ok := h.server.tunnelManager.GetTunnel(payload.TunnelID)
	if !ok {
		return nil
	}

	if tunnel.ClientID != client.ClientID {
		return fmt.Errorf("tunnel does not belong to this client")
	}

	return h.server.tunnelManager.CloseTunnel(payload.TunnelID)
}

func (h *Handler) handleTunnelData(client *Client, msg *common.Message) error {
	var payload common.TunnelDataPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	tunnel, ok := h.server.tunnelManager.GetTunnel(payload.TunnelID)
	if !ok || tunnel.ClientID != client.ClientID {
		return fmt.Errorf("tunnel not found or not owned by client")
	}

	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return err
	}

	return h.server.tunnelManager.HandleAgentData(payload.TunnelID, payload.ConnID, data, payload.IsEOF)
}

func (h *Handler) handleTunnelError(client *Client, msg *common.Message) error {
	var payload common.TunnelErrorPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Warn("tunnel error from agent",
		"tunnel_id", payload.TunnelID,
		"conn_id", payload.ConnID,
		"error", payload.Error)

	return nil
}

func (h *Handler) sendRegisterOK(client *Client) error {
	payload := common.RegisterOKPayload{ClientID: client.ClientID}
	payloadJSON, _ := json.Marshal(payload)
	return client.WriteJSON(common.Message{
		Type:    "register_ok",
		Payload: payloadJSON,
	})
}

func (h *Handler) sendRegisterFail(client *Client, reason string) error {
	payload := common.RegisterFailPayload{Reason: reason}
	payloadJSON, _ := json.Marshal(payload)
	return client.WriteJSON(common.Message{
		Type:    "register_fail",
		Payload: payloadJSON,
	})
}
