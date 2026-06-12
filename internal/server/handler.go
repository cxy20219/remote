package server

import (
	"crypto/ed25519"
	"encoding/hex"
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
	case "tunnel_data_bin":
		return h.handleTunnelDataBinary(client, msg)
	case "tunnel_error":
		return h.handleTunnelError(client, msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (h *Handler) handleRegister(client *Client, msg *common.Message) error {
	var payload common.RegisterPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return h.sendRegisterFail(client, "invalid payload")
	}

	if payload.ReAuth {
		return h.handleReconnect(client, &payload)
	}

	return h.handleNewRegistration(client, &payload)
}

func (h *Handler) handleNewRegistration(client *Client, payload *common.RegisterPayload) error {
	deviceID, err := h.server.deviceMgr.RegisterNewClient(
		payload.DevicePubkey,
		payload.DeviceDHPubkey,
		payload.Hostname,
		payload.OS,
		client.RemoteAddr,
	)
	if err != nil {
		return h.sendRegisterFail(client, err.Error())
	}

	client.ClientID = deviceID
	client.Hostname = payload.Hostname
	client.OS = payload.OS

	h.server.deviceMgr.AddPendingConn(deviceID, client, client.RemoteAddr)

	slog.Info("new device registration pending",
		"device_id", deviceID,
		"hostname", payload.Hostname,
		"ip", client.RemoteAddr)

	pendingPayload := common.RegisterPendingPayload{
		ClientID: deviceID,
		Message:  "waiting for admin approval",
	}
	payloadJSON, _ := json.Marshal(pendingPayload)
	return client.WriteJSON(common.Message{
		Type:    "register_pending",
		Payload: payloadJSON,
	})
}

func (h *Handler) handleReconnect(client *Client, payload *common.RegisterPayload) error {
	ok, device, err := h.server.deviceMgr.ReauthClient(
		payload.ClientID,
		payload.DevicePubkey,
		payload.Timestamp,
		payload.Signature,
	)
	if err != nil {
		slog.Warn("reauth failed, treating as new registration",
			"client_id", payload.ClientID,
			"error", err)
		return h.handleNewRegistration(client, payload)
	}

	if !ok {
		slog.Warn("reauth device not authorized, treating as new registration",
			"client_id", payload.ClientID)
		return h.handleNewRegistration(client, payload)
	}

	if payload.Hostname != "" || payload.OS != "" || payload.DeviceDHPubkey != "" {
		if err := validateDHPubkeyHex(payload.DeviceDHPubkey); err != nil {
			return fmt.Errorf("invalid reauth device dh pubkey: %w", err)
		}
		h.server.stateStore.UpdateDevice(device.ID, func(d *DeviceState) {
			if payload.Hostname != "" {
				d.Hostname = payload.Hostname
				d.Name = payload.Hostname
			}
			if payload.OS != "" {
				d.OS = payload.OS
			}
			if payload.DeviceDHPubkey != "" {
				d.DeviceDHPubkey = payload.DeviceDHPubkey
			}
		})
		if updated := h.server.stateStore.GetDeviceByID(device.ID); updated != nil {
			device = updated
		}
	}

	client.ClientID = device.ID
	client.Hostname = device.Hostname
	client.OS = device.OS

	okPayload, err := h.registerOKPayloadForDevice(device)
	if err != nil {
		slog.Warn("failed to prepare register_ok",
			"client_id", device.ID,
			"error", err)
		return h.sendRegisterFail(client, err.Error())
	}

	if h.server.tunnelManager != nil {
		h.server.tunnelManager.CloseTunnelsByClient(device.ID)
	}
	h.server.clients.Add(client)
	h.server.deviceMgr.RemovePendingConn(client.ClientID)

	slog.Info("client reconnected",
		"client_id", device.ID,
		"hostname", device.Hostname)

	payloadJSON, _ := json.Marshal(okPayload)
	return client.WriteJSON(common.Message{
		Type:    "register_ok",
		Payload: payloadJSON,
	})
}

func (h *Handler) registerOKPayloadForDevice(device *DeviceState) (common.RegisterOKPayload, error) {
	if device == nil {
		return common.RegisterOKPayload{}, fmt.Errorf("device is nil")
	}

	var encKeyEncrypted, serverDHPubkey string
	if device.EncEnabled && device.DeviceDHPubkey != "" {
		key, err := hex.DecodeString(device.EncKey)
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored enc_key: %w", err)
		}
		if len(key) != 32 {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored enc_key size: %d", len(key))
		}

		agentDHPubkey, err := hex.DecodeString(device.DeviceDHPubkey)
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored device dh pubkey: %w", err)
		}
		if len(agentDHPubkey) != 32 {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored device dh pubkey size: %d", len(agentDHPubkey))
		}

		var agentDHPub [32]byte
		copy(agentDHPub[:], agentDHPubkey)
		serverDHPriv, serverDHPub, err := common.GenerateDHKeypair()
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("generate server dh keypair: %w", err)
		}
		sharedSecret, err := common.DHSharedSecret(serverDHPriv, &agentDHPub)
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("compute shared secret: %w", err)
		}
		encKeyEncrypted, err = common.EncryptKeyWithSharedSecret(key, sharedSecret)
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("encrypt enc_key: %w", err)
		}
		serverDHPubkey = common.EncodeBytes(serverDHPub[:])
	}

	payload := common.RegisterOKPayload{
		ClientID:        device.ID,
		EncKeyEncrypted: encKeyEncrypted,
		ServerDHPubkey:  serverDHPubkey,
		EncEnabled:      device.EncEnabled,
	}
	if err := h.signRegisterOKPayload(&payload); err != nil {
		return common.RegisterOKPayload{}, err
	}
	return payload, nil
}

func (h *Handler) signRegisterOKPayload(payload *common.RegisterOKPayload) error {
	if h == nil || h.server == nil || h.server.stateStore == nil || payload == nil {
		return nil
	}
	priv := h.server.stateStore.GetServerSignPrivkey()
	pub := h.server.stateStore.GetServerSignPubkey()
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		return nil
	}
	signature, err := common.SignServerKeyPayload(priv, payload.ClientID, payload.EncEnabled, payload.ServerDHPubkey, payload.EncKeyEncrypted)
	if err != nil {
		return err
	}
	payload.ServerSignPubkey = common.EncodePublicKey(pub)
	payload.ServerSignature = common.EncodeBytes(signature)
	return nil
}

func (h *Handler) handlePing(client *Client, msg *common.Message) error {
	h.server.clients.UpdatePingIfMatch(client.ClientID, client)
	return client.WriteJSON(common.Message{Type: "pong"})
}

func (h *Handler) handleTunnelOpen(client *Client, msg *common.Message) error {
	if h.server.tunnelManager == nil {
		ackPayload := common.TunnelOpenAckPayload{
			Success: false,
			Error:   "tunnel is not enabled",
		}
		payloadJSON, _ := json.Marshal(ackPayload)
		return client.WriteJSON(common.Message{
			Type:    "tunnel_open_ack",
			Payload: payloadJSON,
		})
	}

	var payload common.TunnelOpenPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	publicPort, ln, err := h.server.tunnelManager.AllocatePort()
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
		TunnelExposurePublic,
	); err != nil {
		ln.Close()
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

	if err := h.server.tunnelManager.AcceptOnListener(publicPort, payload.TunnelID, ln); err != nil {
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
	if h.server.tunnelManager == nil {
		return fmt.Errorf("tunnel is not enabled")
	}

	var payload common.TunnelClosePayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
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

func (h *Handler) handleTunnelDataBinary(client *Client, msg *common.Message) error {
	if h.server.tunnelManager == nil {
		return fmt.Errorf("tunnel is not enabled")
	}

	payload := msg.BinaryData
	if payload == nil {
		return fmt.Errorf("missing binary tunnel payload")
	}

	tunnel, ok := h.server.tunnelManager.GetTunnel(payload.TunnelID)
	if !ok || tunnel.ClientID != client.ClientID {
		return fmt.Errorf("tunnel not found or not owned by client")
	}

	if payload.IsEOF && len(payload.Data) == 0 {
		return h.server.tunnelManager.HandleAgentData(payload.TunnelID, payload.ConnID, nil, true)
	}

	data, err := h.server.decryptTunnelBytes(client.ClientID, payload.Data)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	return h.server.tunnelManager.HandleAgentData(payload.TunnelID, payload.ConnID, data, payload.IsEOF)
}

func (h *Handler) handleTunnelError(client *Client, msg *common.Message) error {
	if h.server.tunnelManager == nil {
		slog.Warn("tunnel error from agent but tunnel is not enabled")
		return nil
	}

	var payload common.TunnelErrorPayload
	if err := common.DecodeStrictJSON(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Warn("tunnel error from agent",
		"tunnel_id", payload.TunnelID,
		"conn_id", payload.ConnID,
		"error", payload.Error)

	return nil
}

func (h *Handler) sendRegisterFail(client *Client, reason string) error {
	payload := common.RegisterFailPayload{Reason: reason}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal register_fail", "error", err)
		return err
	}
	return client.WriteJSON(common.Message{
		Type:    "register_fail",
		Payload: payloadJSON,
	})
}

func (h *Handler) sendRegisterOK(client *Client, deviceID, encKeyEncrypted, serverDHPubkey string, encEnabled bool) error {
	payload := common.RegisterOKPayload{
		ClientID:        deviceID,
		EncKeyEncrypted: encKeyEncrypted,
		ServerDHPubkey:  serverDHPubkey,
		EncEnabled:      encEnabled,
	}
	if err := h.signRegisterOKPayload(&payload); err != nil {
		return err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{
		Type:    "register_ok",
		Payload: payloadJSON,
	})
}

func (h *Handler) sendDeviceDeleted(client *Client, reason string) error {
	payload := common.DeviceDeletedPayload{Reason: reason}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{
		Type:    "device_deleted",
		Payload: payloadJSON,
	})
}
