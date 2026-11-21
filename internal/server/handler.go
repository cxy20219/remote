package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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
		return h.handlePing(client)
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
	payload.Hostname = strings.TrimSpace(payload.Hostname)
	payload.OS = strings.TrimSpace(payload.OS)

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
	client.SetEncryptionEnabled(false)

	remoteIP := extractIP(client.RemoteAddr)
	h.server.deviceMgr.AddPendingConn(deviceID, client, remoteIP)

	slog.Info("new device registration pending",
		"device_id", deviceID,
		"hostname", payload.Hostname,
		"ip", remoteIP)

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
		if err := validateDeviceTextField(payload.Hostname, 255, "hostname"); err != nil {
			return err
		}
		if err := validateDeviceTextField(payload.OS, 128, "os"); err != nil {
			return err
		}
		h.server.stateStore.UpdateDevice(device.ID, func(d *DeviceState) {
			if payload.Hostname != "" {
				// Keep an administrator-defined alias; only mirror the
				// hostname while the device still uses the default alias.
				if d.Name == "" || d.Name == d.Hostname {
					d.Name = payload.Hostname
				}
				d.Hostname = payload.Hostname
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

	okPayload, err := h.registerOKPayloadForDevice(device)
	if err != nil {
		slog.Warn("failed to prepare register_ok",
			"client_id", device.ID,
			"error", err)
		return h.sendRegisterFail(client, err.Error())
	}

	client.ClientID = device.ID
	client.Hostname = device.Hostname
	client.OS = device.OS
	client.SetEncryptionEnabled(h.server.deviceEncryptionActive(device))
	h.server.clients.Add(client)
	h.server.deviceMgr.RemovePendingConn(client.ClientID)
	if h.server.tunnelManager != nil {
		// 只解绑，不删定义：register_ok 之后要按原端口重放。必须在新连接
		// 登记之后解绑——DetachClient 靠“当前连接是不是我”区分迟到的收尾。
		h.server.tunnelManager.DetachClient(device.ID, client)
	}

	slog.Info("client reconnected",
		"client_id", device.ID,
		"hostname", device.Hostname)

	payloadJSON, _ := json.Marshal(okPayload)
	if err := client.WriteJSON(common.Message{
		Type:    "register_ok",
		Payload: payloadJSON,
	}); err != nil {
		return err
	}
	// 必须在 register_ok 写成功之后才重放 tunnel_open：agent 在注册期间
	// 对未知消息是直接丢弃的（agent/agent.go 的 default 分支）。
	client.markRegisterOKWritten()
	h.server.scheduleTunnelRestore(client)
	return nil
}

func (h *Handler) registerOKPayloadForDevice(device *DeviceState) (common.RegisterOKPayload, error) {
	if device == nil {
		return common.RegisterOKPayload{}, fmt.Errorf("device is nil")
	}

	encEnabled := device.EncEnabled && device.EncKey != "" && device.DeviceDHPubkey != ""
	var encKeyEncrypted, serverDHPubkey string
	if encEnabled {
		key, err := hex.DecodeString(device.EncKey)
		if err != nil {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored enc_key: %w", err)
		}
		if len(key) != 32 {
			return common.RegisterOKPayload{}, fmt.Errorf("invalid stored enc_key size: %d", len(key))
		}
		encKeyEncrypted, serverDHPubkey, err = sealEncKeyForDevice(device, key)
		if err != nil {
			return common.RegisterOKPayload{}, err
		}
	}

	payload := common.RegisterOKPayload{
		ClientID:        device.ID,
		EncKeyEncrypted: encKeyEncrypted,
		ServerDHPubkey:  serverDHPubkey,
		EncEnabled:      encEnabled,
	}
	if err := h.signRegisterOKPayload(&payload); err != nil {
		return common.RegisterOKPayload{}, err
	}
	return payload, nil
}

func (h *Handler) signRegisterOKPayload(payload *common.RegisterOKPayload) error {
	if h == nil || h.server == nil || h.server.stateStore == nil || payload == nil {
		return fmt.Errorf("server signing context is unavailable")
	}
	priv := h.server.stateStore.GetServerSignPrivkey()
	pub := h.server.stateStore.GetServerSignPubkey()
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("server signing key is unavailable or corrupted")
	}
	signature, err := common.SignServerKeyPayload(priv, payload.ClientID, payload.EncEnabled, payload.ServerDHPubkey, payload.EncKeyEncrypted)
	if err != nil {
		return err
	}
	payload.ServerSignPubkey = common.EncodePublicKey(pub)
	payload.ServerSignature = common.EncodeBytes(signature)
	return nil
}

func (s *Server) sendRegisterOK(client *Client, payload common.RegisterOKPayload) error {
	if client == nil || !client.markRegisterOKSent() {
		return nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := client.WriteJSON(common.Message{Type: "register_ok", Payload: payloadJSON}); err != nil {
		return err
	}
	client.markRegisterOKWritten()
	return nil
}

func (h *Handler) handlePing(client *Client) error {
	h.server.clients.TouchIfMatch(client.ClientID, client)
	return client.WriteJSON(common.Message{Type: "pong"})
}

func (h *Handler) handleTunnelDataBinary(client *Client, msg *common.Message) error {
	if h.server.tunnelManager == nil {
		return fmt.Errorf("tunnel is not enabled")
	}

	payload := msg.BinaryData
	if payload == nil {
		return fmt.Errorf("missing binary tunnel payload")
	}
	if len(payload.Data) > common.TunnelChunkSize+common.TunnelEncryptionOverhead {
		return fmt.Errorf("tunnel payload too large: %d bytes", len(payload.Data))
	}

	tunnel, ok := h.server.tunnelManager.GetTunnel(payload.TunnelID)
	if !ok || tunnel.ClientID != client.ClientID {
		return fmt.Errorf("tunnel not found or not owned by client")
	}

	if payload.IsEOF && len(payload.Data) == 0 {
		return h.server.tunnelManager.HandleAgentData(payload.TunnelID, payload.ConnID, nil, true)
	}

	data, err := h.server.decryptTunnelBytes(client, payload.Data)
	if err != nil {
		h.server.tunnelManager.RemoveExternalConn(payload.ConnID)
		h.server.tunnelManager.sendTunnelEOF(payload.TunnelID, payload.ConnID, client)
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

	if payload.ConnID != "" {
		h.server.tunnelManager.RemoveExternalConn(payload.ConnID)
	}
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

func sendRegisterUpdate(client *Client, updateType string, payload common.RegisterOKPayload) error {
	if client == nil {
		return fmt.Errorf("tunnel client is not connected")
	}
	updatePayload := common.RegisterUpdatePayload{
		Type:             updateType,
		ClientID:         payload.ClientID,
		EncKeyEncrypted:  payload.EncKeyEncrypted,
		ServerDHPubkey:   payload.ServerDHPubkey,
		EncEnabled:       payload.EncEnabled,
		ServerSignPubkey: payload.ServerSignPubkey,
		ServerSignature:  payload.ServerSignature,
	}
	payloadJSON, err := json.Marshal(updatePayload)
	if err != nil {
		return err
	}
	return client.WriteJSON(common.Message{Type: "register_update", Payload: payloadJSON})
}

func sendDeviceDeleted(client *Client, reason string) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
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
