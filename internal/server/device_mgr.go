package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"goremote/internal/common"
)

type PendingConnInfo struct {
	Client   *Client
	Conn     interface{}
	RemoteIP string
}

type DeviceManager struct {
	mu           sync.RWMutex
	store        *StateStore
	pendingConns map[string]*PendingConnInfo
	cryptoMgr    *common.CryptoManager
}

func NewDeviceManager(store *StateStore, cryptoMgr *common.CryptoManager) *DeviceManager {
	dm := &DeviceManager{
		store:        store,
		pendingConns: make(map[string]*PendingConnInfo),
		cryptoMgr:    cryptoMgr,
	}

	devices := store.GetAllDevices()
	for i := range devices {
		d := devices[i]
		if d.Status == "authorized" && d.EncKey != "" {
			key, err := hex.DecodeString(d.EncKey)
			if err != nil {
				slog.Warn("failed to decode enc_key for device", "device_id", d.ID, "error", err)
				continue
			}
			if err := cryptoMgr.SetKey(d.ID, key); err != nil {
				slog.Warn("failed to set enc_key for device", "device_id", d.ID, "error", err)
			}
		}
	}

	return dm
}

func (dm *DeviceManager) RegisterNewClient(deviceSignPubkey, deviceDHPubkey, hostname, osName, remoteIP string) (deviceID string, err error) {
	pubKeyBytes, err := hex.DecodeString(deviceSignPubkey)
	if err != nil {
		return "", fmt.Errorf("invalid device_sign_pubkey: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid device_sign_pubkey size: %d", len(pubKeyBytes))
	}

	dm.mu.Lock()
	for _, d := range dm.store.GetState().Devices {
		if d.DeviceSignPubkey == deviceSignPubkey && d.Status == "pending" {
			dm.store.UpdateDevice(d.ID, func(existing *DeviceState) {
				if hostname != "" {
					existing.Hostname = hostname
					existing.Name = hostname
				}
				if osName != "" {
					existing.OS = osName
				}
				if deviceDHPubkey != "" {
					existing.DeviceDHPubkey = deviceDHPubkey
				}
			})
			dm.mu.Unlock()
			return d.ID, nil
		}
	}
	dm.mu.Unlock()

	deviceID = "client-" + uuid.New().String()[:8]
	now := time.Now()

	device := &DeviceState{
		ID:               deviceID,
		Name:             hostname,
		DeviceSignPubkey: deviceSignPubkey,
		DeviceDHPubkey:   deviceDHPubkey,
		Hostname:         hostname,
		OS:               osName,
		Status:           "pending",
		EncKey:           "",
		EncEnabled:       false,
		IPWhitelist:      []string{},
		FirstSeen:        now,
	}

	dm.store.AddDevice(device)
	slog.Info("new device pending approval", "device_id", deviceID, "hostname", hostname, "ip", remoteIP)
	return deviceID, nil
}

func (dm *DeviceManager) ReauthClient(clientID, deviceSignPubkey string, timestamp int64, signature string) (bool, *DeviceState, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(clientID)
	if device == nil {
		return false, nil, fmt.Errorf("device not found: %s", clientID)
	}

	if device.DeviceSignPubkey != deviceSignPubkey {
		return false, nil, fmt.Errorf("public key mismatch")
	}

	if device.Status != "authorized" {
		return false, nil, nil
	}

	pubKeyBytes, err := hex.DecodeString(device.DeviceSignPubkey)
	if err != nil {
		return false, nil, fmt.Errorf("invalid stored public key: %w", err)
	}

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, nil, fmt.Errorf("invalid signature format: %w", err)
	}

	if !common.VerifyTimestamp(ed25519.PublicKey(pubKeyBytes), clientID, timestamp, sigBytes) {
		return false, nil, fmt.Errorf("signature verification failed")
	}

	if !common.IsTimestampValid(timestamp, 5*time.Minute) {
		return false, nil, fmt.Errorf("timestamp expired")
	}

	return true, device, nil
}

func (dm *DeviceManager) ApproveDevice(deviceID string) (*DeviceState, string, string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(deviceID)
	if device == nil {
		return nil, "", "", fmt.Errorf("device not found: %s", deviceID)
	}

	if device.Status != "pending" {
		return nil, "", "", fmt.Errorf("device is not pending: %s", deviceID)
	}

	encKey, err := common.GenerateEncKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate enc_key: %w", err)
	}

	var serverDHPubkeyStr string
	var encKeyEncrypted string

	if device.DeviceDHPubkey != "" {
		agentDHPubkey, err := hex.DecodeString(device.DeviceDHPubkey)
		if err != nil {
			return nil, "", "", fmt.Errorf("invalid device dh pubkey: %w", err)
		}
		var agentDHPub [32]byte
		copy(agentDHPub[:], agentDHPubkey)

		serverDHPriv, serverDHPub, err := common.GenerateDHKeypair()
		if err != nil {
			return nil, "", "", fmt.Errorf("generate server dh keypair: %w", err)
		}

		sharedSecret, err := common.DHSharedSecret(serverDHPriv, &agentDHPub)
		if err != nil {
			return nil, "", "", fmt.Errorf("compute shared secret: %w", err)
		}

		encKeyEncrypted, err = common.EncryptKeyWithSharedSecret(encKey, sharedSecret)
		if err != nil {
			return nil, "", "", fmt.Errorf("encrypt enc_key: %w", err)
		}

		serverDHPubkeyStr = common.EncodeBytes(serverDHPub[:])
	}

	now := time.Now()
	dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		d.Status = "authorized"
		d.EncKey = hex.EncodeToString(encKey)
		d.EncEnabled = true
		d.ApprovedAt = &now
	})

	dm.cryptoMgr.SetKey(deviceID, encKey)

	updated := dm.store.GetDeviceByID(deviceID)
	return updated, encKeyEncrypted, serverDHPubkeyStr, nil
}

func (dm *DeviceManager) DenyDevice(deviceID string) error {
	dm.RemovePendingConn(deviceID)
	if !dm.store.RemoveDevice(deviceID) {
		return fmt.Errorf("device not found: %s", deviceID)
	}
	return nil
}

func (dm *DeviceManager) DeleteDevice(deviceID string) error {
	dm.cryptoMgr.RemoveKey(deviceID)
	dm.RemovePendingConn(deviceID)
	dm.RemoveAuthorizedConn(deviceID)
	if !dm.store.RemoveDevice(deviceID) {
		return fmt.Errorf("device not found: %s", deviceID)
	}
	return nil
}

func (dm *DeviceManager) RegenerateEncKey(deviceID string) (*DeviceState, string, string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(deviceID)
	if device == nil {
		return nil, "", "", fmt.Errorf("device not found: %s", deviceID)
	}

	if device.Status != "authorized" {
		return nil, "", "", fmt.Errorf("device is not authorized: %s", deviceID)
	}

	newEncKey, err := common.GenerateEncKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate enc_key: %w", err)
	}

	var serverDHPubkeyStr string
	var encKeyEncrypted string

	if device.DeviceDHPubkey != "" {
		agentDHPubkey, err := hex.DecodeString(device.DeviceDHPubkey)
		if err != nil {
			return nil, "", "", fmt.Errorf("invalid device dh pubkey: %w", err)
		}
		var agentDHPub [32]byte
		copy(agentDHPub[:], agentDHPubkey)

		serverDHPriv, serverDHPub, err := common.GenerateDHKeypair()
		if err != nil {
			return nil, "", "", fmt.Errorf("generate server dh keypair: %w", err)
		}

		sharedSecret, err := common.DHSharedSecret(serverDHPriv, &agentDHPub)
		if err != nil {
			return nil, "", "", fmt.Errorf("compute shared secret: %w", err)
		}

		encKeyEncrypted, err = common.EncryptKeyWithSharedSecret(newEncKey, sharedSecret)
		if err != nil {
			return nil, "", "", fmt.Errorf("encrypt enc_key: %w", err)
		}

		serverDHPubkeyStr = common.EncodeBytes(serverDHPub[:])
	}

	dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		d.EncKey = hex.EncodeToString(newEncKey)
		d.EncEnabled = true
	})

	dm.cryptoMgr.SetKey(deviceID, newEncKey)

	updated := dm.store.GetDeviceByID(deviceID)
	return updated, encKeyEncrypted, serverDHPubkeyStr, nil
}

func (dm *DeviceManager) UpdateDeviceConfig(deviceID, name string, encEnabled bool, ipWhitelist []string) (*DeviceState, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	updated := dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		if name != "" {
			d.Name = name
		}
		d.EncEnabled = encEnabled
		if ipWhitelist != nil {
			d.IPWhitelist = ipWhitelist
		}
	})

	if !updated {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	return dm.store.GetDeviceByID(deviceID), nil
}

func (dm *DeviceManager) GetAuthorizedDevices() []DeviceState {
	return dm.store.GetDevicesByStatus("authorized")
}

func (dm *DeviceManager) GetPendingDevices() []DeviceState {
	return dm.store.GetDevicesByStatus("pending")
}

func (dm *DeviceManager) AddPendingConn(deviceID string, client *Client, remoteIP string) {
	dm.mu.Lock()
	var oldConn interface{}
	if old, ok := dm.pendingConns[deviceID]; ok && old.Client != client {
		oldConn = old.Conn
	}
	var conn interface{}
	if client != nil {
		conn = client.Conn
	}
	dm.pendingConns[deviceID] = &PendingConnInfo{
		Client:   client,
		Conn:     conn,
		RemoteIP: remoteIP,
	}
	dm.mu.Unlock()

	closePendingConn(oldConn)
}

func (dm *DeviceManager) RemovePendingConn(deviceID string) {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	delete(dm.pendingConns, deviceID)
	dm.mu.Unlock()

	if info != nil {
		closePendingConn(info.Conn)
	}
}

func (dm *DeviceManager) RemovePendingConnIfMatch(deviceID string, client *Client) {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	if info == nil || info.Client != client {
		dm.mu.Unlock()
		return
	}
	delete(dm.pendingConns, deviceID)
	dm.mu.Unlock()

	closePendingConn(info.Conn)
}

func (dm *DeviceManager) DetachPendingConnIfMatch(deviceID string, client *Client) {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	if info != nil && info.Client == client {
		delete(dm.pendingConns, deviceID)
	}
	dm.mu.Unlock()
}

func closePendingConn(conn interface{}) {
	if closer, ok := conn.(interface{ Close() error }); ok && closer != nil {
		_ = closer.Close()
	}
}

func (dm *DeviceManager) RemoveAuthorizedConn(deviceID string) {
	// No-op in the new design; ClientManager handles online connections
}

func (dm *DeviceManager) GetPendingConn(deviceID string) (*PendingConnInfo, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	info, ok := dm.pendingConns[deviceID]
	return info, ok
}
