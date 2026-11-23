package server

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"goremote/internal/common"
)

const (
	deviceStatusPending    = "pending"
	deviceStatusAuthorized = "authorized"
	maxPendingDevices      = 256
	maxSeenReauthEntries   = 8192
)

var (
	// errDeviceDHKeyMismatch 表示 reauth 携带的 DH 公钥与审批时绑定的不一致。
	// 设备记录里的 DH 公钥决定服务端把隧道密钥封装给谁，审批之后不可变，
	// 任何差异都只能走重新审批，不能在 reauth 里覆盖。
	errDeviceDHKeyMismatch = errors.New("device dh pubkey mismatch")
	// errDeviceDHKeyCorrupt 表示记录里的 DH 公钥无法解析：此时无法判断两者
	// 是否一致，必须 fail closed，绝不按它重新封装密钥。
	errDeviceDHKeyCorrupt = errors.New("stored device dh pubkey is corrupt")
)

// verifyDeviceDHPubkey 判定 reauth 带来的 DH 公钥能否用于本次重连。
//
// 两侧都为空是旧版未加密设备（白名单/明文路径），放行。任一侧有值就必须
// 与记录完全一致：记录为空说明审批时没绑定过公钥，凭空绑定等于把密钥交给
// 一个从未被审批过的公钥，所以按不一致处理，走重新审批。
func verifyDeviceDHPubkey(storedHex, payloadHex string) error {
	if storedHex == "" {
		if payloadHex == "" {
			return nil
		}
		return errDeviceDHKeyMismatch
	}
	storedBytes, err := hex.DecodeString(storedHex)
	if err != nil || len(storedBytes) != 32 {
		return errDeviceDHKeyCorrupt
	}
	payloadBytes, err := hex.DecodeString(payloadHex)
	if err != nil || len(payloadBytes) != 32 {
		return errDeviceDHKeyMismatch
	}
	if subtle.ConstantTimeCompare(storedBytes, payloadBytes) != 1 {
		return errDeviceDHKeyMismatch
	}
	return nil
}

type PendingConn struct {
	Client   *Client
	RemoteIP string
}

type DeviceManager struct {
	mu           sync.RWMutex
	store        *StateStore
	pendingConns map[string]*PendingConn
	cryptoMgr    *common.CryptoManager
	seenReauth   map[string]int64
}

func NewDeviceManager(store *StateStore, cryptoMgr *common.CryptoManager) *DeviceManager {
	dm := &DeviceManager{
		store:        store,
		pendingConns: make(map[string]*PendingConn),
		cryptoMgr:    cryptoMgr,
		seenReauth:   make(map[string]int64),
	}

	for _, device := range store.GetAllDevices() {
		if device.Status != deviceStatusAuthorized || !device.EncEnabled {
			continue
		}
		if device.EncKey == "" || device.DeviceDHPubkey == "" {
			slog.Warn("disabling unusable encryption state for device", "device_id", device.ID)
			store.UpdateDevice(device.ID, func(d *DeviceState) { d.EncEnabled = false })
			continue
		}
		key, err := hex.DecodeString(device.EncKey)
		if err != nil {
			slog.Warn("failed to decode enc_key for device", "device_id", device.ID, "error", err)
			continue
		}
		if err := cryptoMgr.SetKey(device.ID, key); err != nil {
			slog.Warn("failed to set enc_key for device", "device_id", device.ID, "error", err)
		}
	}

	return dm
}

func validateDeviceTextField(value string, maxLen int, label string) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s is too long: %d bytes (max %d)", label, len(value), maxLen)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains control characters", label)
		}
	}
	return nil
}

func validateDHPubkeyHex(deviceDHPubkey string) error {
	if deviceDHPubkey == "" {
		return nil
	}
	keyBytes, err := hex.DecodeString(deviceDHPubkey)
	if err != nil {
		return fmt.Errorf("invalid device dh pubkey: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("invalid device dh pubkey size: %d", len(keyBytes))
	}
	return nil
}

// sealEncKeyForDevice encrypts a tunnel key with X25519 ECDH + HKDF using the
// device's registered DH public key.
func sealEncKeyForDevice(device *DeviceState, encKey []byte) (string, string, error) {
	agentDHPubkey, err := hex.DecodeString(device.DeviceDHPubkey)
	if err != nil {
		return "", "", fmt.Errorf("invalid device dh pubkey: %w", err)
	}
	if len(agentDHPubkey) != 32 {
		return "", "", fmt.Errorf("invalid device dh pubkey size: %d", len(agentDHPubkey))
	}
	var agentDHPub [32]byte
	copy(agentDHPub[:], agentDHPubkey)

	serverDHPriv, serverDHPub, err := common.GenerateDHKeypair()
	if err != nil {
		return "", "", fmt.Errorf("generate server dh keypair: %w", err)
	}
	sharedSecret, err := common.DHSharedSecret(serverDHPriv, &agentDHPub)
	if err != nil {
		return "", "", fmt.Errorf("compute shared secret: %w", err)
	}
	encKeyEncrypted, err := common.EncryptKeyWithSharedSecret(encKey, sharedSecret)
	if err != nil {
		return "", "", fmt.Errorf("encrypt enc_key: %w", err)
	}
	return encKeyEncrypted, common.EncodeBytes(serverDHPub[:]), nil
}

func (dm *DeviceManager) RegisterNewClient(deviceSignPubkey, deviceDHPubkey, hostname, osName, remoteIP string) (deviceID string, err error) {
	pubKeyBytes, err := hex.DecodeString(deviceSignPubkey)
	if err != nil {
		return "", fmt.Errorf("invalid device_sign_pubkey: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid device_sign_pubkey size: %d", len(pubKeyBytes))
	}
	if err := validateDHPubkeyHex(deviceDHPubkey); err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	osName = strings.TrimSpace(osName)
	if err := validateDeviceTextField(hostname, 255, "hostname"); err != nil {
		return "", err
	}
	if err := validateDeviceTextField(osName, 128, "os"); err != nil {
		return "", err
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	if existing := dm.store.GetDeviceBySignPubkey(deviceSignPubkey, deviceStatusPending); existing != nil {
		dm.store.UpdateDevice(existing.ID, func(device *DeviceState) {
			if hostname != "" {
				if device.Name == "" || device.Name == device.Hostname {
					device.Name = hostname
				}
				device.Hostname = hostname
			}
			if osName != "" {
				device.OS = osName
			}
			if deviceDHPubkey != "" {
				device.DeviceDHPubkey = deviceDHPubkey
			}
		})
		return existing.ID, nil
	}

	if dm.store.CountDevicesByStatus(deviceStatusPending) >= maxPendingDevices {
		return "", fmt.Errorf("too many pending devices, approve or deny existing requests first")
	}

	deviceID = "client-" + uuid.NewString()[:16]
	device := &DeviceState{
		ID:               deviceID,
		Name:             hostname,
		DeviceSignPubkey: deviceSignPubkey,
		DeviceDHPubkey:   deviceDHPubkey,
		Hostname:         hostname,
		OS:               osName,
		Status:           deviceStatusPending,
		IPWhitelist:      []string{},
		FirstSeen:        time.Now(),
	}

	dm.store.AddDevice(device)
	slog.Info("new device pending approval", "device_id", deviceID, "hostname", hostname, "ip", remoteIP)
	return deviceID, nil
}

func (dm *DeviceManager) ReauthClient(clientID, deviceSignPubkey, deviceDHPubkey string, timestamp int64, signature string) (bool, *DeviceState, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(clientID)
	if device == nil {
		return false, nil, fmt.Errorf("device not found: %s", clientID)
	}
	if device.DeviceSignPubkey != deviceSignPubkey {
		return false, nil, fmt.Errorf("public key mismatch")
	}
	if device.Status != deviceStatusAuthorized {
		return false, nil, nil
	}
	if !common.IsTimestampValid(timestamp, 5*time.Minute) {
		return false, nil, fmt.Errorf("timestamp expired")
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

	// 签名只覆盖 client_id:timestamp，所以 payload 里的 DH 公钥是未签名数据。
	// 它必须在动任何状态之前与审批时绑定的值核对：通过则本次 register_ok
	// 仍然按记录里的公钥封装，拒绝则连重放缓存都不写——被拒报文不该烧掉
	// 签名，否则合法设备重试会收到 replayed 而不是 mismatch。
	if err := verifyDeviceDHPubkey(device.DeviceDHPubkey, deviceDHPubkey); err != nil {
		return false, nil, err
	}

	cacheKey := clientID + ":" + signature
	if _, replayed := dm.seenReauth[cacheKey]; replayed {
		return false, nil, fmt.Errorf("reauth signature replayed")
	}
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute).Unix()
	for key, seenAt := range dm.seenReauth {
		if seenAt < cutoff {
			delete(dm.seenReauth, key)
		}
	}
	if len(dm.seenReauth) >= maxSeenReauthEntries {
		// A device with a valid key could otherwise grow this cache without
		// bound by signing many timestamps within the replay window.
		for key := range dm.seenReauth {
			delete(dm.seenReauth, key)
			if len(dm.seenReauth) < maxSeenReauthEntries/2 {
				break
			}
		}
	}
	dm.seenReauth[cacheKey] = now.Unix()

	return true, device, nil
}

func (dm *DeviceManager) ApproveDevice(deviceID string) (*DeviceState, string, string, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(deviceID)
	if device == nil {
		return nil, "", "", fmt.Errorf("device not found: %s", deviceID)
	}
	if device.Status != deviceStatusPending {
		return nil, "", "", fmt.Errorf("device is not pending: %s", deviceID)
	}
	if device.DeviceDHPubkey == "" {
		return nil, "", "", fmt.Errorf("device dh public key is required for encrypted approval")
	}

	encKey, err := common.GenerateEncKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate enc_key: %w", err)
	}
	encKeyEncrypted, serverDHPubkey, err := sealEncKeyForDevice(device, encKey)
	if err != nil {
		return nil, "", "", err
	}

	now := time.Now()
	dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		d.Status = deviceStatusAuthorized
		d.EncKey = hex.EncodeToString(encKey)
		d.EncEnabled = true
		d.ApprovedAt = &now
	})
	dm.cryptoMgr.SetKey(deviceID, encKey)

	return dm.store.GetDeviceByID(deviceID), encKeyEncrypted, serverDHPubkey, nil
}

func (dm *DeviceManager) DenyDevice(deviceID string) error {
	dm.mu.Lock()
	device := dm.store.GetDeviceByID(deviceID)
	if device == nil {
		dm.mu.Unlock()
		return fmt.Errorf("device not found: %s", deviceID)
	}
	if device.Status != deviceStatusPending {
		dm.mu.Unlock()
		return fmt.Errorf("device is not pending: %s", deviceID)
	}
	info := dm.pendingConns[deviceID]
	delete(dm.pendingConns, deviceID)
	removed, err := dm.store.RemoveDevice(deviceID)
	if err != nil {
		// 落盘失败：设备还在，pending 连接也要放回去。
		if info != nil {
			dm.pendingConns[deviceID] = info
		}
		dm.mu.Unlock()
		return err
	}
	if !removed {
		dm.mu.Unlock()
		return fmt.Errorf("device not found: %s", deviceID)
	}
	dm.mu.Unlock()

	dm.cryptoMgr.RemoveKey(deviceID)
	if info != nil {
		closeClientConn(info.Client)
	}
	return nil
}

func (dm *DeviceManager) DeleteDevice(deviceID string) error {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	delete(dm.pendingConns, deviceID)
	removed, err := dm.store.RemoveDevice(deviceID)
	if err != nil {
		if info != nil {
			dm.pendingConns[deviceID] = info
		}
		dm.mu.Unlock()
		return err
	}
	if !removed {
		dm.mu.Unlock()
		return fmt.Errorf("device not found: %s", deviceID)
	}
	dm.mu.Unlock()

	dm.cryptoMgr.RemoveKey(deviceID)
	if info != nil {
		closeClientConn(info.Client)
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
	if device.Status != deviceStatusAuthorized {
		return nil, "", "", fmt.Errorf("device is not authorized: %s", deviceID)
	}
	if device.DeviceDHPubkey == "" {
		return nil, "", "", fmt.Errorf("device dh public key is required to regenerate an encryption key")
	}

	newEncKey, err := common.GenerateEncKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate enc_key: %w", err)
	}

	encKeyEncrypted, serverDHPubkey, err := sealEncKeyForDevice(device, newEncKey)
	if err != nil {
		return nil, "", "", err
	}

	dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		d.EncKey = hex.EncodeToString(newEncKey)
		d.EncEnabled = true
	})
	dm.cryptoMgr.SetKey(deviceID, newEncKey)

	return dm.store.GetDeviceByID(deviceID), encKeyEncrypted, serverDHPubkey, nil
}

func (dm *DeviceManager) UpdateDeviceConfig(deviceID, name string, encEnabled bool, ipWhitelist []string) (*DeviceState, error) {
	name = strings.TrimSpace(name)
	if err := validateDeviceTextField(name, 255, "name"); err != nil {
		return nil, err
	}
	dm.mu.Lock()
	defer dm.mu.Unlock()

	device := dm.store.GetDeviceByID(deviceID)
	if device == nil {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	var key []byte
	if encEnabled {
		if device.DeviceDHPubkey == "" {
			return nil, fmt.Errorf("device dh public key is required to enable encryption")
		}
		if device.EncKey == "" {
			generated, err := common.GenerateEncKey()
			if err != nil {
				return nil, fmt.Errorf("generate enc_key: %w", err)
			}
			key = generated
		} else {
			stored, err := hex.DecodeString(device.EncKey)
			if err != nil {
				return nil, fmt.Errorf("invalid stored enc_key: %w", err)
			}
			key = stored
		}
		if err := dm.cryptoMgr.SetKey(deviceID, key); err != nil {
			return nil, err
		}
	} else {
		dm.cryptoMgr.RemoveKey(deviceID)
	}

	if ipWhitelist != nil {
		ipWhitelist = deduplicateIPs(ipWhitelist)
	}
	if !dm.store.UpdateDevice(deviceID, func(d *DeviceState) {
		if name != "" {
			d.Name = name
		}
		if key != nil {
			d.EncKey = hex.EncodeToString(key)
		}
		d.EncEnabled = encEnabled
		if ipWhitelist != nil {
			d.IPWhitelist = ipWhitelist
		}
	}) {
		if encEnabled {
			dm.cryptoMgr.RemoveKey(deviceID)
		}
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	return dm.store.GetDeviceByID(deviceID), nil
}

func (dm *DeviceManager) AddPendingConn(deviceID string, client *Client, remoteIP string) {
	dm.mu.Lock()
	var oldClient *Client
	if old, ok := dm.pendingConns[deviceID]; ok && old.Client != client {
		oldClient = old.Client
	}
	dm.pendingConns[deviceID] = &PendingConn{Client: client, RemoteIP: remoteIP}
	dm.mu.Unlock()

	closeClientConn(oldClient)
}

func (dm *DeviceManager) RemovePendingConn(deviceID string) {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	delete(dm.pendingConns, deviceID)
	dm.mu.Unlock()

	if info != nil {
		closeClientConn(info.Client)
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

	closeClientConn(info.Client)
}

func (dm *DeviceManager) DetachPendingConnIfMatch(deviceID string, client *Client) {
	dm.mu.Lock()
	info := dm.pendingConns[deviceID]
	if info != nil && info.Client == client {
		delete(dm.pendingConns, deviceID)
	}
	dm.mu.Unlock()
}

func (dm *DeviceManager) CloseAllPendingConns() {
	dm.mu.Lock()
	clients := make([]*Client, 0, len(dm.pendingConns))
	for _, info := range dm.pendingConns {
		if info.Client != nil {
			clients = append(clients, info.Client)
		}
	}
	dm.pendingConns = make(map[string]*PendingConn)
	dm.mu.Unlock()

	for _, client := range clients {
		closeClientConn(client)
	}
}

func closeClientConn(client *Client) {
	if client != nil && client.Conn != nil {
		_ = client.Conn.Close()
	}
}

func (dm *DeviceManager) GetPendingConn(deviceID string) (*PendingConn, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	info, ok := dm.pendingConns[deviceID]
	return info, ok
}
