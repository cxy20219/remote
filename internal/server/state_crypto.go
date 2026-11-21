package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	stateEncryptionVersion = 1
	stateEncryptionAlg     = "AES-256-GCM"
	stateEncryptionAAD     = "goremote-server-state-v1"
)

var ErrStateEncryptionKeyRequired = errors.New("state encryption key is required")

type EncryptedState struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type sensitiveStatePlain struct {
	ServerSignPrivkey string            `json:"server_sign_privkey"`
	AdminPasswordHash string            `json:"admin_password_hash"`
	DeviceEncKeys     map[string]string `json:"device_enc_keys"`

	// 两步验证密钥与恢复码哈希：与密码 hash 同等级，配置了 state 加密密钥时只存在于密文里。
	TOTPSecret         string   `json:"totp_secret,omitempty"`
	TOTPRecoveryHashes []string `json:"totp_recovery_hashes,omitempty"`
	TOTPLastStep       int64    `json:"totp_last_step,omitempty"`

	// hub 的 WireGuard 私钥与 TOTP 同等级：配了 state 密钥时只存在于密文里。
	WGHubPrivkey string `json:"wg_hub_privkey,omitempty"`
}

func (s *StateStore) SetEncryptionKey(rawKey string) error {
	key, err := deriveStateEncryptionKey(rawKey)
	if err != nil {
		return err
	}
	s.encryptionKey = key
	return nil
}

func deriveStateEncryptionKey(rawKey string) ([]byte, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, nil
	}
	if strings.HasPrefix(rawKey, "hex:") {
		decoded, err := hex.DecodeString(strings.TrimPrefix(rawKey, "hex:"))
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("state key hex value must decode to 32 bytes")
		}
		return decoded, nil
	}
	if strings.HasPrefix(rawKey, "base64:") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rawKey, "base64:"))
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("state key base64 value must decode to 32 bytes")
		}
		return decoded, nil
	}
	if len(rawKey) < 32 {
		return nil, fmt.Errorf("state key must be at least 32 characters")
	}
	sum := sha256.Sum256([]byte("goremote-state-key:" + rawKey))
	return sum[:], nil
}

func (s *StateStore) encryptSensitiveState(state *ServerState) error {
	if len(s.encryptionKey) == 0 {
		state.Encrypted = nil
		return nil
	}

	plain := sensitiveStatePlain{
		ServerSignPrivkey:  state.ServerSignPrivkey,
		AdminPasswordHash:  state.AdminPasswordHash,
		DeviceEncKeys:      make(map[string]string),
		TOTPSecret:         state.TOTPSecret,
		TOTPRecoveryHashes: state.TOTPRecoveryHashes,
		TOTPLastStep:       state.TOTPLastStep,
		WGHubPrivkey:       state.WGHubPrivkey,
	}
	for _, device := range state.Devices {
		if device.EncKey != "" {
			plain.DeviceEncKeys[device.ID] = device.EncKey
		}
	}

	plainJSON, err := json.Marshal(plain)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plainJSON, []byte(stateEncryptionAAD))

	state.ServerSignPrivkey = ""
	state.AdminPasswordHash = ""
	state.TOTPSecret = ""
	state.TOTPRecoveryHashes = nil
	state.TOTPLastStep = 0
	state.WGHubPrivkey = ""
	for i := range state.Devices {
		state.Devices[i].EncKey = ""
	}
	state.Encrypted = &EncryptedState{
		Version:    stateEncryptionVersion,
		Algorithm:  stateEncryptionAlg,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return nil
}

func (s *StateStore) decryptSensitiveState(state *ServerState) error {
	if state.Encrypted == nil {
		return nil
	}
	if len(s.encryptionKey) == 0 {
		return ErrStateEncryptionKeyRequired
	}
	if state.Encrypted.Version != stateEncryptionVersion || state.Encrypted.Algorithm != stateEncryptionAlg {
		return fmt.Errorf("unsupported encrypted state format")
	}

	nonce, err := base64.StdEncoding.DecodeString(state.Encrypted.Nonce)
	if err != nil {
		return fmt.Errorf("decode encrypted state nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(state.Encrypted.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode encrypted state ciphertext: %w", err)
	}
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plainJSON, err := gcm.Open(nil, nonce, ciphertext, []byte(stateEncryptionAAD))
	if err != nil {
		return fmt.Errorf("decrypt encrypted state: %w", err)
	}

	var plain sensitiveStatePlain
	if err := json.Unmarshal(plainJSON, &plain); err != nil {
		return fmt.Errorf("decode encrypted state payload: %w", err)
	}
	state.ServerSignPrivkey = plain.ServerSignPrivkey
	state.AdminPasswordHash = plain.AdminPasswordHash
	state.TOTPSecret = plain.TOTPSecret
	state.TOTPRecoveryHashes = plain.TOTPRecoveryHashes
	state.TOTPLastStep = plain.TOTPLastStep
	state.WGHubPrivkey = plain.WGHubPrivkey
	for i := range state.Devices {
		if encKey, ok := plain.DeviceEncKeys[state.Devices[i].ID]; ok {
			state.Devices[i].EncKey = encKey
		}
	}
	return nil
}
