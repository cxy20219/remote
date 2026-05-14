package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"goremote/internal/common"
)

type AgentIdentity struct {
	ServerURL         string `json:"server_url"`
	ClientID          string `json:"client_id,omitempty"`
	DeviceSignPrivkey string `json:"device_sign_privkey"`
	DeviceSignPubkey  string `json:"device_sign_pubkey"`
	DeviceDHPrivkey   string `json:"device_dh_privkey,omitempty"`
	DeviceDHPubkey    string `json:"device_dh_pubkey,omitempty"`
	EncKey            string `json:"enc_key,omitempty"`
	EncEnabled        bool   `json:"enc_enabled,omitempty"`
	ServerSignPubkey  string `json:"server_sign_pubkey,omitempty"`
}

func defaultIdentityDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".goremote")
}

func LoadIdentity(dir string) (*AgentIdentity, error) {
	if dir == "" {
		dir = defaultIdentityDir()
	}
	path := filepath.Join(dir, "identity")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read identity: %w", err)
	}

	var id AgentIdentity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	return &id, nil
}

func CreateIdentity(dir string, serverURL string) (*AgentIdentity, error) {
	if dir == "" {
		dir = defaultIdentityDir()
	}

	signPubKey, signPrivKey, err := common.GenerateSignKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate sign keypair: %w", err)
	}

	dhPrivKey, dhPubKey, err := common.GenerateDHKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate DH keypair: %w", err)
	}

	id := &AgentIdentity{
		ServerURL:         serverURL,
		DeviceSignPrivkey: common.EncodePrivateKey(signPrivKey),
		DeviceSignPubkey:  common.EncodePublicKey(signPubKey),
		DeviceDHPrivkey:   common.EncodeBytes(dhPrivKey[:]),
		DeviceDHPubkey:    common.EncodeBytes(dhPubKey[:]),
	}

	if err := id.Save(dir); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}

	slog.Info("new identity created", "dir", dir)
	return id, nil
}

func (id *AgentIdentity) Save(dir string) error {
	if dir == "" {
		dir = defaultIdentityDir()
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	path := filepath.Join(dir, "identity")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename identity: %w", err)
	}

	return nil
}

func (id *AgentIdentity) GetSignPrivKey() (ed25519.PrivateKey, error) {
	b, err := common.DecodePrivateKey(id.DeviceSignPrivkey)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(b), nil
}

func (id *AgentIdentity) GetSignPubKey() (ed25519.PublicKey, error) {
	b, err := common.DecodePublicKey(id.DeviceSignPubkey)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

func (id *AgentIdentity) GetDHPrivKey() (*[32]byte, error) {
	b, err := common.DecodeBytes(id.DeviceDHPrivkey)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid DH private key size: %d", len(b))
	}
	var key [32]byte
	copy(key[:], b)
	return &key, nil
}

func (id *AgentIdentity) GetDHPubKey() (*[32]byte, error) {
	b, err := common.DecodeBytes(id.DeviceDHPubkey)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid DH public key size: %d", len(b))
	}
	var key [32]byte
	copy(key[:], b)
	return &key, nil
}

func (id *AgentIdentity) DecryptEncKey(encKeyEncrypted, serverDHPubkeyHex string) ([]byte, error) {
	dhPrivKey, err := id.GetDHPrivKey()
	if err != nil {
		return nil, fmt.Errorf("get DH private key: %w", err)
	}

	serverDHPubkeyBytes, err := common.DecodeBytes(serverDHPubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode server DH pubkey: %w", err)
	}
	if len(serverDHPubkeyBytes) != 32 {
		return nil, fmt.Errorf("invalid server DH public key size: %d", len(serverDHPubkeyBytes))
	}
	var serverDHPub [32]byte
	copy(serverDHPub[:], serverDHPubkeyBytes)

	sharedSecret, err := common.DHSharedSecret(dhPrivKey, &serverDHPub)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	encKey, err := common.DecryptKeyWithSharedSecret(encKeyEncrypted, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt enc_key: %w", err)
	}

	return encKey, nil
}