package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

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

// 测试钩子：注入 fsync 失败，验证失败路径不会留下半截文件、也不会破坏
// 已经存在的 identity。
var (
	syncIdentityFile = func(f *os.File) error { return f.Sync() }
	syncIdentityDir  = func(f *os.File) error { return f.Sync() }
)

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

	// 与 server 的 StateStore 同一套原子落盘语义：写 tmp → fsync → rename →
	// fsync 目录。identity 里是设备私钥和 ClientID，掉电丢一半就要求重新审批。
	path := filepath.Join(dir, "identity")
	tmp := path + ".tmp"

	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create identity temp file: %w", err)
	}
	discard := func(err error) error {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := file.Write(data); err != nil {
		return discard(fmt.Errorf("write identity: %w", err))
	}
	// 残留的 .tmp 可能带着旧权限，OpenFile 的 0600 只在创建时生效。
	if err := file.Chmod(0o600); err != nil {
		return discard(fmt.Errorf("chmod identity temp file: %w", err))
	}
	if err := syncIdentityFile(file); err != nil {
		return discard(fmt.Errorf("sync identity: %w", err))
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close identity temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename identity: %w", err)
	}

	// rename 已经生效，身份文件对进程重启可见。目录 fsync 只影响「掉电后
	// rename 还在不在」：Windows 上对目录 Sync 不可用，按平台跳过；其他平台
	// 失败也只记日志、不返回错误——不能让调用方以为身份没写进去。
	if runtime.GOOS != "windows" {
		if dirFile, openErr := os.Open(dir); openErr == nil {
			if syncErr := syncIdentityDir(dirFile); syncErr != nil {
				slog.Debug("identity file renamed but the directory could not be synced; durable across process restarts, power loss may roll back",
					"dir", dir, "error", syncErr)
			}
			dirFile.Close()
		}
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
