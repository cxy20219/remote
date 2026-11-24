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
	"log/slog"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// stateEncryptionVersion 是当前写入的信封格式版本；v2 在 v1 的 GCM
	// 信封上增加 kdf/kdf_params/salt 三个字段，业务 schema 不变。
	stateEncryptionVersion = 2
	// stateEncryptionVersionLegacy 是单次 SHA-256 派生的旧格式，只读兼容。
	stateEncryptionVersionLegacy = 1
	stateEncryptionAlg           = "AES-256-GCM"
	stateEncryptionAAD           = "goremote-server-state-v1"

	stateKDFNone     = "none"
	stateKDFArgon2id = "argon2id-v1"

	stateKDFSaltSize = 16
	// argon2id 参数：64MiB 内存 / 3 轮 / 2 并行。本机约 50ms，1.6GB 的小
	// 机器上估 300-500ms，且只在启动或迁移时算一次，不在请求路径上。
	stateKDFArgon2MemoryKiB   = 64 * 1024
	stateKDFArgon2Iterations  = 3
	stateKDFArgon2Parallelism = 2

	// 读取信封时的参数上限：手改或损坏的文件不能把启动打成 OOM/长跑。
	// 超限直接报错，不做静默降级。
	stateKDFMinMemoryKiB   = 8 * 1024
	stateKDFMaxMemoryKiB   = 256 * 1024
	stateKDFMaxIterations  = 10
	stateKDFMaxParallelism = 16
	stateKDFMaxSaltSize    = 64
)

var ErrStateEncryptionKeyRequired = errors.New("state encryption key is required")

// ErrStateDecryptionFailed 表示「有密钥，但打不开」：密钥不对，或密文被改过。
// 单独一个哨兵，是为了让启动失败能直接告诉运维「是 key 错了」而不是一句
// cipher: message authentication failed。
var ErrStateDecryptionFailed = errors.New("state decryption failed (wrong state key or corrupted ciphertext)")

type EncryptedState struct {
	Version    int             `json:"version"`
	Algorithm  string          `json:"algorithm"`
	KDF        string          `json:"kdf,omitempty"`
	KDFParams  *StateKDFParams `json:"kdf_params,omitempty"`
	Salt       string          `json:"salt,omitempty"`
	Nonce      string          `json:"nonce"`
	Ciphertext string          `json:"ciphertext"`
}

// StateKDFParams 是信封里持久化的 argon2id 参数。写盘时原样写回，读取时按
// 上限校验：每次 Save 重新生成 salt 或改参数都等于换密钥，所以这两件事都
// 必须以文件里的值为准。
type StateKDFParams struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// stateEnvelope 是当前落盘格式所需的全部派生信息：真正用于 AES 的 key，
// 以及写回信封时要带上的 kdf/salt/params。
type stateEnvelope struct {
	version int
	kdf     string
	params  StateKDFParams
	salt    []byte
	key     []byte
}

type sensitiveStatePlain struct {
	ServerSignPrivkey string            `json:"server_sign_privkey"`
	AdminPasswordHash string            `json:"admin_password_hash"`
	DeviceEncKeys     map[string]string `json:"device_enc_keys"`

	// 两步验证密钥与恢复码哈希：与密码 hash 同等级，配置了 state 加密密钥时只存在于密文里。
	TOTPSecret         string   `json:"totp_secret,omitempty"`
	TOTPRecoveryHashes []string `json:"totp_recovery_hashes,omitempty"`
	TOTPLastStep       int64    `json:"totp_last_step,omitempty"`
}

// SetEncryptionKey 只校验并记录原始密钥，不立刻派生：口令模式下 salt 持久化
// 在状态文件的信封里，必须等 Load 读到文件才能确定。全熵密钥（hex:/base64:）
// 的派生是直通，没有这个问题，但统一延迟到 Load/首次写盘，避免两套路径。
//
// 必须在 Load 之前调用。
func (s *StateStore) SetEncryptionKey(rawKey string) error {
	if _, _, err := splitStateKey(rawKey); err != nil {
		return err
	}
	s.rawStateKey = strings.TrimSpace(rawKey)
	return nil
}

// SetStateKDFLegacy 强制只写 v1 信封（单次 SHA-256 派生），用于升级后的
// 一次性回滚。必须在 Load 之前调用。对已经是 v2 的文件会降级重写为 v1。
func (s *StateStore) SetStateKDFLegacy(legacy bool) {
	s.kdfLegacy = legacy
}

// splitStateKey 把配置的密钥拆成两种形态：hex:/base64: 的 32 字节全熵密钥
// 直接使用；其余 ≥32 字符的串视为口令，写入时走 argon2id。
func splitStateKey(rawKey string) (direct []byte, passphrase string, err error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, "", nil
	}
	if strings.HasPrefix(rawKey, "hex:") {
		decoded, err := hex.DecodeString(strings.TrimPrefix(rawKey, "hex:"))
		if err != nil || len(decoded) != 32 {
			return nil, "", fmt.Errorf("state key hex value must decode to 32 bytes")
		}
		return decoded, "", nil
	}
	if strings.HasPrefix(rawKey, "base64:") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rawKey, "base64:"))
		if err != nil || len(decoded) != 32 {
			return nil, "", fmt.Errorf("state key base64 value must decode to 32 bytes")
		}
		return decoded, "", nil
	}
	if len(rawKey) < 32 {
		return nil, "", fmt.Errorf("state key must be at least 32 characters")
	}
	return nil, rawKey, nil
}

// deriveLegacyStateEncryptionKey 是 v1 信封的派生：单次 SHA-256，无 salt。
// 只用于读旧文件、v1 回滚和 v2→v1 降级，新写入不再使用。
func deriveLegacyStateEncryptionKey(rawKey string) ([]byte, error) {
	direct, passphrase, err := splitStateKey(rawKey)
	if err != nil {
		return nil, err
	}
	if direct != nil {
		return direct, nil
	}
	if passphrase == "" {
		return nil, nil
	}
	sum := sha256.Sum256([]byte("goremote-state-key:" + passphrase))
	return sum[:], nil
}

func newDirectEnvelope(key []byte) *stateEnvelope {
	return &stateEnvelope{
		version: stateEncryptionVersion,
		kdf:     stateKDFNone,
		key:     append([]byte(nil), key...),
	}
}

func newPassphraseEnvelope(passphrase string) (*stateEnvelope, error) {
	salt := make([]byte, stateKDFSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	params := StateKDFParams{
		MemoryKiB:   stateKDFArgon2MemoryKiB,
		Iterations:  stateKDFArgon2Iterations,
		Parallelism: stateKDFArgon2Parallelism,
	}
	return &stateEnvelope{
		version: stateEncryptionVersion,
		kdf:     stateKDFArgon2id,
		params:  params,
		salt:    salt,
		key:     deriveArgon2idKey(passphrase, salt, params),
	}, nil
}

func deriveArgon2idKey(passphrase string, salt []byte, params StateKDFParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, params.Iterations, params.MemoryKiB, params.Parallelism, 32)
}

func (p StateKDFParams) validate() error {
	if p.MemoryKiB < stateKDFMinMemoryKiB || p.MemoryKiB > stateKDFMaxMemoryKiB {
		return fmt.Errorf("memory_kib %d outside %d-%d", p.MemoryKiB, stateKDFMinMemoryKiB, stateKDFMaxMemoryKiB)
	}
	if p.Iterations < 1 || p.Iterations > stateKDFMaxIterations {
		return fmt.Errorf("iterations %d outside 1-%d", p.Iterations, stateKDFMaxIterations)
	}
	if p.Parallelism < 1 || p.Parallelism > stateKDFMaxParallelism {
		return fmt.Errorf("parallelism %d outside 1-%d", p.Parallelism, stateKDFMaxParallelism)
	}
	return nil
}

// buildEnvelope 按当前配置生成一个可用于写盘的新信封。
func (s *StateStore) buildEnvelope() (*stateEnvelope, error) {
	direct, passphrase, err := splitStateKey(s.rawStateKey)
	if err != nil {
		return nil, err
	}
	if s.kdfLegacy {
		key, err := deriveLegacyStateEncryptionKey(s.rawStateKey)
		if err != nil {
			return nil, err
		}
		return &stateEnvelope{version: stateEncryptionVersionLegacy, key: key}, nil
	}
	if direct != nil {
		return newDirectEnvelope(direct), nil
	}
	return newPassphraseEnvelope(passphrase)
}

// envelopeFromEncrypted 按 v2 信封里的 kdf/salt/params 重新派生 AES key。
// 信封声明的 kdf 必须与配置的密钥形态匹配，配错直接报错，不猜。
func envelopeFromEncrypted(rawKey string, enc *EncryptedState) (*stateEnvelope, error) {
	direct, passphrase, err := splitStateKey(rawKey)
	if err != nil {
		return nil, err
	}

	switch enc.KDF {
	case stateKDFNone:
		if direct == nil {
			return nil, fmt.Errorf("state file requires a raw 32-byte key (kdf %q) but a passphrase was configured", stateKDFNone)
		}
		return newDirectEnvelope(direct), nil

	case stateKDFArgon2id:
		if direct != nil {
			return nil, fmt.Errorf("state file uses %s but a raw 32-byte key was configured", stateKDFArgon2id)
		}
		params := StateKDFParams{}
		if enc.KDFParams != nil {
			params = *enc.KDFParams
		}
		if err := params.validate(); err != nil {
			return nil, fmt.Errorf("invalid kdf parameters in state file: %w", err)
		}
		salt, err := base64.StdEncoding.DecodeString(enc.Salt)
		if err != nil {
			return nil, fmt.Errorf("decode state kdf salt: %w", err)
		}
		if len(salt) < stateKDFSaltSize || len(salt) > stateKDFMaxSaltSize {
			return nil, fmt.Errorf("state kdf salt must be %d-%d bytes, got %d", stateKDFSaltSize, stateKDFMaxSaltSize, len(salt))
		}
		return &stateEnvelope{
			version: stateEncryptionVersion,
			kdf:     stateKDFArgon2id,
			params:  params,
			salt:    salt,
			key:     deriveArgon2idKey(passphrase, salt, params),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported state kdf %q", enc.KDF)
	}
}

// decryptSensitiveState 解析文件里的 encrypted 信封、准备好 s.envelope，
// 并把敏感字段解密回 state。
//
// v1 文件解密成功后，除非 --state-kdf=legacy，否则准备一个 v2 目标信封放在
// s.pendingEnvelope，由 Load 触发写盘迁移；写盘成功才提交（见 writeState）。
// v2 文件在 --state-kdf=legacy 下反向准备 v1 目标信封，用于回滚旧二进制。
func (s *StateStore) decryptSensitiveState(state *ServerState) error {
	if state.Encrypted == nil {
		if s.rawStateKey == "" {
			return nil
		}
		envelope, err := s.buildEnvelope()
		if err != nil {
			return err
		}
		s.envelope = envelope
		return nil
	}

	enc := state.Encrypted
	if enc.Algorithm != stateEncryptionAlg {
		return fmt.Errorf("unsupported encrypted state format")
	}

	switch enc.Version {
	case stateEncryptionVersionLegacy:
		if s.rawStateKey == "" {
			return ErrStateEncryptionKeyRequired
		}
		legacyKey, err := deriveLegacyStateEncryptionKey(s.rawStateKey)
		if err != nil {
			return err
		}
		if len(legacyKey) == 0 {
			return ErrStateEncryptionKeyRequired
		}
		s.envelope = &stateEnvelope{version: stateEncryptionVersionLegacy, key: legacyKey}
		if err := openEncryptedPayload(state, legacyKey, enc); err != nil {
			return fmt.Errorf("%w: %v", ErrStateDecryptionFailed, err)
		}
		if s.kdfLegacy {
			return nil
		}
		// 解密成功之后才准备迁移信封；写盘失败时 Load 继续启动，
		// 文件保持 v1，下次 Save 再试。
		pending, err := s.buildEnvelope()
		if err != nil {
			return err
		}
		s.pendingEnvelope = pending
		return nil

	case stateEncryptionVersion:
		if s.rawStateKey == "" {
			return ErrStateEncryptionKeyRequired
		}
		envelope, err := envelopeFromEncrypted(s.rawStateKey, enc)
		if err != nil {
			return err
		}
		s.envelope = envelope
		if err := openEncryptedPayload(state, envelope.key, enc); err != nil {
			return fmt.Errorf("%w: %v", ErrStateDecryptionFailed, err)
		}
		if s.kdfLegacy {
			// 显式回滚：把 v2 降级回 v1，旧二进制才能读。这是一次安全性
			// 降级，必须让操作者在日志里看见。
			slog.Warn("--state-kdf=legacy is downgrading the encrypted state file to the legacy v1 format; passphrase-derived keys fall back to a single SHA-256")
			pending, err := s.buildEnvelope()
			if err != nil {
				return err
			}
			s.pendingEnvelope = pending
		}
		return nil

	default:
		return fmt.Errorf("unsupported encrypted state format")
	}
}

func openEncryptedPayload(state *ServerState, key []byte, enc *EncryptedState) error {
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return fmt.Errorf("decode encrypted state nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode encrypted state ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
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
	for i := range state.Devices {
		if encKey, ok := plain.DeviceEncKeys[state.Devices[i].ID]; ok {
			state.Devices[i].EncKey = encKey
		}
	}
	return nil
}

// encryptSensitiveState 用当前信封（有迁移目标时用目标信封）加密敏感字段，
// 并把信封的 kdf/salt/params 原样写回。每次 Save 复用同一 salt/params，只换
// nonce——换 salt 等于换密钥。
func (s *StateStore) encryptSensitiveState(state *ServerState) error {
	envelope := s.envelope
	if s.pendingEnvelope != nil {
		envelope = s.pendingEnvelope
	}
	if envelope == nil {
		if s.rawStateKey != "" {
			return fmt.Errorf("state encryption envelope is not initialized")
		}
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
	block, err := aes.NewCipher(envelope.key)
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
	for i := range state.Devices {
		state.Devices[i].EncKey = ""
	}

	encrypted := &EncryptedState{
		Version:    envelope.version,
		Algorithm:  stateEncryptionAlg,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if envelope.version >= stateEncryptionVersion {
		encrypted.KDF = envelope.kdf
		if envelope.kdf == stateKDFArgon2id {
			params := envelope.params
			encrypted.KDFParams = &params
			encrypted.Salt = base64.StdEncoding.EncodeToString(envelope.salt)
		}
	}
	state.Encrypted = encrypted
	return nil
}
