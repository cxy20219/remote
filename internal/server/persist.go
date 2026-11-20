package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"goremote/internal/common"
)

const (
	stateSyncInterval = 3 * time.Second
	adminPasswordSize = 18 // bytes; base64url yields 24 characters
)

type ServerSettings struct {
	PortRangeStart      int      `json:"port_range_start"`
	PortRangeEnd        int      `json:"port_range_end"`
	MaxTunnelsPerClient int      `json:"max_tunnels_per_client"`
	DefaultLocalAddr    string   `json:"default_local_addr"`
	PublicHost          string   `json:"public_host"`
	MaxConnPerMin       int      `json:"max_conn_per_min"`
	LoginRateLimit      int      `json:"login_rate_limit"`
	BlacklistThreshold  int      `json:"blacklist_threshold"`
	GlobalWhitelist     []string `json:"global_whitelist"`
	MaxBodySizeMB       int      `json:"max_body_size_mb"`
	HeartbeatInterval   int      `json:"heartbeat_interval"`
	HeartbeatTimeout    int      `json:"heartbeat_timeout"`
}

type DeviceState struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	DeviceSignPubkey string     `json:"device_sign_pubkey"`
	DeviceDHPubkey   string     `json:"device_dh_pubkey"`
	Hostname         string     `json:"hostname"`
	OS               string     `json:"os"`
	Status           string     `json:"status"`
	EncKey           string     `json:"enc_key"`
	EncEnabled       bool       `json:"enc_enabled"`
	IPWhitelist      []string   `json:"ip_whitelist"`
	FirstSeen        time.Time  `json:"first_seen"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
}

type ServerState struct {
	ServerSignPrivkey string          `json:"server_sign_privkey"`
	ServerSignPubkey  string          `json:"server_sign_pubkey"`
	AdminPasswordHash string          `json:"admin_password_hash"`
	Settings          ServerSettings  `json:"settings"`
	Devices           []DeviceState   `json:"devices"`
	Encrypted         *EncryptedState `json:"encrypted,omitempty"`

	// 管理员两步验证（TOTP）。配置了 state 加密密钥时，这三项会被搬进
	// Encrypted 密文并在明文层置空；未配置密钥时以明文落盘（文件权限 0600），
	// 启动时会打告警。旧 state 文件没有这些字段，零值即「未启用」。
	TOTPSecret         string   `json:"totp_secret,omitempty"`
	TOTPRecoveryHashes []string `json:"totp_recovery_hashes,omitempty"`
	TOTPLastStep       int64    `json:"totp_last_step,omitempty"`
}

func defaultSettings() ServerSettings {
	return ServerSettings{
		PortRangeStart:      10000,
		PortRangeEnd:        20000,
		MaxTunnelsPerClient: 10,
		DefaultLocalAddr:    "127.0.0.1",
		MaxConnPerMin:       10,
		LoginRateLimit:      5,
		BlacklistThreshold:  100,
		GlobalWhitelist:     []string{},
		MaxBodySizeMB:       defaultMaxBodySizeMB,
		HeartbeatInterval:   30,
		HeartbeatTimeout:    90,
	}
}

// normalizeSettings repairs out-of-range persisted values while preserving
// explicit zero values that disable a limit.
func normalizeSettings(settings ServerSettings) ServerSettings {
	defaults := defaultSettings()

	if settings.PortRangeStart < 1 || settings.PortRangeStart > 65535 {
		settings.PortRangeStart = defaults.PortRangeStart
	}
	if settings.PortRangeEnd < 1 || settings.PortRangeEnd > 65535 {
		settings.PortRangeEnd = defaults.PortRangeEnd
	}
	if settings.PortRangeStart > settings.PortRangeEnd {
		settings.PortRangeStart = defaults.PortRangeStart
		settings.PortRangeEnd = defaults.PortRangeEnd
	}
	if settings.MaxTunnelsPerClient < 0 {
		settings.MaxTunnelsPerClient = 0
	}
	if settings.MaxTunnelsPerClient > 10000 {
		settings.MaxTunnelsPerClient = 10000
	}
	if settings.DefaultLocalAddr == "" {
		settings.DefaultLocalAddr = defaults.DefaultLocalAddr
	}
	if settings.MaxConnPerMin < 0 {
		settings.MaxConnPerMin = 0
	}
	if settings.MaxConnPerMin > 1000000 {
		settings.MaxConnPerMin = 1000000
	}
	if settings.LoginRateLimit < 0 {
		settings.LoginRateLimit = 0
	}
	if settings.LoginRateLimit > 1000000 {
		settings.LoginRateLimit = 1000000
	}
	if settings.BlacklistThreshold < 0 {
		settings.BlacklistThreshold = 0
	}
	if settings.BlacklistThreshold > 1000000 {
		settings.BlacklistThreshold = 1000000
	}
	if settings.GlobalWhitelist == nil {
		settings.GlobalWhitelist = []string{}
	}
	if settings.MaxBodySizeMB < 0 {
		settings.MaxBodySizeMB = 0
	}
	if settings.MaxBodySizeMB > 1024 {
		settings.MaxBodySizeMB = 1024
	}
	if settings.HeartbeatInterval < 1 || settings.HeartbeatInterval > 86400 {
		settings.HeartbeatInterval = defaults.HeartbeatInterval
	}
	if settings.HeartbeatTimeout < 1 || settings.HeartbeatTimeout > 86400 {
		settings.HeartbeatTimeout = defaults.HeartbeatTimeout
	}
	return settings
}

func cloneSettings(settings ServerSettings) ServerSettings {
	cloned := settings
	if settings.GlobalWhitelist != nil {
		cloned.GlobalWhitelist = append([]string(nil), settings.GlobalWhitelist...)
	}
	return cloned
}

func cloneDevice(device DeviceState) DeviceState {
	cloned := device
	if device.IPWhitelist != nil {
		cloned.IPWhitelist = append([]string(nil), device.IPWhitelist...)
	}
	if device.ApprovedAt != nil {
		approvedAt := *device.ApprovedAt
		cloned.ApprovedAt = &approvedAt
	}
	return cloned
}

func cloneServerState(state *ServerState) ServerState {
	if state == nil {
		return ServerState{}
	}

	cloned := *state
	cloned.Settings = cloneSettings(state.Settings)
	if state.Devices != nil {
		cloned.Devices = make([]DeviceState, len(state.Devices))
		for i := range state.Devices {
			cloned.Devices[i] = cloneDevice(state.Devices[i])
		}
	}
	if state.Encrypted != nil {
		encrypted := *state.Encrypted
		cloned.Encrypted = &encrypted
	}
	if state.TOTPRecoveryHashes != nil {
		cloned.TOTPRecoveryHashes = append([]string(nil), state.TOTPRecoveryHashes...)
	}
	return cloned
}

type StateStore struct {
	mu            sync.RWMutex
	saveMu        sync.Mutex
	state         *ServerState
	deviceIndex   map[string]int
	path          string
	encryptionKey []byte
	dirty         bool
	stopCh        chan struct{}
	stopOnce      sync.Once
	startOnce     sync.Once
	wg            sync.WaitGroup
}

func NewStateStore(path string) *StateStore {
	return &StateStore{
		path:        path,
		stopCh:      make(chan struct{}),
		deviceIndex: make(map[string]int),
		state: &ServerState{
			Settings: defaultSettings(),
			Devices:  []DeviceState{},
		},
	}
}

func (s *StateStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.initNew()
		}
		return err
	}

	state := ServerState{
		Settings: defaultSettings(),
		Devices:  []DeviceState{},
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if state.Devices == nil {
		state.Devices = []DeviceState{}
	}
	var legacy struct {
		AdminPasswordPlain string `json:"admin_password_plain"`
	}
	_ = json.Unmarshal(data, &legacy)
	wasPlaintext := state.Encrypted == nil
	if err := s.decryptSensitiveState(&state); err != nil {
		return err
	}
	state.Settings = normalizeSettings(state.Settings)

	s.state = &state
	s.rebuildDeviceIndexLocked()
	if (len(s.encryptionKey) > 0 && wasPlaintext) || legacy.AdminPasswordPlain != "" {
		if err := s.writeState(cloneServerState(&state)); err != nil {
			return err
		}
	}
	slog.Info("server state loaded", "path", s.path, "devices", len(state.Devices))
	return nil
}

func (s *StateStore) initNew() error {
	pubKey, privKey, err := common.GenerateSignKeypair()
	if err != nil {
		return err
	}

	password, err := generateAdminPassword()
	if err != nil {
		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.state = &ServerState{
		ServerSignPrivkey: hex.EncodeToString(privKey),
		ServerSignPubkey:  hex.EncodeToString(pubKey),
		AdminPasswordHash: string(hashedPassword),
		Settings:          defaultSettings(),
		Devices:           []DeviceState{},
	}

	if err := s.writeState(cloneServerState(s.state)); err != nil {
		return err
	}

	slog.Info("========================================")
	slog.Info("Generated admin credentials")
	slog.Info("Admin password (first run only)", "password", password)
	slog.Info("========================================")
	return nil
}

func generateAdminPassword() (string, error) {
	raw := make([]byte, adminPasswordSize)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate admin password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Save writes the current state synchronously.
func (s *StateStore) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	snapshot := cloneServerState(s.state)
	s.dirty = false
	s.mu.Unlock()

	if err := s.writeState(snapshot); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *StateStore) writeState(state ServerState) error {
	if s.path == "" {
		return nil
	}
	if err := s.encryptSensitiveState(&state); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmp, s.path)
}

func (s *StateStore) StartSyncLoop() {
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go s.syncLoop()
	})
}

func (s *StateStore) syncLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(stateSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.flushDirty(); err != nil {
				slog.Error("failed to save state", "error", err)
			}
		case <-s.stopCh:
			if err := s.flushDirty(); err != nil {
				slog.Error("failed to save state on shutdown", "error", err)
			}
			return
		}
	}
}

func (s *StateStore) flushDirty() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	s.dirty = false
	snapshot := cloneServerState(s.state)
	s.mu.Unlock()

	if err := s.writeState(snapshot); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *StateStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

func (s *StateStore) GetSettings() ServerSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSettings(s.state.Settings)
}

func (s *StateStore) UpdateSettings(fn func(*ServerSettings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state.Settings)
	s.dirty = true
}

func (s *StateStore) rebuildDeviceIndexLocked() {
	s.deviceIndex = make(map[string]int, len(s.state.Devices))
	for i := range s.state.Devices {
		s.deviceIndex[s.state.Devices[i].ID] = i
	}
}

func (s *StateStore) GetDeviceByID(id string) *DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index, ok := s.deviceIndex[id]; ok && index < len(s.state.Devices) && s.state.Devices[index].ID == id {
		device := cloneDevice(s.state.Devices[index])
		return &device
	}
	// Fallback for stores constructed directly (tests) or after manual edits.
	for i := range s.state.Devices {
		if s.state.Devices[i].ID == id {
			device := cloneDevice(s.state.Devices[i])
			return &device
		}
	}
	return nil
}

func (s *StateStore) GetDeviceBySignPubkey(pubkey, status string) *DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.state.Devices {
		if s.state.Devices[i].DeviceSignPubkey == pubkey && s.state.Devices[i].Status == status {
			device := cloneDevice(s.state.Devices[i])
			return &device
		}
	}
	return nil
}

func (s *StateStore) CountDevicesByStatus(status string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for i := range s.state.Devices {
		if s.state.Devices[i].Status == status {
			count++
		}
	}
	return count
}

// AnyDeviceMatches scans devices under the read lock. The callback must not
// retain or mutate the device pointer.
func (s *StateStore) AnyDeviceMatches(match func(*DeviceState) bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.state.Devices {
		if match(&s.state.Devices[i]) {
			return true
		}
	}
	return false
}

func (s *StateStore) GetDevicesByStatus(status string) []DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []DeviceState
	for _, d := range s.state.Devices {
		if d.Status == status {
			result = append(result, cloneDevice(d))
		}
	}
	return result
}

func (s *StateStore) GetAllDevices() []DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]DeviceState, len(s.state.Devices))
	for i := range s.state.Devices {
		result[i] = cloneDevice(s.state.Devices[i])
	}
	return result
}

func (s *StateStore) AddDevice(device *DeviceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deviceIndex == nil {
		s.rebuildDeviceIndexLocked()
	}
	s.deviceIndex[device.ID] = len(s.state.Devices)
	s.state.Devices = append(s.state.Devices, *device)
	s.dirty = true
}

func (s *StateStore) UpdateDevice(id string, fn func(*DeviceState)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Devices {
		if s.state.Devices[i].ID == id {
			fn(&s.state.Devices[i])
			s.dirty = true
			return true
		}
	}
	return false
}

func (s *StateStore) RemoveDevice(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deviceIndex == nil {
		s.rebuildDeviceIndexLocked()
	}
	for i, d := range s.state.Devices {
		if d.ID == id {
			s.state.Devices = append(s.state.Devices[:i], s.state.Devices[i+1:]...)
			delete(s.deviceIndex, id)
			for j := i; j < len(s.state.Devices); j++ {
				s.deviceIndex[s.state.Devices[j].ID] = j
			}
			s.dirty = true
			return true
		}
	}
	return false
}

func (s *StateStore) GetServerSignPrivkey() ed25519.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := hex.DecodeString(s.state.ServerSignPrivkey)
	return ed25519.PrivateKey(b)
}

func (s *StateStore) GetServerSignPubkey() ed25519.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := hex.DecodeString(s.state.ServerSignPubkey)
	return ed25519.PublicKey(b)
}

func (s *StateStore) VerifyAdminPassword(password string) bool {
	s.mu.RLock()
	hash := s.state.AdminPasswordHash
	s.mu.RUnlock()
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// TOTPConfig 是管理员两步验证的持久化配置快照。
type TOTPConfig struct {
	Secret         string
	RecoveryHashes []string
	LastStep       int64
}

// Enabled 表示管理员已启用 TOTP。
func (c TOTPConfig) Enabled() bool { return c.Secret != "" }

// TOTPConfig 返回当前配置的副本。
func (s *StateStore) TOTPConfig() TOTPConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return TOTPConfig{
		Secret:         s.state.TOTPSecret,
		RecoveryHashes: append([]string(nil), s.state.TOTPRecoveryHashes...),
		LastStep:       s.state.TOTPLastStep,
	}
}

// SetTOTPConfig 整块替换两步验证配置并同步落盘。
// 只允许「启用」和「关闭」这种整块语义使用；恢复码消费与时间步推进必须走
// ConsumeTOTPRecoveryCode / CompareAndSwapTOTPLastStep，否则并发下会互相回滚。
func (s *StateStore) SetTOTPConfig(cfg TOTPConfig) error {
	hashes := make([]string, len(cfg.RecoveryHashes))
	copy(hashes, cfg.RecoveryHashes)

	s.mu.Lock()
	s.state.TOTPSecret = cfg.Secret
	s.state.TOTPRecoveryHashes = hashes
	s.state.TOTPLastStep = cfg.LastStep
	s.dirty = true
	s.mu.Unlock()
	return s.Save()
}

// TOTPLastStep 返回最后接受的时间步（防重放）。
func (s *StateStore) TOTPLastStep() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.TOTPLastStep
}

// CompareAndSwapTOTPLastStep 仅当当前值仍等于 oldStep 且 newStep > oldStep 时推进，
// 返回是否成功。并发下同一个码只能有一个调用者推进成功。
func (s *StateStore) CompareAndSwapTOTPLastStep(oldStep, newStep int64) bool {
	if newStep <= oldStep {
		return false
	}
	s.mu.Lock()
	if s.state.TOTPLastStep != oldStep {
		s.mu.Unlock()
		return false
	}
	s.state.TOTPLastStep = newStep
	s.dirty = true
	s.mu.Unlock()
	return true
}

// ConsumeTOTPRecoveryCode 原子消费一个恢复码哈希：命中则移除并返回剩余数量。
// 并发下同一个恢复码只会有一次 ok=true。比较始终遍历全表，避免提前返回泄漏位置。
func (s *StateStore) ConsumeTOTPRecoveryCode(hash string) (remaining int, consumed bool, err error) {
	target := []byte(hash)
	s.mu.Lock()
	idx := -1
	for i, candidate := range s.state.TOTPRecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(candidate), target) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		n := len(s.state.TOTPRecoveryHashes)
		s.mu.Unlock()
		return n, false, nil
	}
	next := make([]string, 0, len(s.state.TOTPRecoveryHashes)-1)
	next = append(next, s.state.TOTPRecoveryHashes[:idx]...)
	next = append(next, s.state.TOTPRecoveryHashes[idx+1:]...)
	s.state.TOTPRecoveryHashes = next
	s.dirty = true
	remaining = len(next)
	s.mu.Unlock()
	if err := s.Save(); err != nil {
		return remaining, true, err
	}
	return remaining, true, nil
}

// EncryptionEnabled 表示 state 敏感字段是否走 AES-256-GCM 加密区。
func (s *StateStore) EncryptionEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.encryptionKey) > 0
}

func (s *StateStore) SetAdminPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.state.AdminPasswordHash = string(hashedPassword)
	s.dirty = true
	s.mu.Unlock()
	return s.Save()
}
