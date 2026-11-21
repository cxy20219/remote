package server

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"goremote/internal/common"
)

const stateSyncInterval = 3 * time.Second

// errDevicePersist 标记「设备内存状态已经改好，但落盘失败」。API 层据此
// 返回 500：磁盘故障不是客户端错误。
var errDevicePersist = errors.New("device state could not be persisted")

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

// TunnelState 是隧道的持久化定义。只含定义字段：运行时绑定（Client、
// listener）、派生的 bind_addr 与 status/last_error 都不落盘。
type TunnelState struct {
	TunnelID   string    `json:"tunnel_id"`
	ClientID   string    `json:"client_id"`
	Protocol   string    `json:"protocol"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  int       `json:"local_port"`
	PublicPort int       `json:"public_port"`
	Exposure   string    `json:"exposure"`
	CreatedAt  time.Time `json:"created_at"`
}

type ServerState struct {
	ServerSignPrivkey string          `json:"server_sign_privkey"`
	ServerSignPubkey  string          `json:"server_sign_pubkey"`
	AdminPasswordHash string          `json:"admin_password_hash"`
	Settings          ServerSettings  `json:"settings"`
	Devices           []DeviceState   `json:"devices"`
	Tunnels           []TunnelState   `json:"tunnels,omitempty"`
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
		BlacklistThreshold:  10,
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
	if state.Tunnels != nil {
		cloned.Tunnels = append([]TunnelState(nil), state.Tunnels...)
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

	// 首次启动不生成管理员密码：AdminPasswordHash 留空即「未初始化」，
	// 由初始化向导通过 POST /api/setup/password 设置。绝不在日志里打印任何凭据。
	s.state = &ServerState{
		ServerSignPrivkey: hex.EncodeToString(privKey),
		ServerSignPubkey:  hex.EncodeToString(pubKey),
		Settings:          defaultSettings(),
		Devices:           []DeviceState{},
	}

	if err := s.writeState(cloneServerState(s.state)); err != nil {
		return err
	}
	return nil
}

// AdminPasswordInitialized 报告管理员密码是否已设置；false 表示首次初始化未完成。
func (s *StateStore) AdminPasswordInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state != nil && s.state.AdminPasswordHash != ""
}

// SetInitialAdminPassword 仅在尚未设置管理员密码时写入首个密码。
// 密码 hash 在锁外计算（bcrypt 慢），空值检查在锁内二次确认，
// 保证并发 setup 请求只有一个能成功；返回 false 表示已被别人初始化。
// Save 失败时必须回滚内存，否则进程内「已初始化」而磁盘仍为空，
// 重启后又回到向导，管理员会以为密码设置成功过。
func (s *StateStore) SetInitialAdminPassword(password string) (bool, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	if s.state.AdminPasswordHash != "" {
		s.mu.Unlock()
		return false, nil
	}
	s.state.AdminPasswordHash = string(hash)
	s.dirty = true
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.mu.Lock()
		if s.state.AdminPasswordHash == string(hash) {
			s.state.AdminPasswordHash = ""
			s.dirty = true
		}
		s.mu.Unlock()
		return true, err
	}
	return true, nil
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

// syncDir 把 rename 落进目录项。单独抽出来是为了让测试能注入失败；生产
// 实现就是 f.Sync()。
var syncDir = func(f *os.File) error { return f.Sync() }

// writeState 原子落盘：写 tmp → fsync → rename → fsync 目录。
//
// rename 成功即视为落盘成功：磁盘上的 state 已换成新内容，进程重启一定
// 读到它。rename 之后目录 fsync 失败只影响“掉电后 rename 还在不在”，这种情况
// 只记 WARN，不回滚内存、也不返回错误——否则会出现“接口报 500、磁盘却是
// 新内容，重启后改动又生效”的自相矛盾。返回错误只可能是 rename 之前失败
// （写 tmp / chmod / file.Sync / rename 本身），那时磁盘仍是旧内容。
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	discard := func(err error) error {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := file.Write(data); err != nil {
		return discard(err)
	}
	// OpenFile 的权限只在创建时生效，残留的 .tmp 可能带着旧权限。
	if err := file.Chmod(0o600); err != nil {
		return discard(err)
	}
	if err := file.Sync(); err != nil {
		return discard(err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	// rename 已经生效：从这里开始磁盘就是新内容了。目录 fsync 只是让这次
	// rename 也扛住掉电，失败不上报、不回滚。
	dirFile, err := os.Open(dir)
	if err != nil {
		slog.Warn("state file renamed but the directory could not be opened for fsync; durable across process restarts, power loss may roll back",
			"dir", dir, "error", err)
		return nil
	}
	syncErr := syncDir(dirFile)
	dirFile.Close()
	if syncErr != nil {
		slog.Warn("state file renamed but the directory could not be synced; durable across process restarts, power loss may roll back",
			"dir", dir, "error", syncErr)
	}
	return nil
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

// RemoveDevice 删除设备并同步落盘：删除后 3 秒内崩溃不能让设备复活，所以
// 返回前必须完成 Save。保存失败时把设备放回列表并返回错误。
func (s *StateStore) RemoveDevice(id string) (bool, error) {
	removed, device := s.takeDeviceLocked(id)
	if !removed {
		return false, nil
	}
	if err := s.Save(); err != nil {
		s.restoreRemovedDevice(device)
		return true, fmt.Errorf("%w: %v", errDevicePersist, err)
	}
	return true, nil
}

// takeDeviceLocked 把设备从内存列表摘掉。用 defer 解锁：这段里任何 panic
// 都不能把 s.mu 永久带走（整个 StateStore 会随之失去响应）。
func (s *StateStore) takeDeviceLocked(id string) (bool, DeviceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deviceIndex == nil {
		s.rebuildDeviceIndexLocked()
	}
	for i, d := range s.state.Devices {
		if d.ID != id {
			continue
		}
		s.state.Devices = append(s.state.Devices[:i], s.state.Devices[i+1:]...)
		delete(s.deviceIndex, id)
		for j := i; j < len(s.state.Devices); j++ {
			s.deviceIndex[s.state.Devices[j].ID] = j
		}
		s.dirty = true
		return true, d
	}
	return false, DeviceState{}
}

// restoreRemovedDevice 把 Save 失败的设备放回列表。删除与回滚之间可能有
// 并发的删除/新增，删除时记下的下标已经不可信（往更短的切片里插会 panic，
// 而 panic 发生在持锁区间会把整个 StateStore 锁死），所以这里按 ID 确认
// 设备确实缺席后再追加。列表顺序不是 state 的语义，追加是安全的。
func (s *StateStore) restoreRemovedDevice(device DeviceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.state.Devices {
		if d.ID == device.ID {
			return
		}
	}
	s.state.Devices = append(s.state.Devices, device)
	s.rebuildDeviceIndexLocked()
	s.dirty = true
}

// GetTunnels 返回持久化的隧道定义副本。
func (s *StateStore) GetTunnels() []TunnelState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.Tunnels == nil {
		return nil
	}
	return append([]TunnelState(nil), s.state.Tunnels...)
}

// ReplaceTunnels 用给定定义替换持久层并同步落盘。保存失败时恢复旧列表，让
// 调用方的内存回滚与磁盘保持一致。
func (s *StateStore) ReplaceTunnels(tunnels []TunnelState) error {
	s.mu.Lock()
	previous := s.state.Tunnels
	s.state.Tunnels = append([]TunnelState(nil), tunnels...)
	s.dirty = true
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.mu.Lock()
		s.state.Tunnels = previous
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
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
