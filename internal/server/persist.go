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
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"goremote/internal/common"
)

const stateSyncInterval = 3 * time.Second

// stateSchemaVersion 是 ServerState 业务结构的 schema 版本：字段改名、删除或
// 语义变化时 +1，并补一步迁移。它与 encrypted.version（加密信封格式）是两套
// 独立的版本空间，不要合并成一个数字。
//
// 0 表示「未版本化的历史格式」，不是第 0 版格式：本轮之前写出的文件都没有
// schema_version 字段。把它与 1 分开，将来才能区分「v1 有 bug」和「没有标记」。
const stateSchemaVersion = 1

// 断线留痕：每设备只保留最近 deviceDisconnectHistoryLimit 条记录，面板的
// disconnects_24h 由这些记录现算，不另存计数（避免计数与记录对不上）。
const (
	deviceDisconnectHistoryLimit = 50
	deviceDisconnectWindow       = 24 * time.Hour
)

// lastSeenPersistInterval 是 last_seen 落盘的最粗粒度。心跳本身只有 30 秒一次，
// 但设备多起来后「每次心跳都标脏」会把全量写盘推到 3 秒一次的频率（同步循环的
// 上限）。内存里始终是最新值，落盘最多丢 1 分钟精度，够面板显示。
const lastSeenPersistInterval = time.Minute

// persistStaleThreshold 是「有未落盘的改动、但超过这么久还没写成功」的判定线，
// /health 据此把状态标成 degraded。
const persistStaleThreshold = 30 * time.Second

// 断线原因。取值是面板契约，不要改：server_shutdown 让「发版重启」与真正的
// 网络故障（read_timeout / heartbeat_timeout）在面板上可区分。
//
// 没有 write_error：服务端写失败最终都表现为读循环超时退出，硬造一个永远不会
// 出现的取值只会让契约说谎。
const (
	disconnectReasonReadTimeout      = "read_timeout"
	disconnectReasonHeartbeatTimeout = "heartbeat_timeout"
	disconnectReasonServerShutdown   = "server_shutdown"
	disconnectReasonUnknown          = "unknown"
)

// ErrStateTooNew 表示状态文件的 schema 比当前二进制新。必须在解密、迁移、
// 写盘之前就拒绝：老二进制读到新文件时，不认识的字段在反序列化阶段就已经丢了，
// 再 Save 一次会把它们永久删掉——这是最典型的静默数据丢失。
var ErrStateTooNew = errors.New("state file schema is newer than this binary")

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

	// 断线留痕。LastSeen 在心跳时更新（掉线后就停在这一刻），DisconnectHistory
	// 只保留最近 deviceDisconnectHistoryLimit 条，Disconnects24h 不落盘、由 API
	// 现算。这几项加进来时零值可用，所以不升 schema 版本。
	LastSeen             *time.Time         `json:"last_seen,omitempty"`
	LastDisconnectAt     *time.Time         `json:"last_disconnect_at,omitempty"`
	LastDisconnectReason string             `json:"last_disconnect_reason,omitempty"`
	DisconnectHistory    []DeviceDisconnect `json:"disconnect_history,omitempty"`
}

// DeviceDisconnect 是一次断线留痕。
type DeviceDisconnect struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
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

	// LastDisconnectAt 是这条隧道最近一次断开（设备掉线或服务端关闭）的时刻。
	// 它落盘：重启后面板仍能看到「上次断开是什么时候」，否则每次发版都会把它
	// 清空，正好丢掉我们想观察的那次断线。
	LastDisconnectAt *time.Time `json:"last_disconnect_at,omitempty"`
}

type ServerState struct {
	// SchemaVersion 在明文区：版本必须在解密之前可读（否则「文件太新」要等
	// 密钥配对才知道），而且它是兼容标记，不是秘密。JSON 里排最前便于人工查看。
	SchemaVersion     int             `json:"schema_version,omitempty"`
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
	if device.LastSeen != nil {
		lastSeen := *device.LastSeen
		cloned.LastSeen = &lastSeen
	}
	if device.LastDisconnectAt != nil {
		lastDisconnectAt := *device.LastDisconnectAt
		cloned.LastDisconnectAt = &lastDisconnectAt
	}
	if device.DisconnectHistory != nil {
		cloned.DisconnectHistory = append([]DeviceDisconnect(nil), device.DisconnectHistory...)
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
	mu          sync.RWMutex
	saveMu      sync.Mutex
	state       *ServerState
	deviceIndex map[string]int
	path        string

	// 状态加密：rawStateKey 是配置的原始密钥（空 = 不加密），在 Load 之前
	// 由 SetEncryptionKey 设置。envelope 是当前磁盘信封对应的派生信息；
	// pendingEnvelope 是 v1↔v2 待迁移目标，写盘成功后才提交（见 writeState）。
	rawStateKey     string
	kdfLegacy       bool
	envelope        *stateEnvelope
	pendingEnvelope *stateEnvelope

	// 落盘健康度（/health 用）。lastPersistOK 是最近一次成功写盘的时刻，
	// 或者启动时成功读到文件的时刻（此后还没写过盘时，这就是磁盘上的真相）；
	// lastPersistFail 是最近一次写盘失败的时刻；dirtySince 是第一次出现未落盘
	// 改动的时刻，由同步循环维护。
	lastPersistOK   atomic.Int64
	lastPersistFail atomic.Int64
	dirtySince      atomic.Int64
	// lastSeenPersist 是最近一次因 last_seen 标脏的时刻，用来把「每心跳一次写盘」
	// 压到最粗 1 分钟一次。
	lastSeenPersist atomic.Int64

	dirty bool
	// devicesVersion 在设备记录发生任何变化（增/删/改/回滚）时递增。
	// 隧道 accept 路径按它判断编译好的设备白名单是否过期，避免每次连接都
	// 全量重建 matcher。
	devicesVersion uint64
	stopCh         chan struct{}
	stopOnce       sync.Once
	startOnce      sync.Once
	wg             sync.WaitGroup
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

// checkStateSchemaVersion 在反序列化之后、解码与写盘之前拦下「文件比二进制新」。
func checkStateSchemaVersion(version int) error {
	if version < 0 {
		return fmt.Errorf("state file has invalid schema_version %d", version)
	}
	if version > stateSchemaVersion {
		return fmt.Errorf("%w: file has schema %d, this binary supports up to %d; upgrade the binary (or restore a backup) instead of starting an older build",
			ErrStateTooNew, version, stateSchemaVersion)
	}
	return nil
}

// migrateStateLocked 把内存里的状态逐级升到当前版本。调用者持有 s.mu，并负责
// 在成功后落盘一次。
//
// 约束（新增迁移时照做）：
//   - 纯内存变换：不写盘、不读配置、不看 time.Now，重试必须得到同一结果；
//   - 逐级前进，禁止跳版；已发布的步骤永不修改，只能追加下一步；
//   - 每步只搬它要搬的字段，不顺手「修值」（修值归 normalizeSettings，且迁移
//     先于 normalize，不得依赖 normalize 的结果）。
func migrateStateLocked(state *ServerState) error {
	for version := state.SchemaVersion; version < stateSchemaVersion; version++ {
		if err := migrateStateStep(state, version); err != nil {
			return fmt.Errorf("migrate state schema %d -> %d: %w", version, version+1, err)
		}
		state.SchemaVersion = version + 1
	}
	if state.SchemaVersion != stateSchemaVersion {
		return fmt.Errorf("state schema migration ended at %d, want %d", state.SchemaVersion, stateSchemaVersion)
	}
	return nil
}

// migrateStateStep 执行 version -> version+1 的一步迁移。
func migrateStateStep(state *ServerState, version int) error {
	switch version {
	case 0:
		// v0 -> v1 是 identity 迁移：v0 就是本轮之前的全部字段，语义与 v1 相同，
		// 这一版没有字段改名，只是补上版本号本身。下一次不兼容改动按
		// case 1: … 追加，不要修改这一段。
		return nil
	default:
		return fmt.Errorf("no migration registered for state schema %d", version)
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
	// 版本检查必须在解密、迁移、写盘之前：老二进制读到新文件还继续跑，未知字段
	// 在反序列化阶段已经丢了，下一次 Save 会把它们永久删掉。
	if err := checkStateSchemaVersion(state.SchemaVersion); err != nil {
		return err
	}
	loadedSchemaVersion := state.SchemaVersion
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
	// 迁移在解密之后（将来触及敏感区的迁移才能看到明文）、normalize 之前。
	if err := migrateStateLocked(&state); err != nil {
		return err
	}
	state.Settings = normalizeSettings(state.Settings)

	s.state = &state
	s.rebuildDeviceIndexLocked()
	migrated := loadedSchemaVersion != state.SchemaVersion
	// 明文重写（首次启用加密 / 清掉旧版明文密码）和 schema 迁移都是「内存已经
	// 是新结构，磁盘还是旧的」，落盘失败必须 fail closed：继续跑会让内存与磁盘
	// 分叉，由 NewServer panic 让下次启动重跑同一步。
	needsRewrite := migrated || (len(s.rawStateKey) > 0 && wasPlaintext) || legacy.AdminPasswordPlain != ""
	switch {
	case needsRewrite:
		// 这里也覆盖「迁移 + 信封迁移同时触发」：writeState 成功时才提交新信封，
		// 失败则连信封一起保留旧状态，绝不半途写坏。
		if err := s.writeState(cloneServerState(&state)); err != nil {
			return fmt.Errorf("persist state rewrite: %w", err)
		}
	case s.pendingEnvelope != nil:
		// 只是信封格式迁移（v1→v2，或 --state-kdf=legacy 下的 v2→v1）：解密已经
		// 成功，写失败不阻塞启动。文件保持原格式，下次 Save 再试；绝不在
		// 解密成功前碰文件，最坏结果是“还是旧格式”，不是“文件损坏”。
		if err := s.writeState(cloneServerState(&state)); err != nil {
			slog.Error("state encryption envelope migration failed; keeping the previous format on disk and retrying on next save",
				"path", s.path, "error", err)
		}
	}
	// 只有写盘成功（或根本不需要写）才会走到这里，所以这条日志不会谎报。
	if migrated {
		slog.Info("state schema migrated", "path", s.path, "from", loadedSchemaVersion, "to", state.SchemaVersion)
	}
	// 读到文件、解密、迁移都成功 = 磁盘状态可用。此后还没写过盘时，这就是
	// /health 里 last_persist_ok 的基线（否则空闲实例会一直显示「从未落盘」）。
	if s.lastPersistOK.Load() == 0 {
		s.lastPersistOK.Store(time.Now().UnixNano())
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
		SchemaVersion:     stateSchemaVersion,
		ServerSignPrivkey: hex.EncodeToString(privKey),
		ServerSignPubkey:  hex.EncodeToString(pubKey),
		Settings:          defaultSettings(),
		Devices:           []DeviceState{},
	}

	// 新文件必须在第一次写盘前定下信封：口令模式下 salt 一旦生成就要持久化，
	// 之后每次 Save 只能复用它。
	if s.rawStateKey != "" {
		envelope, err := s.buildEnvelope()
		if err != nil {
			return err
		}
		s.envelope = envelope
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
// PersistStatus 返回最近一次成功落盘的时间，以及落盘是否健康。
//
// 不健康有两种：最近一次写盘失败还没被后续成功写盘覆盖；或者有未落盘的改动
// 且已经超过 persistStaleThreshold（同步循环每 3 秒跑一次，所以这个窗口足够
// 区分「刚好在写」和「写不动了」）。
func (s *StateStore) PersistStatus() (lastOK time.Time, healthy bool) {
	okAt := s.lastPersistOK.Load()
	if okAt > 0 {
		lastOK = time.Unix(0, okAt)
	}
	if failAt := s.lastPersistFail.Load(); failAt > okAt {
		return lastOK, false
	}
	if since := s.dirtySince.Load(); since != 0 && time.Since(time.Unix(0, since)) > persistStaleThreshold {
		return lastOK, false
	}
	return lastOK, true
}

// RecordDeviceDisconnect 记一条断线留痕：更新 last_seen、上次断开时间与原因，
// 追加进最近 deviceDisconnectHistoryLimit 条历史，并标脏等同步循环落盘。
//
// 调用方在设备已经离线之后调用，所以这里只改 state，不做任何网络操作。
func (s *StateStore) RecordDeviceDisconnect(deviceID, reason string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, ok := s.deviceIndex[deviceID]
	if !ok {
		return
	}
	device := &s.state.Devices[index]
	seen := at
	device.LastSeen = &seen
	disconnectedAt := at
	device.LastDisconnectAt = &disconnectedAt
	device.LastDisconnectReason = reason

	device.DisconnectHistory = append(device.DisconnectHistory, DeviceDisconnect{At: at, Reason: reason})
	if len(device.DisconnectHistory) > deviceDisconnectHistoryLimit {
		device.DisconnectHistory = append([]DeviceDisconnect(nil),
			device.DisconnectHistory[len(device.DisconnectHistory)-deviceDisconnectHistoryLimit:]...)
	}
	s.dirty = true
}

// TouchDeviceSeen 更新设备的 last_seen。内存里每次都更新，但只有距上次标脏超过
// lastSeenPersistInterval 时才标脏——否则每台设备每 30 秒的心跳都会触发一次全量
// 落盘，设备一多就把同步循环顶到 3 秒一次的上限。丢电最坏丢 1 分钟精度。
func (s *StateStore) TouchDeviceSeen(deviceID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, ok := s.deviceIndex[deviceID]
	if !ok {
		return
	}
	seen := at
	s.state.Devices[index].LastSeen = &seen

	if at.Sub(time.Unix(0, s.lastSeenPersist.Load())) < lastSeenPersistInterval {
		return
	}
	s.lastSeenPersist.Store(at.UnixNano())
	s.dirty = true
}

// SetTunnelDefinitions 只更新内存里的定义并标脏，不做同步落盘。断线路径用它：
// 正在持着 tm.mu 时不能做全量 fsync，否则网络抖一下就会卡住所有隧道操作；
// 落盘交给下一次同步循环，和同一轮的设备断线记录一起写。
func (s *StateStore) SetTunnelDefinitions(tunnels []TunnelState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.Tunnels = append([]TunnelState(nil), tunnels...)
	s.dirty = true
}

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
	s.dirtySince.Store(0)
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
func (s *StateStore) writeState(state ServerState) (err error) {
	// 落盘健康度给 /health 用：任何一次失败都记下来，直到下一次成功写盘覆盖。
	defer func() {
		if err != nil {
			s.lastPersistFail.Store(time.Now().UnixNano())
		}
	}()

	if s.path == "" {
		return nil
	}
	// 防御：配置了密钥但还没经过 Load（直接构造的 store）。先定下信封，
	// 绝不把敏感字段以明文写进一个按加密配置运行的进程。
	if s.rawStateKey != "" && s.envelope == nil && s.pendingEnvelope == nil {
		envelope, err := s.buildEnvelope()
		if err != nil {
			return err
		}
		s.envelope = envelope
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
	// rename 生效就是磁盘上的新内容：这里记成功。后面的目录 fsync 只影响
	// 掉电语义，失败只记 WARN，不算落盘失败。
	s.lastPersistOK.Store(time.Now().UnixNano())
	// rename 已经生效：磁盘上就是新信封。现在才提交迁移目标，后续 Save
	// 复用同一 salt/params（换 salt = 换密钥）。
	if s.pendingEnvelope != nil {
		s.envelope = s.pendingEnvelope
		s.pendingEnvelope = nil
		slog.Info("state encryption envelope migrated", "version", s.envelope.version, "kdf", s.envelope.kdf)
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
		s.dirtySince.Store(0)
		s.mu.Unlock()
		return nil
	}
	if s.dirtySince.Load() == 0 {
		s.dirtySince.Store(time.Now().UnixNano())
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
	s.dirtySince.Store(0)
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

// DevicesVersion 返回设备记录的变更版本号。任何设备增删改都会让它递增，
// 读取方可以据此判断自己缓存的派生数据（例如编译后的 IP 白名单）是否过期。
func (s *StateStore) DevicesVersion() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devicesVersion
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
	s.devicesVersion++
	s.dirty = true
}

func (s *StateStore) UpdateDevice(id string, fn func(*DeviceState)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Devices {
		if s.state.Devices[i].ID == id {
			fn(&s.state.Devices[i])
			s.devicesVersion++
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
		s.devicesVersion++
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
	s.devicesVersion++
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
//
// 落盘顺序是先写后提交：在快照上删掉这个码、写盘成功之后才改内存。
// 反过来（先删内存再 Save）会出现「接口报 500、码其实已经烧掉，下次 flush
// 还会把删除写回磁盘」——对外返回失败却让码永久失效，用户失去最后一个
// 自助出口。现在写失败时内存一个字节都没动，返回失败 ⇒ 码仍然可用。
//
// saveMu 把这次快照写盘与其他 Save/flushDirty 串行：拿到 saveMu 之后才取
// 快照，磁盘上不会被更旧的状态覆盖回来。
func (s *StateStore) ConsumeTOTPRecoveryCode(hash string) (remaining int, consumed bool, err error) {
	target := []byte(hash)

	s.saveMu.Lock()
	defer s.saveMu.Unlock()

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
	hashes := s.state.TOTPRecoveryHashes
	snapshot := cloneServerState(s.state)
	next := make([]string, 0, len(hashes)-1)
	next = append(next, hashes[:idx]...)
	next = append(next, hashes[idx+1:]...)
	snapshot.TOTPRecoveryHashes = next
	current := len(hashes)
	s.mu.Unlock()

	if err := s.writeState(snapshot); err != nil {
		// 内存没动：这个码还能再用，调用方也应该把这个错误报出去。
		return current, false, err
	}

	// 提交内存。等待写盘期间可能有别的恢复码被消费，所以按当前列表重新找
	// 一次；找不到说明已经有人删过了。
	s.mu.Lock()
	if commitIdx := findRecoveryHash(s.state.TOTPRecoveryHashes, target); commitIdx >= 0 {
		remainingHashes := make([]string, 0, len(s.state.TOTPRecoveryHashes)-1)
		remainingHashes = append(remainingHashes, s.state.TOTPRecoveryHashes[:commitIdx]...)
		remainingHashes = append(remainingHashes, s.state.TOTPRecoveryHashes[commitIdx+1:]...)
		s.state.TOTPRecoveryHashes = remainingHashes
	}
	remaining = len(s.state.TOTPRecoveryHashes)
	s.mu.Unlock()
	return remaining, true, nil
}

// findRecoveryHash 返回哈希在列表中的下标；遍历全表，不提前返回，避免
// 通过耗时泄漏命中位置。无命中返回 -1。
func findRecoveryHash(hashes []string, target []byte) int {
	idx := -1
	for i, candidate := range hashes {
		if subtle.ConstantTimeCompare([]byte(candidate), target) == 1 {
			idx = i
		}
	}
	return idx
}

// EncryptionEnabled 表示 state 敏感字段是否走 AES-256-GCM 加密区。
// 配置了密钥即为 true：真正派生的 AES key 要到 Load 读到信封（或首次写盘）
// 才确定，TOTP 门禁不能等派生完成才放行。
func (s *StateStore) EncryptionEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rawStateKey != ""
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
