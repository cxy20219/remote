package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"goremote/internal/common"
)

type ServerSettings struct {
	PortRangeStart    int      `json:"port_range_start"`
	PortRangeEnd      int      `json:"port_range_end"`
	MaxTunnelsPerClient int    `json:"max_tunnels_per_client"`
	DefaultLocalAddr  string   `json:"default_local_addr"`
	PublicHost        string   `json:"public_host"`
	MaxConnPerMin     int      `json:"max_conn_per_min"`
	LoginRateLimit    int      `json:"login_rate_limit"`
	BlacklistThreshold int     `json:"blacklist_threshold"`
	GlobalWhitelist   []string `json:"global_whitelist"`
	MaxBodySizeMB     int      `json:"max_body_size_mb"`
	HeartbeatInterval int      `json:"heartbeat_interval"`
	HeartbeatTimeout   int      `json:"heartbeat_timeout"`
}

type DeviceState struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	DeviceSignPubkey string  `json:"device_sign_pubkey"`
	DeviceDHPubkey  string    `json:"device_dh_pubkey"`
	Hostname        string    `json:"hostname"`
	OS              string    `json:"os"`
	Status          string    `json:"status"`
	EncKey          string    `json:"enc_key"`
	EncEnabled      bool      `json:"enc_enabled"`
	IPWhitelist     []string  `json:"ip_whitelist"`
	FirstSeen       time.Time `json:"first_seen"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
}

type ServerState struct {
	ServerSignPrivkey string         `json:"server_sign_privkey"`
	ServerSignPubkey  string         `json:"server_sign_pubkey"`
	AdminPasswordHash string         `json:"admin_password_hash"`
	AdminPassword     string         `json:"admin_password_plain,omitempty"`
	Settings          ServerSettings `json:"settings"`
	Devices           []DeviceState  `json:"devices"`
}

func defaultSettings() ServerSettings {
	return ServerSettings{
		PortRangeStart:    10000,
		PortRangeEnd:      20000,
		MaxTunnelsPerClient: 10,
		DefaultLocalAddr:  "127.0.0.1",
		MaxConnPerMin:     10,
		LoginRateLimit:    5,
		BlacklistThreshold: 100,
		GlobalWhitelist:   []string{},
		MaxBodySizeMB:     0,
		HeartbeatInterval: 30,
		HeartbeatTimeout:  90,
	}
}

type StateStore struct {
	mu     sync.RWMutex
	state  *ServerState
	path   string
	dirty  bool
	stopCh chan struct{}
}

func NewStateStore(path string) *StateStore {
	s := &StateStore{
		path:   path,
		stopCh: make(chan struct{}),
		state: &ServerState{
			Settings: defaultSettings(),
			Devices:  []DeviceState{},
		},
	}
	return s
}

func NewStateStoreWithSettings(settings ServerSettings) *StateStore {
	s := &StateStore{
		path:   "",
		stopCh: make(chan struct{}),
		state: &ServerState{
			Settings: settings,
			Devices:  []DeviceState{},
		},
	}
	return s
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

	var state ServerState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	if state.Settings.PortRangeStart == 0 {
		state.Settings.PortRangeStart = 10000
	}
	if state.Settings.PortRangeEnd == 0 {
		state.Settings.PortRangeEnd = 20000
	}

	s.state = &state
	slog.Info("server state loaded", "path", s.path, "devices", len(state.Devices))
	return nil
}

func (s *StateStore) initNew() error {
	pubKey, privKey, err := common.GenerateSignKeypair()
	if err != nil {
		return err
	}

	password := uuid.New().String()[:12]
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.state = &ServerState{
		ServerSignPrivkey: hex.EncodeToString(privKey),
		ServerSignPubkey:  hex.EncodeToString(pubKey),
		AdminPasswordHash: string(hashedPassword),
		AdminPassword:     password,
		Settings:          defaultSettings(),
		Devices:           []DeviceState{},
	}

	slog.Info("========================================")
	slog.Info("Generated admin credentials")
	slog.Info("Admin password", "password", password)
	slog.Info("========================================")

	return s.saveLocked()
}

func (s *StateStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

func (s *StateStore) saveLocked() error {
	copy := *s.state
	copy.AdminPassword = ""

	data, err := json.MarshalIndent(copy, "", "  ")
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

func (s *StateStore) MarkDirty() {
	s.dirty = true
}

func (s *StateStore) StartSyncLoop() {
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if s.dirty {
					s.mu.Lock()
					s.dirty = false
					err := s.saveLocked()
					s.mu.Unlock()
					if err != nil {
						slog.Error("failed to save state", "error", err)
					}
				}
			case <-s.stopCh:
				s.mu.Lock()
				if s.dirty {
					s.saveLocked()
				}
				s.mu.Unlock()
				return
			}
		}
	}()
}

func (s *StateStore) Stop() {
	close(s.stopCh)
}

func (s *StateStore) GetState() *ServerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *StateStore) GetSettings() ServerSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Settings
}

func (s *StateStore) UpdateSettings(fn func(*ServerSettings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state.Settings)
	s.dirty = true
}

func (s *StateStore) GetDeviceByID(id string) *DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.state.Devices {
		if s.state.Devices[i].ID == id {
			return &s.state.Devices[i]
		}
	}
	return nil
}

func (s *StateStore) GetDevicesByStatus(status string) []DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []DeviceState
	for _, d := range s.state.Devices {
		if d.Status == status {
			result = append(result, d)
		}
	}
	return result
}

func (s *StateStore) GetAllDevices() []DeviceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]DeviceState, len(s.state.Devices))
	copy(result, s.state.Devices)
	return result
}

func (s *StateStore) AddDevice(device *DeviceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	for i, d := range s.state.Devices {
		if d.ID == id {
			s.state.Devices = append(s.state.Devices[:i], s.state.Devices[i+1:]...)
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
	defer s.mu.RUnlock()
	return bcrypt.CompareHashAndPassword([]byte(s.state.AdminPasswordHash), []byte(password)) == nil
}

func (s *StateStore) GetAdminPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AdminPassword
}

func (s *StateStore) ClearAdminPassword() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.AdminPassword = ""
}