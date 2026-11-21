package server

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/server/netplane"
)

// vpnApplyBudget 是写接口等待内核应用的上限（设计 §4）。
const vpnApplyBudget = 5 * time.Second

// NetplaneSnapshot 把 state 翻译成 netplane 的期望状态。
//
// 快照包含所有已绑定公钥的设备（含已停用的）：停用设备也要交给后台，
// 否则停用后 peer 不会被移除。未绑定的设备不出现在快照里。
func (s *StateStore) NetplaneSnapshot() (netplane.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	settings := s.state.Settings
	prefix, hubAddress, err := wgInterfaceAddress(settings.WGCIDR)
	if err != nil {
		return netplane.Snapshot{}, err
	}
	snapshot := netplane.Snapshot{
		Hub: netplane.Hub{
			Interface:  wgInterfaceName,
			PrivateKey: s.state.WGHubPrivkey,
			CIDR:       prefix.String(),
			Address:    hubAddress.String(),
			Listen:     settings.WGListen,
			MTU:        wgMTUHub,
			Endpoint:   wgEndpoint(settings.PublicHost, settings.WGListen),
		},
	}
	for i := range s.state.Devices {
		device := &s.state.Devices[i]
		if device.WGPublicKey == "" {
			continue
		}
		snapshot.Peers = append(snapshot.Peers, netplane.Peer{
			DeviceID:  device.ID,
			PublicKey: device.WGPublicKey,
			Address:   device.WGIP,
			Role:      device.WGRole,
			Enabled:   device.WGEnabled,
			Version:   device.WGVersion,
		})
	}
	return snapshot, nil
}

// wgLock 返回一台设备的操作锁：同一设备的 PUT/DELETE 从进接口持到响应写完，
// 后台 reconcile 不取这把锁（否则等待 appliedVersion 时会互相等死，审计 v4-A5）。
func (s *Server) wgLock(deviceID string) *sync.Mutex {
	s.wgLocksMu.Lock()
	defer s.wgLocksMu.Unlock()
	if s.wgLocks == nil {
		s.wgLocks = make(map[string]*sync.Mutex)
	}
	lock, ok := s.wgLocks[deviceID]
	if !ok {
		lock = &sync.Mutex{}
		s.wgLocks[deviceID] = lock
	}
	return lock
}

// vpnConfigured 报告组网是否已经被使用过：hub 私钥存在，或已有设备绑定公钥。
func (s *Server) vpnConfigured() bool {
	if s.stateStore == nil {
		return false
	}
	if s.stateStore.WGHubPrivateKey() != "" {
		return true
	}
	for _, device := range s.stateStore.GetAllDevices() {
		if device.WGPublicKey != "" {
			return true
		}
	}
	return false
}

// vpnEncryptionBlocked 报告「组网已配置但 state 未加密」这一拒绝启动条件。
// 启动路径据此拒绝启动 netplane（fail closed），而不是只打一条告警继续跑。
func (s *Server) vpnEncryptionBlocked() bool {
	return s.vpnConfigured() && !s.stateStore.EncryptionEnabled()
}

// ensureHubKey 保证 hub 私钥存在。并发的首个绑定只会生成一次。
//
// 没有 state 加密密钥时直接拒绝（实现须知 #6）：hub 私钥是唯一能对所有设备
// 做主动 MITM 的密钥，0600 明文只挡普通用户，root、备份、快照都能拿走。
// 这里再兜一层，避免将来新增调用点绕过 handler 的检查。
func (s *Server) ensureHubKey() error {
	if !s.stateStore.EncryptionEnabled() {
		return ErrWGStateEncryptionRequired
	}
	s.wgHubMu.Lock()
	defer s.wgHubMu.Unlock()
	if s.stateStore.WGHubPrivateKey() != "" {
		return nil
	}
	key, err := newWGHubPrivateKey()
	if err != nil {
		return err
	}
	if err := s.stateStore.SetWGHubPrivateKey(key); err != nil {
		return err
	}
	// 首次生成也要留痕：这条路径以前完全静默，出错时无法从日志判断 hub 身份
	// 是什么时候、以什么方式建立的。
	slog.Info("wireguard hub key generated and stored in the encrypted state blob")
	return nil
}

// hubPublicKey 返回模板里要写的 hub 公钥。
func (s *Server) hubPublicKey() (string, error) {
	return wgHubPublicKey(s.stateStore.WGHubPrivateKey())
}

type reauthContextKey string

const (
	reauthPasswordKey reauthContextKey = "goremote.reauth.password"
	reauthTOTPKey     reauthContextKey = "goremote.reauth.totp"
)

// reauthHeaderMiddleware 在请求进入任何可能 panic 的中间件之前，把二次认证
// 凭据从请求头搬进 context 并删除请求头。
//
// gin 的 Recovery 在 panic 时会 dump 请求头（secureRequestDump），只脱敏
// Authorization。X-Reauth-Password / X-Reauth-TOTP 是管理员密码与动态码：
// 若 panic 发生在 adminWrite / SetupGate / authMiddleware（都在 reauth 之前
// 运行），这两个头会原文进 stderr。所以摘头必须放在这些中间件之前，由引擎
// 第一层中间件完成，而不能等 reauthMiddleware 自己摘。
func reauthHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		password := c.GetHeader("X-Reauth-Password")
		code := c.GetHeader("X-Reauth-TOTP")
		c.Request.Header.Del("X-Reauth-Password")
		c.Request.Header.Del("X-Reauth-TOTP")
		if password != "" {
			c.Set(string(reauthPasswordKey), password)
		}
		if code != "" {
			c.Set(string(reauthTOTPKey), code)
		}
		c.Next()
	}
}

// reauthMiddleware 校验写接口的二次认证。凭据由 reauthHeaderMiddleware
// 从请求头搬到 context（请求头上已经不存在），这里只读 context，避免下游
// 任何日志/panic 转储再看到原文。401（无会话）由 authMiddleware 先给。
func (s *Server) reauthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		password := c.GetString(string(reauthPasswordKey))
		code := c.GetString(string(reauthTOTPKey))

		if password == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin password required", "code": "REAUTH_REQUIRED"})
			return
		}
		if err := s.adminAuth.CheckPassword(c.ClientIP(), password); err != nil {
			if errors.Is(err, ErrAdminLoginLocked) {
				c.Header("Retry-After", "60")
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts, try again later", "code": "REAUTH_LOCKED"})
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin password is incorrect", "code": "REAUTH_FAILED"})
			return
		}
		if s.adminAuth.TOTPEnabled() {
			if strings.TrimSpace(code) == "" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "totp code required", "code": "REAUTH_TOTP_REQUIRED"})
				return
			}
			// 复用登录用的挑战：一次性、绑 IP、最多 3 次尝试、时间步 CAS 防重放。
			challenge, err := s.adminAuth.BeginTOTPChallenge(c.ClientIP())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "totp is unavailable", "code": "REAUTH_TOTP_UNAVAILABLE"})
				return
			}
			if err := s.adminAuth.VerifyTOTPChallenge(c.ClientIP(), challenge, code); err != nil {
				if errors.Is(err, ErrAdminLoginLocked) {
					c.Header("Retry-After", "60")
					c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts, try again later", "code": "REAUTH_LOCKED"})
					return
				}
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "totp code is incorrect", "code": "REAUTH_TOTP_FAILED"})
				return
			}
		}
		c.Next()
	}
}

type deviceVPNRequest struct {
	Pubkey string `json:"pubkey"`
	Role   string `json:"role"`
}

// wgErrorStatus 把内部错误映射成设计 §5 的状态码。
func wgErrorStatus(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrWGDeviceNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
	case errors.Is(err, ErrWGPrivateKey):
		// 不回显、不记日志、不写 state。误拒约 6.23%，必须给「重新生成密钥对」
		// 的出口，否则用户重贴同一把公钥会永远 400（实现须知 #2）。
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "这个值看起来是私钥，已拒绝保存",
			"code":  "PUBKEY_LOOKS_LIKE_PRIVATE_KEY",
			"hint":  "这里要贴 Public key。若你确认复制的是 Public key，说明命中了约 6% 的误判：图形客户端请删除该隧道并重新创建（会生成新密钥对），命令行请重新执行 wg genkey | tee privatekey | wg pubkey，然后贴新的 Public key。同一个公钥反复提交会一直返回 400，不是网络问题。",
		})
	case errors.Is(err, ErrWGInvalidPubkey):
		c.JSON(http.StatusBadRequest, gin.H{"error": "wireguard public key must be 32 bytes of base64", "code": "INVALID_PUBKEY"})
	case errors.Is(err, ErrWGInvalidRole):
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be client or endpoint", "code": "INVALID_ROLE"})
	case errors.Is(err, ErrWGPubkeyTaken):
		c.JSON(http.StatusConflict, gin.H{"error": "this public key is already bound to another device", "code": "PUBKEY_IN_USE"})
	case errors.Is(err, ErrWGRoleLocked):
		c.JSON(http.StatusConflict, gin.H{"error": "role is fixed at first binding; unbind first", "code": "ROLE_LOCKED"})
	case errors.Is(err, ErrWGCIDRLocked):
		c.JSON(http.StatusConflict, gin.H{"error": "wireguard cidr is locked", "code": "CIDR_LOCKED"})
	case errors.Is(err, ErrWGNoFreeAddress):
		c.JSON(http.StatusConflict, gin.H{"error": "wireguard address pool is exhausted", "code": "POOL_EXHAUSTED"})
	case errors.Is(err, ErrWGSuperseded):
		// 设计 §4：这是「这次写被更晚的写覆盖了」，不是服务端故障；500 会让
		// 客户端当成基础设施错误去重试，越重试越错。
		c.JSON(http.StatusConflict, gin.H{"error": "the device was changed by another write before this one reached the kernel; reload and retry", "code": "SUPERSEDED"})
	case errors.Is(err, ErrWGStateEncryptionRequired):
		c.JSON(http.StatusConflict, gin.H{"error": stateEncryptionRequiredMessage, "code": "STATE_ENCRYPTION_REQUIRED"})
	case errors.Is(err, ErrWGNotAuthorized):
		c.JSON(http.StatusConflict, gin.H{"error": "device must be approved before it can join the network", "code": "DEVICE_NOT_AUTHORIZED"})
	case errors.Is(err, ErrWGNoBinding):
		c.JSON(http.StatusNotFound, gin.H{"error": "device has no wireguard binding"})
	case errors.Is(err, netplane.ErrInfra):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "wireguard infrastructure is unavailable", "code": "WG_INFRA"})
	case errors.Is(err, netplane.ErrDevice):
		c.JSON(http.StatusInternalServerError, gin.H{"error": "the kernel rejected this peer", "code": "WG_PEER_ERROR"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wireguard operation failed"})
	}
}

var (
	// ErrWGNotAuthorized 表示设备还没通过审批。
	ErrWGNotAuthorized = errors.New("device is not authorized")
	// ErrWGNoBinding 表示设备当前没有绑定公钥。
	ErrWGNoBinding = errors.New("device has no wireguard binding")
)

// vpnTemplateResponse 是 PUT 成功时返回的非机密模板。
type vpnTemplateResponse struct {
	DeviceID string   `json:"device_id"`
	WGIP     string   `json:"wg_ip"`
	Role     string   `json:"role"`
	Endpoint string   `json:"endpoint"`
	Template string   `json:"template"`
	Notes    []string `json:"notes"`
	Applied  uint64   `json:"applied"`
	ACLReady bool     `json:"acl_ready"`
}

// handleAPIPutDeviceVPN 绑定/替换设备公钥（同一把公钥重复提交是幂等的）。
func (s *Server) handleAPIPutDeviceVPN(c *gin.Context) {
	deviceID := c.Param("id")
	c.Header("Cache-Control", "no-store")

	var req deviceVPNRequest
	if !decodeStrictJSON(c, &req) {
		return
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = wgRoleClient
	}
	if role != wgRoleClient && role != wgRoleEndpoint {
		wgErrorStatus(c, ErrWGInvalidRole)
		return
	}
	publicKey, _, err := decodeWGPublicKey(req.Pubkey)
	if err != nil {
		wgErrorStatus(c, err)
		return
	}

	// 启用组网会生成 hub 私钥；没有 state 加密密钥就不允许启用（实现须知 #6）。
	// 这条优先于 infra 检查：配置错误比内核错误更该先被指出，而且它是确定性的。
	if !s.stateStore.EncryptionEnabled() {
		wgErrorStatus(c, ErrWGStateEncryptionRequired)
		return
	}
	if s.netplane == nil {
		wgErrorStatus(c, netplane.ErrInfra)
		return
	}
	if detail := s.netplane.InfraError(); detail != "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "wireguard infrastructure is unavailable", "code": "WG_INFRA", "detail": detail})
		return
	}
	if err := s.ensureHubKey(); err != nil {
		wgErrorStatus(c, err)
		return
	}

	lock := s.wgLock(deviceID)
	lock.Lock()
	defer lock.Unlock()

	previous := s.stateStore.GetDeviceByID(deviceID)
	if previous == nil {
		wgErrorStatus(c, ErrWGDeviceNotFound)
		return
	}
	settings := s.stateStore.GetSettings()
	// 防御性校验：隧道端口池以后可能被改到包含 51820，那样隧道先绑就会占掉
	// WireGuard 的监听端口（EADDRINUSE，报错难查）。设置接口改区间时已经挡了
	// 一次，这里再兜一层，因为改区间与启用组网可能发生在不同时间。
	if settings.WGListen >= settings.PortRangeStart && settings.WGListen <= settings.PortRangeEnd {
		c.JSON(http.StatusConflict, gin.H{
			"error": "the tunnel port range includes the wireguard listen port; change port_range_start/port_range_end first",
			"code":  "LISTEN_PORT_CONFLICT",
		})
		return
	}
	prefix, _, err := wgInterfaceAddress(settings.WGCIDR)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wireguard cidr is invalid"})
		return
	}
	if err := ensureCIDRFree(settings.WGCIDR, settings.PublicHost); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "CIDR_CONFLICT"})
		return
	}

	var version uint64
	err = s.stateStore.AllocateWGDevice(deviceID, func(device *DeviceState, all []DeviceState) error {
		if device.Status != deviceStatusAuthorized {
			return ErrWGNotAuthorized
		}
		if wgPubkeyInUse(publicKey, all, deviceID) {
			return ErrWGPubkeyTaken
		}
		if device.WGPublicKey == "" {
			address, err := allocateWGAddress(prefix, all, deviceID)
			if err != nil {
				return err
			}
			device.WGIP = address
			device.WGRole = role
		} else if device.WGRole != role {
			return ErrWGRoleLocked
		}
		device.WGPublicKey = publicKey
		device.WGEnabled = true
		device.WGKeyIssued = wgKeyIssuedAt()
		device.WGVersion++
		device.WGError = ""
		version = device.WGVersion
		return nil
	})
	if err != nil {
		wgErrorStatus(c, err)
		return
	}
	if err := s.stateStore.Save(); err != nil {
		s.restoreDevice(previous)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist state"})
		return
	}

	s.netplane.Bump()
	if err := s.netplane.Wait(c.Request.Context(), deviceID, version, vpnApplyBudget); err != nil {
		wgErrorStatus(c, err)
		return
	}
	current := s.stateStore.GetDeviceByID(deviceID)
	if current == nil || current.WGPublicKey != publicKey || !current.WGEnabled {
		wgErrorStatus(c, ErrWGSuperseded)
		return
	}

	hubPublicKey, err := s.hubPublicKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hub key is unavailable"})
		return
	}
	endpoint := net.JoinHostPort(s.advertisedTunnelHost(c.Request.Host), strconv.Itoa(settings.WGListen))
	c.JSON(http.StatusOK, vpnTemplateResponse{
		DeviceID: deviceID,
		WGIP:     current.WGIP,
		Role:     current.WGRole,
		Endpoint: endpoint,
		Template: wgTemplate(current.WGIP, hubPublicKey, endpoint, settings.WGCIDR),
		Notes:    wgTemplateNotes(),
		Applied:  version,
		ACLReady: false,
	})
}

// handleAPIDeleteDeviceVPN 解绑：先停用并落盘，等内核撤销，再清绑定记录。
// 顺序不能反：先清记录再撤销，撤销失败时面板已经没有记录、VPN 却还通。
func (s *Server) handleAPIDeleteDeviceVPN(c *gin.Context) {
	deviceID := c.Param("id")
	c.Header("Cache-Control", "no-store")

	if s.netplane == nil {
		wgErrorStatus(c, netplane.ErrInfra)
		return
	}
	if detail := s.netplane.InfraError(); detail != "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "wireguard infrastructure is unavailable", "code": "WG_INFRA", "detail": detail})
		return
	}

	lock := s.wgLock(deviceID)
	lock.Lock()
	defer lock.Unlock()

	device := s.stateStore.GetDeviceByID(deviceID)
	if device == nil {
		wgErrorStatus(c, ErrWGDeviceNotFound)
		return
	}
	if device.WGPublicKey == "" {
		wgErrorStatus(c, ErrWGNoBinding)
		return
	}
	previous := *device

	var revokeVersion uint64
	if err := s.stateStore.AllocateWGDevice(deviceID, func(current *DeviceState, _ []DeviceState) error {
		current.WGEnabled = false
		current.WGVersion++
		revokeVersion = current.WGVersion
		return nil
	}); err != nil {
		wgErrorStatus(c, err)
		return
	}
	if err := s.stateStore.Save(); err != nil {
		s.restoreDevice(&previous)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist state"})
		return
	}

	s.netplane.Bump()
	if err := s.netplane.Wait(c.Request.Context(), deviceID, revokeVersion, vpnApplyBudget); err != nil {
		wgErrorStatus(c, err)
		return
	}

	// 内核已经撤销，才把绑定记录清掉。
	if err := s.stateStore.AllocateWGDevice(deviceID, func(current *DeviceState, _ []DeviceState) error {
		current.WGPublicKey = ""
		current.WGIP = ""
		current.WGRole = ""
		current.WGKeyIssued = nil
		current.WGError = ""
		current.WGVersion++
		return nil
	}); err != nil {
		wgErrorStatus(c, err)
		return
	}
	if err := s.stateStore.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wireguard peer was revoked but the binding record could not be cleared"})
		return
	}
	s.netplane.Bump()
	c.Status(http.StatusNoContent)
}

// restoreDevice 在落盘失败时把内存回滚成操作前的样子。
func (s *Server) restoreDevice(previous *DeviceState) {
	if previous == nil {
		return
	}
	snapshot := *previous
	_ = s.stateStore.AllocateWGDevice(previous.ID, func(device *DeviceState, _ []DeviceState) error {
		*device = snapshot
		return nil
	})
}

// ensureCIDRFree 拒绝把已知公网地址所在的网段吸进隧道（设计 §2）。
func ensureCIDRFree(cidr, publicHost string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return errors.New("invalid wireguard cidr")
	}
	host := strings.TrimSpace(publicHost)
	if host == "" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && prefix.Contains(ip) {
		return errors.New("wireguard cidr contains public_host; pick a cidr that does not overlap the server address")
	}
	return nil
}

// vpnPeerStatus 是状态接口里的一台设备。
type vpnPeerStatus struct {
	DeviceID          string `json:"device_id"`
	Name              string `json:"name"`
	WGIP              string `json:"wg_ip"`
	Role              string `json:"role"`
	Enabled           bool   `json:"enabled"`
	Version           uint64 `json:"wg_version"`
	AppliedVersion    uint64 `json:"applied_version"`
	Error             string `json:"wg_error,omitempty"`
	HandshakeAge      int64  `json:"handshake_age"`
	PubkeyFingerprint string `json:"pubkey_fingerprint"`
}

// handleAPIGetVPNStatus 汇总 netplane 的期望/实际状态和每台设备的握手年龄。
func (s *Server) handleAPIGetVPNStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	settings := s.stateStore.GetSettings()
	if s.netplane == nil {
		c.JSON(http.StatusOK, gin.H{
			"iface":       wgInterfaceName,
			"endpoint":    net.JoinHostPort(s.advertisedTunnelHost(c.Request.Host), strconv.Itoa(settings.WGListen)),
			"cidr":        settings.WGCIDR,
			"listen":      settings.WGListen,
			"gen":         0,
			"applied":     0,
			"infra_error": "wireguard networking is not enabled",
			"blocked":     "",
			"state_encryption_enabled": s.stateStore.EncryptionEnabled(),
			"acl_ready":                false,
			"peers":                    []vpnPeerStatus{},
		})
		return
	}

	status := s.netplane.Status()
	byID := make(map[string]netplane.PeerStatus, len(status.Peers))
	for _, peer := range status.Peers {
		byID[peer.DeviceID] = peer
	}
	peers := make([]vpnPeerStatus, 0, len(byID))
	for _, device := range s.stateStore.GetAllDevices() {
		if device.WGPublicKey == "" {
			continue
		}
		peer := byID[device.ID]
		peers = append(peers, vpnPeerStatus{
			DeviceID:          device.ID,
			Name:              device.Name,
			WGIP:              device.WGIP,
			Role:              device.WGRole,
			Enabled:           device.WGEnabled,
			Version:           device.WGVersion,
			AppliedVersion:    peer.AppliedVersion,
			Error:             peer.Error,
			HandshakeAge:      peer.HandshakeAge,
			PubkeyFingerprint: wgPubkeyFingerprint(device.WGPublicKey),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"iface":                    wgInterfaceName,
		"endpoint":                 net.JoinHostPort(s.advertisedTunnelHost(c.Request.Host), strconv.Itoa(settings.WGListen)),
		"cidr":                     settings.WGCIDR,
		"listen":                   settings.WGListen,
		"gen":                      status.Gen,
		"applied":                  status.Applied,
		"infra_error":              status.InfraError,
		"blocked":                  status.Blocked,
		"state_encryption_enabled": s.stateStore.EncryptionEnabled(),
		"acl_ready":                status.ACLReady,
		"peers":                    peers,
	})
}
