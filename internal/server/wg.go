package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// 组网固定值（设计 §4/§6）。阶段 1 只做 IPv4。
const (
	wgInterfaceName = "wg-grm"
	wgHubAddress    = "10.77.0.1"
	wgMTUHub        = 1420
	wgMTUClient     = 1380
	wgKeepalive     = 25
	wgMaxDevices    = 253 // .2-.254

	defaultWGCIDR   = "10.77.0.0/24"
	defaultWGListen = 51820

	wgRoleClient   = "client"
	wgRoleEndpoint = "endpoint"
)

var (
	// ErrWGDeviceNotFound 表示设备记录不存在。
	ErrWGDeviceNotFound = errors.New("device not found")
	// ErrWGInvalidPubkey 表示公钥不是合法的 32 字节 base64 曲线点。
	ErrWGInvalidPubkey = errors.New("invalid wireguard public key")
	// ErrWGPrivateKey 表示提交的值带 clamp 特征，几乎可以确定是私钥。
	ErrWGPrivateKey = errors.New("PUBKEY_LOOKS_LIKE_PRIVATE_KEY")
	// ErrWGPubkeyTaken 表示同一把公钥已经绑在另一台设备上。
	ErrWGPubkeyTaken = errors.New("wireguard public key already bound to another device")
	// ErrWGRoleLocked 表示角色只在首次绑定时设置，之后必须解绑重绑。
	ErrWGRoleLocked = errors.New("wireguard role is fixed at first binding; unbind and bind again to change it")
	// ErrWGCIDRLocked 表示已经有设备绑定，CIDR 不能再改。
	ErrWGCIDRLocked = errors.New("wireguard cidr is locked while a device is bound")
	// ErrWGNoFreeAddress 表示地址池（253 个）已经用尽。
	ErrWGNoFreeAddress = errors.New("wireguard address pool exhausted")
	// ErrWGSuperseded 表示等待内核应用期间，该设备又被别的写覆盖了。
	ErrWGSuperseded = errors.New("wireguard change superseded by a newer write")
	// ErrWGInvalidRole 表示角色不是 client/endpoint。
	ErrWGInvalidRole = errors.New("wireguard role must be client or endpoint")
	// ErrWGDisabled 表示组网功能没有运行时（未配置/未启用）。
	ErrWGDisabled = errors.New("wireguard networking is not enabled")
	// ErrWGStateEncryptionRequired 表示 hub 私钥只能进 state 加密区：没有配
	// state 加密密钥时拒绝启用组网，绝不把 hub 私钥明文落盘（实现须知 #6）。
	ErrWGStateEncryptionRequired = errors.New("state encryption is required to enable wireguard networking")
	// ErrWGPublicHostRequired 表示既没配 public_host，本次请求的 Host 又是
	// 回环/未指定地址：生成的 Endpoint 设备永远连不上，必须先填 public_host。
	ErrWGPublicHostRequired = errors.New("public_host is required: the request host is not reachable from devices")
)

// stateEncryptionRequiredMessage 是 409 的对外文案：给运维一个能照做的出口。
const stateEncryptionRequiredMessage = "state encryption is required to enable wireguard networking: set GOREMOTE_STATE_KEY (at least 32 characters) or --state-key, then restart. The hub private key is never written to a plaintext state file"

// decodeWGPublicKey 解析并校验一把设备公钥。
//
// 返回值不是机密，但错误也不能把输入回显出去：误贴私钥时调用方只回报
// ErrWGPrivateKey，绝不把原值写进日志或响应体。
func decodeWGPublicKey(raw string) (string, [32]byte, error) {
	var zero [32]byte
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", zero, ErrWGInvalidPubkey
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		// 接受不带 padding 的写法（部分客户端会去掉尾部 '='）。
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil || len(decoded) != 32 {
		return "", zero, ErrWGInvalidPubkey
	}
	var key [32]byte
	copy(key[:], decoded)

	if key == zero {
		return "", zero, ErrWGInvalidPubkey
	}
	// X25519 对低阶点会返回全零输出（crypto/ecdh 与 curve25519 都把这种点判错）。
	basePoint := [32]byte{9}
	if _, err := curve25519.X25519(basePoint[:], key[:]); err != nil {
		return "", zero, ErrWGInvalidPubkey
	}
	// clamp 特征：首字节低 3 位为 0、末字节高**两**位为 01（wireguard 的
	// clamp 把 bit255 清 0、bit254 置 1；X25519 公钥本身 bit255 恒为 0，所以
	// 只写 `&0x80==0` 是恒真条件，会把谓词退化成 1/8）。
	// wg genkey 生成的私钥 100% 命中；合法公钥误报约 6.2%（20 万把实测，
	// 见 TestClampHeuristicFalsePositiveRate）。
	// 这里宁可误拒也不让私钥落盘：误拒可重新生成，落盘不可撤回。
	if looksLikeClampedPrivateKey(key) {
		return "", zero, ErrWGPrivateKey
	}
	return base64.StdEncoding.EncodeToString(key[:]), key, nil
}

// looksLikeClampedPrivateKey 判断 32 字节是否带 X25519 clamp 特征。
//
// 条件是「首字节低 3 位全 0」且「末字节高两位为 01」。第二条在合法公钥上
// 的概率是 1/2（bit255 恒 0，只剩 bit254），所以总误报约 1/16 = 6.25%。
// 写成 `key[31]&0x80 == 0` 会让第二条恒真，误报翻倍到 12.5%——20 万把实测
// 12.303%，正是 C3 那条 bug。
func looksLikeClampedPrivateKey(key [32]byte) bool {
	return key[0]&0x07 == 0 && key[31]&0xC0 == 0x40
}

// wgPubkeyFingerprint 是日志/状态里可以出现的公钥指纹。
func wgPubkeyFingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:8])
}

// wgInterfaceAddress 把 CIDR 转成 hub 地址（网络号 + 1）。
func wgInterfaceAddress(cidr string) (netip.Prefix, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("invalid wireguard cidr %q", cidr)
	}
	if prefix.Bits() > 30 || prefix.Bits() < 16 {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("wireguard cidr must be between /16 and /30")
	}
	base := prefix.Masked().Addr()
	raw := base.As4()
	raw[3]++
	hub := netip.AddrFrom4(raw)
	if !prefix.Contains(hub) {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("wireguard cidr %q is too small", cidr)
	}
	return prefix.Masked(), hub, nil
}

// wgAddressPool 返回可用设备地址：网络号 +2 到广播地址 -1（.1 是 hub）。
func wgAddressPool(prefix netip.Prefix) []netip.Addr {
	base := prefix.Masked().Addr().As4()
	broadcast := prefix.Masked().Addr()
	maskBits := prefix.Bits()
	var addresses []netip.Addr
	for host := 2; host <= 254; host++ {
		raw := base
		raw[3] = byte(host)
		address := netip.AddrFrom4(raw)
		if !prefix.Contains(address) {
			continue
		}
		if lastAddress(prefix) == address || (maskBits == 32 && broadcast == address) {
			continue // 广播地址不能分给设备
		}
		addresses = append(addresses, address)
	}
	return addresses
}

// lastAddress 返回前缀的最后一个地址（IPv4 的广播地址）。
func lastAddress(prefix netip.Prefix) netip.Addr {
	base := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	hostBits := 32 - bits
	last := base
	for bit := 0; bit < hostBits; bit++ {
		last[3-bit/8] |= 1 << (bit % 8)
	}
	return netip.AddrFrom4(last)
}

// wgAddressInUse 报告某个地址是否已经分配给快照里的其它设备。
func wgAddressInUse(address string, devices []DeviceState, skipID string) bool {
	for i := range devices {
		if devices[i].ID == skipID {
			continue
		}
		if devices[i].WGIP == address && devices[i].WGPublicKey != "" {
			return true
		}
	}
	return false
}

// wgPubkeyInUse 报告公钥是否绑在别的设备上。
func wgPubkeyInUse(publicKey string, devices []DeviceState, skipID string) bool {
	for i := range devices {
		if devices[i].ID == skipID {
			continue
		}
		if devices[i].WGPublicKey == publicKey {
			return true
		}
	}
	return false
}

// allocateWGAddress 返回第一个空闲地址；池满返回 ErrWGNoFreeAddress。
func allocateWGAddress(prefix netip.Prefix, devices []DeviceState, skipID string) (string, error) {
	for _, candidate := range wgAddressPool(prefix) {
		text := candidate.String()
		if !wgAddressInUse(text, devices, skipID) {
			return text, nil
		}
	}
	return "", ErrWGNoFreeAddress
}

// wgEndpoint 返回模板里给设备用的 Endpoint（公网 host:port）。
func wgEndpoint(publicHost string, listen int) string {
	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(listen))
}

// wgTemplate 生成可以照抄的隧道配置。不包含任何私钥：私钥只存在于设备上，
// 这里连 "PrivateKey" 这个词都不出现（验收判据 §12.2 会对响应体 grep）。
func wgTemplate(address, hubPublicKey, endpoint, cidr string) string {
	var builder strings.Builder
	builder.WriteString("[Interface]\n")
	builder.WriteString("Address = " + address + "/32\n")
	builder.WriteString("MTU = " + strconv.Itoa(wgMTUClient) + "\n")
	builder.WriteString("\n[Peer]\n")
	builder.WriteString("PublicKey = " + hubPublicKey + "\n")
	builder.WriteString("Endpoint = " + endpoint + "\n")
	builder.WriteString("AllowedIPs = " + cidr + "\n")
	builder.WriteString("PersistentKeepalive = " + strconv.Itoa(wgKeepalive) + "\n")
	return builder.String()
}

// wgTemplateNotes 是模板旁边给人看的说明。同样不出现私钥值。
func wgTemplateNotes() []string {
	return []string{
		"私钥留在你的设备上：官方客户端自己生成，Linux/NAS 用 wg genkey 生成后填进配置的私钥行，不要上传。",
		"Address / MTU / [Peer] 三段照抄；AllowedIPs 只有组网网段，访问家里 LAN 请直接用内网地址。",
		"官方客户端填完点保存即可；Linux/NAS 保存成 600 权限的文件后 wg-quick up。",
	}
}

// newWGHubPrivateKey 生成 hub 的 X25519 私钥（base64）。
func newWGHubPrivateKey() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), nil
}

// wgHubPublicKey 从 hub 私钥推导公钥（base64）。
func wgHubPublicKey(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid wireguard hub private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// wgKeyIssuedAt 是绑定时间戳的写点，单独抽出来便于测试。
func wgKeyIssuedAt() *time.Time {
	now := time.Now().UTC()
	return &now
}
