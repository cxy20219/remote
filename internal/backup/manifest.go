// Package backup 实现 GoRemote 的离线备份与恢复：把一个部署真正需要的少数
// 文件打成带清单的 tar.gz，恢复时先整包校验、再逐文件校验、再离线加载状态，
// 最后原子交换目录。
//
// 明确不做：增量备份、远端上传、自写加密容器、跨版本降级、自动轮换清理。
// 归档的机密性靠两件事：默认不含 state key（密钥留在这台机器上/由人保管），
// 以及 0600 的文件权限。需要连密钥一起搬时由调用方显式选择，并在 manifest
// 与产物文件名上双重标记——让「这个包里有密钥」在任何时候都一眼可见。
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// FormatVersion 是归档格式版本。格式不兼容时升它，而不是靠字段缺省猜。
const FormatVersion = 1

// 归档内的固定路径。restore 只接受这张白名单：包里的任何其他路径都会被
// 拒绝，避免一个被篡改的归档把文件写到目标目录之外。
const (
	ManifestPath  = "manifest.json"
	RuntimePath   = "meta/runtime.json"
	StateEnvPath  = "meta/state.env"
	StatePath     = "data/server-state.json"
	BlacklistPath = "data/blacklist.json"
	CertPath      = "certs/server.crt"
	CertKeyPath   = "certs/server.key"
)

// 状态在包里的形态，写进 manifest 供恢复前判断「要不要密钥」。
const (
	EncryptionEncrypted = "encrypted"
	EncryptionPlaintext = "plaintext"
)

const (
	// maxMemberBytes 单文件上限：状态与黑名单都在 1MB 量级，64MB 足够宽松，
	// 同时挡住「解压炸弹把自己撑爆」。
	maxMemberBytes = 64 << 20
	// maxTotalBytes 整包解压上限。
	maxTotalBytes = 256 << 20
)

// ToolInfo 记录打这个包的二进制，便于事后回答「这个包是谁、什么时候打的」。
type ToolInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// FileEntry 是 manifest 里的一个成员。size 与 sha256 在恢复时逐个复核。
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Manifest 是归档的目录：必须是包内第一个成员，否则 restore 直接拒绝。
//
// 三个 contains_* 是给人和工具看的风险标记，不是装饰——restore 会校验它们
// 与实际内容一致，manifest 说「没有密钥」但包里塞了 state.env 会被拒绝。
type Manifest struct {
	Format                   int         `json:"format"`
	CreatedAt                time.Time   `json:"created_at"`
	Tool                     ToolInfo    `json:"tool"`
	Host                     string      `json:"host"`
	StateSchema              int         `json:"state_schema"`
	StateEncryption          string      `json:"state_encryption"`
	ContainsStateKey         bool        `json:"contains_state_key"`
	ContainsPlaintextSecrets bool        `json:"contains_plaintext_secrets"`
	ContainsTLSKey           bool        `json:"contains_tls_key"`
	Files                    []FileEntry `json:"files"`
}

// Runtime 是 mkdir 出来给人看的运行现场快照：这个包是从哪台机器的哪个目录
// 出来的、当时有多少设备与隧道。它不参与任何校验决策（那是 manifest 的活）。
type Runtime struct {
	CreatedAt         time.Time `json:"created_at"`
	Tool              ToolInfo  `json:"tool"`
	Host              string    `json:"host"`
	DataDir           string    `json:"data_dir"`
	CertsDir          string    `json:"certs_dir"`
	StateSchema       int       `json:"state_schema"`
	StateEncryption   string    `json:"state_encryption"`
	Devices           int       `json:"devices"`
	AuthorizedDevices int       `json:"authorized_devices"`
	Tunnels           int       `json:"tunnels"`
	Ports             []int     `json:"ports"`
}

// allowedMembers 是归档允许出现的全部路径。manifest.json 也在这里，
// 但它是唯一被特殊对待（必须第一个）的成员。
var allowedMembers = map[string]bool{
	ManifestPath:  true,
	RuntimePath:   true,
	StateEnvPath:  true,
	StatePath:     true,
	BlacklistPath: true,
	CertPath:      true,
	CertKeyPath:   true,
}

// validateMemberPath 只放行白名单内的相对路径，并显式拒绝任何可能逃出
// 解压目录的写法。归档是我们自己打的，但恢复必须按不可信输入对待。
func validateMemberPath(path string) error {
	if path == "" {
		return fmt.Errorf("archive contains an entry with an empty name")
	}
	if strings.Contains(path, "\\") {
		return fmt.Errorf("archive entry %q uses a backslash", path)
	}
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("archive entry %q is an absolute path", path)
	}
	if path != strings.TrimPrefix(path, "./") || strings.Contains(path, "..") {
		return fmt.Errorf("archive entry %q is not a clean relative path", path)
	}
	if !allowedMembers[path] {
		return fmt.Errorf("archive entry %q is not part of a goremote backup", path)
	}
	return nil
}

// hashBytes 返回 hex sha256，全部校验共用同一种表示。
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func formatMode(mode os.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

func parseMode(raw string) (os.FileMode, error) {
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid file mode %q in manifest: %w", raw, err)
	}
	if value > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q in manifest: only permission bits are allowed", raw)
	}
	return os.FileMode(value), nil
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
