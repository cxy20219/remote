package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"goremote/internal/common"
	"goremote/internal/server"
)

// CreateOptions 是 backup 子命令的全部输入。
type CreateOptions struct {
	// DataDir 必须包含 server-state.json；可选 blacklist.json。
	DataDir string
	// CertsDir 里有 server.crt / server.key 时一并打包；两个都没有就跳过，
	// 只有一个则拒绝（半套证书是坏部署，不能打成「可恢复」的包）。
	CertsDir string
	OutDir   string
	// IncludeKey 把 state 密钥一起打包，必须同时给 StateEnvFile。
	IncludeKey   bool
	StateEnvFile string
	// AllowPlaintext 允许备份一份没有加密的状态（敏感字段是明文）。
	AllowPlaintext bool

	// Now / Host 由测试注入；零值表示取真实时间与本机主机名。
	Now  time.Time
	Host string
}

// CreateResult 描述一次成功的备份。
type CreateResult struct {
	Archive  string
	SHA256   string
	Size     int64
	Manifest Manifest
	Runtime  Runtime
}

// stateSummary 是「不解密也要知道」的状态概况。设备与隧道定义都在明文区，
// 所以默认档（不含密钥）照样能给出准确的计数与端口表。
type stateSummary struct {
	SchemaVersion int
	Encrypted     bool
	Devices       int
	Tunnels       int
	Ports         []int
}

func inspectState(data []byte) (stateSummary, error) {
	var raw struct {
		SchemaVersion int               `json:"schema_version"`
		Encrypted     json.RawMessage   `json:"encrypted"`
		Devices       []json.RawMessage `json:"devices"`
		Tunnels       []struct {
			PublicPort int `json:"public_port"`
		} `json:"tunnels"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return stateSummary{}, fmt.Errorf("parse data/server-state.json: %w", err)
	}
	summary := stateSummary{
		SchemaVersion: raw.SchemaVersion,
		Encrypted:     len(raw.Encrypted) > 0 && string(raw.Encrypted) != "null",
		Devices:       len(raw.Devices),
		Tunnels:       len(raw.Tunnels),
	}
	seen := make(map[int]struct{}, len(raw.Tunnels))
	for _, tunnel := range raw.Tunnels {
		if tunnel.PublicPort > 0 {
			seen[tunnel.PublicPort] = struct{}{}
		}
	}
	summary.Ports = make([]int, 0, len(seen))
	for port := range seen {
		summary.Ports = append(summary.Ports, port)
	}
	sort.Ints(summary.Ports)
	return summary, nil
}

// Create 打一个备份包并更新账本。
//
// 顺序是刻意的：先把所有文件读进内存并算好哈希，再写 manifest，最后写归档。
// 这样 manifest 在写下第一个 tar 成员之前就是完整的，不需要回填。
func Create(opts CreateOptions) (*CreateResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	dataDir := filepath.Clean(opts.DataDir)
	certsDir := filepath.Clean(opts.CertsDir)
	outDir := filepath.Clean(opts.OutDir)

	stateFile := filepath.Join(dataDir, "server-state.json")
	stateBytes, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found: --data must point at the directory that holds server-state.json", stateFile)
		}
		return nil, err
	}
	summary, err := inspectState(stateBytes)
	if err != nil {
		return nil, err
	}

	encryption := EncryptionEncrypted
	if !summary.Encrypted {
		encryption = EncryptionPlaintext
	}
	// 明文状态里躺着 TOTP 密钥与设备密钥。默认拒绝不是洁癖：一个「看起来
	// 正常」的备份包把明文密钥带出服务器，正是最难被发现的那类泄漏。
	if !summary.Encrypted && !opts.AllowPlaintext {
		return nil, fmt.Errorf("%s is not encrypted: it contains plaintext secrets (TOTP secret, device keys). Re-run with --allow-plaintext to include it anyway", stateFile)
	}

	var keyRaw []byte
	if opts.IncludeKey {
		if opts.StateEnvFile == "" {
			return nil, errors.New("--include-key requires --state-env-file: the state key must come from a file we can copy, not from the environment")
		}
		if !summary.Encrypted {
			return nil, errors.New("--include-key is meaningless: the state file is not encrypted")
		}
		key, raw, err := readStateEnvFile(opts.StateEnvFile)
		if err != nil {
			return nil, err
		}
		// 证明这把密钥真的能打开这份状态。否则会产出一个「标着含密钥、
		// 实际打不开」的包，等到真的要用它恢复时才发现。
		if _, err := server.ValidateStateFile(stateFile, key); err != nil {
			return nil, fmt.Errorf("the key in %s does not open %s: %w", opts.StateEnvFile, stateFile, err)
		}
		keyRaw = raw
	}

	host := opts.Host
	if host == "" {
		if name, err := os.Hostname(); err == nil {
			host = name
		}
	}
	tool := ToolInfo{Version: common.BuildVersion(), Commit: common.BuildCommit()}

	runtimeInfo := Runtime{
		CreatedAt:       now,
		Tool:            tool,
		Host:            host,
		DataDir:         absPath(dataDir),
		CertsDir:        absPath(certsDir),
		StateSchema:     summary.SchemaVersion,
		StateEncryption: encryption,
		Devices:         summary.Devices,
		Tunnels:         summary.Tunnels,
		Ports:           summary.Ports,
	}
	runtimeBytes, err := marshalJSON(runtimeInfo)
	if err != nil {
		return nil, err
	}

	members := []member{
		{path: RuntimePath, data: runtimeBytes, mode: 0o600},
		{path: StatePath, data: stateBytes, mode: 0o600},
	}

	if data, err := os.ReadFile(filepath.Join(dataDir, "blacklist.json")); err == nil {
		members = append(members, member{path: BlacklistPath, data: data, mode: 0o600})
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	hasTLSKey := false
	certData, certErr := os.ReadFile(filepath.Join(certsDir, "server.crt"))
	keyData, keyErr := os.ReadFile(filepath.Join(certsDir, "server.key"))
	switch {
	case certErr == nil && keyErr == nil:
		hasTLSKey = true
		members = append(members,
			member{path: CertPath, data: certData, mode: 0o644},
			member{path: CertKeyPath, data: keyData, mode: 0o600},
		)
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		slog.Info("no TLS keypair in the certs dir; the archive will not contain certificates", "certs_dir", certsDir)
	case certErr != nil && !os.IsNotExist(certErr):
		return nil, certErr
	case keyErr != nil && !os.IsNotExist(keyErr):
		return nil, keyErr
	default:
		return nil, fmt.Errorf("%s holds only half of the TLS keypair (server.crt / server.key); refusing to archive a broken deployment", certsDir)
	}

	if len(keyRaw) > 0 {
		members = append(members, member{path: StateEnvPath, data: keyRaw, mode: 0o600})
	}

	manifest := Manifest{
		Format:                   FormatVersion,
		CreatedAt:                now,
		Tool:                     tool,
		Host:                     host,
		StateSchema:              summary.SchemaVersion,
		StateEncryption:          encryption,
		ContainsStateKey:         len(keyRaw) > 0,
		ContainsPlaintextSecrets: !summary.Encrypted,
		ContainsTLSKey:           hasTLSKey,
		Files:                    make([]FileEntry, 0, len(members)),
	}
	for _, entry := range members {
		manifest.Files = append(manifest.Files, FileEntry{
			Path:   entry.path,
			Size:   int64(len(entry.data)),
			Mode:   formatMode(entry.mode),
			SHA256: hashBytes(entry.data),
		})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifestBytes, err := marshalJSON(manifest)
	if err != nil {
		return nil, err
	}

	if hasTLSKey {
		slog.Warn("the backup archive contains the TLS private key (certs/server.key); store it with the same care as the certificate itself", "certs_dir", certsDir)
	}
	if len(keyRaw) > 0 {
		slog.Warn("the backup archive contains the state encryption key (meta/state.env); anyone who gets this file can read every secret in it", "state_env_file", opts.StateEnvFile)
	}

	base := "goremote-backup-" + now.Format("20060102T150405Z")
	if opts.IncludeKey {
		base += ".with-key"
	}
	archivePath := filepath.Join(outDir, base+".tar.gz")
	if err := writeArchive(archivePath, manifestBytes, members, now); err != nil {
		return nil, err
	}
	sum, size, err := checksumFile(archivePath)
	if err != nil {
		return nil, err
	}
	if err := writeChecksumSidecar(archivePath, sum); err != nil {
		return nil, err
	}

	mode := server.BackupModeEncrypted
	switch {
	case !summary.Encrypted:
		mode = server.BackupModePlaintext
	case opts.IncludeKey:
		mode = server.BackupModeEncryptedWithKey
	}
	if err := server.RecordBackupSuccess(dataDir, archivePath, size, sum, mode, now); err != nil {
		// 归档已经写成功，不能因为元数据失败就说备份失败；但也不能假装没事。
		slog.Error("backup archive written but the ledger could not be updated; the panel will keep showing the previous backup time",
			"data_dir", dataDir, "error", err)
	}

	return &CreateResult{Archive: archivePath, SHA256: sum, Size: size, Manifest: manifest, Runtime: runtimeInfo}, nil
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
