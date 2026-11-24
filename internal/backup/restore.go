package backup

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"goremote/internal/common"
	"goremote/internal/server"
)

// ErrConfirmationRequired 表示恢复本身是破坏性的，必须显式加 --yes。
// 单独定义是为了让调用方能把它和真正的失败区分开（退出码不同）。
var ErrConfirmationRequired = errors.New("restore replaces the current data directory; re-run with --yes to apply, or use --dry-run to preview")

// RestoreOptions 是 restore 子命令的全部输入。
type RestoreOptions struct {
	Archive string
	// DataDir 是目标数据目录（会被整体替换，旧的改名成 data.bak-<ts>）。
	DataDir string
	// CertsDir 只在 --restore-certs 时被替换。
	CertsDir string

	// KeyFile / Key 是解密状态用的密钥来源，二选一。Key 来自 GOREMOTE_STATE_KEY。
	KeyFile string
	Key     string

	// InstallKey 把归档里的 meta/state.env 写到 StateEnvFile。默认不装：
	// 恢复一份数据不等于接管一台机器的密钥。
	InstallKey   bool
	StateEnvFile string

	RestoreCerts bool
	DryRun       bool
	// Yes 是执行破坏性操作的许可。--dry-run 不需要它。
	Yes bool

	Now time.Time
	Out io.Writer
}

// RestoreResult 描述一次恢复看到/做了什么，dry-run 时就是「会做什么」。
type RestoreResult struct {
	Archive       string
	ArchiveSHA256 string
	Manifest      Manifest
	Snapshot      server.StateSnapshot

	DataDir  string
	CertsDir string

	RestoreCerts    bool
	ArchiveHasCerts bool
	InstallKey      bool
	StateEnvFile    string

	// LockHeld 只在 --dry-run 里可能为 true：服务在跑时真实恢复会被拒绝。
	LockHeld bool
	DryRun   bool

	DataBackupDir  string
	CertsBackupDir string
	CertsRestored  bool
	InstalledKey   bool
}

// Restore 校验归档、离线加载状态、再原子替换目录。
//
// 每一步失败都返回错误并由调用方给非零退出码，绝不 panic：这是灾难恢复路径，
// 出问题时运维最需要的是一个说清楚「现在磁盘上是什么状态」的句子。
func Restore(opts RestoreOptions) (*RestoreResult, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	if strings.TrimSpace(opts.Archive) == "" {
		return nil, errors.New("--from is required")
	}
	dataDir := filepath.Clean(opts.DataDir)
	certsDir := filepath.Clean(opts.CertsDir)

	result := &RestoreResult{
		Archive:      opts.Archive,
		DataDir:      dataDir,
		CertsDir:     certsDir,
		RestoreCerts: opts.RestoreCerts,
		InstallKey:   opts.InstallKey,
		StateEnvFile: opts.StateEnvFile,
		DryRun:       opts.DryRun,
	}

	// 1. 整包 sha256：先证明「这个包没被改过」，再做任何解包。
	archiveSum, err := verifyArchiveChecksum(opts.Archive)
	if err != nil {
		return nil, err
	}
	result.ArchiveSHA256 = archiveSum

	// 2. 解到临时目录。真实恢复必须解在同一文件系统（rename 跨设备会失败），
	//    dry-run 则用系统临时目录，保证数据目录旁边不留任何东西。
	workDir, err := makeWorkDir(dataDir, opts.DryRun)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)

	manifest, extracted, err := readArchive(opts.Archive, workDir)
	if err != nil {
		return nil, err
	}
	result.Manifest = manifest
	result.ArchiveHasCerts = extracted[CertPath] && extracted[CertKeyPath]

	// 3. 清单与实际内容双向核对 + 逐文件 sha256。
	if err := verifyManifest(manifest, extracted, workDir); err != nil {
		return nil, err
	}

	// 4. 密钥与离线加载。
	key, archivedKeyRaw, err := resolveRestoreKey(opts, manifest, extracted, workDir)
	if err != nil {
		return nil, err
	}
	if err := checkInstallKey(opts, manifest, key); err != nil {
		return nil, err
	}

	stateFile := filepath.Join(workDir, filepath.FromSlash(StatePath))
	snapshot, err := server.ValidateStateFile(stateFile, key)
	if err != nil {
		return nil, fmt.Errorf("offline state validation failed, this archive would not boot: %w", err)
	}
	result.Snapshot = snapshot
	if snapshot.SchemaVersion != manifest.StateSchema {
		return nil, fmt.Errorf("manifest.json says state_schema %d but the state file is %d", manifest.StateSchema, snapshot.SchemaVersion)
	}
	if snapshot.Encrypted != (manifest.StateEncryption == EncryptionEncrypted) {
		return nil, fmt.Errorf("manifest.json says state_encryption=%q but the state file disagrees", manifest.StateEncryption)
	}

	// 5. 目标目录与「服务是否在跑」。
	dataExisted := false
	if info, statErr := os.Stat(dataDir); statErr == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", dataDir)
		}
		dataExisted = true
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	lockPath := filepath.Join(dataDir, ".lock")
	var dataLock *common.FileLock
	if dataExisted {
		if opts.DryRun {
			held, probeErr := common.ProbeLockFile(lockPath)
			if probeErr != nil {
				return nil, probeErr
			}
			result.LockHeld = held
		} else {
			dataLock, err = common.TryLockFile(lockPath)
			if err != nil {
				if errors.Is(err, common.ErrLockBusy) {
					return nil, fmt.Errorf("the server is running: %s is held. Stop goremote.service (or the process) and try again", lockPath)
				}
				return nil, err
			}
			defer dataLock.Release()
		}
	}

	result.writePlan(out)

	if opts.DryRun {
		fmt.Fprintf(out, "\nDry run: nothing was changed.\n")
		return result, nil
	}
	if !opts.Yes {
		return result, ErrConfirmationRequired
	}
	return applyRestore(result, opts, workDir, dataDir, certsDir, dataExisted, ledgerOf(dataDir), archivedKeyRaw, now, out)
}

// applyRestore 执行真正的替换。每一步失败都回滚到调用前的状态。
func applyRestore(
	result *RestoreResult,
	opts RestoreOptions,
	workDir, dataDir, certsDir string,
	dataExisted bool,
	ledger server.BackupLedger,
	archivedKeyRaw []byte,
	now time.Time,
	out io.Writer,
) (*RestoreResult, error) {
	newData := filepath.Join(workDir, "data")
	if _, err := os.Stat(newData); err != nil {
		return nil, fmt.Errorf("the extracted archive has no data directory: %w", err)
	}

	// 先在新目录里建锁并持有：目录一落到目标位置，锁就已经在里面，中间没有
	// 「目录已换、锁还没建」的空窗。旧目录上的锁仍在手上，负责证明服务已停。
	newLock, lockErr := common.TryLockFile(filepath.Join(newData, ".lock"))
	if lockErr != nil {
		slog.Warn("could not pre-lock the restored data directory; the swap itself is still safe because the old lock is held",
			"error", lockErr)
	} else {
		defer newLock.Release()
	}

	stamp := now.Format("20060102-150405")
	dataBackup := ""
	if dataExisted {
		dataBackup = uniquePath(dataDir + ".bak-" + stamp)
		if err := os.Rename(dataDir, dataBackup); err != nil {
			return nil, fmt.Errorf("move the current data dir aside: %w", err)
		}
		result.DataBackupDir = dataBackup
	}
	if err := os.Rename(newData, dataDir); err != nil {
		if dataBackup != "" {
			if rbErr := os.Rename(dataBackup, dataDir); rbErr != nil {
				return nil, fmt.Errorf("install the restored data dir: %v; rolling back also failed: %w (the previous data is at %s)", err, rbErr, dataBackup)
			}
			result.DataBackupDir = ""
		}
		return nil, fmt.Errorf("install the restored data dir: %w", err)
	}

	// rollbackData 把刚换上去的数据目录挪开，再把备份换回来。
	rollbackData := func() error {
		parked := filepath.Join(workDir, "data-rollback")
		if err := os.Rename(dataDir, parked); err != nil {
			return fmt.Errorf("move the restored data dir out of the way: %w", err)
		}
		if dataBackup != "" {
			if err := os.Rename(dataBackup, dataDir); err != nil {
				return fmt.Errorf("put the previous data dir back: %w", err)
			}
			result.DataBackupDir = ""
		}
		return nil
	}

	rollbackCerts := func() {
		if result.CertsBackupDir == "" {
			return
		}
		parked := filepath.Join(workDir, "certs-rollback")
		if err := os.Rename(certsDir, parked); err != nil {
			slog.Error("could not move the restored certs aside during rollback", "certs_dir", certsDir, "error", err)
			return
		}
		if err := os.Rename(result.CertsBackupDir, certsDir); err != nil {
			slog.Error("could not put the previous certs back during rollback", "certs_dir", certsDir, "backup", result.CertsBackupDir, "error", err)
			return
		}
		result.CertsBackupDir = ""
	}

	// 证书是可选的：只有显式 --restore-certs 且包里确实有证书才动。
	if opts.RestoreCerts && result.ArchiveHasCerts {
		newCerts := filepath.Join(workDir, "certs")
		if err := os.MkdirAll(filepath.Dir(certsDir), 0o700); err != nil {
			_ = rollbackData()
			return nil, err
		}
		certsExisted := false
		if _, statErr := os.Stat(certsDir); statErr == nil {
			certsExisted = true
		}
		certsBackup := ""
		if certsExisted {
			certsBackup = uniquePath(certsDir + ".bak-" + stamp)
			if err := os.Rename(certsDir, certsBackup); err != nil {
				_ = rollbackData()
				return nil, fmt.Errorf("move the current certs dir aside: %w", err)
			}
			result.CertsBackupDir = certsBackup
		}
		if err := os.Rename(newCerts, certsDir); err != nil {
			if certsExisted {
				if rbErr := os.Rename(certsBackup, certsDir); rbErr != nil {
					slog.Error("could not restore the previous certs dir", "backup", certsBackup, "error", rbErr)
				}
				result.CertsBackupDir = ""
			}
			_ = rollbackData()
			return nil, fmt.Errorf("install the restored certs dir: %w", err)
		}
		result.CertsRestored = true
	}

	if opts.InstallKey {
		if err := writeFileAtomic(opts.StateEnvFile, archivedKeyRaw, 0o600); err != nil {
			rollbackCerts()
			if rbErr := rollbackData(); rbErr != nil {
				return nil, fmt.Errorf("install the state key: %v; rolling back the data dir also failed: %w", err, rbErr)
			}
			return nil, fmt.Errorf("install the state key: %w", err)
		}
		result.InstalledKey = true
	}

	// 账本随旧目录被换走了：把旧账本写回新目录，并记下这次恢复。
	// 它失败不影响「数据已经恢复成功」这个事实，所以只告警。
	if err := server.RecordRestore(dataDir, ledger, now); err != nil {
		slog.Warn("the data was restored but the backup ledger could not be updated", "data_dir", dataDir, "error", err)
	}

	result.writeApplied(out)
	return result, nil
}

// resolveRestoreKey 决定用哪把密钥做离线加载。
func resolveRestoreKey(opts RestoreOptions, manifest Manifest, extracted map[string]bool, workDir string) (key string, archivedRaw []byte, err error) {
	archivedKey := ""
	if extracted[StateEnvPath] {
		archivedRaw, err = os.ReadFile(filepath.Join(workDir, filepath.FromSlash(StateEnvPath)))
		if err != nil {
			return "", nil, err
		}
		archivedKey, err = parseStateEnv(string(archivedRaw))
		if err != nil {
			return "", nil, fmt.Errorf("meta/state.env in the archive: %w", err)
		}
	}

	explicit := strings.TrimSpace(opts.Key)
	if opts.KeyFile != "" {
		if explicit != "" {
			return "", nil, errors.New("the state key was provided twice (--key-file and GOREMOTE_STATE_KEY); configure exactly one")
		}
		explicit, err = readKeyFileStrict(opts.KeyFile)
		if err != nil {
			return "", nil, err
		}
	}

	switch manifest.StateEncryption {
	case EncryptionPlaintext:
		if explicit != "" {
			slog.Warn("the archive holds an unencrypted state; ignoring the state key you provided")
		}
		return "", archivedRaw, nil
	case EncryptionEncrypted:
		if explicit != "" {
			if archivedKey != "" && archivedKey != explicit {
				return "", nil, errors.New("the key you provided does not match meta/state.env inside the archive; one of them is wrong")
			}
			return explicit, archivedRaw, nil
		}
		// --install-key 本身就是「我要用包里那把密钥」，允许它充当校验密钥。
		if opts.InstallKey {
			if archivedKey == "" {
				return "", nil, errors.New("--install-key needs meta/state.env inside the archive, but it was created without --include-key")
			}
			return archivedKey, archivedRaw, nil
		}
		return "", nil, errors.New("the state in this archive is encrypted: pass --key-file or set GOREMOTE_STATE_KEY (an archive holds the key only when it was created with --include-key)")
	default:
		return "", nil, fmt.Errorf("unknown state_encryption %q in manifest.json", manifest.StateEncryption)
	}
}

// checkInstallKey 在动任何文件之前把「装密钥」的前置条件全部验证完。
func checkInstallKey(opts RestoreOptions, manifest Manifest, key string) error {
	if !opts.InstallKey {
		return nil
	}
	if manifest.StateEncryption != EncryptionEncrypted {
		return errors.New("--install-key is only valid for an archive whose state is encrypted")
	}
	if opts.StateEnvFile == "" {
		return errors.New("--install-key requires --state-env-file: that is where the key gets written")
	}
	existing, err := os.ReadFile(opts.StateEnvFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	existingKey, parseErr := parseStateEnv(string(existing))
	if parseErr != nil {
		return fmt.Errorf("%s exists but does not hold a state key (%v); refusing to overwrite it", opts.StateEnvFile, parseErr)
	}
	if existingKey != key {
		return fmt.Errorf("%s already holds a different state key; refusing to overwrite it", opts.StateEnvFile)
	}
	return nil
}

// verifyManifest 把清单和实际解出来的内容双向对齐，并逐个复核哈希。
func verifyManifest(manifest Manifest, extracted map[string]bool, workDir string) error {
	if manifest.Format != FormatVersion {
		return fmt.Errorf("archive format %d is not supported (this binary reads %d)", manifest.Format, FormatVersion)
	}
	if manifest.StateSchema < 0 {
		return fmt.Errorf("manifest.json has an invalid state_schema %d", manifest.StateSchema)
	}
	if supported := server.SupportedStateSchemaVersion(); manifest.StateSchema > supported {
		return fmt.Errorf("the archive's state schema %d is newer than this binary supports (%d); upgrade the binary instead of restoring it", manifest.StateSchema, supported)
	}
	switch manifest.StateEncryption {
	case EncryptionEncrypted, EncryptionPlaintext:
	default:
		return fmt.Errorf("manifest.json has an unknown state_encryption %q", manifest.StateEncryption)
	}
	if !extracted[StatePath] {
		return fmt.Errorf("archive has no %s", StatePath)
	}
	// 风险标记必须和实际内容一致：manifest 说「没有密钥」却塞了 state.env，
	// 或者反过来，都说明这个包被改过。
	if manifest.ContainsStateKey != extracted[StateEnvPath] {
		return fmt.Errorf("manifest.json says contains_state_key=%t but the archive disagrees", manifest.ContainsStateKey)
	}
	hasCerts := extracted[CertPath] && extracted[CertKeyPath]
	if manifest.ContainsTLSKey != hasCerts {
		return fmt.Errorf("manifest.json says contains_tls_key=%t but the archive disagrees", manifest.ContainsTLSKey)
	}
	if extracted[CertPath] != extracted[CertKeyPath] {
		return errors.New("archive holds only half of the TLS keypair (certs/server.crt / certs/server.key)")
	}
	if manifest.StateEncryption == EncryptionPlaintext && !manifest.ContainsPlaintextSecrets {
		return errors.New("manifest.json says the state is plaintext but contains_plaintext_secrets is false")
	}

	listed := make(map[string]bool, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path == ManifestPath {
			return fmt.Errorf("manifest.json lists itself; a manifest cannot vouch for its own hash")
		}
		if err := validateMemberPath(entry.Path); err != nil {
			return err
		}
		if listed[entry.Path] {
			return fmt.Errorf("manifest.json lists %q more than once", entry.Path)
		}
		listed[entry.Path] = true
		if !extracted[entry.Path] {
			return fmt.Errorf("manifest.json lists %q but the archive does not contain it", entry.Path)
		}
	}
	for path := range extracted {
		if path == ManifestPath {
			continue
		}
		if !listed[path] {
			return fmt.Errorf("archive contains %q which manifest.json does not list", path)
		}
	}

	for _, entry := range manifest.Files {
		target := filepath.Join(workDir, filepath.FromSlash(entry.Path))
		data, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		if int64(len(data)) != entry.Size {
			return fmt.Errorf("%s is %d bytes, manifest.json says %d", entry.Path, len(data), entry.Size)
		}
		if got := hashBytes(data); got != entry.SHA256 {
			return fmt.Errorf("%s does not match its manifest hash (want %s, got %s)", entry.Path, entry.SHA256, got)
		}
		mode, err := parseMode(entry.Mode)
		if err != nil {
			return err
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
	}
	return nil
}

// makeWorkDir 为解包准备临时目录。真实恢复必须与目标数据目录同文件系统；
// dry-run 用系统临时目录，保证目标旁边什么都不留。
func makeWorkDir(dataDir string, dryRun bool) (string, error) {
	parent := os.TempDir()
	if !dryRun {
		parent = filepath.Dir(dataDir)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", err
		}
	}
	return os.MkdirTemp(parent, ".goremote-restore-")
}

// uniquePath 避免同一秒内两次操作撞名。
func uniquePath(base string) string {
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base
	}
	for index := 2; index < 1000; index++ {
		candidate := fmt.Sprintf("%s-%d", base, index)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
}

// ledgerOf 读旧数据目录的账本；目录不存在时返回零值。
func ledgerOf(dataDir string) server.BackupLedger {
	if _, err := os.Stat(dataDir); err != nil {
		return server.BackupLedger{}
	}
	return server.ReadBackupLedger(dataDir)
}

func yesNo(value bool) string {
	if value {
		return "included"
	}
	return "not included"
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, " ")
}

// writePlan 打印「这个包是什么、将会发生什么」。dry-run 与真实恢复共用它，
// 所以确认之前看到的就是将要执行的那件事。
func (r *RestoreResult) writePlan(w io.Writer) {
	m := r.Manifest
	fmt.Fprintf(w, "archive      : %s\n", r.Archive)
	fmt.Fprintf(w, "sha256       : %s\n", r.ArchiveSHA256)
	fmt.Fprintf(w, "created at   : %s\n", m.CreatedAt.UTC().Format(time.RFC3339))
	if m.Tool.Commit != "" {
		fmt.Fprintf(w, "tool         : %s (commit %s)\n", m.Tool.Version, m.Tool.Commit)
	} else {
		fmt.Fprintf(w, "tool         : %s\n", m.Tool.Version)
	}
	if m.Host != "" {
		fmt.Fprintf(w, "host         : %s\n", m.Host)
	}
	fmt.Fprintf(w, "state        : schema %d, %s, %d devices (%d authorized), %d tunnels\n",
		r.Snapshot.SchemaVersion, m.StateEncryption, r.Snapshot.Devices, r.Snapshot.AuthorizedDevices, r.Snapshot.Tunnels)
	fmt.Fprintf(w, "tunnel ports : %s\n", formatPorts(r.Snapshot.Ports))
	fmt.Fprintf(w, "files        : %d\n", len(m.Files))
	fmt.Fprintf(w, "secrets      : state key %s, TLS key %s, plaintext secrets %s\n",
		yesNo(m.ContainsStateKey), yesNo(m.ContainsTLSKey), yesNo(m.ContainsPlaintextSecrets))

	switch {
	case !r.RestoreCerts:
		fmt.Fprintf(w, "certs        : %s left untouched (pass --restore-certs to replace it)\n", r.CertsDir)
	case !r.ArchiveHasCerts:
		fmt.Fprintf(w, "certs        : archive contains no certs, nothing to restore\n")
	default:
		fmt.Fprintf(w, "certs        : %s will be replaced\n", r.CertsDir)
	}
	if r.InstallKey {
		fmt.Fprintf(w, "state key    : will be written to %s\n", r.StateEnvFile)
	} else {
		fmt.Fprintf(w, "state key    : not installed (pass --install-key --state-env-file to write it)\n")
	}
	fmt.Fprintf(w, "data         : %s will be replaced (previous dir kept as %s.bak-<ts>)\n", r.DataDir, r.DataDir)
	if r.LockHeld {
		fmt.Fprintf(w, "server       : RUNNING — a real restore would be refused until it stops\n")
	} else {
		fmt.Fprintf(w, "server       : not running\n")
	}
	if r.DryRun {
		fmt.Fprintf(w, "mode         : DRY RUN\n")
	} else {
		fmt.Fprintf(w, "mode         : APPLY\n")
	}
}

// writeApplied 在真正换完之后打印结果；此时才敢说「旧的在哪」。
func (r *RestoreResult) writeApplied(w io.Writer) {
	fmt.Fprintf(w, "\nrestored %s from %s\n", r.DataDir, filepath.Base(r.Archive))
	if r.DataBackupDir != "" {
		fmt.Fprintf(w, "previous data dir kept at %s\n", r.DataBackupDir)
	}
	if r.CertsRestored {
		fmt.Fprintf(w, "restored %s\n", r.CertsDir)
		if r.CertsBackupDir != "" {
			fmt.Fprintf(w, "previous certs dir kept at %s\n", r.CertsBackupDir)
		}
	}
	if r.InstalledKey {
		fmt.Fprintf(w, "state key written to %s\n", r.StateEnvFile)
	}
}
