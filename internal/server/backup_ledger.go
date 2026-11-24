package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const backupLedgerVersion = 1

// 备份档标识：决定面板上「上次备份」旁边该怎么提示。
const (
	// BackupModeEncrypted：状态已加密、密钥不在包里（默认档，恢复时要人工给 key）。
	BackupModeEncrypted = "encrypted"
	// BackupModeEncryptedWithKey：状态已加密且密钥随包（显式 --include-key）。
	BackupModeEncryptedWithKey = "encrypted_with_key"
	// BackupModePlaintext：状态本身没加密，包里的敏感字段是明文。
	BackupModePlaintext = "plaintext"
)

// BackupLedger 记录最近一次成功备份与最近一次恢复。
//
// 它单独落 data/backup-ledger.json，有两个刻意的选择：
//   - 不进备份归档：否则恢复一次旧包，就会把「上次备份时间」倒退成那个包的
//     创建时间，面板显示的是历史而不是事实；
//   - 不并进 server-state.json：后者是会被高频重写的安全核心状态（管理员
//     hash、设备、隧道），混进运维元数据只会放大每次写盘的体积与风险。
type BackupLedger struct {
	Version       int    `json:"version"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastArchive   string `json:"last_archive,omitempty"`
	LastSize      int64  `json:"last_size,omitempty"`
	LastSHA256    string `json:"last_sha256,omitempty"`
	LastMode      string `json:"last_mode,omitempty"`
	LastRestoreAt string `json:"last_restore_at,omitempty"`
}

func BackupLedgerPath(dataDir string) string {
	return filepath.Join(dataDir, "backup-ledger.json")
}

// ReadBackupLedger 读取账本；文件不存在或损坏都返回零值账本而不是错误——
// 它是观测元数据，任何情况下都不能挡住面板或恢复流程。
func ReadBackupLedger(dataDir string) BackupLedger {
	zero := BackupLedger{Version: backupLedgerVersion}
	data, err := os.ReadFile(BackupLedgerPath(dataDir))
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read the backup ledger; treating it as empty", "data_dir", dataDir, "error", err)
		}
		return zero
	}
	var ledger BackupLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		slog.Warn("backup ledger is unreadable; treating it as empty", "data_dir", dataDir, "error", err)
		return zero
	}
	if ledger.Version != backupLedgerVersion {
		slog.Warn("backup ledger has an unexpected version; treating it as empty",
			"data_dir", dataDir, "version", ledger.Version, "want", backupLedgerVersion)
		return zero
	}
	return ledger
}

// WriteBackupLedger 原子写入账本（tmp + fsync + rename），权限 0600。
func WriteBackupLedger(dataDir string, ledger BackupLedger) error {
	ledger.Version = backupLedgerVersion
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	path := BackupLedgerPath(dataDir)
	tmp := path + ".tmp"
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
	if err := file.Sync(); err != nil {
		return discard(err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// RecordBackupSuccess 在备份成功后更新账本。archive 只存文件名：面板是给
// 远程管理员看的，没有必要把服务器的绝对路径暴露给一个可能被盗的会话。
func RecordBackupSuccess(dataDir, archive string, size int64, sha256Hex, mode string, at time.Time) error {
	ledger := ReadBackupLedger(dataDir)
	ledger.LastSuccessAt = at.UTC().Format(time.RFC3339)
	ledger.LastArchive = filepath.Base(archive)
	ledger.LastSize = size
	ledger.LastSHA256 = sha256Hex
	ledger.LastMode = mode
	return WriteBackupLedger(dataDir, ledger)
}

// RecordRestore 记录一次成功恢复。账本若随旧 data 目录一起被换走，
// 调用方应先把旧账本读出来再写回新目录。
func RecordRestore(dataDir string, ledger BackupLedger, at time.Time) error {
	ledger.LastRestoreAt = at.UTC().Format(time.RFC3339)
	return WriteBackupLedger(dataDir, ledger)
}

// BackupStatusResponse 是 GET /api/backup/status 的响应体。字段名即契约。
type BackupStatusResponse struct {
	LastSuccessAt string `json:"last_success_at"`
	LastArchive   string `json:"last_archive"`
	LastSize      int64  `json:"last_size"`
	LastSHA256    string `json:"last_sha256"`
	LastMode      string `json:"last_mode"`
	LastRestoreAt string `json:"last_restore_at"`
}

// BackupStatus 把账本转成 API 形状；从未备份时各字段为空串 / 0。
func BackupStatus(dataDir string) BackupStatusResponse {
	ledger := ReadBackupLedger(dataDir)
	return BackupStatusResponse{
		LastSuccessAt: ledger.LastSuccessAt,
		LastArchive:   ledger.LastArchive,
		LastSize:      ledger.LastSize,
		LastSHA256:    ledger.LastSHA256,
		LastMode:      ledger.LastMode,
		LastRestoreAt: ledger.LastRestoreAt,
	}
}
