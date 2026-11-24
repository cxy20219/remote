package backup

import (
	"bytes"
	"embed"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goremote/internal/common"
	"goremote/internal/server"
)

// prewarmLock 先建出 data/.lock 再放掉：服务启动后这个文件本来就会存在，
// 先把它创建出来，测试快照才不会被「首次建锁」这种正常副作用干扰。
func prewarmLock(t *testing.T, dataDir string) {
	t.Helper()
	lock, err := common.TryLockFile(filepath.Join(dataDir, ".lock"))
	if err != nil {
		t.Fatalf("prewarm lock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
}

// assertNoTempDirs 确认解包临时目录没有残留（成功恢复会留下 .bak，那是有意的）。
func assertNoTempDirs(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".goremote-restore-") {
			t.Fatalf("a temporary restore directory was left behind: %s", entry.Name())
		}
	}
}

// assertNoLeftovers 确认目标目录旁边既没有临时目录也没有 .bak 残留。
func assertNoLeftovers(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".goremote-restore-") {
			t.Fatalf("a temporary restore directory was left behind: %s", name)
		}
		if strings.Contains(name, ".bak-") {
			t.Fatalf("a backup directory was left behind: %s", name)
		}
	}
}

func restoreInto(t *testing.T, opts RestoreOptions) (*RestoreResult, error) {
	t.Helper()
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Now.IsZero() {
		opts.Now = testNow
	}
	return Restore(opts)
}

func TestRestoreReplacesDataAndKeepsPrevious(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})
	prewarmLock(t, f.dataDir)
	before := snapshotTree(t, f.dataDir)
	archivedState, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}

	// 制造一次「事故」：把设备全删掉，再恢复。
	store := server.NewStateStore(f.statePath)
	if err := store.SetEncryptionKey(f.key); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	for _, device := range store.GetAllDevices() {
		if _, err := store.RemoveDevice(device.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	restored, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  f.dataDir,
		CertsDir: f.certsDir,
		KeyFile:  f.keyFile,
		Yes:      true,
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}

	after, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, archivedState) {
		t.Fatal("the restored state file does not match the archived bytes")
	}

	if restored.DataBackupDir == "" {
		t.Fatal("the previous data dir must be kept")
	}
	if !strings.Contains(filepath.Base(restored.DataBackupDir), ".bak-") {
		t.Fatalf("previous data dir = %s, want a .bak-<ts> name", restored.DataBackupDir)
	}
	backupSnapshot := snapshotTree(t, restored.DataBackupDir)
	// 备份目录是「事故后」的那份内容，必须与恢复后的目录不同，否则测试没有区分力。
	if sameSnapshot(before, backupSnapshot) {
		t.Fatal("the kept data dir equals the pre-incident snapshot; the fixture did not actually change")
	}
	if _, err := os.Stat(filepath.Join(restored.DataBackupDir, "server-state.json")); err != nil {
		t.Fatalf("the kept data dir has no state file: %v", err)
	}

	if restored.Snapshot.Devices != 3 || restored.Snapshot.Tunnels != 4 {
		t.Fatalf("snapshot = %+v", restored.Snapshot)
	}
	assertNoTempDirs(t, f.root)
}

func TestRestoreDryRunChangesNothing(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})
	prewarmLock(t, f.dataDir)

	dataBefore := snapshotTree(t, f.dataDir)
	certsBefore := snapshotTree(t, f.certsDir)
	rootBefore := snapshotTree(t, f.root)

	var out bytes.Buffer
	restored, err := restoreInto(t, RestoreOptions{
		Archive:      result.Archive,
		DataDir:      f.dataDir,
		CertsDir:     f.certsDir,
		KeyFile:      f.keyFile,
		RestoreCerts: true,
		DryRun:       true,
		Out:          &out,
	})
	if err != nil {
		t.Fatalf("dry run must not need --yes and must succeed: %v", err)
	}
	if !restored.DryRun {
		t.Fatal("result must be marked as a dry run")
	}
	if restored.DataBackupDir != "" || restored.CertsBackupDir != "" {
		t.Fatal("a dry run must not report any backup directory")
	}
	if !sameSnapshot(dataBefore, snapshotTree(t, f.dataDir)) {
		t.Fatal("the data dir changed during a dry run")
	}
	if !sameSnapshot(certsBefore, snapshotTree(t, f.certsDir)) {
		t.Fatal("the certs dir changed during a dry run")
	}
	if !sameSnapshot(rootBefore, snapshotTree(t, f.root)) {
		t.Fatal("the parent directory changed during a dry run (a temp dir or .bak was created)")
	}
	if !strings.Contains(out.String(), "dry run") && !strings.Contains(out.String(), "DRY RUN") {
		t.Fatalf("the dry run must say so, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "3 devices") {
		t.Fatalf("the plan should describe the state, got:\n%s", out.String())
	}
}

func TestRestoreRequiresYes(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})
	prewarmLock(t, f.dataDir)
	before := snapshotTree(t, f.dataDir)

	var out bytes.Buffer
	_, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  f.dataDir,
		CertsDir: f.certsDir,
		KeyFile:  f.keyFile,
		Out:      &out,
	})
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("err = %v, want ErrConfirmationRequired", err)
	}
	if !sameSnapshot(before, snapshotTree(t, f.dataDir)) {
		t.Fatal("a refused restore must not touch the data dir")
	}
	if !strings.Contains(out.String(), "APPLY") {
		t.Fatalf("the plan should have been printed before the refusal, got:\n%s", out.String())
	}
}

func TestRestoreNeedsTheStateKey(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	targetRoot := t.TempDir()
	targetData := filepath.Join(targetRoot, "data")
	targetCerts := filepath.Join(targetRoot, "certs")

	_, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  targetData,
		CertsDir: targetCerts,
		Yes:      true,
	})
	if err == nil {
		t.Fatal("restoring an encrypted state without a key must fail")
	}
	if !strings.Contains(err.Error(), "--key-file") || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("the error must say how to pass the key, got: %v", err)
	}
	if _, statErr := os.Stat(targetData); !os.IsNotExist(statErr) {
		t.Fatal("a failed restore must not create the target data dir")
	}

	wrongKeyFile := filepath.Join(f.root, "wrong.env")
	wrongKey := "base64:" + base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	if err := os.WriteFile(wrongKeyFile, []byte(common.StateKeyEnvName+"="+wrongKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  targetData,
		CertsDir: targetCerts,
		KeyFile:  wrongKeyFile,
		Yes:      true,
	})
	if err == nil || !strings.Contains(err.Error(), "offline state validation failed") {
		t.Fatalf("a wrong key must fail offline validation, got: %v", err)
	}
	if _, statErr := os.Stat(targetData); !os.IsNotExist(statErr) {
		t.Fatal("a wrong key must not create the target data dir")
	}
}

func TestRestoreRefusesWhileServerRuns(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})
	prewarmLock(t, f.dataDir)

	lock, err := common.TryLockFile(filepath.Join(f.dataDir, ".lock"))
	if err != nil {
		t.Fatalf("hold the lock: %v", err)
	}
	defer lock.Release()

	before := snapshotTree(t, f.dataDir)
	_, err = restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  f.dataDir,
		CertsDir: f.certsDir,
		KeyFile:  f.keyFile,
		Yes:      true,
	})
	if err == nil || !strings.Contains(err.Error(), "server is running") {
		t.Fatalf("a running server must block the restore, got: %v", err)
	}
	if !sameSnapshot(before, snapshotTree(t, f.dataDir)) {
		t.Fatal("a blocked restore must not touch the data dir")
	}

	// dry-run 不写盘，但要把「现在恢复会被拒」说出来。
	dry, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  f.dataDir,
		CertsDir: f.certsDir,
		KeyFile:  f.keyFile,
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !dry.LockHeld {
		t.Fatal("dry run must report that the server is holding the lock")
	}
}

func TestRestoreInstallKey(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{IncludeKey: true, StateEnvFile: f.keyFile})
	sourceBytes, err := os.ReadFile(f.keyFile)
	if err != nil {
		t.Fatal(err)
	}

	targetRoot := t.TempDir()
	targetData := filepath.Join(targetRoot, "data")
	targetCerts := filepath.Join(targetRoot, "certs")
	keyTarget := filepath.Join(targetRoot, "state.env")

	// 1. --install-key 但没给 --state-env-file。
	_, err = restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts,
		InstallKey: true, Yes: true,
	})
	if err == nil || !strings.Contains(err.Error(), "--state-env-file") {
		t.Fatalf("--install-key without a destination must fail, got %v", err)
	}

	// 2. 正常装：不带 --key-file 也能用包里的密钥完成校验。
	restored, err := restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts,
		InstallKey: true, StateEnvFile: keyTarget, Yes: true,
	})
	if err != nil {
		t.Fatalf("restore with --install-key: %v", err)
	}
	if !restored.InstalledKey {
		t.Fatal("result must report the key installation")
	}
	installed, err := os.ReadFile(keyTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, sourceBytes) {
		t.Fatal("the installed key file is not byte-identical to the archived one")
	}
	info, err := os.Stat(keyTarget)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("installed key mode = %04o, want 0600", perm)
	}

	// 3. 目标已有同一把钥匙：允许（幂等）。
	if _, err := restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts,
		InstallKey: true, StateEnvFile: keyTarget, Yes: true,
	}); err != nil {
		t.Fatalf("reinstalling the same key must be allowed: %v", err)
	}

	// 4. 目标已有另一把钥匙：拒绝，且数据不动。
	otherKeyTarget := filepath.Join(targetRoot, "other.env")
	otherKey := "base64:" + base64.StdEncoding.EncodeToString(bytesRepeat(0x11, 32))
	if err := os.WriteFile(otherKeyTarget, []byte(common.StateKeyEnvName+"="+otherKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, targetData)
	_, err = restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts,
		InstallKey: true, StateEnvFile: otherKeyTarget, Yes: true,
	})
	if err == nil || !strings.Contains(err.Error(), "different state key") {
		t.Fatalf("a conflicting key must be refused, got %v", err)
	}
	if !sameSnapshot(before, snapshotTree(t, targetData)) {
		t.Fatal("a refused key install must not touch the data dir")
	}

	// 5. 包里没有密钥却要求安装。
	noKey := f.create(t, CreateOptions{Now: testNow.Add(2 * time.Hour)})
	_, err = restoreInto(t, RestoreOptions{
		Archive: noKey.Archive, DataDir: filepath.Join(targetRoot, "data2"), CertsDir: targetCerts,
		InstallKey: true, StateEnvFile: filepath.Join(targetRoot, "state2.env"), Yes: true,
	})
	if err == nil || !strings.Contains(err.Error(), "without --include-key") {
		t.Fatalf("installing a key from an archive that has none must fail, got %v", err)
	}
}

func TestRestoreRestoresCertsOnlyWhenAsked(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	targetRoot := t.TempDir()
	targetData := filepath.Join(targetRoot, "data")
	targetCerts := filepath.Join(targetRoot, "certs")

	if _, err := restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts, KeyFile: f.keyFile, Yes: true,
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(targetCerts); !os.IsNotExist(err) {
		t.Fatal("certs must not be restored without --restore-certs")
	}

	restored, err := restoreInto(t, RestoreOptions{
		Archive: result.Archive, DataDir: targetData, CertsDir: targetCerts, KeyFile: f.keyFile,
		RestoreCerts: true, Yes: true, Now: testNow.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("restore with certs: %v", err)
	}
	if !restored.CertsRestored {
		t.Fatal("result must report the certs restore")
	}
	want, err := os.ReadFile(f.certKeyPth)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(targetCerts, "server.key"))
	if err != nil {
		t.Fatalf("restored certs dir has no server.key: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the restored TLS key does not match the archived one")
	}
	info, err := os.Stat(filepath.Join(targetCerts, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("restored TLS key mode = %04o, want 0600", perm)
	}
}

// TestRestoreRollsBackWhenCertsSwapFails 是「交换中途失败要回滚」那条判据：
// 数据目录已经换好、证书换失败时，数据目录必须原样退回。
func TestRestoreRollsBackWhenCertsSwapFails(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})
	prewarmLock(t, f.dataDir)

	// 先改一下当前状态，才能区分「回滚成功」与「恢复成功」。
	store := server.NewStateStore(f.statePath)
	if err := store.SetEncryptionKey(f.key); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	store.AddDevice(&server.DeviceState{ID: "dev-marker", Name: "marker", Status: "authorized"})
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, f.dataDir)

	// 目标证书目录的父路径是个普通文件，MkdirAll 必然失败。
	blocked := filepath.Join(f.root, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := restoreInto(t, RestoreOptions{
		Archive:      result.Archive,
		DataDir:      f.dataDir,
		CertsDir:     filepath.Join(blocked, "certs"),
		KeyFile:      f.keyFile,
		RestoreCerts: true,
		Yes:          true,
	})
	if err == nil {
		t.Fatal("the restore should have failed while swapping the certs")
	}
	if !sameSnapshot(before, snapshotTree(t, f.dataDir)) {
		t.Fatal("the data dir was not rolled back after the certs swap failed")
	}

	snapshot, err := server.ValidateStateFile(f.statePath, f.key)
	if err != nil {
		t.Fatalf("the rolled-back state must still load: %v", err)
	}
	if snapshot.Devices != 4 {
		t.Fatalf("devices = %d, want the 4 devices of the modified (rolled back) state", snapshot.Devices)
	}
	assertNoLeftovers(t, f.root)
}

func TestRestorePlaintextArchiveNeedsNoKey(t *testing.T) {
	f := newFixture(t, false)
	result := f.create(t, CreateOptions{AllowPlaintext: true})

	targetRoot := t.TempDir()
	restored, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  filepath.Join(targetRoot, "data"),
		CertsDir: filepath.Join(targetRoot, "certs"),
		Yes:      true,
	})
	if err != nil {
		t.Fatalf("restore of a plaintext archive: %v", err)
	}
	if restored.Snapshot.Encrypted {
		t.Fatal("a plaintext archive must load as plaintext")
	}
	if restored.Snapshot.Devices != 3 || restored.Snapshot.Tunnels != 4 {
		t.Fatalf("snapshot = %+v", restored.Snapshot)
	}
}

func TestRestoreRejectsNewerStateSchema(t *testing.T) {
	f := newFixture(t, true)

	stateBytes, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	members := []member{{path: StatePath, data: stateBytes, mode: 0o600}}
	manifestBytes, err := marshalJSON(Manifest{
		Format:          FormatVersion,
		CreatedAt:       testNow,
		StateSchema:     99,
		StateEncryption: EncryptionEncrypted,
		Files: []FileEntry{
			{Path: StatePath, Size: int64(len(stateBytes)), Mode: "0600", SHA256: hashBytes(stateBytes)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(f.outDir, "newer.tar.gz")
	if err := writeArchive(archivePath, manifestBytes, members, testNow); err != nil {
		t.Fatal(err)
	}
	sum, _, err := checksumFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeChecksumSidecar(archivePath, sum); err != nil {
		t.Fatal(err)
	}

	_, err = restoreInto(t, RestoreOptions{
		Archive:  archivePath,
		DataDir:  filepath.Join(f.root, "other", "data"),
		CertsDir: filepath.Join(f.root, "other", "certs"),
		KeyFile:  f.keyFile,
		Yes:      true,
	})
	if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("a future state schema must be refused, got %v", err)
	}
}

func TestRestorePreservesLedger(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	prewarmLock(t, f.dataDir)
	restored, err := restoreInto(t, RestoreOptions{
		Archive:  result.Archive,
		DataDir:  f.dataDir,
		CertsDir: f.certsDir,
		KeyFile:  f.keyFile,
		Yes:      true,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.DataBackupDir == "" {
		t.Fatal("the previous data dir must be kept so its ledger can be carried over")
	}

	status := server.BackupStatus(f.dataDir)
	if status.LastRestoreAt != testNow.Format(time.RFC3339) {
		t.Fatalf("last_restore_at = %q", status.LastRestoreAt)
	}
	if status.LastSuccessAt == "" || status.LastArchive != filepath.Base(result.Archive) {
		t.Fatalf("the ledger was lost in the swap: %+v", status)
	}
}

// TestRestoredDataStartsServer 是阶段验收那条「从备份包恢复到临时目录后服务
// 能正常启动、设备身份保留」：真起一次服务，不是只读文件。
func TestRestoredDataStartsServer(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	targetRoot := t.TempDir()
	targetData := filepath.Join(targetRoot, "data")
	targetCerts := filepath.Join(targetRoot, "certs")

	if _, err := restoreInto(t, RestoreOptions{
		Archive:      result.Archive,
		DataDir:      targetData,
		CertsDir:     targetCerts,
		KeyFile:      f.keyFile,
		RestoreCerts: true,
		Yes:          true,
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	config := &server.Config{
		Server:   server.ServerConfig{Host: "127.0.0.1", Port: 0},
		Security: server.SecurityConfig{StateKey: f.key},
		Tunnel:   server.TunnelConfig{Enabled: true},
	}
	config.SetDataDir(targetData)
	// NewServer 读不出状态会直接返回错误，所以这一行本身就是「能启动」的证据。
	srv, err := server.NewServer(config, embed.FS{})
	if err != nil {
		t.Fatalf("the restored data dir cannot be loaded: %v", err)
	}
	// 用真实监听等就绪，而不是拿 TryLockFile 去探 data/.lock：探锁自己会抢锁，
	// 撞上 Start 的取锁就让 Start 以 lock busy 直接失败，用例最后只看到超时。
	// /health 返回 200 就一定已过取锁那一步。
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("find free port: %v", listenErr)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	srv.Addr = addr

	// Start 的错误不能丢：等就绪时 Start 已经返回就先打出那个错误。
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-startErr:
			if err == nil {
				t.Fatal("the restored server returned from Start() before it was ready")
			}
			t.Fatalf("the restored server failed to start: %v", err)
		default:
		}
		resp, getErr := client.Get("http://" + addr + "/health")
		if getErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the restored server did not become ready: %v", getErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 服务已经在应答请求，说明它确实持住了 data/.lock：此刻另开描述符抢不到。
	if held, probeErr := common.ProbeLockFile(filepath.Join(targetData, ".lock")); probeErr != nil || !held {
		t.Fatalf("data/.lock is not held by the running server: held=%v err=%v", held, probeErr)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	snapshot, err := server.ValidateStateFile(filepath.Join(targetData, "server-state.json"), f.key)
	if err != nil {
		t.Fatalf("the restored state no longer loads: %v", err)
	}
	if snapshot.Devices != 3 || snapshot.AuthorizedDevices != 3 {
		t.Fatalf("devices = %d (%d authorized), want 3 / 3", snapshot.Devices, snapshot.AuthorizedDevices)
	}
	if snapshot.Tunnels != 4 {
		t.Fatalf("tunnels = %d, want 4", snapshot.Tunnels)
	}
	// 目标证书目录是真实恢复出来的，TLS 私有钥必须 0600。
	info, err := os.Stat(filepath.Join(targetCerts, "server.key"))
	if err != nil {
		t.Fatalf("restored TLS key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("restored TLS key mode = %04o, want 0600", perm)
	}
}
