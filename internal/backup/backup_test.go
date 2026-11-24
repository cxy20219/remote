package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"goremote/internal/server"
)

// testStateKey 是测试用的 32 字节全熵密钥。真实部署从 /etc/goremote/state.env 来。
func testStateKey() string {
	return "base64:" + base64.StdEncoding.EncodeToString(bytesRepeat(0x42, 32))
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}

var testNow = time.Date(2026, 11, 25, 1, 2, 3, 0, time.UTC)

// fixture 是一套可备份的部署：data/（含 3 台设备、4 条隧道、黑名单）、certs/、state.env。
type fixture struct {
	root       string
	dataDir    string
	certsDir   string
	outDir     string
	keyFile    string
	key        string
	statePath  string
	certPath   string
	certKeyPth string
}

func newFixture(t *testing.T, encrypted bool) *fixture {
	t.Helper()

	root := t.TempDir()
	f := &fixture{
		root:       root,
		dataDir:    filepath.Join(root, "data"),
		certsDir:   filepath.Join(root, "certs"),
		outDir:     filepath.Join(root, "backups"),
		keyFile:    filepath.Join(root, "state.env"),
		key:        testStateKey(),
		statePath:  filepath.Join(root, "data", "server-state.json"),
		certPath:   filepath.Join(root, "certs", "server.crt"),
		certKeyPth: filepath.Join(root, "certs", "server.key"),
	}
	for _, dir := range []string{f.dataDir, f.certsDir, f.outDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	store := server.NewStateStore(f.statePath)
	if encrypted {
		if err := store.SetEncryptionKey(f.key); err != nil {
			t.Fatalf("set state key: %v", err)
		}
	}
	if err := store.Load(); err != nil {
		t.Fatalf("load fresh state: %v", err)
	}
	if _, err := store.SetInitialAdminPassword("TestPassword123!"); err != nil {
		t.Fatalf("set admin password: %v", err)
	}
	for index := 1; index <= 3; index++ {
		store.AddDevice(&server.DeviceState{
			ID:     deviceID(index),
			Name:   deviceID(index),
			Status: "authorized",
			OS:     "linux",
		})
	}
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	tunnels := make([]server.TunnelState, 0, 4)
	for index := 0; index < 4; index++ {
		tunnels = append(tunnels, server.TunnelState{
			TunnelID:   "tun-" + deviceID(index+1),
			ClientID:   deviceID(1),
			Protocol:   "tcp",
			LocalAddr:  "127.0.0.1",
			LocalPort:  22,
			PublicPort: 15000 + index,
			Exposure:   "public",
			CreatedAt:  now,
		})
	}
	if err := store.ReplaceTunnels(tunnels); err != nil {
		t.Fatalf("replace tunnels: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	blacklist := `{"version":1,"entries":[{"ip":"203.0.113.7","reason":"test","created_at":"2026-11-20T10:00:00Z"}]}` + "\n"
	if err := os.WriteFile(filepath.Join(f.dataDir, "blacklist.json"), []byte(blacklist), 0o600); err != nil {
		t.Fatalf("write blacklist: %v", err)
	}
	if err := os.WriteFile(f.certPath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(f.certKeyPth, []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("write cert key: %v", err)
	}
	if err := os.WriteFile(f.keyFile, []byte(StateKeyEnvName+"="+f.key+"\n"), 0o600); err != nil {
		t.Fatalf("write state.env: %v", err)
	}
	return f
}

func deviceID(index int) string {
	return "dev-" + string(rune('0'+index))
}

func (f *fixture) create(t *testing.T, opts CreateOptions) *CreateResult {
	t.Helper()
	if opts.DataDir == "" {
		opts.DataDir = f.dataDir
	}
	if opts.CertsDir == "" {
		opts.CertsDir = f.certsDir
	}
	if opts.OutDir == "" {
		opts.OutDir = f.outDir
	}
	if opts.Now.IsZero() {
		opts.Now = testNow
	}
	if opts.Host == "" {
		opts.Host = "test-host"
	}
	result, err := Create(opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return result
}

func tarMembers(t *testing.T, archivePath string) []string {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gzipReader.Close()

	var names []string
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, header.Name)
	}
	return names
}

// snapshotTree 记录目录里每个文件的权限与内容哈希，用来证明「什么都没变」。
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		if entry.IsDir() {
			out[rel+"/"] = "dir"
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out[rel] = info.Mode().Perm().String() + ":" + hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

func sameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func TestCreateWritesManifestFirstWithChecksums(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	members := tarMembers(t, result.Archive)
	if len(members) < 2 {
		t.Fatalf("archive holds %d members, want at least 2", len(members))
	}
	if members[0] != ManifestPath {
		t.Fatalf("first member = %q, want %q (a restore refuses anything else)", members[0], ManifestPath)
	}
	rest := members[1:]
	if !sort.StringsAreSorted(rest) {
		t.Fatalf("archive members are not sorted: %v", rest)
	}
	for _, name := range members {
		if !allowedMembers[name] {
			t.Fatalf("archive contains %q which is not in the whitelist", name)
		}
	}
	if !contains(members, StatePath) || !contains(members, CertKeyPath) {
		t.Fatalf("archive is missing required members: %v", members)
	}
	if contains(members, ledgerFileName) {
		t.Fatalf("the backup ledger must never be archived: %v", members)
	}
	if contains(members, "data/.lock") {
		t.Fatalf("the lock file must never be archived: %v", members)
	}

	if result.Manifest.ContainsStateKey {
		t.Fatal("a default backup must not contain the state key")
	}
	if !result.Manifest.ContainsTLSKey {
		t.Fatal("the TLS keypair must be in the archive by default")
	}
	if result.Manifest.ContainsPlaintextSecrets {
		t.Fatal("an encrypted state must not be marked as holding plaintext secrets")
	}
	if result.Manifest.StateEncryption != EncryptionEncrypted {
		t.Fatalf("state_encryption = %q", result.Manifest.StateEncryption)
	}
	if result.Manifest.StateSchema != server.SupportedStateSchemaVersion() {
		t.Fatalf("state_schema = %d, want %d", result.Manifest.StateSchema, server.SupportedStateSchemaVersion())
	}
	if result.Manifest.Host != "test-host" {
		t.Fatalf("host = %q", result.Manifest.Host)
	}
	if result.Runtime.Devices != 3 || result.Runtime.Tunnels != 4 {
		t.Fatalf("runtime summary = %d devices / %d tunnels, want 3 / 4", result.Runtime.Devices, result.Runtime.Tunnels)
	}

	// 每个文件的大小与哈希都要和磁盘上的原件对得上。
	for _, entry := range result.Manifest.Files {
		source := map[string]string{
			RuntimePath:   "",
			StatePath:     f.statePath,
			BlacklistPath: filepath.Join(f.dataDir, "blacklist.json"),
			CertPath:      f.certPath,
			CertKeyPath:   f.certKeyPth,
		}[entry.Path]
		if source == "" {
			continue
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		if int64(len(data)) != entry.Size {
			t.Fatalf("%s size = %d, manifest says %d", entry.Path, len(data), entry.Size)
		}
		if got := hashBytes(data); got != entry.SHA256 {
			t.Fatalf("%s hash = %s, manifest says %s", entry.Path, got, entry.SHA256)
		}
	}

	// 独立校验和必须与产物的真实哈希一致。
	if _, err := verifyArchiveChecksum(result.Archive); err != nil {
		t.Fatalf("checksum sidecar does not verify: %v", err)
	}
	sum, size, err := checksumFile(result.Archive)
	if err != nil {
		t.Fatalf("checksumFile: %v", err)
	}
	if sum != result.SHA256 || size != result.Size {
		t.Fatalf("result reports %s/%d, file is %s/%d", result.SHA256, result.Size, sum, size)
	}
	if !strings.HasSuffix(result.Archive, "goremote-backup-20261125T010203Z.tar.gz") {
		t.Fatalf("archive name = %s", filepath.Base(result.Archive))
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// ledgerFileName 是 data/backup-ledger.json 的文件名；它永远不能进归档。
var ledgerFileName = filepath.Base(server.BackupLedgerPath("data"))

func TestCreateRecordsLedger(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	status := server.BackupStatus(f.dataDir)
	if status.LastSuccessAt != testNow.Format(time.RFC3339) {
		t.Fatalf("last_success_at = %q", status.LastSuccessAt)
	}
	if status.LastArchive != filepath.Base(result.Archive) {
		t.Fatalf("last_archive = %q, want the base name %q", status.LastArchive, filepath.Base(result.Archive))
	}
	if status.LastSize != result.Size || status.LastSHA256 != result.SHA256 {
		t.Fatalf("ledger size/sha = %d/%s, want %d/%s", status.LastSize, status.LastSHA256, result.Size, result.SHA256)
	}
	if status.LastMode != server.BackupModeEncrypted {
		t.Fatalf("last_mode = %q, want %q", status.LastMode, server.BackupModeEncrypted)
	}

	// 账本文件本身不能被写进下一个包。
	second := f.create(t, CreateOptions{Now: testNow.Add(time.Hour)})
	if contains(tarMembers(t, second.Archive), ledgerFileName) {
		t.Fatal("the ledger leaked into a later archive")
	}
}

func TestCreateRefusesPlaintextStateByDefault(t *testing.T) {
	f := newFixture(t, false)

	_, err := Create(CreateOptions{DataDir: f.dataDir, CertsDir: f.certsDir, OutDir: f.outDir, Now: testNow})
	if err == nil {
		t.Fatal("backing up a plaintext state must be refused by default")
	}
	if !strings.Contains(err.Error(), "--allow-plaintext") {
		t.Fatalf("error should name the flag: %v", err)
	}

	result := f.create(t, CreateOptions{AllowPlaintext: true})
	if !result.Manifest.ContainsPlaintextSecrets {
		t.Fatal("a plaintext backup must be marked contains_plaintext_secrets")
	}
	if result.Manifest.StateEncryption != EncryptionPlaintext {
		t.Fatalf("state_encryption = %q", result.Manifest.StateEncryption)
	}
	if server.BackupStatus(f.dataDir).LastMode != server.BackupModePlaintext {
		t.Fatalf("last_mode = %q", server.BackupStatus(f.dataDir).LastMode)
	}
}

func TestCreateIncludeKeyGuards(t *testing.T) {
	f := newFixture(t, true)

	// 1. 没给 --state-env-file。
	_, err := Create(CreateOptions{DataDir: f.dataDir, CertsDir: f.certsDir, OutDir: f.outDir, IncludeKey: true, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "--state-env-file") {
		t.Fatalf("--include-key without --state-env-file must fail, got %v", err)
	}

	// 2. 密钥打不开这份状态：宁可现在失败，也不产出一个「标着含密钥却打不开」的包。
	wrongKeyFile := filepath.Join(f.root, "wrong.env")
	wrongKey := "base64:" + base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	if err := os.WriteFile(wrongKeyFile, []byte(StateKeyEnvName+"="+wrongKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Create(CreateOptions{DataDir: f.dataDir, CertsDir: f.certsDir, OutDir: f.outDir, IncludeKey: true, StateEnvFile: wrongKeyFile, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("a mismatched key must fail the backup, got %v", err)
	}

	// 3. 正常档：文件名带标记，manifest 标 contains_state_key。
	result := f.create(t, CreateOptions{IncludeKey: true, StateEnvFile: f.keyFile})
	if !strings.Contains(filepath.Base(result.Archive), ".with-key") {
		t.Fatalf("archive name %q must carry the .with-key marker", filepath.Base(result.Archive))
	}
	if !result.Manifest.ContainsStateKey {
		t.Fatal("manifest must mark contains_state_key")
	}
	if !contains(tarMembers(t, result.Archive), StateEnvPath) {
		t.Fatal("meta/state.env must be in a with-key archive")
	}
	if server.BackupStatus(f.dataDir).LastMode != server.BackupModeEncryptedWithKey {
		t.Fatalf("last_mode = %q", server.BackupStatus(f.dataDir).LastMode)
	}

	// 4. 明文状态不允许带密钥档。
	plain := newFixture(t, false)
	_, err = Create(CreateOptions{DataDir: plain.dataDir, CertsDir: plain.certsDir, OutDir: plain.outDir, IncludeKey: true, StateEnvFile: plain.keyFile, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Fatalf("--include-key on a plaintext state must fail, got %v", err)
	}
}

func TestCreateRejectsHalfTLSKeypair(t *testing.T) {
	f := newFixture(t, true)
	if err := os.Remove(f.certKeyPth); err != nil {
		t.Fatal(err)
	}
	_, err := Create(CreateOptions{DataDir: f.dataDir, CertsDir: f.certsDir, OutDir: f.outDir, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "half of the TLS keypair") {
		t.Fatalf("a half-backed TLS deployment must be refused, got %v", err)
	}
}

func TestCreateWithoutCertsStillWorks(t *testing.T) {
	f := newFixture(t, true)
	if err := os.Remove(f.certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.certKeyPth); err != nil {
		t.Fatal(err)
	}
	result := f.create(t, CreateOptions{})
	if result.Manifest.ContainsTLSKey {
		t.Fatal("manifest must not claim a TLS key when there is none")
	}
	if contains(tarMembers(t, result.Archive), CertPath) {
		t.Fatal("no certs should be archived")
	}
}

func TestCreateRequiresStateFile(t *testing.T) {
	f := newFixture(t, true)
	empty := filepath.Join(f.root, "empty")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Create(CreateOptions{DataDir: empty, CertsDir: f.certsDir, OutDir: f.outDir, Now: testNow})
	if err == nil || !strings.Contains(err.Error(), "server-state.json") {
		t.Fatalf("a data dir without server-state.json must fail, got %v", err)
	}
}

func TestManifestRejectsSelfReferenceAndUnknownMembers(t *testing.T) {
	workDir := t.TempDir()
	stateBytes := []byte(`{"schema_version":1}`)
	if err := os.MkdirAll(filepath.Join(workDir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "data", "server-state.json"), stateBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	base := Manifest{
		Format:          FormatVersion,
		StateSchema:     1,
		StateEncryption: EncryptionEncrypted,
		Files: []FileEntry{
			{Path: StatePath, Size: int64(len(stateBytes)), Mode: "0600", SHA256: hashBytes(stateBytes)},
		},
	}
	extracted := map[string]bool{ManifestPath: true, StatePath: true}
	if err := verifyManifest(base, extracted, workDir); err != nil {
		t.Fatalf("a well-formed manifest must verify: %v", err)
	}

	// 自引用：manifest 给自己的哈希背书毫无意义。
	selfRef := base
	selfRef.Files = append(append([]FileEntry(nil), base.Files...),
		FileEntry{Path: ManifestPath, Size: 1, Mode: "0600", SHA256: "x"})
	if err := verifyManifest(selfRef, extracted, workDir); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("a manifest listing itself must be rejected, got %v", err)
	}

	// 包里多了一个清单没列的文件。
	extra := map[string]bool{ManifestPath: true, StatePath: true, BlacklistPath: true}
	if err := verifyManifest(base, extra, workDir); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Fatalf("an unlisted member must be rejected, got %v", err)
	}

	// 清单列了包里没有的文件。
	missing := map[string]bool{ManifestPath: true, StatePath: true}
	withBlacklist := base
	withBlacklist.Files = append(append([]FileEntry(nil), base.Files...),
		FileEntry{Path: BlacklistPath, Size: 2, Mode: "0600", SHA256: "x"})
	if err := verifyManifest(withBlacklist, missing, workDir); err == nil || !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("a listed-but-absent member must be rejected, got %v", err)
	}

	// 哈希对不上。
	tampered := base
	tampered.Files = []FileEntry{{Path: StatePath, Size: int64(len(stateBytes)), Mode: "0600", SHA256: "deadbeef"}}
	if err := verifyManifest(tampered, map[string]bool{ManifestPath: true, StatePath: true}, workDir); err == nil || !strings.Contains(err.Error(), "manifest hash") {
		t.Fatalf("a bad file hash must be rejected, got %v", err)
	}

	// 未知加密标记。
	unknown := base
	unknown.StateEncryption = "rot13"
	if err := verifyManifest(unknown, extracted, workDir); err == nil || !strings.Contains(err.Error(), "state_encryption") {
		t.Fatalf("an unknown state_encryption must be rejected, got %v", err)
	}
}

type tarMember struct {
	name string
	body []byte
}

func TestReadArchiveRejectsHostileMembers(t *testing.T) {
	writeArchiveWith := func(t *testing.T, members []tarMember) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "hostile.tar.gz")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		gzipWriter := gzip.NewWriter(file)
		tarWriter := tar.NewWriter(gzipWriter)
		for _, member := range members {
			header := &tar.Header{Name: member.name, Mode: 0o600, Size: int64(len(member.body)), Typeflag: tar.TypeReg}
			if err := tarWriter.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := tarWriter.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
		if err := tarWriter.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gzipWriter.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	manifestBytes, err := json.Marshal(Manifest{Format: FormatVersion, StateSchema: 1, StateEncryption: EncryptionEncrypted})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		members []tarMember
		want    string
	}{
		{
			name:    "manifest must be first",
			members: []tarMember{{StatePath, []byte("{}")}, {ManifestPath, manifestBytes}},
			want:    "first member",
		},
		{
			name:    "path traversal",
			members: []tarMember{{ManifestPath, manifestBytes}, {"../evil", []byte("x")}},
			want:    "clean relative path",
		},
		{
			name:    "absolute path",
			members: []tarMember{{ManifestPath, manifestBytes}, {"/etc/passwd", []byte("x")}},
			want:    "absolute path",
		},
		{
			name:    "duplicate member",
			members: []tarMember{{ManifestPath, manifestBytes}, {StatePath, []byte("{}")}, {StatePath, []byte("{}")}},
			want:    "more than once",
		},
		{
			name:    "unknown member",
			members: []tarMember{{ManifestPath, manifestBytes}, {"data/extra.json", []byte("{}")}},
			want:    "not part of a goremote backup",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			archivePath := writeArchiveWith(t, testCase.members)
			_, _, err := readArchive(archivePath, t.TempDir())
			if err == nil {
				t.Fatalf("archive was accepted, want an error containing %q", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

func TestVerifyArchiveChecksumDetectsTampering(t *testing.T) {
	f := newFixture(t, true)
	result := f.create(t, CreateOptions{})

	// 篡改一个字节，sidecar 就对不上了。
	data, err := os.ReadFile(result.Archive)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(result.Archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchiveChecksum(result.Archive); err == nil || !strings.Contains(err.Error(), "was modified or corrupted") {
		t.Fatalf("tampering went undetected: %v", err)
	}

	// 没有 .sha256 就拒绝。
	fresh := newFixture(t, true)
	freshResult := fresh.create(t, CreateOptions{})
	if err := os.Remove(freshResult.Archive + ".sha256"); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchiveChecksum(freshResult.Archive); err == nil || !strings.Contains(err.Error(), ".sha256") {
		t.Fatalf("a missing sidecar must be refused, got %v", err)
	}
}

func TestParseStateEnvAcceptsBothFormats(t *testing.T) {
	key := testStateKey()
	cases := map[string]string{
		"env file":    "GOREMOTE_STATE_KEY=" + key + "\n",
		"export form": "export GOREMOTE_STATE_KEY=" + key + "\n",
		"quoted":      "GOREMOTE_STATE_KEY=\"" + key + "\"\n",
		"comments":    "# comment\n\nGOREMOTE_STATE_KEY=" + key + "\n",
		"bare key":    key + "\n",
		"other lines": "FOO=bar\nGOREMOTE_STATE_KEY=" + key + "\n",
	}
	for name, content := range cases {
		got, err := parseStateEnv(content)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != key {
			t.Fatalf("%s: parsed %q", name, got)
		}
	}

	bad := map[string]string{
		"empty":          "",
		"empty value":    "GOREMOTE_STATE_KEY=\n",
		"multiline junk": "not-a-key\nanother-line\n",
	}
	for name, content := range bad {
		if _, err := parseStateEnv(content); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}

	// 密钥文件必须是 0600 的普通文件。
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.env")
	if err := os.WriteFile(loose, []byte("GOREMOTE_STATE_KEY="+key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readStateEnvFile(loose); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("a world-readable key file must be refused, got %v", err)
	}

	symlink := filepath.Join(dir, "link.env")
	if err := os.Symlink(filepath.Join(dir, "missing.env"), symlink); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	if _, _, err := readStateEnvFile(symlink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked key file must be refused, got %v", err)
	}
}

func TestValidateStateFileNeedsKeyForEncryptedState(t *testing.T) {
	f := newFixture(t, true)

	snapshot, err := server.ValidateStateFile(f.statePath, f.key)
	if err != nil {
		t.Fatalf("ValidateStateFile with the right key: %v", err)
	}
	if snapshot.Devices != 3 || snapshot.Tunnels != 4 || snapshot.AuthorizedDevices != 3 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !snapshot.Encrypted {
		t.Fatal("an encrypted state must report Encrypted=true")
	}

	if _, err := server.ValidateStateFile(f.statePath, ""); !errors.Is(err, server.ErrStateEncryptionKeyRequired) {
		t.Fatalf("an encrypted state without a key must return ErrStateEncryptionKeyRequired, got %v", err)
	}
	wrongKey := "base64:" + base64.StdEncoding.EncodeToString(bytesRepeat(0x24, 32))
	if _, err := server.ValidateStateFile(f.statePath, wrongKey); err == nil {
		t.Fatal("a wrong key must fail validation instead of loading garbage")
	}
}
