package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// randomWGPublicKey 生成一个能通过校验的公钥。约 6% 的公钥会命中 clamp 特征
// （设计 §5 的误报率），所以这里重试几次。
func randomWGPublicKey(t *testing.T) string {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		encoded := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		if _, _, err := decodeWGPublicKey(encoded); err == nil {
			return encoded
		}
	}
	t.Fatal("could not generate a public key that passes validation")
	return ""
}

func TestDecodeWGPublicKey(t *testing.T) {
	valid := randomWGPublicKey(t)
	if _, _, err := decodeWGPublicKey(valid); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", ErrWGInvalidPubkey},
		{"not base64", "not-a-key", ErrWGInvalidPubkey},
		{"short", base64.StdEncoding.EncodeToString([]byte("short")), ErrWGInvalidPubkey},
		{"zero", base64.StdEncoding.EncodeToString(make([]byte, 32)), ErrWGInvalidPubkey},
		{"low order one", base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...)), ErrWGInvalidPubkey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeWGPublicKey(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}

	// 不带 padding 的 base64 也要接受。
	if _, _, err := decodeWGPublicKey(strings.TrimRight(valid, "=")); err != nil {
		t.Fatalf("unpadded key rejected: %v", err)
	}
}

func TestDecodeWGPublicKeyRejectsClampedPrivateKey(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		// 复刻 wg genkey 的 clamp：首字节低 3 位清零、末字节最高位清零、次高位之一置位。
		raw := key.Bytes()
		raw[0] &= 248
		raw[31] &= 127
		raw[31] |= 64
		encoded := base64.StdEncoding.EncodeToString(raw)
		if _, _, err := decodeWGPublicKey(encoded); !errors.Is(err, ErrWGPrivateKey) {
			t.Fatalf("want ErrWGPrivateKey, got %v (attempt %d)", err, attempt)
		}
		return
	}
}

func TestWGTemplateHasNoPrivateKey(t *testing.T) {
	template := wgTemplate("10.77.0.2", "hub-public-key", "203.0.113.10:51820", defaultWGCIDR)
	if strings.Contains(template, "PrivateKey") {
		t.Fatal("template must never mention a private key")
	}
	for _, want := range []string{"[Interface]", "Address = 10.77.0.2/32", "MTU = 1380", "[Peer]", "PublicKey = hub-public-key", "Endpoint = 203.0.113.10:51820", "AllowedIPs = 10.77.0.0/24", "PersistentKeepalive = 25"} {
		if !strings.Contains(template, want) {
			t.Fatalf("template missing %q:\n%s", want, template)
		}
	}
	for _, note := range wgTemplateNotes() {
		if strings.Contains(note, "PrivateKey") {
			t.Fatalf("notes must not carry the literal word PrivateKey: %q", note)
		}
	}
}

func TestHubKeyRoundTrip(t *testing.T) {
	privateKey, err := newWGHubPrivateKey()
	if err != nil {
		t.Fatalf("generate hub key: %v", err)
	}
	publicKey, err := wgHubPublicKey(privateKey)
	if err != nil {
		t.Fatalf("derive hub public key: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("hub public key is not 32 bytes of base64: %v", err)
	}
}

func TestSaveSyncsFileAndDirectory(t *testing.T) {
	_, store := newTestConfig(t)

	var fileSyncs, dirSyncs int32
	originalFile, originalDir := syncStateFile, syncStateDir
	syncStateFile = func(file *os.File) error {
		atomic.AddInt32(&fileSyncs, 1)
		return file.Sync()
	}
	syncStateDir = func(dir *os.File) error {
		atomic.AddInt32(&dirSyncs, 1)
		return dir.Sync()
	}
	t.Cleanup(func() {
		syncStateFile, syncStateDir = originalFile, originalDir
	})

	store.UpdateSettings(func(settings *ServerSettings) { settings.PublicHost = "example.test" })
	if err := store.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := atomic.LoadInt32(&fileSyncs); got != 1 {
		t.Fatalf("state file must be fsynced exactly once, got %d", got)
	}
	if got := atomic.LoadInt32(&dirSyncs); got != 1 {
		t.Fatalf("state directory must be fsynced exactly once, got %d", got)
	}
}

func TestSaveSurfacesSyncFailure(t *testing.T) {
	_, store := newTestConfig(t)

	originalFile := syncStateFile
	syncStateFile = func(*os.File) error { return errors.New("injected sync failure") }
	t.Cleanup(func() { syncStateFile = originalFile })

	store.UpdateSettings(func(settings *ServerSettings) { settings.PublicHost = "example.test" })
	if err := store.Save(); err == nil {
		t.Fatal("a failed fsync must fail Save")
	}
}

func TestSaveSurfacesDirectorySyncFailure(t *testing.T) {
	_, store := newTestConfig(t)

	var fileSyncs int32
	originalFile, originalDir := syncStateFile, syncStateDir
	syncStateFile = func(file *os.File) error {
		atomic.AddInt32(&fileSyncs, 1)
		return file.Sync()
	}
	syncStateDir = func(*os.File) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() {
		syncStateFile, syncStateDir = originalFile, originalDir
	})

	store.UpdateSettings(func(settings *ServerSettings) { settings.PublicHost = "example.test" })
	if err := store.Save(); err == nil {
		t.Fatal("a failed directory fsync must fail Save")
	}

	// 失败后必须保持 dirty：下一次 Save 要真的重写，而不是直接 return nil。
	syncStateDir = originalDir
	if err := store.Save(); err != nil {
		t.Fatalf("retry after restoring the directory fsync should succeed: %v", err)
	}
	if got := atomic.LoadInt32(&fileSyncs); got != 2 {
		t.Fatalf("a failed directory fsync must leave the store dirty so the retry rewrites the file; file syncs = %d, want 2", got)
	}
}

func TestAllocateWGDeviceConcurrentAddresses(t *testing.T) {
	_, store := newTestConfig(t)
	const devices = 10
	for index := 0; index < devices; index++ {
		store.AddDevice(&DeviceState{ID: fmt.Sprintf("dev-%d", index), Status: deviceStatusAuthorized})
	}
	prefix, _, err := wgInterfaceAddress(defaultWGCIDR)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}

	var wait sync.WaitGroup
	failures := make(chan error, devices)
	for index := 0; index < devices; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			deviceID := fmt.Sprintf("dev-%d", index)
			publicKey := randomWGPublicKey(t)
			err := store.AllocateWGDevice(deviceID, func(device *DeviceState, all []DeviceState) error {
				address, err := allocateWGAddress(prefix, all, deviceID)
				if err != nil {
					return err
				}
				device.WGIP = address
				device.WGPublicKey = publicKey
				device.WGEnabled = true
				device.WGVersion++
				return nil
			})
			if err != nil {
				failures <- err
				return
			}
			if err := store.Save(); err != nil {
				failures <- err
			}
		}(index)
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("concurrent allocation failed: %v", failure)
	}

	seen := make(map[string]bool, devices)
	for _, device := range store.GetAllDevices() {
		if device.WGIP == "" {
			t.Fatalf("device %s got no address", device.ID)
		}
		if seen[device.WGIP] {
			t.Fatalf("duplicate address %s", device.WGIP)
		}
		seen[device.WGIP] = true
	}
	if len(seen) != devices {
		t.Fatalf("expected %d distinct addresses, got %d", devices, len(seen))
	}
}

func TestAllocateWGDeviceUnknownDevice(t *testing.T) {
	_, store := newTestConfig(t)
	err := store.AllocateWGDevice("missing", func(*DeviceState, []DeviceState) error {
		t.Fatal("callback must not run for a missing device")
		return nil
	})
	if !errors.Is(err, ErrWGDeviceNotFound) {
		t.Fatalf("want ErrWGDeviceNotFound, got %v", err)
	}
}

func TestWGAddressPoolExhaustion(t *testing.T) {
	prefix, _, err := wgInterfaceAddress("10.99.0.0/29")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	addresses := wgAddressPool(prefix)
	if len(addresses) != 5 {
		t.Fatalf("a /29 should offer 5 host addresses, got %d", len(addresses))
	}
	devices := make([]DeviceState, 0, len(addresses))
	for index, address := range addresses {
		devices = append(devices, DeviceState{ID: fmt.Sprintf("d%d", index), WGIP: address.String(), WGPublicKey: "key"})
	}
	if _, err := allocateWGAddress(prefix, devices, ""); !errors.Is(err, ErrWGNoFreeAddress) {
		t.Fatalf("want ErrWGNoFreeAddress, got %v", err)
	}
}

func TestHubPrivateKeyIsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-state.json")
	stateKey := "test-state-key-0123456789abcdef0123456789abcdef"

	store := NewStateStore(path)
	if err := store.SetEncryptionKey(stateKey); err != nil {
		t.Fatalf("set encryption key: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	privateKey, err := newWGHubPrivateKey()
	if err != nil {
		t.Fatalf("generate hub key: %v", err)
	}
	if err := store.SetWGHubPrivateKey(privateKey); err != nil {
		t.Fatalf("store hub key: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if strings.Contains(string(raw), privateKey) {
		t.Fatal("the hub private key must not appear in the state file when encryption is on")
	}

	reloaded := NewStateStore(path)
	if err := reloaded.SetEncryptionKey(stateKey); err != nil {
		t.Fatalf("set encryption key on reload: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.WGHubPrivateKey(); got != privateKey {
		t.Fatalf("hub key did not survive the encrypted round trip")
	}
}

func TestDecodeWGPublicKeyAcceptsLooseClampFalsePositive(t *testing.T) {
	// 这把合法公钥只命中「末字节最高位为 0」的宽松谓词（byte31=0x26，
	// 高两位 00；byte0 低 3 位也是 0）。审计实测旧谓词会 400 拒掉它。
	const publicKey = "qDplFtiKEhZhega3bvKEeURhzoy02mF2zAWJySAU5CY="
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		t.Fatalf("fixture must be 32 bytes of base64: %v", err)
	}
	if raw[0]&0x07 != 0 || raw[31]&0xC0 != 0 {
		t.Fatalf("fixture no longer exercises the loose predicate: byte0=%#x byte31=%#x", raw[0], raw[31])
	}
	normalized, decoded, err := decodeWGPublicKey(publicKey)
	if err != nil {
		t.Fatalf("a valid public key that only matches the loose clamp predicate must be accepted, got %v", err)
	}
	if normalized != publicKey {
		t.Fatalf("normalised key changed: %q -> %q", publicKey, normalized)
	}
	if got := base64.StdEncoding.EncodeToString(decoded[:]); got != publicKey {
		t.Fatalf("decoded key changed: %q", got)
	}
}

func TestClampHeuristicFalsePositiveRate(t *testing.T) {
	if testing.Short() {
		t.Skip("generating X25519 public keys is slow in -short mode")
	}
	// 默认 2 万把；审阅要求 20 万把时用
	// GOREMOTE_WG_CLAMP_SAMPLES=200000 go test -run TestClampHeuristicFalsePositiveRate -v
	samples := 20000
	if raw := os.Getenv("GOREMOTE_WG_CLAMP_SAMPLES"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid GOREMOTE_WG_CLAMP_SAMPLES=%q", raw)
		}
		samples = parsed
	}

	basePoint := [32]byte{9}
	var privateKey [32]byte
	clampHits, looseHits := 0, 0
	for index := 0; index < samples; index++ {
		if _, err := rand.Read(privateKey[:]); err != nil {
			t.Fatalf("random private key: %v", err)
		}
		publicKey, err := curve25519.X25519(privateKey[:], basePoint[:])
		if err != nil {
			t.Fatalf("derive public key: %v", err)
		}
		var key [32]byte
		copy(key[:], publicKey)
		if looksLikeClampedPrivateKey(key) {
			clampHits++
		}
		// 只用于对照：这条是修复前的谓词，证明样本量能区分 6.25% 与 12.5%。
		if key[0]&0x07 == 0 && key[31]&0x80 == 0 {
			looseHits++
		}
	}

	rate := float64(clampHits) / float64(samples)
	looseRate := float64(looseHits) / float64(samples)
	t.Logf("samples=%d clamp_hits=%d (%.3f%%) loose_predicate_hits=%d (%.3f%%)", samples, clampHits, rate*100, looseHits, looseRate*100)
	if rate < 0.045 || rate > 0.085 {
		t.Fatalf("clamp heuristic false-positive rate is %.3f%%, want about 6.25%%; the old `&0x80==0` predicate reports about 12.5%%", rate*100)
	}
	if looseRate < 0.09 {
		t.Fatalf("sanity check failed: the old loose predicate should stay above 9%%, got %.3f%%", looseRate*100)
	}
}
