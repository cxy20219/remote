package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testIdentity() *AgentIdentity {
	return &AgentIdentity{
		ServerURL:         "wss://example.test/ws",
		ClientID:          "client-1",
		DeviceSignPrivkey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		DeviceSignPubkey:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		DeviceDHPrivkey:   "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
		DeviceDHPubkey:    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
	}
}

// 保存后必须是完整可读的 0600 文件，且不留下临时文件。
func TestSaveIdentityWritesCompleteFile(t *testing.T) {
	dir := t.TempDir()
	id := testIdentity()

	if err := id.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := filepath.Join(dir, "identity")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity mode = %o, want 600", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind after a successful save (err=%v)", err)
	}

	reloaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if reloaded == nil {
		t.Fatal("identity file should exist")
	}
	if reloaded.ClientID != id.ClientID ||
		reloaded.DeviceSignPrivkey != id.DeviceSignPrivkey ||
		reloaded.DeviceDHPrivkey != id.DeviceDHPrivkey {
		t.Fatal("reloaded identity differs from what was saved")
	}
}

// fsync 失败时：返回错误、旧文件内容一个字节都不能变、临时文件必须清掉。
// 这条对应「掉电/磁盘故障不能把设备身份写成半截，导致重新审批」。
func TestSaveIdentityFailureKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	id := testIdentity()
	if err := id.Save(dir); err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}

	original := syncIdentityFile
	syncIdentityFile = func(*os.File) error { return errors.New("injected fsync failure") }
	defer func() { syncIdentityFile = original }()

	id.ClientID = "client-2"
	if err := id.Save(dir); err == nil {
		t.Fatal("Save should report the injected fsync failure")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity after failed save: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("identity file changed after a failed save:\nbefore=%s\nafter=%s", before, after)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind after a failed save (err=%v)", err)
	}

	// 钩子恢复后，正常保存必须能覆盖旧文件。
	syncIdentityFile = original
	if err := id.Save(dir); err != nil {
		t.Fatalf("Save after restoring the hook: %v", err)
	}
	reloaded, err := LoadIdentity(dir)
	if err != nil || reloaded == nil {
		t.Fatalf("LoadIdentity after recovery: %v (nil=%v)", err, reloaded == nil)
	}
	if reloaded.ClientID != "client-2" {
		t.Fatalf("client ID = %q, want client-2", reloaded.ClientID)
	}
}
