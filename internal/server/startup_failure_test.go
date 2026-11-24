package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"goremote/internal/common"
)

// 启动失败路径的用例真跑一次二进制：退出码是给 systemd 看的，只有真实进程
// 才能证明它确实是 2、并且没有 panic。

var serverBinary struct {
	once sync.Once
	path string
	err  error
}

func buildServerBinary(t *testing.T) string {
	t.Helper()
	serverBinary.once.Do(func() {
		dir, err := os.MkdirTemp("", "goremote-server-bin-")
		if err != nil {
			serverBinary.err = err
			return
		}
		path := filepath.Join(dir, "goremote-server")
		builder := exec.Command("go", "build", "-o", path, "goremote/cmd/server")
		if output, buildErr := builder.CombinedOutput(); buildErr != nil {
			serverBinary.err = errors.New("go build goremote/cmd/server: " + buildErr.Error() + "\n" + string(output))
			return
		}
		serverBinary.path = path
	})
	if serverBinary.err != nil {
		t.Fatalf("%v", serverBinary.err)
	}
	return serverBinary.path
}

func envWithout(name string) []string {
	out := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, name+"=") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// runServerBinary 跑一次注定失败的启动，返回退出码与合并输出。
func runServerBinary(t *testing.T, binary string, args, env []string) (int, string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(output)
	}
	t.Fatalf("run %s: %v", binary, err)
	return -1, ""
}

func newStartupStateDir(t *testing.T, key string) string {
	t.Helper()
	dir := t.TempDir()
	store := NewStateStore(filepath.Join(dir, "server-state.json"))
	if key != "" {
		if err := store.SetEncryptionKey(key); err != nil {
			t.Fatalf("set state key: %v", err)
		}
	}
	if err := store.Load(); err != nil {
		t.Fatalf("load state: %v", err)
	}
	if _, err := store.SetInitialAdminPassword("TestPassword123!"); err != nil {
		t.Fatalf("set admin password: %v", err)
	}
	return dir
}

func startupTestKey() string {
	return "base64:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 32))
}

func assertNoPanic(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(output, "panic:") || strings.Contains(output, "goroutine ") {
		t.Fatalf("startup panicked instead of exiting cleanly:\n%s", output)
	}
}

// TestStartupWithoutStateKeyExitsCleanly 覆盖「只给 data/、没有 key」：
// 必须是 exit 2 + 一句能照着做的错误，不是 panic，也不是空状态启动。
func TestStartupWithoutStateKeyExitsCleanly(t *testing.T) {
	t.Parallel()
	dir := newStartupStateDir(t, startupTestKey())
	binary := buildServerBinary(t)

	code, output := runServerBinary(t,
		binary,
		[]string{"--data", dir, "--host", "127.0.0.1", "--port", "0"},
		envWithout(common.StateKeyEnvName))

	if code != ExitStateError {
		t.Fatalf("exit code = %d, want %d (systemd needs a stable code to stop retrying)\n%s", code, ExitStateError, output)
	}
	assertNoPanic(t, output)
	for _, want := range []string{"encrypted but no state key", "--state-key-file", "goremote-server restore --from", "RestartPreventExitStatus"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output should mention %q:\n%s", want, output)
		}
	}
}

// TestStartupWithWrongStateKeyExitsCleanly：key 给了但不对，也不能 panic。
func TestStartupWithWrongStateKeyExitsCleanly(t *testing.T) {
	t.Parallel()
	dir := newStartupStateDir(t, startupTestKey())
	binary := buildServerBinary(t)

	wrongKey := "base64:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	keyFile := filepath.Join(t.TempDir(), "state.env")
	if err := os.WriteFile(keyFile, []byte(common.StateKeyEnvName+"="+wrongKey+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	code, output := runServerBinary(t,
		binary,
		[]string{"--data", dir, "--host", "127.0.0.1", "--port", "0", "--state-key-file", keyFile},
		envWithout(common.StateKeyEnvName))

	if code != ExitStateError {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitStateError, output)
	}
	assertNoPanic(t, output)
	for _, want := range []string{"does not open", "wrong key", "goremote-server restore --from"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output should mention %q:\n%s", want, output)
		}
	}
}

// TestStartupWithNewerStateSchemaExitsCleanly：状态文件比二进制新，要指向升级而不是降级。
func TestStartupWithNewerStateSchemaExitsCleanly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "server-state.json")
	if err := os.WriteFile(statePath, []byte(`{"schema_version":99,"devices":[]}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	binary := buildServerBinary(t)

	code, output := runServerBinary(t,
		binary,
		[]string{"--data", dir, "--host", "127.0.0.1", "--port", "0"},
		envWithout(common.StateKeyEnvName))

	if code != ExitStateError {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitStateError, output)
	}
	assertNoPanic(t, output)
	if !strings.Contains(output, "upgrade the goremote-server binary") {
		t.Fatalf("output should tell the operator to upgrade:\n%s", output)
	}
	if !strings.Contains(output, "schema 99") {
		t.Fatalf("output should name the offending schema version:\n%s", output)
	}
}

// TestStartupAcceptsEnvironmentFileKey 是 --key-file 与 --state-key-file 分叉的
// 回归用例：backup --include-key / restore --install-key 写出来的 state.env
// 必须能直接当 --state-key-file 用。
func TestStartupAcceptsEnvironmentFileKey(t *testing.T) {
	key := startupTestKey()
	dir := newStartupStateDir(t, key)
	binary := buildServerBinary(t)

	keyFile := filepath.Join(t.TempDir(), "state.env")
	if err := os.WriteFile(keyFile, []byte("# generated by restore --install-key\n"+common.StateKeyEnvName+"="+key+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	port := freeLoopbackPort(t)
	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(binary,
		"--data", dir, "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--state-key-file", keyFile)
	cmd.Env = envWithout(common.StateKeyEnvName)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/health"
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-waitCh:
			logged, _ := os.ReadFile(logPath)
			t.Fatalf("the server exited before becoming healthy: %v\n%s", waitErr, logged)
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
			}
		}
		if healthy {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !healthy {
		_ = cmd.Process.Kill()
		<-waitCh
		logged, _ := os.ReadFile(logPath)
		t.Fatalf("the server never answered /health with the EnvironmentFile key\n%s", logged)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	if err := <-waitCh; err != nil {
		logged, _ := os.ReadFile(logPath)
		t.Fatalf("the server did not shut down cleanly: %v\n%s", err, logged)
	}
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// TestReadStateKeyFileAcceptsEnvironmentFile 是上面那条回归用例的单元版本：
// 解析结果必须是纯密钥，而不是 "GOREMOTE_STATE_KEY=..." 整行。
func TestReadStateKeyFileAcceptsEnvironmentFile(t *testing.T) {
	t.Parallel()
	key := startupTestKey()
	dir := t.TempDir()

	cases := map[string]string{
		"environment file": common.StateKeyEnvName + "=" + key + "\n",
		"export form":      "export " + common.StateKeyEnvName + "=" + key + "\n",
		"quoted":           common.StateKeyEnvName + "=\"" + key + "\"\n",
		"bare key":         key + "\n",
	}
	for name, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".env")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		got, err := readStateKeyFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != key {
			t.Fatalf("%s: parsed %q, want %q", name, got, key)
		}
	}

	bad := filepath.Join(dir, "bad.env")
	if err := os.WriteFile(bad, []byte("line-one\nline-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateKeyFile(bad); err == nil {
		t.Fatal("a multi-line file without a key line must be rejected")
	}
}
