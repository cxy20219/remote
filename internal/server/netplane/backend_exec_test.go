package netplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type recordedCommand struct {
	name string
	args []string
}

func newFakeExecBackend(handlers func(name string, args []string) (string, bool)) (*ExecBackend, *[]recordedCommand) {
	commands := &[]recordedCommand{}
	backend := &ExecBackend{
		Interface:   "wg-grm",
		LookupPath:  func(string) (string, error) { return "/usr/bin/true", nil },
		WriteSysctl: func(string, string) error { return nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			*commands = append(*commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			if handlers != nil {
				if output, ok := handlers(name, args); ok {
					if strings.HasPrefix(output, "ERR:") {
						return nil, errors.New(strings.TrimPrefix(output, "ERR:"))
					}
					return []byte(output), nil
				}
			}
			return nil, nil
		},
	}
	return backend, commands
}

func commandText(commands []recordedCommand) string {
	var builder strings.Builder
	for _, command := range commands {
		builder.WriteString(command.name + " " + strings.Join(command.args, " ") + "\n")
	}
	return builder.String()
}

func TestExecBackendProbeReportsMissingTools(t *testing.T) {
	backend := &ExecBackend{Interface: "wg-grm", LookupPath: func(name string) (string, error) {
		return "", fmt.Errorf("%s not found", name)
	}}
	if err := backend.Probe(context.Background()); err == nil {
		t.Fatal("a missing tool must fail Probe")
	}
}

func TestExecBackendEnsureCreatesInterface(t *testing.T) {
	backend, commands := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "show" {
			return "ERR:device does not exist", true
		}
		return "", false
	})
	hub := Hub{Interface: "wg-grm", PrivateKey: "cHJpdmF0ZQ==", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820, MTU: 1420}
	if err := backend.Ensure(context.Background(), hub); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	text := commandText(*commands)
	for _, want := range []string{
		"ip link add wg-grm type wireguard",
		"wg set wg-grm private-key",
		"ip addr replace 10.77.0.1/24 dev wg-grm",
		"ip link set wg-grm mtu 1420",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing command %q in:\n%s", want, text)
		}
	}
	// Ensure 只配置、不 up：up 必须留到 ACL 与 peer 之后（M1）。
	if strings.Contains(text, "mtu 1420 up") || strings.Contains(text, "link set wg-grm up") {
		t.Fatalf("Ensure must not bring the interface up:\n%s", text)
	}
	// 私钥只经过命令里的临时文件，用完必须删掉。
	keyPath := ""
	for _, command := range *commands {
		for index, arg := range command.args {
			if arg == "private-key" && index+1 < len(command.args) {
				keyPath = command.args[index+1]
			}
		}
	}
	if keyPath == "" || keyPath == "cHJpdmF0ZQ==" {
		t.Fatalf("the hub key should be written to a temp file, got %q", keyPath)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("the temp key file must be removed after use, stat err=%v", err)
	}
}

func TestExecBackendApplyAddsAndRemoves(t *testing.T) {
	dump := "iface\t51820\tpub\t0\npeer-existing\t(none)\t1.2.3.4:1\t10.77.0.9/32\t0\t0\t0\toff\n"
	backend, commands := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "wg" && len(args) >= 3 && args[0] == "show" {
			return dump, true
		}
		return "", false
	})
	failures, err := backend.Apply(context.Background(), []Peer{
		{DeviceID: "dev-1", PublicKey: "peer-new", Address: "10.77.0.2", Enabled: true, Version: 1},
		{DeviceID: "dev-2", PublicKey: "peer-off", Address: "10.77.0.3", Enabled: false, Version: 1},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	text := commandText(*commands)
	if !strings.Contains(text, "wg set wg-grm peer peer-new allowed-ips 10.77.0.2/32") {
		t.Fatalf("missing add command:\n%s", text)
	}
	if !strings.Contains(text, "wg set wg-grm peer peer-existing remove") {
		t.Fatalf("missing removal of a stale peer:\n%s", text)
	}
	if strings.Contains(text, "peer-off") {
		t.Fatalf("a disabled device must not be configured:\n%s", text)
	}
}

func TestExecBackendApplyReportsPerPeerFailure(t *testing.T) {
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "wg" && len(args) >= 3 && args[0] == "show" {
			return "", true // 空 dump，避免 nil 输出被当成错误
		}
		if name == "wg" && len(args) >= 4 && args[0] == "set" && args[3] == "peer-bad" {
			return "ERR:peer rejected", true
		}
		return "", false
	})
	failures, err := backend.Apply(context.Background(), []Peer{
		{DeviceID: "bad", PublicKey: "peer-bad", Address: "10.77.0.2", Enabled: true, Version: 1},
		{DeviceID: "good", PublicKey: "peer-good", Address: "10.77.0.3", Enabled: true, Version: 1},
	})
	if err != nil {
		t.Fatalf("a single bad peer must not fail the round: %v", err)
	}
	if failures["bad"] == nil {
		t.Fatal("the rejected peer should be reported against its device")
	}
	if _, ok := failures["good"]; ok {
		t.Fatal("the healthy peer must not be marked failed")
	}
}

func TestExecBackendHandshakesParseDump(t *testing.T) {
	// fixture 是 `wg show wg-grm dump` 的原文格式。首行是接口
	// （private-key, public-key, listen-port, fwmark），peer 行是
	// public-key, preshared-key, endpoint, allowed-ips, latest-handshake,
	// transfer-rx, transfer-tx, persistent-keepalive。
	//
	// 时间戳按「30 秒前」动态生成，断言具体范围而不是「字段存在」：索引一旦
	// 错位到 transfer-rx（下一列），age 会变成 now-rx，range 断言立刻失败。
	handshake := time.Now().Unix() - 30
	dump := fmt.Sprintf(
		"privkey\tpubkey\t51820\toff\n"+
			"peer-a\t(none)\t203.0.113.5:51820\t10.77.0.2/32\t%d\t987654321\t123456789\toff\n"+
			"peer-b\t(none)\t203.0.113.6:51820\t10.77.0.3/32\t0\t55555\t66666\toff\n",
		handshake,
	)
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "wg" && len(args) >= 3 && args[0] == "show" {
			return dump, true
		}
		return "", false
	})
	stats, err := backend.PeerStats(context.Background())
	if err != nil {
		t.Fatalf("peer stats: %v", err)
	}
	peerA, ok := stats["peer-a"]
	if !ok {
		t.Fatal("peer-a missing from peer stats")
	}
	if peerA.HandshakeAge < 25 || peerA.HandshakeAge > 40 {
		t.Fatalf("peer-a handshaked 30s ago; want age in (25,40), got %d (did the parser read transfer-rx instead of latest-handshake?)", peerA.HandshakeAge)
	}
	// 第 6/7 列是 hub 视角的收发字节数；前端靠它判断链路是否真的在走数据。
	if peerA.RXBytes != 987654321 || peerA.TXBytes != 123456789 {
		t.Fatalf("rx/tx parsed as %d/%d, want 987654321/123456789", peerA.RXBytes, peerA.TXBytes)
	}
	// 从未握手的设备即使 rx/tx 不为 0，握手年龄也必须是 0，不能被流量计数冒充。
	if stats["peer-b"].HandshakeAge != 0 {
		t.Fatalf("never-handshaked peer should have age 0, got %d", stats["peer-b"].HandshakeAge)
	}
	if stats["peer-b"].RXBytes != 55555 || stats["peer-b"].TXBytes != 66666 {
		t.Fatalf("never-handshaked peer should still report rx/tx, got %d/%d", stats["peer-b"].RXBytes, stats["peer-b"].TXBytes)
	}
}

func TestExecBackendEnsureHardensInterface(t *testing.T) {
	backend, _ := newFakeExecBackend(nil)
	var paths []string
	backend.WriteSysctl = func(path, value string) error {
		if value != "0" {
			t.Fatalf("sysctl %s should be 0, got %q", path, value)
		}
		paths = append(paths, path)
		return nil
	}
	hub := Hub{Interface: "wg-grm", PrivateKey: "cHJpdmF0ZQ==", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820, MTU: 1420}
	if err := backend.Ensure(context.Background(), hub); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	want := []string{
		"/proc/sys/net/ipv4/conf/wg-grm/accept_redirects",
		"/proc/sys/net/ipv4/conf/wg-grm/send_redirects",
	}
	if len(paths) != len(want) {
		t.Fatalf("sysctl writes = %v, want %v", paths, want)
	}
	for index := range want {
		if paths[index] != want[index] {
			t.Fatalf("sysctl[%d] = %q, want %q", index, paths[index], want[index])
		}
	}
}

func TestExecBackendEnsureUsesConfiguredTempDir(t *testing.T) {
	keyDir := t.TempDir()
	var keyPath string
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "wg" && len(args) >= 4 && args[0] == "set" && args[2] == "private-key" {
			keyPath = args[3]
			info, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("the hub key file must exist while wg runs: %v", err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("hub key file mode = %o, want 600", info.Mode().Perm())
			}
		}
		return "", false
	})
	backend.TempDir = keyDir
	hub := Hub{Interface: "wg-grm", PrivateKey: "cHJpdmF0ZQ==", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820, MTU: 1420}
	if err := backend.Ensure(context.Background(), hub); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// 密钥临时文件必须落在注入的目录（生产默认是 /dev/shm），不能是 /tmp。
	if keyPath == "" {
		t.Fatal("wg set private-key was not called")
	}
	if !strings.HasPrefix(keyPath, keyDir+string(os.PathSeparator)) {
		t.Fatalf("hub key file %q is outside the configured dir %q", keyPath, keyDir)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("the hub key file must be removed after use, stat err=%v", err)
	}
}

func TestExecBackendApplyACLWritesRulesetAndRunsNft(t *testing.T) {
	var ruleset string
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "nft" && len(args) == 2 && args[0] == "-f" {
			data, err := os.ReadFile(args[1])
			if err != nil {
				t.Fatalf("read ruleset file: %v", err)
			}
			ruleset = string(data)
			return "", true
		}
		return "", false
	})
	acl := ACL{Interface: "wg-grm", Clients: []string{"10.77.0.2/32"}, Endpoints: []string{"10.77.0.3/32"}}
	if err := backend.ApplyACL(context.Background(), acl); err != nil {
		t.Fatalf("apply acl: %v", err)
	}
	for _, want := range []string{
		"table inet goremote",
		`iifname "wg-grm" jump wg_fwd`,
		`oifname "wg-grm" jump wg_fwd_rev`,
		"elements = { 10.77.0.2/32 }",
		"elements = { 10.77.0.3/32 }",
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, ruleset)
		}
	}
}

func TestExecBackendACLExistsParsesListTables(t *testing.T) {
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "nft" && len(args) == 2 && args[0] == "list" && args[1] == "tables" {
			return "table inet filter\ntable inet goremote\n", true
		}
		return "", false
	})
	exists, err := backend.ACLExists(context.Background())
	if err != nil {
		t.Fatalf("acl exists: %v", err)
	}
	if !exists {
		t.Fatal("table inet goremote should be detected")
	}

	backend, _ = newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "nft" && len(args) == 2 && args[0] == "list" && args[1] == "tables" {
			return "table inet filter\n", true
		}
		return "", false
	})
	exists, err = backend.ACLExists(context.Background())
	if err != nil {
		t.Fatalf("acl exists: %v", err)
	}
	if exists {
		t.Fatal("a missing table must report false")
	}
}

// 端口冲突只会在 ip link set up 暴露：wg set listen-port 提前返回 0，
// wg show 也照样显示 51820。这里模拟内核返回 rc=2，断言 Ensure 失败，
// 并且不再继续写 sysctl（up 是最后一道闸门）。
// 端口冲突只会在 ip link set up 暴露：wg set listen-port 提前返回 0，
// wg show 也照样显示 51820。Ensure 必须成功（配置阶段无冲突），Up 必须失败。
func TestExecBackendUpFailsWhenPortIsInUse(t *testing.T) {
	var sysctls int
	backend, _ := newFakeExecBackend(func(name string, args []string) (string, bool) {
		if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "set" && args[len(args)-1] == "up" {
			return "ERR:RTNETLINK answers: Address already in use", true
		}
		return "", false
	})
	backend.WriteSysctl = func(string, string) error {
		sysctls++
		return nil
	}
	hub := Hub{Interface: "wg-grm", PrivateKey: "cHJpdmF0ZQ==", CIDR: "10.77.0.0/24", Address: "10.77.0.1", Listen: 51820, MTU: 1420}
	if err := backend.Ensure(context.Background(), hub); err != nil {
		t.Fatalf("Ensure must not bring the link up, got: %v", err)
	}
	if sysctls != 2 {
		t.Fatalf("redirects are disabled while the interface is down; got %d sysctl writes", sysctls)
	}
	err := backend.Up(context.Background())
	if err == nil {
		t.Fatal("a failed ip link set up must fail Up")
	}
	if !strings.Contains(err.Error(), "bring wg-grm up") || !strings.Contains(err.Error(), "Address already in use") {
		t.Fatalf("the error should name the up failure, got %v", err)
	}
}

func TestExecBackendUpBringsInterfaceUp(t *testing.T) {
	backend, commands := newFakeExecBackend(nil)
	if err := backend.Up(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if text := commandText(*commands); !strings.Contains(text, "ip link set wg-grm up") {
		t.Fatalf("missing up command:\n%s", text)
	}
}

// ACL.Interface 与 backend.Interface 是两份独立配置；不一致时规则永远不命中
// （表看起来正常、drop 计数恒为 0），必须 fail-closed 且不调用 nft。
func TestExecBackendApplyACLRejectsInterfaceMismatch(t *testing.T) {
	backend, commands := newFakeExecBackend(nil)
	err := backend.ApplyACL(context.Background(), ACL{Interface: "wg-other", Clients: []string{"10.77.0.2/32"}})
	if err == nil {
		t.Fatal("a mismatched ACL interface must be rejected")
	}
	if !strings.Contains(err.Error(), "wg-other") || !strings.Contains(err.Error(), "wg-grm") {
		t.Fatalf("the error should name both interfaces, got %v", err)
	}
	if len(*commands) != 0 {
		t.Fatalf("nft must not run for a mismatched interface, got commands: %s", commandText(*commands))
	}
}

// `ip -o link show` 输出里的标志位是唯一可靠判据：WireGuard 设备没有载波，
// 接口 up 时 operstate 仍是 UNKNOWN，按第二列判断会把健康接口永远报成 DOWN。
func TestExecBackendLinkUpParsesFlags(t *testing.T) {
	const downTail = " mtu 1420 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000\\    link/none\n"
	cases := []struct {
		name    string
		output  string
		want    bool
		wantErr bool
	}{
		{
			name:   "wireguard interface is up",
			output: "5: wg-grm: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none\n",
			want:   true,
		},
		{
			name:   "administratively down",
			output: "5: wg-grm: <POINTOPOINT,NOARP>" + downTail,
			want:   false,
		},
		{
			// 只有 LOWER_UP、没有 UP：按完整名字匹配，不能被子串骗过去。
			name:   "lower_up alone does not count as up",
			output: "5: wg-grm: <POINTOPOINT,NOARP,LOWER_UP>" + downTail,
			want:   false,
		},
		{
			name:    "device missing",
			output:  `ERR:Device "wg-grm" does not exist.`,
			wantErr: true,
		},
		{
			name:    "unparsable output",
			output:  "wg-grm\n",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend, commands := newFakeExecBackend(func(name string, args []string) (string, bool) {
				if name == "ip" && len(args) == 5 && args[0] == "-o" && args[1] == "link" && args[2] == "show" && args[3] == "dev" && args[4] == "wg-grm" {
					return tc.output, true
				}
				return "", false
			})
			up, err := backend.LinkUp(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want a probe error, got up=%v", up)
				}
				if up {
					t.Fatal("a failed probe must report the link as down")
				}
			} else {
				if err != nil {
					t.Fatalf("link up: %v", err)
				}
				if up != tc.want {
					t.Fatalf("link up = %v, want %v", up, tc.want)
				}
			}
			if text := commandText(*commands); !strings.Contains(text, "ip -o link show dev wg-grm") {
				t.Fatalf("probe must read the interface flags, got:\n%s", text)
			}
		})
	}
}
