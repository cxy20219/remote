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
		Interface:  "wg-grm",
		LookupPath: func(string) (string, error) { return "/usr/bin/true", nil },
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
		"ip link set wg-grm mtu 1420 up",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing command %q in:\n%s", want, text)
		}
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
	ages, err := backend.Handshakes(context.Background())
	if err != nil {
		t.Fatalf("handshakes: %v", err)
	}
	age, ok := ages["peer-a"]
	if !ok {
		t.Fatal("peer-a missing from handshakes")
	}
	if age < 25 || age > 40 {
		t.Fatalf("peer-a handshaked 30s ago; want age in (25,40), got %d (did the parser read transfer-rx instead of latest-handshake?)", age)
	}
	// 从未握手的设备即使 rx/tx 不为 0 也必须是 0，不能被流量计数冒充。
	if ages["peer-b"] != 0 {
		t.Fatalf("never-handshaked peer should be 0, got %d", ages["peer-b"])
	}
}

