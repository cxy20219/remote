package netplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ExecBackend 通过 iproute2 + wireguard-tools 改内核。
//
// 为什么走命令而不是自己写 netlink：阶段 1 只需要建一个接口和若干 peer，
// `ip` / `wg` 是部署侧本来就要装的工具（阶段 0 的 wireguard-tools 清单），
// 而手写 Generic Netlink 要维护几百行协议代码且无法在本机（macOS）验证。
// 代价是部署侧必须有这两个二进制，缺了就是清晰的 infraErr，不会假装成功。
type ExecBackend struct {
	Interface string
	// LookupPath 可注入，测试用来模拟工具缺失。
	LookupPath func(string) (string, error)
	// Run 可注入，测试用来记录命令。
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewExecBackend 返回使用真实环境的后端。
func NewExecBackend(iface string) *ExecBackend {
	if iface == "" {
		iface = DefaultInterface
	}
	return &ExecBackend{Interface: iface, LookupPath: exec.LookPath, Run: runCommand}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return output, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
	}
	return output, nil
}

func (b *ExecBackend) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if b.Run != nil {
		return b.Run(ctx, name, args...)
	}
	return runCommand(ctx, name, args...)
}

func (b *ExecBackend) lookup(name string) error {
	lookup := b.LookupPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup(name); err != nil {
		return fmt.Errorf("required tool %q is missing (install iproute2 and wireguard-tools): %w", name, err)
	}
	return nil
}

// Probe 检查工具链是否可用。内核模块是否存在由 Ensure 的第一次真实调用暴露。
func (b *ExecBackend) Probe(ctx context.Context) error {
	if err := b.lookup("ip"); err != nil {
		return err
	}
	if err := b.lookup("wg"); err != nil {
		return err
	}
	return nil
}

// Ensure 建/改 wg 接口并置为 up。私钥只以临时文件形式出现在命令里，用完立刻删。
func (b *ExecBackend) Ensure(ctx context.Context, hub Hub) error {
	iface := b.interfaceName(hub)
	if _, err := b.run(ctx, "ip", "link", "show", iface); err != nil {
		if _, addErr := b.run(ctx, "ip", "link", "add", iface, "type", "wireguard"); addErr != nil {
			return fmt.Errorf("create %s: %w", iface, addErr)
		}
	}
	if hub.PrivateKey != "" {
		keyFile, err := os.CreateTemp("", "goremote-wg-*.key")
		if err != nil {
			return fmt.Errorf("create hub key file: %w", err)
		}
		path := keyFile.Name()
		defer os.Remove(path)
		if err := keyFile.Chmod(0600); err != nil {
			keyFile.Close()
			return fmt.Errorf("chmod hub key file: %w", err)
		}
		if _, err := keyFile.WriteString(strings.TrimSpace(hub.PrivateKey) + "\n"); err != nil {
			keyFile.Close()
			return fmt.Errorf("write hub key file: %w", err)
		}
		if err := keyFile.Close(); err != nil {
			return fmt.Errorf("close hub key file: %w", err)
		}
		if _, err := b.run(ctx, "wg", "set", iface, "private-key", path, "listen-port", strconv.Itoa(hub.Listen)); err != nil {
			return fmt.Errorf("configure %s: %w", iface, err)
		}
	} else if hub.Listen > 0 {
		if _, err := b.run(ctx, "wg", "set", iface, "listen-port", strconv.Itoa(hub.Listen)); err != nil {
			return fmt.Errorf("configure %s: %w", iface, err)
		}
	}

	if hub.Address != "" {
		bits := 24
		if cidr := strings.TrimSpace(hub.CIDR); cidr != "" {
			if index := strings.LastIndex(cidr, "/"); index >= 0 {
				if parsed, err := strconv.Atoi(cidr[index+1:]); err == nil {
					bits = parsed
				}
			}
		}
		address := hub.Address + "/" + strconv.Itoa(bits)
		if _, err := b.run(ctx, "ip", "addr", "replace", address, "dev", iface); err != nil {
			return fmt.Errorf("assign %s: %w", address, err)
		}
	}

	mtu := hub.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	if _, err := b.run(ctx, "ip", "link", "set", iface, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", iface, err)
	}
	return nil
}

func (b *ExecBackend) interfaceName(hub Hub) string {
	if b.Interface != "" {
		return b.Interface
	}
	if hub.Interface != "" {
		return hub.Interface
	}
	return DefaultInterface
}

// Apply 对齐 peer 集合。新增/更新先做，删除后做（审计 A1 的顺序）；
// 单个 peer 失败只记给该设备，不阻塞别的设备。
func (b *ExecBackend) Apply(ctx context.Context, peers []Peer) (map[string]error, error) {
	iface := b.interfaceName(Hub{})
	actual, err := b.dump(ctx, iface)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]Peer, len(peers))
	failures := make(map[string]error)
	for _, peer := range peers {
		if peer.PublicKey == "" || peer.Address == "" || !peer.Enabled {
			continue
		}
		desired[peer.PublicKey] = peer
		if _, err := b.run(ctx, "wg", "set", iface, "peer", peer.PublicKey, "allowed-ips", peer.Address+"/32"); err != nil {
			failures[peer.DeviceID] = err
		}
	}
	for publicKey := range actual {
		if _, ok := desired[publicKey]; ok {
			continue
		}
		if _, err := b.run(ctx, "wg", "set", iface, "peer", publicKey, "remove"); err != nil {
			return failures, fmt.Errorf("remove stale peer %s: %w", publicKey, err)
		}
	}
	return failures, nil
}

// Handshakes 返回 公钥 → 最近握手距今秒数；0 表示从未握手。
func (b *ExecBackend) Handshakes(ctx context.Context) (map[string]int64, error) {
	iface := b.interfaceName(Hub{})
	rows, err := b.dump(ctx, iface)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	result := make(map[string]int64, len(rows))
	for publicKey, handshake := range rows {
		if handshake <= 0 {
			result[publicKey] = 0
			continue
		}
		age := now - handshake
		if age < 0 {
			age = 0
		}
		result[publicKey] = age
	}
	return result, nil
}

// Down 把接口拉下来；接口本来就不存在也算成功。
func (b *ExecBackend) Down(ctx context.Context) error {
	iface := b.interfaceName(Hub{})
	if _, err := b.run(ctx, "ip", "link", "show", iface); err != nil {
		return nil
	}
	if _, err := b.run(ctx, "ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("bring %s down: %w", iface, err)
	}
	return nil
}

// dump 解析 `wg show <iface> dump`：第一行是接口，其余每行一个 peer，
// 制表符分隔。peer 行的字段顺序（wg(8)）是：
//
//	public-key, preshared-key, endpoint, allowed-ips, latest-handshake,
//	transfer-rx, transfer-tx, persistent-keepalive
//
// 即索引 3 是 allowed-ips、4 是 latest-handshake、5 是 transfer-rx。
func (b *ExecBackend) dump(ctx context.Context, iface string) (map[string]int64, error) {
	// 索引 4 是 latest-handshake（Unix 秒）；取 5 会读到 transfer-rx，
	// 把「已握手」解析成天文数字、「没握手」解析成 0，判据整个反掉。
	const handshakeField = 4

	output, err := b.run(ctx, "wg", "show", iface, "dump")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]int64{}, nil
		}
		return nil, fmt.Errorf("read %s peers: %w", iface, err)
	}
	rows := make(map[string]int64)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for index, line := range lines {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[handshakeField], 10, 64)
		rows[fields[0]] = handshake
	}
	return rows, nil
}
