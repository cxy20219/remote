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
	// TempDir 可注入：私钥临时文件与 nft 规则文件的目录。空值时优先
	// /dev/shm（内存盘，SIGKILL 不会在磁盘上留下私钥），再退回 os.TempDir()。
	TempDir string
	// WriteSysctl 可注入，测试用来记录 accept_redirects/send_redirects。
	WriteSysctl func(path, value string) error
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
//
// nft 是 ACL 的硬依赖：没有它就不允许接口以「peer 在、ACL 没就绪」的状态
// 工作，所以 Probe 失败会让整轮 fail-closed（接口 down、写接口 503）。
func (b *ExecBackend) Probe(ctx context.Context) error {
	if err := b.lookup("ip"); err != nil {
		return err
	}
	if err := b.lookup("wg"); err != nil {
		return err
	}
	if err := b.lookup("nft"); err != nil {
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
		keyFile, err := os.CreateTemp(b.tempDir(), "goremote-wg-*.key")
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
	// 只设 MTU，不 up：接口要保持 down 直到 ACL 与 peer 都就位（见 Up）。
	if _, err := b.run(ctx, "ip", "link", "set", iface, "mtu", strconv.Itoa(mtu)); err != nil {
		return fmt.Errorf("set %s mtu: %w", iface, err)
	}
	// 关掉接口上的 ICMP redirect：peer 不能靠 redirect 改写 hub 的路由。
	for _, key := range []string{"accept_redirects", "send_redirects"} {
		path := "/proc/sys/net/ipv4/conf/" + iface + "/" + key
		write := b.WriteSysctl
		if write == nil {
			write = writeSysctl
		}
		if err := write(path, "0"); err != nil {
			return fmt.Errorf("disable %s on %s: %w", key, iface, err)
		}
	}
	return nil
}

// Up 把接口置为 up。这是 reconcile 的最后一步：接口 down 时 ACL 的
// iifname 不匹配任何包，所以从建接口到表就绪全程不存在无 ACL 的转发窗口。
// 端口冲突（EADDRINUSE）只在这里暴露，退出码必须被调用方检查。
func (b *ExecBackend) Up(ctx context.Context) error {
	iface := b.interfaceName(Hub{})
	if _, err := b.run(ctx, "ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", iface, err)
	}
	return nil
}

// LinkUp 只读地报告接口的管理状态（IFF_UP），不改变任何东西。
//
// 不用 `ip -br link show` 的第二列（operstate）判断：WireGuard 设备没有载波，
// 接口 up 时 operstate 仍报 UNKNOWN，按它判断会把健康接口永远报成不健康。
// 这里解析标志位尖括号里的名字，`ip link set down` 会清掉 IFF_UP。
func (b *ExecBackend) LinkUp(ctx context.Context) (bool, error) {
	iface := b.interfaceName(Hub{})
	output, err := b.run(ctx, "ip", "-o", "link", "show", "dev", iface)
	if err != nil {
		return false, fmt.Errorf("read %s link state: %w", iface, err)
	}
	flags, ok := linkFlags(string(output))
	if !ok {
		return false, fmt.Errorf("parse %s link flags: unexpected output %q", iface, strings.TrimSpace(string(output)))
	}
	return flags["UP"], nil
}

// linkFlags 提取 `ip link show` 输出里第一对尖括号内的标志集合。按完整名字
// 取，避免把 LOWER_UP 当成 UP。
func linkFlags(output string) (map[string]bool, bool) {
	open := strings.IndexByte(output, '<')
	if open < 0 {
		return nil, false
	}
	rest := output[open+1:]
	closeIndex := strings.IndexByte(rest, '>')
	if closeIndex < 0 {
		return nil, false
	}
	flags := make(map[string]bool)
	for _, flag := range strings.Split(rest[:closeIndex], ",") {
		if flag = strings.TrimSpace(flag); flag != "" {
			flags[flag] = true
		}
	}
	return flags, true
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}

// tempDir 优先 /dev/shm：hub 私钥只以临时文件形式交给 wg，进程被 SIGKILL 时
// 内存盘不会把私钥留到磁盘上。没有 /dev/shm 的环境退回系统临时目录。
func (b *ExecBackend) tempDir() string {
	if b.TempDir != "" {
		return b.TempDir
	}
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		return "/dev/shm"
	}
	return os.TempDir()
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

// ApplyACL 用 `nft -f` 原子替换 table inet goremote。
//
// 规则文件不机密，但仍然写到 0600 的临时文件并在命令结束后删除；整份文件
// 在一个内核事务里提交，语法/权限/内核拒绝都会让整批回滚，不会留下半套。
func (b *ExecBackend) ApplyACL(ctx context.Context, acl ACL) error {
	// 表里的 iifname/oifname 必须和真正被管理的接口一致。两个字段各自独立，
	// 将来改一个漏一个就会出现「表装好了、规则永远不命中、drop 计数恒为 0」
	// 的静默失效；这里一行断言把它变成 fail-closed。
	if expected := b.interfaceName(Hub{}); acl.Interface != expected {
		return fmt.Errorf("refusing to install ACL for interface %q: backend manages %q", acl.Interface, expected)
	}
	file, err := os.CreateTemp(b.tempDir(), "goremote-acl-*.nft")
	if err != nil {
		return fmt.Errorf("create nft ruleset file: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)

	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("chmod nft ruleset file: %w", err)
	}
	if _, err := file.WriteString(buildACLTable(acl)); err != nil {
		file.Close()
		return fmt.Errorf("write nft ruleset: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close nft ruleset file: %w", err)
	}
	if _, err := b.run(ctx, "nft", "-f", path); err != nil {
		return fmt.Errorf("apply nft table inet goremote: %w", err)
	}
	return nil
}

// ACLExists 用 `nft list tables` 判断表在不在。表被外部删掉时 reconcile
// 必须能发现并重装，不能让接口在无 ACL 状态下继续跑。
func (b *ExecBackend) ACLExists(ctx context.Context) (bool, error) {
	output, err := b.run(ctx, "nft", "list", "tables")
	if err != nil {
		return false, fmt.Errorf("list nft tables: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "table inet goremote" {
			return true, nil
		}
	}
	return false, nil
}

// PeerStats 返回 公钥 → 最近握手年龄与收发字节数。
func (b *ExecBackend) PeerStats(ctx context.Context) (map[string]PeerStats, error) {
	iface := b.interfaceName(Hub{})
	rows, err := b.dump(ctx, iface)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	result := make(map[string]PeerStats, len(rows))
	for publicKey, row := range rows {
		stats := PeerStats{RXBytes: row.rx, TXBytes: row.tx}
		if row.handshake > 0 {
			age := now - row.handshake
			if age < 0 {
				age = 0
			}
			stats.HandshakeAge = age
		}
		result[publicKey] = stats
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

// dumpPeer 是 `wg show dump` 一行里状态接口要用到的几列。
type dumpPeer struct {
	handshake int64
	rx        int64
	tx        int64
}

// dump 解析 `wg show <iface> dump`：第一行是接口，其余每行一个 peer，
// 制表符分隔。peer 行的字段顺序（wg(8)）是：
//
//	public-key, preshared-key, endpoint, allowed-ips, latest-handshake,
//	transfer-rx, transfer-tx, persistent-keepalive
//
// 即索引 3 是 allowed-ips、4 是 latest-handshake、5 是 transfer-rx、6 是
// transfer-tx。
func (b *ExecBackend) dump(ctx context.Context, iface string) (map[string]dumpPeer, error) {
	// 索引 4 是 latest-handshake（Unix 秒）；取 5 会读到 transfer-rx，
	// 把「已握手」解析成天文数字、「没握手」解析成 0，判据整个反掉。
	const (
		handshakeField = 4
		rxField        = 5
		txField        = 6
	)

	output, err := b.run(ctx, "wg", "show", iface, "dump")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]dumpPeer{}, nil
		}
		return nil, fmt.Errorf("read %s peers: %w", iface, err)
	}
	rows := make(map[string]dumpPeer)
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
		rx, _ := strconv.ParseInt(fields[rxField], 10, 64)
		tx, _ := strconv.ParseInt(fields[txField], 10, 64)
		rows[fields[0]] = dumpPeer{handshake: handshake, rx: rx, tx: tx}
	}
	return rows, nil
}
