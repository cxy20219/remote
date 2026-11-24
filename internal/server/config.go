package server

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"goremote/internal/common"
)

type Config struct {
	Server   ServerConfig
	Security SecurityConfig
	Tunnel   TunnelConfig
	Swagger  SwaggerConfig
	Log      LogConfig
	dataDir  string
}

const (
	defaultMaxBodySizeMB = 10
	// swaggerDefaultEnabled 故意为 false：发布版不该默认暴露一个调试用的 API
	// 文档入口，需要时用 --swagger 显式打开。测试会钉住这个值。
	swaggerDefaultEnabled = false
)

type ServerConfig struct {
	Host string
	Port int
	TLS  TLSConfig
}

type TLSConfig struct {
	Enabled bool
	Cert    string
	Key     string
}

type SecurityConfig struct {
	StateKey     string
	StateKeyFile string
	// StateKeyFromFlag 记录密钥是否来自 --state-key：命令行可见，启动时要告警。
	StateKeyFromFlag bool
	// StateKDFLegacy 强制只写 v1 状态格式，用于升级后的一次性回滚。
	StateKDFLegacy bool
	AllowedOrigins []string
	// TrustedProxies 只信任这里列出的反代地址；为空表示不信任任何代理头，
	// 直接使用 TCP 对端 IP（默认行为）。反代部署必须显式配置。
	TrustedProxies []string
}

type TunnelConfig struct {
	Enabled bool
	// AAD 控制是否对新协商的连接启用 v2 帧（GCM AAD = 帧头）。默认开启；
	// 关闭时 101 不回 X-Goremote-AAD，新连接自然回落 v1，旧 agent 始终 v1。
	AAD bool
	// ExternalIdleTimeout 是公网侧连接的空闲读超时。<=0 表示用包内默认值
	// （defaultExternalIdleTimeout，10 分钟）。运维按隧道类型调整：SSH 交互
	// 可能长时间静默，批量端口转发可以更短。
	ExternalIdleTimeout time.Duration
}

type SwaggerConfig struct {
	Enabled bool
}

type LogConfig struct {
	Level      string
	File       string
	MaxSizeMB  int
	MaxBackups int
}

func ParseConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Server.Host, "host", "0.0.0.0", "listen host")
	flag.IntVar(&cfg.Server.Port, "port", 8080, "listen port")
	flag.StringVar(&cfg.Server.TLS.Cert, "tls-cert", "", "TLS certificate path")
	flag.StringVar(&cfg.Server.TLS.Key, "tls-key", "", "TLS key path")
	flag.StringVar(&cfg.dataDir, "data", "./data", "data directory for server-state.json")

	allowedOrigins := flag.String("allowed-origins", "", "comma-separated browser origins allowed to open /ws")
	trustedProxies := flag.String("trusted-proxies", "", "comma-separated reverse-proxy IPs/CIDRs trusted for X-Forwarded-For (empty = trust none)")

	flag.BoolVar(&cfg.Tunnel.Enabled, "tunnel", true, "enable tunnel feature")
	flag.BoolVar(&cfg.Tunnel.AAD, "tunnel-aad", true, "bind tunnel data frames to their header with AES-GCM AAD (proto=2 agents only; off = legacy v1 frames)")
	flag.DurationVar(&cfg.Tunnel.ExternalIdleTimeout, "external-idle-timeout", defaultExternalIdleTimeout, "idle read timeout for public tunnel connections (<=0 uses the built-in default)")
	flag.BoolVar(&cfg.Swagger.Enabled, "swagger", swaggerDefaultEnabled, "enable swagger UI (off by default)")
	flag.StringVar(&cfg.Security.StateKey, "state-key", "", "state encryption key (visible in ps; prefer GOREMOTE_STATE_KEY or --state-key-file)")
	flag.StringVar(&cfg.Security.StateKeyFile, "state-key-file", "", "path to a 0600 file holding the state encryption key (no trailing newline required)")
	stateKDF := flag.String("state-kdf", "", "state encryption format: v2 (default, argon2id for passphrases) or legacy (write v1 for rollback)")

	flag.StringVar(&cfg.Log.Level, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&cfg.Log.File, "log-file", "", "log file path (empty writes JSON logs to stdout)")
	flag.IntVar(&cfg.Log.MaxSizeMB, "log-max-size-mb", common.DefaultLogMaxSizeMB, "max size in MB before rotating log file")
	flag.IntVar(&cfg.Log.MaxBackups, "log-max-backups", common.DefaultLogBackups, "number of rotated log files to keep")

	flag.Parse()

	if (cfg.Server.TLS.Cert == "") != (cfg.Server.TLS.Key == "") {
		fmt.Fprintln(os.Stderr, "--tls-cert and --tls-key must be provided together")
		os.Exit(2)
	}
	cfg.Server.TLS.Enabled = cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != ""
	cfg.Security.AllowedOrigins = splitCommaList(*allowedOrigins)
	cfg.Security.TrustedProxies = splitCommaList(*trustedProxies)

	legacyKDF, err := parseStateKDF(*stateKDF)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cfg.Security.StateKDFLegacy = legacyKDF

	// 密钥来源三者互斥：同时给两个无法判断用哪个，用错密钥要在 Load 时才
	// 以 GCM 认证失败暴露，报错误导。这里直接失败并点名冲突项。
	envKey := os.Getenv("GOREMOTE_STATE_KEY")
	if sources := stateKeySources(cfg.Security.StateKey, envKey, cfg.Security.StateKeyFile); len(sources) > 1 {
		fmt.Fprintf(os.Stderr, "state encryption key configured through multiple sources (%s); configure exactly one\n", strings.Join(sources, ", "))
		os.Exit(2)
	}
	cfg.Security.StateKeyFromFlag = cfg.Security.StateKey != ""
	if cfg.Security.StateKey == "" {
		cfg.Security.StateKey = envKey
	}
	if cfg.Security.StateKeyFile != "" {
		key, err := readStateKeyFile(cfg.Security.StateKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--state-key-file: %v\n", err)
			os.Exit(2)
		}
		cfg.Security.StateKey = key
	}
	// 在启动入口就校验格式：否则要等到 NewServer 里 panic 才暴露。
	if _, _, err := splitStateKey(cfg.Security.StateKey); err != nil {
		fmt.Fprintf(os.Stderr, "invalid state encryption key: %v\n", err)
		os.Exit(2)
	}

	return cfg
}

// parseStateKDF 解析 --state-kdf。默认（空）写 v2；legacy 只写 v1 供回滚。
func parseStateKDF(raw string) (legacy bool, err error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "v2":
		return false, nil
	case "legacy":
		return true, nil
	default:
		return false, fmt.Errorf("invalid --state-kdf value %q: want v2 (default) or legacy", raw)
	}
}

// stateKeySources 汇总实际配置的密钥来源，用于互斥校验。
func stateKeySources(flagKey, envKey, filePath string) []string {
	sources := make([]string, 0, 3)
	if flagKey != "" {
		sources = append(sources, "--state-key")
	}
	if envKey != "" {
		sources = append(sources, "GOREMOTE_STATE_KEY")
	}
	if filePath != "" {
		sources = append(sources, "--state-key-file")
	}
	return sources
}

// readStateKeyFile 读取 --state-key-file。只接受普通文件，且不能被组/其他
// 用户读到或写到；symlink 一律拒绝，避免部署时把密钥指向一个可被替换的路径。
// Windows 没有可用的 POSIX 权限位，跳过权限检查（该 flag 的隔离保证只在
// POSIX 上成立）。
func readStateKeyFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink; point the flag at the real key file", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return "", fmt.Errorf("%s has mode %04o; it must not be accessible by group or others (use 0600)", path, perm)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return key, nil
}

func splitCommaList(raw string) []string {
	result := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (c *Config) DataDir() string {
	return c.dataDir
}

// SetDataDir 给包外调用方（cmd、备份恢复的端到端测试）指定数据目录。
// dataDir 不导出是为了让 ParseConfig 成为唯一的默认值来源，避免出现
// 「结构体字面量忘了填 dataDir，state 悄悄写到当前目录」的部署事故。
func (c *Config) SetDataDir(dir string) {
	c.dataDir = dir
}

func (c *Config) Addr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}
