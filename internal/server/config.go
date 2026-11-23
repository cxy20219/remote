package server

import (
	"flag"
	"fmt"
	"net"
	"os"
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

const defaultMaxBodySizeMB = 10

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
	StateKey       string
	AllowedOrigins []string
	// TrustedProxies 只信任这里列出的反代地址；为空表示不信任任何代理头，
	// 直接使用 TCP 对端 IP（默认行为）。反代部署必须显式配置。
	TrustedProxies []string
}

type TunnelConfig struct {
	Enabled bool
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
	flag.DurationVar(&cfg.Tunnel.ExternalIdleTimeout, "external-idle-timeout", defaultExternalIdleTimeout, "idle read timeout for public tunnel connections (<=0 uses the built-in default)")
	flag.BoolVar(&cfg.Swagger.Enabled, "swagger", true, "enable swagger UI")
	flag.StringVar(&cfg.Security.StateKey, "state-key", "", "state encryption key (prefer GOREMOTE_STATE_KEY)")

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
	if cfg.Security.StateKey == "" {
		cfg.Security.StateKey = os.Getenv("GOREMOTE_STATE_KEY")
	}

	return cfg
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

func (c *Config) Addr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}
