package server

import (
	"flag"
	"fmt"

	"goremote/internal/common"
)

type Config struct {
	Server   ServerConfig
	Admin    AdminConfig
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
	Enabled            bool
	Cert               string
	Key                string
	InsecureSkipVerify bool
}

type AdminConfig struct {
	Password string
}

type SecurityConfig struct {
	AllowedOrigins     []string
	LoginRateLimit     int
	MaxBodySizeMB      int
	MaxConnPerMin      int
	GlobalWhitelist    []string
	BlacklistThreshold int
}

type TunnelConfig struct {
	Enabled             bool
	PortRangeStart      int
	PortRangeEnd        int
	MaxTunnelsPerClient int
	PublicHost          string
	DefaultLocalAddr    string
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

	flag.BoolVar(&cfg.Tunnel.Enabled, "tunnel", true, "enable tunnel feature")
	flag.IntVar(&cfg.Tunnel.PortRangeStart, "port-start", 10000, "tunnel port range start")
	flag.IntVar(&cfg.Tunnel.PortRangeEnd, "port-end", 20000, "tunnel port range end")
	flag.IntVar(&cfg.Tunnel.MaxTunnelsPerClient, "max-tunnels", 10, "max tunnels per client")
	flag.StringVar(&cfg.Tunnel.DefaultLocalAddr, "local-addr", "127.0.0.1", "default local address for tunnels")
	flag.StringVar(&cfg.Tunnel.PublicHost, "public-host", "", "public host for tunnel addresses")

	flag.BoolVar(&cfg.Swagger.Enabled, "swagger", true, "enable swagger UI")

	flag.StringVar(&cfg.Log.Level, "log-level", "info", "log level: debug, info, warn, error")
	flag.StringVar(&cfg.Log.File, "log-file", "", "log file path (empty writes JSON logs to stdout)")
	flag.IntVar(&cfg.Log.MaxSizeMB, "log-max-size-mb", common.DefaultLogMaxSizeMB, "max size in MB before rotating log file")
	flag.IntVar(&cfg.Log.MaxBackups, "log-max-backups", common.DefaultLogBackups, "number of rotated log files to keep")

	flag.Parse()

	cfg.Server.TLS.Enabled = cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != ""
	cfg.Security.LoginRateLimit = 5
	cfg.Security.MaxConnPerMin = 10
	cfg.Security.BlacklistThreshold = 100
	cfg.Security.GlobalWhitelist = []string{}
	cfg.Security.AllowedOrigins = []string{}
	cfg.Security.MaxBodySizeMB = defaultMaxBodySizeMB

	return cfg
}

func (c *Config) DataDir() string {
	return c.dataDir
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
