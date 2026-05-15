package server

import (
	"flag"
	"fmt"
)

type Config struct {
	Server   ServerConfig
	Admin    AdminConfig
	Security SecurityConfig
	Tunnel   TunnelConfig
	Swagger  SwaggerConfig
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
