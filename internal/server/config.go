package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds server configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Auth      AuthConfig      `yaml:"auth"`
	Heartbeat HeartbeatConfig `yaml:"heartbeat"`
	Log       LogConfig       `yaml:"log"`
	Tunnel    TunnelConfig    `yaml:"tunnel"`
}

// TunnelConfig holds tunnel configuration
type TunnelConfig struct {
	Enabled             bool   `yaml:"enabled"`
	PortRangeStart      int    `yaml:"port_range_start"`       // allocated public port range start
	PortRangeEnd        int    `yaml:"port_range_end"`         // allocated public port range end
	MaxTunnelsPerClient int    `yaml:"max_tunnels_per_client"` // max tunnels allowed per client
	PublicHost          string `yaml:"public_host"`            // optional externally reachable host returned by API
	DefaultLocalAddr    string `yaml:"default_local_addr"`     // default target address on the agent
}

// ServerConfig holds WebSocket server configuration
type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Key string `yaml:"key"`
}

// HeartbeatConfig holds heartbeat configuration
type HeartbeatConfig struct {
	Interval int `yaml:"interval"` // heartbeat check interval in seconds
	Timeout  int `yaml:"timeout"`  // heartbeat timeout in seconds
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level string `yaml:"level"` // debug/info/warn/error
	File  string `yaml:"file"`  // empty for stdout
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 8080
	}
	if config.Heartbeat.Interval == 0 {
		config.Heartbeat.Interval = 30
	}
	if config.Heartbeat.Timeout == 0 {
		config.Heartbeat.Timeout = 90
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}

	// Tunnel defaults
	if config.Tunnel.PortRangeStart == 0 {
		config.Tunnel.PortRangeStart = 10000
	}
	if config.Tunnel.PortRangeEnd == 0 {
		config.Tunnel.PortRangeEnd = 20000
	}
	if config.Tunnel.MaxTunnelsPerClient == 0 {
		config.Tunnel.MaxTunnelsPerClient = 10
	}
	if config.Tunnel.DefaultLocalAddr == "" {
		config.Tunnel.DefaultLocalAddr = "127.0.0.1"
	}
	// NOTE: Tunnel.Enabled 默认 false，用户显式开启

	return &config, nil
}
