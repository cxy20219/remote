package agent

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	IdentityDir string          `yaml:"-"`
	Server      ServerConfig    `yaml:"server"`
	Agent       AgentConfig     `yaml:"agent"`
	Heartbeat   HeartbeatConfig `yaml:"heartbeat"`
	Reconnect   ReconnectConfig `yaml:"reconnect"`
	Log         LogConfig       `yaml:"log"`
	Tunnel      TunnelConfig    `yaml:"tunnel"`
}

type ServerConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CA                 string `yaml:"ca"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type AgentConfig struct {
	Hostname string `yaml:"hostname"`
	OS       string `yaml:"os"`
}

type HeartbeatConfig struct {
	Interval int `yaml:"interval"`
}

type ReconnectConfig struct {
	Interval    int `yaml:"interval"`
	MaxAttempts int `yaml:"max_attempts"`
	MaxInterval int `yaml:"max_interval"`
}

type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type TunnelConfig struct {
	Enabled bool `yaml:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Address: "localhost:8080",
		},
		Heartbeat: HeartbeatConfig{
			Interval: 30,
		},
		Reconnect: ReconnectConfig{
			Interval:    5,
			MaxAttempts: 0,
			MaxInterval: 60,
		},
		Log: LogConfig{
			Level: "info",
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.Server.Address == "" {
		config.Server.Address = "localhost:8080"
	}
	if config.Heartbeat.Interval == 0 {
		config.Heartbeat.Interval = 30
	}
	if config.Reconnect.Interval == 0 {
		config.Reconnect.Interval = 5
	}
	if config.Reconnect.MaxInterval == 0 {
		config.Reconnect.MaxInterval = 60
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}

	return &config, nil
}
