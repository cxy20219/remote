package agent

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"goremote/internal/common"
)

type Config struct {
	IdentityDir string          `yaml:"-"`
	Server      ServerConfig    `yaml:"server"`
	Agent       AgentConfig     `yaml:"agent"`
	Heartbeat   HeartbeatConfig `yaml:"heartbeat"`
	Reconnect   ReconnectConfig `yaml:"reconnect"`
	Log         LogConfig       `yaml:"log"`
}

type ServerConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
	// LegacyHandshake 让本连接不带任何握手参数（proto/ver/commit/caps），
	// 行为与 v2.8.0 之前的 agent 完全一致。
	//
	// 它不是给普通用户用的：反向代理/WAF 改写 WS 握手时会得到同样的结果，
	// 这个开关用来复现和定位那类问题，也是兼容矩阵里「老 agent × 新服务端」
	// 那一格的实现方式。
	LegacyHandshake bool `yaml:"legacy_handshake"`
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
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
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
			Level:      "info",
			MaxSizeMB:  common.DefaultLogMaxSizeMB,
			MaxBackups: common.DefaultLogBackups,
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
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
	if config.Log.MaxSizeMB <= 0 {
		config.Log.MaxSizeMB = common.DefaultLogMaxSizeMB
	}
	if config.Log.MaxBackups <= 0 {
		config.Log.MaxBackups = common.DefaultLogBackups
	}

	return &config, nil
}
