package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"goremote/internal/agent"
	"goremote/internal/common"
)

func main() {
	serverAddr := flag.String("server", "", "server address (e.g., YOUR_SERVER:8080)")
	tlsEnabled := flag.Bool("tls", false, "enable TLS")
	tlsCA := flag.String("tls-ca", "", "TLS CA certificate path")
	insecureSkipVerify := flag.Bool("tls-insecure", false, "skip TLS certificate verification")
	configPath := flag.String("config", "", "config file path (optional, CLI flags take precedence)")
	identityDir := flag.String("identity-dir", "", "identity storage directory (default: $HOME/.goremote)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error")
	logFile := flag.String("log-file", "", "log file path (empty writes JSON logs to stdout)")
	logMaxSizeMB := flag.Int("log-max-size-mb", 0, "max size in MB before rotating log file")
	logMaxBackups := flag.Int("log-max-backups", 0, "number of rotated log files to keep")
	flag.Parse()

	agentCfg := agent.DefaultConfig()

	if *configPath != "" {
		loadedCfg, err := agent.LoadConfig(*configPath)
		if err != nil {
			slog.Error("failed to load config", "error", err)
			os.Exit(1)
		}
		agentCfg = loadedCfg
	}

	if *serverAddr != "" {
		agentCfg.Server.Address = *serverAddr
	}
	if *tlsEnabled {
		agentCfg.Server.TLS.Enabled = true
	}
	if *tlsCA != "" {
		agentCfg.Server.TLS.CA = *tlsCA
	}
	if *insecureSkipVerify {
		agentCfg.Server.TLS.InsecureSkipVerify = true
	}
	if *logLevel != "" {
		agentCfg.Log.Level = *logLevel
	}
	if *logFile != "" {
		agentCfg.Log.File = *logFile
	}
	if *logMaxSizeMB > 0 {
		agentCfg.Log.MaxSizeMB = *logMaxSizeMB
	}
	if *logMaxBackups > 0 {
		agentCfg.Log.MaxBackups = *logMaxBackups
	}

	if agentCfg.Server.Address == "" {
		fmt.Println("Usage: agent <server_address>")
		fmt.Println("  e.g., agent YOUR_SERVER:8080")
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	agent.InitLogger(agentCfg.Log.Level, agentCfg.Log.File, agentCfg.Log.MaxSizeMB, agentCfg.Log.MaxBackups)

	identityDirVal := *identityDir
	agentCfg.IdentityDir = identityDirVal
	identity, err := agent.LoadIdentity(identityDirVal)
	if err != nil {
		slog.Error("failed to load identity", "error", err)
		os.Exit(1)
	}

	if identity == nil {
		slog.Info("no existing identity found, creating new one")
		identity, err = agent.CreateIdentity(identityDirVal, agentCfg.Server.Address)
		if err != nil {
			slog.Error("failed to create identity", "error", err)
			os.Exit(1)
		}
	}

	if identity.ServerURL != agentCfg.Server.Address {
		slog.Info("server URL changed, updating identity",
			"old", identity.ServerURL,
			"new", agentCfg.Server.Address)
		identity.ServerURL = agentCfg.Server.Address
		identity.ClientID = ""
		identity.EncKey = ""
		if err := identity.Save(identityDirVal); err != nil {
			slog.Error("failed to save identity", "error", err)
		}
	}

	hostname := agentCfg.Agent.Hostname
	if hostname == "" {
		hostname = common.GetHostname()
	}
	osName := agentCfg.Agent.OS
	if osName == "" {
		osName = common.GetOS()
	}

	slog.Info("agent starting",
		"server", agentCfg.Server.Address,
		"hostname", hostname,
		"os", osName,
		"client_id", identity.ClientID)

	ag := agent.NewAgent(agentCfg, identity)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutdown signal received")
		ag.Stop()
		os.Exit(0)
	}()

	if err := ag.Run(); err != nil {
		slog.Error("agent error", "error", err)
		os.Exit(1)
	}
}
