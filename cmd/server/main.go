package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"goremote/internal/server"
	"goremote/web"

	_ "goremote/docs"
)

func init() {
	gin.DisableConsoleColor()
}

func main() {
	configPath := flag.String("config", "config/server.yaml", "path to config file")
	flag.Parse()

	config, err := server.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	server.InitLogger(config.Log.Level, config.Log.File)

	srv := server.NewServer(config, web.StaticFS)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutdown signal received")
		srv.Stop()
		os.Exit(0)
	}()

	slog.Info("server starting")
	if err := srv.Start(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
