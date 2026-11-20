package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
	"goremote/internal/server"
	"goremote/web"

	_ "goremote/docs"
)

func init() {
	gin.DisableConsoleColor()
}

func main() {
	config := server.ParseConfig()

	common.InitLogger(config.Log.Level, config.Log.File, config.Log.MaxSizeMB, config.Log.MaxBackups)

	srv := server.NewServer(config, web.StaticFS)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	startErr := make(chan error, 1)
	go func() {
		startErr <- srv.Start()
	}()

	select {
	case err := <-startErr:
		if err != nil {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	case <-sigCh:
		slog.Info("shutdown signal received")
		if err := srv.Stop(); err != nil {
			slog.Warn("server shutdown error", "error", err)
		}
		if err := <-startErr; err != nil {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}
}
