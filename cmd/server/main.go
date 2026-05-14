package main

import (
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
	config := server.ParseConfig()

	server.InitLogger("info", "")

	srv := server.NewServer(config, web.StaticFS)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutdown signal received")
		srv.Stop()
		os.Exit(0)
	}()

	slog.Info("server starting", "addr", config.Addr())
	if err := srv.Start(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}