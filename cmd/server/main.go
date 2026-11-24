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

// GoRemote 管理 API。
//
// swagger 只描述 HTTP 管理接口：/ws 是 agent 的 WebSocket 隧道入口，不走本规范。
// 文档由 scripts/gen-swagger.sh 从 internal/server 的 handler 注解生成，CI 会校验
// 「重新生成后工作区无改动」，所以改路由或字段必须同步改注解。
//
// @title GoRemote 管理 API
// @version 2.8.0
// @description 面板使用的 HTTP 管理接口。除 /health、/api/setup/*、/api/login* 外都需要管理员会话 Cookie。
// @BasePath /
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
