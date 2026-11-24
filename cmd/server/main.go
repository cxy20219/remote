package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
	// 子命令在 ParseConfig 之前分派：backup/restore 有各自的 flagset，混进
	// 服务端的 --port/--data 会让参数互相污染。只有以 '-' 开头的 argv[1]
	// 才可能是服务端参数，所以「不像子命令就当服务端启动」是安全的。
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "backup":
			os.Exit(runBackup(os.Args[2:]))
		case "restore":
			os.Exit(runRestore(os.Args[2:]))
		case "help", "version":
			fmt.Fprintf(os.Stdout, "goremote-server %s\n\n%s", common.BuildVersion(), usageText())
			os.Exit(exitOK)
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usageText())
			os.Exit(exitUsage)
		}
	}
	os.Exit(runServer())
}

func usageText() string {
	return `usage:
  goremote-server [server flags]
  goremote-server backup  --data DIR --certs DIR --out DIR [--include-key --state-env-file FILE] [--allow-plaintext]
  goremote-server restore --from ARCHIVE [--data DIR] [--certs DIR] [--key-file FILE|GOREMOTE_STATE_KEY]
                          [--install-key --state-env-file FILE] [--restore-certs] [--dry-run] [--yes]

"goremote-server -h" lists the server flags; "goremote-server backup -h" /
"goremote-server restore -h" list the subcommand flags.
`
}

func runServer() int {
	config := server.ParseConfig()

	common.InitLogger(config.Log.Level, config.Log.File, config.Log.MaxSizeMB, config.Log.MaxBackups)

	srv, err := server.NewServer(config, web.StaticFS)
	if err != nil {
		// 两种读者：journalctl 里的结构化日志，和盯着终端的运维。后者那句话
		// 必须能直接照着做，所以它走 stderr 的纯文本，不走 slog 的 JSON。
		slog.Error("server state is not usable", "data_dir", config.DataDir(), "error", err)
		fmt.Fprintf(os.Stderr, "\ngoremote-server cannot start:\n%v\n\nexit status %d — add RestartPreventExitStatus=%d to the systemd unit, otherwise Restart=always retries this failure every few seconds.\n",
			err, server.ExitStateError, server.ExitStateError)
		return server.ExitStateError
	}

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
			return exitError
		}
		return exitOK
	case <-sigCh:
		slog.Info("shutdown signal received")
		if err := srv.Stop(); err != nil {
			slog.Warn("server shutdown error", "error", err)
		}
		if err := <-startErr; err != nil {
			slog.Error("server error", "error", err)
			return exitError
		}
		return exitOK
	}
}
