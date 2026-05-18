package server

import (
	"log/slog"
	"os"

	"goremote/internal/common"
)

// InitLogger initializes the slog logger
func InitLogger(level, file string, maxSizeMB, maxBackups int) {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	if file == "" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		w, err := common.NewRotatingFileWriter(file, maxSizeMB, maxBackups)
		if err != nil {
			slog.Warn("failed to open log file, using stdout", "error", err)
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = slog.NewJSONHandler(w, opts)
		}
	}

	slog.SetDefault(slog.New(handler))
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
