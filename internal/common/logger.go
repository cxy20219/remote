package common

import (
	"log/slog"
	"os"
)

// InitLogger initializes the process-wide slog logger.
func InitLogger(level, file string, maxSizeMB, maxBackups int) {
	opts := &slog.HandlerOptions{Level: parseLogLevel(level)}

	var handler slog.Handler
	if file == "" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		writer, err := NewRotatingFileWriter(file, maxSizeMB, maxBackups)
		if err != nil {
			slog.Warn("failed to open log file, using stdout", "error", err)
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = slog.NewJSONHandler(writer, opts)
		}
	}

	slog.SetDefault(slog.New(handler))
}

func parseLogLevel(level string) slog.Level {
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
