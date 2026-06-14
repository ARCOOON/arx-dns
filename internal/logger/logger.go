package logger

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Level is the global slog level variable used by the JSON handler.
// It can be updated at runtime to change verbosity without restarting handlers.
var Level slog.LevelVar

// ParseLevel maps a configuration string to a slog.Level.
// Allowed values: DEBUG, INFO, WARN, ERROR (case-insensitive).
func ParseLevel(raw string) (slog.Level, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q (expected DEBUG, INFO, WARN, or ERROR)", raw)
	}
}

// New configures a JSON slog.Logger writing to stdout with the given level.
// The returned logger is also registered as slog.Default().
func New(logLevel string) (*slog.Logger, error) {
	level, err := ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	Level.Set(level)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &Level,
	})
	l := slog.New(handler)
	slog.SetDefault(l)
	return l, nil
}
