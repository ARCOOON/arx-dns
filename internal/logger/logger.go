package logger

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Level is the global slog level variable shared by all log sinks.
// It can be updated at runtime to change verbosity without restarting handlers.
var Level slog.LevelVar

var (
	mu          sync.RWMutex
	ring        = NewRingBuffer(defaultRingCapacity)
	broadcaster = NewBroadcaster()
	fileLogger  *lumberjack.Logger
	runtimeCfg  = DefaultConfig("INFO")
)

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

// New configures a multi-target slog.Logger: colorized console output, rotating
// JSON file logs, and in-memory history with live SSE broadcast. When db is
// non-nil, settings are loaded from and seeded into main.db configuration.
func New(logLevel string, db *sql.DB) (*slog.Logger, error) {
	cfg, err := LoadConfig(db, logLevel)
	if err != nil {
		return nil, err
	}
	return newWithConfig(cfg)
}

func newWithConfig(cfg Config) (*slog.Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	if err := ensureLogDirectory(cfg.Rotation.FilePath); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	file := &lumberjack.Logger{
		Filename:   cfg.Rotation.FilePath,
		MaxSize:    cfg.Rotation.MaxSizeMB,
		MaxBackups: cfg.Rotation.MaxBackups,
		MaxAge:     cfg.Rotation.MaxAgeDays,
	}

	handlerOpts := &slog.HandlerOptions{Level: &Level}
	streamWriter := NewStreamWriter(ring, broadcaster)
	handler := NewMultiHandler(
		NewConsoleHandler(os.Stdout, handlerOpts),
		slog.NewJSONHandler(file, handlerOpts),
		slog.NewJSONHandler(streamWriter, handlerOpts),
	)
	l := slog.New(handler)
	slog.SetDefault(l)

	mu.Lock()
	fileLogger = file
	runtimeCfg = cfg
	mu.Unlock()

	Level.Set(level)
	return l, nil
}

// SetLevel updates the global slog level at runtime.
func SetLevel(raw string) error {
	level, err := ParseLevel(raw)
	if err != nil {
		return err
	}
	Level.Set(level)

	mu.Lock()
	runtimeCfg.Level = strings.ToUpper(strings.TrimSpace(raw))
	mu.Unlock()
	return nil
}

// CurrentConfig returns a copy of the active logging configuration.
func CurrentConfig() Config {
	mu.RLock()
	defer mu.RUnlock()
	return runtimeCfg
}

// UpdateConfig applies runtime logging settings and optionally persists them.
func UpdateConfig(db *sql.DB, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := SetLevel(cfg.Level); err != nil {
		return err
	}

	mu.Lock()
	if fileLogger != nil {
		fileLogger.Filename = strings.TrimSpace(cfg.Rotation.FilePath)
		fileLogger.MaxSize = cfg.Rotation.MaxSizeMB
		fileLogger.MaxBackups = cfg.Rotation.MaxBackups
		fileLogger.MaxAge = cfg.Rotation.MaxAgeDays
	}
	runtimeCfg = cfg
	mu.Unlock()

	if err := ensureLogDirectory(cfg.Rotation.FilePath); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	if db != nil {
		return SaveConfig(db, cfg)
	}
	return nil
}

// History returns the in-memory ring buffer snapshot.
func History() []string {
	return ring.Snapshot()
}

// Subscribe registers a live log stream consumer.
func Subscribe() chan string {
	return broadcaster.Subscribe()
}

// Unsubscribe removes a live log stream consumer.
func Unsubscribe(ch chan string) {
	broadcaster.Unsubscribe(ch)
}
