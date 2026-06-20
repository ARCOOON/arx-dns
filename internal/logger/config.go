package logger

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	configKeyLogLevel      = "log_level"
	configKeyLogMaxSize    = "log_max_size"
	configKeyLogMaxBackups = "log_max_backups"
	configKeyLogMaxAge     = "log_max_age"
	configKeyLogFilePath   = "log_file_path"

	defaultLogFilePath   = "./logs/arx-dns.log"
	defaultLogMaxSize    = 50
	defaultLogMaxBackups = 3
	defaultLogMaxAge     = 28
)

// RotationConfig controls lumberjack file rotation parameters.
type RotationConfig struct {
	FilePath   string `json:"file_path"`
	MaxSizeMB  int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	MaxAgeDays int    `json:"max_age_days"`
}

// Config is the persisted and runtime logging configuration.
type Config struct {
	Level    string         `json:"level"`
	Rotation RotationConfig `json:"rotation"`
}

// DefaultConfig returns the baseline logging configuration.
func DefaultConfig(level string) Config {
	if strings.TrimSpace(level) == "" {
		level = "INFO"
	}
	return Config{
		Level: strings.ToUpper(strings.TrimSpace(level)),
		Rotation: RotationConfig{
			FilePath:   defaultLogFilePath,
			MaxSizeMB:  defaultLogMaxSize,
			MaxBackups: defaultLogMaxBackups,
			MaxAgeDays: defaultLogMaxAge,
		},
	}
}

// LoadConfig reads logging settings from main.db, seeding defaults when missing.
func LoadConfig(db *sql.DB, defaultLevel string) (Config, error) {
	cfg := DefaultConfig(defaultLevel)
	if db == nil {
		return cfg, nil
	}

	rows, err := db.Query(`SELECT key, value FROM configuration WHERE key IN (?, ?, ?, ?, ?);`,
		configKeyLogLevel,
		configKeyLogMaxSize,
		configKeyLogMaxBackups,
		configKeyLogMaxAge,
		configKeyLogFilePath,
	)
	if err != nil {
		return Config{}, fmt.Errorf("query log configuration: %w", err)
	}
	defer rows.Close()

	values := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return Config{}, fmt.Errorf("scan log configuration row: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return Config{}, fmt.Errorf("iterate log configuration rows: %w", err)
	}

	if len(values) == 0 {
		if err := SaveConfig(db, cfg); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	if raw, ok := values[configKeyLogLevel]; ok && strings.TrimSpace(raw) != "" {
		cfg.Level = strings.ToUpper(strings.TrimSpace(raw))
	}
	if raw, ok := values[configKeyLogFilePath]; ok && strings.TrimSpace(raw) != "" {
		cfg.Rotation.FilePath = strings.TrimSpace(raw)
	}
	if raw, ok := values[configKeyLogMaxSize]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			cfg.Rotation.MaxSizeMB = n
		}
	}
	if raw, ok := values[configKeyLogMaxBackups]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 0 {
			cfg.Rotation.MaxBackups = n
		}
	}
	if raw, ok := values[configKeyLogMaxAge]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 0 {
			cfg.Rotation.MaxAgeDays = n
		}
	}

	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// SaveConfig persists logging settings to main.db.
func SaveConfig(db *sql.DB, cfg Config) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin configuration transaction: %w", err)
	}

	entries := map[string]string{
		configKeyLogLevel:      strings.ToUpper(strings.TrimSpace(cfg.Level)),
		configKeyLogFilePath:   strings.TrimSpace(cfg.Rotation.FilePath),
		configKeyLogMaxSize:    strconv.Itoa(cfg.Rotation.MaxSizeMB),
		configKeyLogMaxBackups: strconv.Itoa(cfg.Rotation.MaxBackups),
		configKeyLogMaxAge:     strconv.Itoa(cfg.Rotation.MaxAgeDays),
	}

	for key, value := range entries {
		if _, err := tx.Exec(`
INSERT INTO configuration (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value;
`, key, value); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("upsert configuration key %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit log configuration: %w", err)
	}
	return nil
}

func validateConfig(cfg Config) error {
	if _, err := ParseLevel(cfg.Level); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Rotation.FilePath) == "" {
		return fmt.Errorf("rotation file path is required")
	}
	if cfg.Rotation.MaxSizeMB <= 0 {
		return fmt.Errorf("rotation max_size_mb must be greater than zero")
	}
	if cfg.Rotation.MaxBackups < 0 {
		return fmt.Errorf("rotation max_backups must be zero or greater")
	}
	if cfg.Rotation.MaxAgeDays < 0 {
		return fmt.Errorf("rotation max_age_days must be zero or greater")
	}
	return nil
}

func ensureLogDirectory(filePath string) error {
	dir := filepath.Dir(filePath)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
