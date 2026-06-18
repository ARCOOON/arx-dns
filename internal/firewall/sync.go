package firewall

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/armon/go-radix"
)

const (
	// SyncHTTPTimeout is the per-feed HTTP client timeout during blocklist sync.
	SyncHTTPTimeout = 30 * time.Second
	feedFilePrefix  = "feed-"
	feedFileSuffix  = ".list"
)

var syncRunning atomic.Bool

// SyncInProgress reports whether a blocklist sync worker is currently running.
func SyncInProgress() bool {
	return syncRunning.Load()
}

// SyncBlocklistSources downloads all enabled feeds into dir, then reloads the engine.
func SyncBlocklistSources(ctx context.Context, db *sql.DB, dir string, engine *Engine, logger *slog.Logger) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("blocklists directory must not be empty")
	}
	if logger == nil {
		logger = slog.Default()
	}

	sources, err := ListEnabledBlocklistSources(db)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create blocklists directory %q: %w", dir, err)
	}

	if err := removeManagedFeedFiles(dir); err != nil {
		return err
	}

	client := &http.Client{Timeout: SyncHTTPTimeout}

	for _, source := range sources {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		path := feedFilePath(dir, source.ID)
		if err := downloadFeed(ctx, client, source.URL, path); err != nil {
			logger.Error("failed to download blocklist feed",
				"source_id", source.ID,
				"url", source.URL,
				"path", path,
				"error", err,
			)
			continue
		}

		domainCount, countErr := countDomainsInFile(path)
		if countErr != nil {
			logger.Error("failed to count domains in blocklist feed",
				"source_id", source.ID,
				"url", source.URL,
				"path", path,
				"error", countErr,
			)
		} else if err := UpdateBlocklistSourceStats(db, source.ID, domainCount); err != nil {
			logger.Error("failed to update blocklist source stats",
				"source_id", source.ID,
				"url", source.URL,
				"domain_count", domainCount,
				"error", err,
			)
		}

		logger.Info("downloaded blocklist feed",
			"source_id", source.ID,
			"url", source.URL,
			"path", path,
			"domains", domainCount,
		)
	}

	if engine != nil {
		LoadFromDirWithDB(dir, db, engine, logger)
	}

	return nil
}

// StartBlocklistSync launches SyncBlocklistSources in a background goroutine.
// Returns false when a sync is already running.
func StartBlocklistSync(db *sql.DB, dir string, engine *Engine, logger *slog.Logger) bool {
	if !syncRunning.CompareAndSwap(false, true) {
		return false
	}

	go func() {
		defer syncRunning.Store(false)

		if err := SyncBlocklistSources(context.Background(), db, dir, engine, logger); err != nil {
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("blocklist sync failed", "directory", dir, "error", err)
			return
		}

		if logger == nil {
			logger = slog.Default()
		}
		logger.Info("blocklist sync completed", "directory", dir)
	}()

	return true
}

func feedFilePath(dir string, id int64) string {
	return filepath.Join(dir, fmt.Sprintf("%s%d%s", feedFilePrefix, id, feedFileSuffix))
}

func removeManagedFeedFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read blocklists directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !isManagedFeedFile(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove managed feed file %q: %w", path, err)
		}
	}

	return nil
}

func isManagedFeedFile(name string) bool {
	return strings.HasPrefix(name, feedFilePrefix) && strings.HasSuffix(name, feedFileSuffix)
}

func downloadFeed(ctx context.Context, client *http.Client, sourceURL, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "arx-dns-blocklist-sync/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}

	_, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write feed file: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", closeErr)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename feed file: %w", err)
	}

	return nil
}

func countDomainsInFile(path string) (int, error) {
	tree := radix.New()
	count, err := LoadBlocklistFile(path, tree)
	if err != nil {
		return 0, err
	}
	return count, nil
}
