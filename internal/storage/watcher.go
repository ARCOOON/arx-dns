package storage

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/ARCOOON/arx-dns/internal/config"
)

const defaultReloadDebounce = 500 * time.Millisecond

// StartWatcher watches cfg.Directory and its internal subdirectory for create,
// write, and remove events on .zone files and hot-reloads both views atomically.
func StartWatcher(ctx context.Context, cfg config.ZonesConfig, store *Memory, logger *slog.Logger) error {
	return startWatcher(ctx, cfg.Directory, store, logger)
}

func startWatcher(ctx context.Context, dir string, store *Memory, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return err
	}
	watchInternalDir(watcher, dir, logger)

	go runWatcher(ctx, watcher, dir, store, logger, defaultReloadDebounce)
	logger.Info("zone file watcher started", "directory", dir, "debounce", defaultReloadDebounce.String())
	return nil
}

func watchInternalDir(watcher *fsnotify.Watcher, root string, logger *slog.Logger) {
	internalDir := filepath.Join(root, internalViewDir)
	if _, err := os.Stat(internalDir); err != nil {
		return
	}
	if err := watcher.Add(internalDir); err != nil {
		logger.Warn("failed to watch internal zones directory", "path", internalDir, "error", err)
	}
}

func runWatcher(ctx context.Context, watcher *fsnotify.Watcher, dir string, store *Memory, logger *slog.Logger, debounce time.Duration) {
	defer watcher.Close()

	var (
		mu     sync.Mutex
		timer  *time.Timer
		reload = func(trigger string) {
			logger.Info("zone reload triggered", "directory", dir, "trigger", trigger)

			publicTree, internalTree, publicLoaded, publicSkipped, internalLoaded, internalSkipped := buildViewsFromDir(dir, logger)
			if publicTree == nil {
				logger.Warn("zone reload skipped; public directory unavailable", "directory", dir)
				return
			}

			store.SwapPublicTree(publicTree)
			store.SwapInternalTree(internalTree)
			logger.Info("zone reload complete",
				"directory", dir,
				"public_loaded", publicLoaded,
				"public_skipped", publicSkipped,
				"internal_loaded", internalLoaded,
				"internal_skipped", internalSkipped,
			)
		}
		scheduleReload = func(trigger string) {
			mu.Lock()
			defer mu.Unlock()

			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}

			timer = time.AfterFunc(debounce, func() {
				reload(trigger)
			})
		}
	)

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			if timer != nil {
				timer.Stop()
			}
			mu.Unlock()
			logger.Info("zone file watcher stopped", "directory", dir)
			return

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Error("zone file watcher error", "directory", dir, "error", err)

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) && isInternalDirCreate(event, dir) {
				watchInternalDir(watcher, dir, logger)
			}
			if !isZoneFileEvent(event) {
				continue
			}
			scheduleReload(event.Op.String())
		}
	}
}

func isInternalDirCreate(event fsnotify.Event, root string) bool {
	internalDir := filepath.Join(root, internalViewDir)
	return event.Name == internalDir && event.Has(fsnotify.Create)
}

func isZoneFileEvent(event fsnotify.Event) bool {
	if strings.EqualFold(filepath.Ext(event.Name), ".zone") {
		switch {
		case event.Has(fsnotify.Create),
			event.Has(fsnotify.Write),
			event.Has(fsnotify.Remove):
			return true
		}
	}
	return false
}
