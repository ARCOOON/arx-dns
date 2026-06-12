package storage

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultReloadDebounce = 500 * time.Millisecond

// StartWatcher watches dir for create, write, and remove events on .zone files and
// hot-reloads the store by building a new radix tree and swapping it in atomically.
// The watcher runs until ctx is cancelled.
func StartWatcher(ctx context.Context, dir string, store *Memory, logger *slog.Logger) error {
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

	go runWatcher(ctx, watcher, dir, store, logger, defaultReloadDebounce)
	logger.Info("zone file watcher started", "directory", dir, "debounce", defaultReloadDebounce.String())
	return nil
}

func runWatcher(ctx context.Context, watcher *fsnotify.Watcher, dir string, store *Memory, logger *slog.Logger, debounce time.Duration) {
	defer watcher.Close()

	var (
		mu     sync.Mutex
		timer  *time.Timer
		reload = func(trigger string) {
			logger.Info("zone reload triggered", "directory", dir, "trigger", trigger)

			tree, loaded, skipped := buildTreeFromDir(dir, logger)
			if tree == nil {
				logger.Warn("zone reload skipped; directory unavailable", "directory", dir)
				return
			}

			store.SwapTree(tree)
			logger.Info("zone reload complete", "directory", dir, "loaded", loaded, "skipped", skipped)
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
			if !isZoneFileEvent(event) {
				continue
			}
			scheduleReload(event.Op.String())
		}
	}
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
