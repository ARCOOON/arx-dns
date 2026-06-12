package firewall

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/ARCOOON/arx-dns/internal/config"
)

const defaultReloadDebounce = 500 * time.Millisecond

// StartWatcher watches cfg.BlocklistsDirectory for create, write, and remove
// events on blocklist files and hot-reloads the firewall radix tree atomically.
func StartWatcher(ctx context.Context, cfg config.FirewallConfig, engine *Engine, logger *slog.Logger) error {
	return startWatcher(ctx, cfg.BlocklistsDirectory, engine, logger)
}

func startWatcher(ctx context.Context, dir string, engine *Engine, logger *slog.Logger) error {
	if engine == nil {
		return nil
	}
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

	go runWatcher(ctx, watcher, dir, engine, logger, defaultReloadDebounce)
	logger.Info("blocklist watcher started", "directory", dir, "debounce", defaultReloadDebounce.String())
	return nil
}

func runWatcher(ctx context.Context, watcher *fsnotify.Watcher, dir string, engine *Engine, logger *slog.Logger, debounce time.Duration) {
	defer watcher.Close()

	var (
		mu     sync.Mutex
		timer  *time.Timer
		reload = func(trigger string) {
			logger.Info("blocklist reload triggered", "directory", dir, "trigger", trigger)
			LoadFromDir(dir, engine, logger)
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
			logger.Info("blocklist watcher stopped", "directory", dir)
			return

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Error("blocklist watcher error", "directory", dir, "error", err)

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !isBlocklistFileEvent(event) {
				continue
			}
			scheduleReload(event.Op.String())
		}
	}
}

func isBlocklistFileEvent(event fsnotify.Event) bool {
	if strings.EqualFold(filepath.Ext(event.Name), ".zone") {
		return false
	}
	switch {
	case event.Has(fsnotify.Create),
		event.Has(fsnotify.Write),
		event.Has(fsnotify.Remove):
		return true
	default:
		return false
	}
}
