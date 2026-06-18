package firewall

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/armon/go-radix"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// Load reads all regular files in cfg.BlocklistsDirectory (HOSTS-formatted or plain
// domain lists), builds a fresh radix tree, and atomically swaps it into the engine.
func Load(cfg config.FirewallConfig, engine *Engine, logger *slog.Logger) {
	LoadFromDir(cfg.BlocklistsDirectory, engine, logger)
}

// LoadFromDir reads all regular files in dir, builds a fresh radix tree, and
// atomically swaps it into the engine.
func LoadFromDir(dir string, engine *Engine, logger *slog.Logger) {
	if engine == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	tree, loaded, skipped := buildTreeFromDir(dir, logger)
	if tree == nil {
		tree = radix.New()
	}
	engine.SwapTree(tree)

	logger.Info("blocklist loading complete",
		"directory", dir,
		"files_loaded", loaded,
		"files_skipped", skipped,
		"domains", tree.Len(),
	)
}

func buildTreeFromDir(dir string, logger *slog.Logger) (*radix.Tree, int, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("blocklists directory not found", "path", dir)
			return nil, 0, 0
		}
		logger.Error("failed to read blocklists directory", "path", dir, "error", err)
		return nil, 0, 0
	}

	tree := radix.New()
	var loaded, skipped int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		count, err := LoadBlocklistFile(path, tree)
		if err != nil {
			logger.Error("skipped malformed blocklist file", "path", path, "error", err)
			skipped++
			continue
		}
		loaded++
		logger.Info("loaded blocklist file", "path", path, "domains", count)
	}

	return tree, loaded, skipped
}
