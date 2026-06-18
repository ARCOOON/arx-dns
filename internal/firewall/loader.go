package firewall

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/armon/go-radix"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// Load reads all regular files in cfg.BlocklistsDirectory (HOSTS-formatted or plain
// domain lists), merges custom domains from db when provided, builds a fresh radix tree,
// and atomically swaps it into the engine.
func Load(cfg config.FirewallConfig, db *sql.DB, engine *Engine, logger *slog.Logger) {
	LoadFromDirWithDB(cfg.BlocklistsDirectory, db, engine, logger)
}

// LoadFromDir reads all regular files in dir, builds a fresh radix tree, and
// atomically swaps it into the engine.
func LoadFromDir(dir string, engine *Engine, logger *slog.Logger) {
	LoadFromDirWithDB(dir, nil, engine, logger)
}

// LoadFromDirWithDB reads blocklist files from dir, optionally merges custom domains
// from db, builds a fresh radix tree, and atomically swaps it into the engine.
func LoadFromDirWithDB(dir string, db *sql.DB, engine *Engine, logger *slog.Logger) {
	if engine == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	tree, loaded, skipped, custom := buildTreeFromDir(dir, db, logger)
	if tree == nil {
		tree = radix.New()
	}
	engine.SwapTree(tree)

	logger.Info("blocklist loading complete",
		"directory", dir,
		"files_loaded", loaded,
		"files_skipped", skipped,
		"custom_domains", custom,
		"domains", tree.Len(),
	)
}

func buildTreeFromDir(dir string, db *sql.DB, logger *slog.Logger) (*radix.Tree, int, int, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("blocklists directory not found", "path", dir)
			tree := radix.New()
			custom := ingestCustomDomains(db, tree, logger)
			return tree, 0, 0, custom
		}
		logger.Error("failed to read blocklists directory", "path", dir, "error", err)
		return nil, 0, 0, 0
	}

	tree := radix.New()
	enabledSourceIDs := enabledBlocklistSourceIDs(db, logger)
	var loaded, skipped int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if sourceID, ok := sourceIDFromFeedFile(entry.Name()); ok && db != nil && !enabledSourceIDs[sourceID] {
			logger.Info("skipped disabled blocklist feed file", "path", path, "source_id", sourceID)
			skipped++
			continue
		}

		count, err := LoadBlocklistFile(path, tree)
		if err != nil {
			logger.Error("skipped malformed blocklist file", "path", path, "error", err)
			skipped++
			continue
		}
		loaded++
		logger.Info("loaded blocklist file", "path", path, "domains", count)
	}

	custom := ingestCustomDomains(db, tree, logger)
	return tree, loaded, skipped, custom
}

func ingestCustomDomains(db *sql.DB, tree *radix.Tree, logger *slog.Logger) int {
	if db == nil || tree == nil {
		return 0
	}

	entries, err := ListCustomBlocklistDomains(db)
	if err != nil {
		logger.Error("failed to load custom blocklist domains", "error", err)
		return 0
	}

	var count int
	for _, entry := range entries {
		reversed := ReverseDomain(entry.Domain)
		if reversed == "" {
			continue
		}
		if _, ok := tree.Get(reversed); ok {
			continue
		}
		tree.Insert(reversed, struct{}{})
		count++
	}

	if count > 0 {
		logger.Info("loaded custom blocklist domains", "domains", count)
	}

	return count
}

func enabledBlocklistSourceIDs(db *sql.DB, logger *slog.Logger) map[int64]bool {
	ids := make(map[int64]bool)
	if db == nil {
		return ids
	}

	sources, err := ListEnabledBlocklistSources(db)
	if err != nil {
		logger.Error("failed to list enabled blocklist sources", "error", err)
		return ids
	}
	for _, source := range sources {
		ids[source.ID] = true
	}
	return ids
}

func sourceIDFromFeedFile(name string) (int64, bool) {
	if !isManagedFeedFile(name) {
		return 0, false
	}

	idPart := strings.TrimPrefix(name, feedFilePrefix)
	idPart = strings.TrimSuffix(idPart, feedFileSuffix)
	id, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
