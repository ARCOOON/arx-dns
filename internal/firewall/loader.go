package firewall

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/armon/go-radix"
)

// LoadFromDir reads all regular files in dir (one domain per line), builds a
// fresh radix tree, and atomically swaps it into the engine.
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
		count, err := loadBlocklistFile(path, tree)
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

func loadBlocklistFile(path string, tree *radix.Tree) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open blocklist: %w", err)
	}
	defer f.Close()

	return ingestBlocklist(f, tree)
}

func ingestBlocklist(r io.Reader, tree *radix.Tree) (int, error) {
	scanner := bufio.NewScanner(r)
	var count int

	for scanner.Scan() {
		domain := parseBlocklistLine(scanner.Text())
		if domain == "" {
			continue
		}

		reversed := ReverseDomain(domain)
		if reversed == "" {
			continue
		}

		if _, ok := tree.Get(reversed); ok {
			continue
		}
		tree.Insert(reversed, struct{}{})
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("read blocklist: %w", err)
	}
	return count, nil
}

func parseBlocklistLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}
