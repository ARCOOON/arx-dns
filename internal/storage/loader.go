package storage

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"
)

// LoadZonesFromDir scans dir for files with a .zone extension, builds a new radix
// tree, and atomically swaps it into store. Malformed files are logged and skipped;
// loading never panics. When dir does not exist, the active tree is left unchanged.
func LoadZonesFromDir(dir string, store *Memory, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	tree, loaded, skipped := buildTreeFromDir(dir, logger)
	if tree == nil {
		return
	}

	store.SwapTree(tree)
	logger.Info("zone loading complete", "directory", dir, "loaded", loaded, "skipped", skipped)
}

func buildTreeFromDir(dir string, logger *slog.Logger) (*radix.Tree, int, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("zones directory not found", "path", dir)
			return nil, 0, 0
		}
		logger.Error("failed to read zones directory", "path", dir, "error", err)
		return nil, 0, 0
	}

	tree := radix.New()
	var loaded, skipped int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".zone") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := loadZoneFile(path, tree, logger); err != nil {
			logger.Error("skipped malformed zone file", "path", path, "error", err)
			skipped++
			continue
		}
		loaded++
	}

	return tree, loaded, skipped
}

func loadZoneFile(path string, tree *radix.Tree, logger *slog.Logger) error {
	origin, err := resolveZoneOrigin(path)
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open zone file: %w", err)
	}
	defer f.Close()

	parser := mdns.NewZoneParser(f, origin, path)
	var count int
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		insertRR(tree, rr)
		count++
	}
	if err := parser.Err(); err != nil {
		return fmt.Errorf("parse zone (origin %s): %w", origin, err)
	}

	logger.Info("loaded zone file", "path", path, "origin", origin, "records", count)
	return nil
}

func resolveZoneOrigin(path string) (string, error) {
	if origin := originFromFilename(path); origin != "" {
		return origin, nil
	}

	origin, err := originFromFile(path)
	if err != nil {
		return "", fmt.Errorf("resolve $ORIGIN: %w", err)
	}
	if origin == "" {
		return "", fmt.Errorf("no zone origin: filename must be <apex>.zone or file must contain $ORIGIN")
	}
	return origin, nil
}

func originFromFilename(path string) string {
	base := filepath.Base(path)
	if !strings.EqualFold(filepath.Ext(base), ".zone") {
		return ""
	}

	name := strings.TrimSuffix(base, filepath.Ext(base))
	if name == "" {
		return ""
	}
	return NormalizeName(name)
}

func originFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	origin, err := scanOriginDirective(f)
	if err != nil {
		return "", err
	}
	return origin, nil
}

func scanOriginDirective(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.EqualFold(fields[0], "$ORIGIN") {
			continue
		}
		return NormalizeName(fields[1]), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}
