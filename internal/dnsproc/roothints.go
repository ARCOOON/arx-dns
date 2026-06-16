package dnsproc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	rootHintsCacheMaxAge  = 30 * 24 * time.Hour
	rootHintsHTTPTimeout  = 30 * time.Second
	rootHintsHTTPMaxBytes = 1 << 20
)

var rootHintsFetchURL = rootHintsFetchURLDefault

const rootHintsFetchURLDefault = "https://www.internic.net/domain/named.root"

// RootHintsFetchURLForTest returns the active root hints download URL.
func RootHintsFetchURLForTest() string {
	return rootHintsFetchURL
}

// SetRootHintsFetchURLForTest overrides the root hints download URL for tests.
func SetRootHintsFetchURLForTest(url string) {
	if strings.TrimSpace(url) == "" {
		rootHintsFetchURL = rootHintsFetchURLDefault
		return
	}
	rootHintsFetchURL = url
}

// LoadRootHints returns root server addresses from cachePath.
// When autoUpdate is true, stale or missing files are refreshed from InterNIC.
// When autoUpdate is false, only the local file is read (externally managed).
// On failure it logs and returns normalized fallback addresses so the engine can
// still serve local zones without internet at boot.
func LoadRootHints(cachePath string, autoUpdate bool, fallback []string, logger *slog.Logger) []string {
	hints, err := FetchOrLoadRootHints(cachePath, autoUpdate)
	if err == nil {
		return hints
	}

	if logger != nil {
		if autoUpdate {
			logger.Error("failed to load root hints, using built-in fallback",
				"cache", cachePath,
				"error", err,
			)
		} else {
			logger.Warn("externally managed root hints missing, falling back to internal list",
				"file", cachePath,
				"error", err,
			)
		}
	}

	normalized, normErr := NormalizeUpstreams(fallback)
	if normErr != nil || len(normalized) == 0 {
		if logger != nil {
			logger.Error("built-in root hints fallback is invalid", "error", normErr)
		}
		return nil
	}
	return normalized
}

// FetchOrLoadRootHints returns root server addresses from cachePath.
// When autoUpdate is false, the file is read and parsed without checking age or
// contacting InterNIC. When autoUpdate is true, the file is refreshed from InterNIC
// when missing or older than 30 days, then A/AAAA records are parsed into host:port form.
func FetchOrLoadRootHints(cachePath string, autoUpdate bool) ([]string, error) {
	cachePath = strings.TrimSpace(cachePath)
	if cachePath == "" {
		return nil, errors.New("root hints cache path must not be empty")
	}

	if !autoUpdate {
		return loadRootHintsFromFile(cachePath)
	}

	needsFetch := true
	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < rootHintsCacheMaxAge {
			needsFetch = false
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat root hints cache %q: %w", cachePath, err)
	}

	if needsFetch {
		body, err := downloadRootHints()
		if err != nil {
			if data, readErr := os.ReadFile(cachePath); readErr == nil {
				hints, parseErr := parseRootHints(data)
				if parseErr == nil && len(hints) > 0 {
					return hints, nil
				}
			}
			return nil, err
		}
		if err := writeRootHintsCache(cachePath, body); err != nil {
			return nil, err
		}
	}

	return loadRootHintsFromFile(cachePath)
}

func loadRootHintsFromFile(cachePath string) ([]string, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("read root hints file %q: %w", cachePath, err)
	}

	hints, err := parseRootHints(data)
	if err != nil {
		return nil, err
	}
	if len(hints) == 0 {
		return nil, errors.New("no root hint addresses found in root hints file")
	}
	return hints, nil
}

func downloadRootHints() ([]byte, error) {
	client := &http.Client{Timeout: rootHintsHTTPTimeout}

	req, err := http.NewRequest(http.MethodGet, rootHintsFetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create root hints request: %w", err)
	}
	req.Header.Set("User-Agent", "arx-dns/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch root hints from %s: %w", rootHintsFetchURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch root hints from %s: unexpected status %s", rootHintsFetchURL, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, rootHintsHTTPMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("read root hints response: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("root hints response body is empty")
	}
	return body, nil
}

func writeRootHintsCache(cachePath string, body []byte) error {
	dir := filepath.Dir(cachePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create root hints cache directory: %w", err)
		}
	}

	tmpPath := cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, body, 0o644); err != nil {
		return fmt.Errorf("write root hints cache temp file: %w", err)
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace root hints cache: %w", err)
	}
	return nil
}

func parseRootHints(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	out := make([]string, 0, 26)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		rrType := fields[2]
		if rrType != "A" && rrType != "AAAA" {
			continue
		}

		addr, err := normalizeRootHintAddress(fields[3])
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse root hints: %w", err)
	}

	normalized, err := NormalizeUpstreams(out)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func normalizeRootHintAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty root hint address")
	}

	if host, port, err := net.SplitHostPort(raw); err == nil {
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("invalid root hint IP %q", host)
		}
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(host, port), nil
	}

	if net.ParseIP(raw) == nil {
		return "", fmt.Errorf("invalid root hint IP %q", raw)
	}
	return net.JoinHostPort(raw, "53"), nil
}
