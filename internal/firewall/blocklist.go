package firewall

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/armon/go-radix"
)

// LoadBlocklistFile parses a single blocklist file into tree.
func LoadBlocklistFile(path string, tree *radix.Tree) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open blocklist: %w", err)
	}
	defer f.Close()

	return IngestBlocklist(f, tree)
}

// IngestBlocklist parses r and inserts unique reversed domains into tree.
func IngestBlocklist(r io.Reader, tree *radix.Tree) (int, error) {
	scanner := bufio.NewScanner(r)
	var count int

	for scanner.Scan() {
		for _, domain := range ParseBlocklistLine(scanner.Text()) {
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
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("read blocklist: %w", err)
	}
	return count, nil
}

// ParseBlocklistLine extracts blocked domain names from one line.
// Supports plain domain lists (one domain per line) and standard HOSTS format
// (IP address followed by one or more hostnames). Comments (#) and blank lines
// are ignored.
func ParseBlocklistLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	if net.ParseIP(fields[0]) != nil {
		if len(fields) < 2 {
			return nil
		}
		domains := make([]string, 0, len(fields)-1)
		for _, host := range fields[1:] {
			if domain := normalizeDomain(host); domain != "" {
				domains = append(domains, domain)
			}
		}
		return domains
	}

	if domain := normalizeDomain(fields[0]); domain != "" {
		return []string{domain}
	}
	return nil
}
