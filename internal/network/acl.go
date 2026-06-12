package network

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// ACL holds trusted CIDR prefixes for recursive query authorization.
// Prefixes are parsed once at startup; Contains performs allocation-free matching.
type ACL struct {
	prefixes []netip.Prefix
}

// ParseACL parses a comma-separated list of CIDR prefixes into an ACL.
func ParseACL(csv string) (*ACL, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return &ACL{}, nil
	}

	parts := strings.Split(csv, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("parse trusted subnet %q: %w", part, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return &ACL{prefixes: prefixes}, nil
}

// ACLFromConfig builds the recursive-query ACL from application configuration.
func ACLFromConfig(cfg config.Config) (*ACL, error) {
	csv, err := cfg.TrustedSubnetsCSV()
	if err != nil {
		return nil, err
	}
	return ParseACL(csv)
}

// Trusted returns true when addr falls within any configured prefix.
// An unset ACL (no prefixes) treats every address as untrusted.
func (a *ACL) Trusted(addr netip.Addr) bool {
	if a == nil || len(a.prefixes) == 0 {
		return false
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range a.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
