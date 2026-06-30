package config

import (
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// ValidateRootAnchors checks that configured root trust anchor records are valid DNSKEY or DS RRs.
func (c SecurityConfig) ValidateRootAnchors() error {
	for i, raw := range c.RootAnchors {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		rr, err := mdns.NewRR(raw)
		if err != nil {
			return fmt.Errorf("security.root_anchors[%d]: %w", i, err)
		}
		switch rr.(type) {
		case *mdns.DNSKEY, *mdns.DS:
		default:
			return fmt.Errorf("security.root_anchors[%d]: must be a DNSKEY or DS record", i)
		}
	}
	return nil
}

// NormalizedRootAnchors returns trimmed, non-empty root anchor record strings.
func (c SecurityConfig) NormalizedRootAnchors() []string {
	out := make([]string, 0, len(c.RootAnchors))
	for _, raw := range c.RootAnchors {
		raw = strings.TrimSpace(raw)
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}
