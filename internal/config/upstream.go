package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const defaultDNSPort = "53"

// ParseUpstreamAddress validates an upstream resolver entry and returns the storage
// form with implicit port 53 omitted. Custom ports are preserved in host:port form.
func ParseUpstreamAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty upstream address")
	}

	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			if err := validateUpstreamHost(raw); err != nil {
				return "", err
			}
			return raw, nil
		}
		if addr, parseErr := netip.ParseAddr(raw); parseErr == nil {
			return addr.String(), nil
		}
		if err := validateUpstreamHost(raw); err != nil {
			return "", err
		}
		return raw, nil
	}

	if host == "" || port == "" {
		return "", fmt.Errorf("invalid upstream address %q", raw)
	}
	portNum, convErr := strconv.Atoi(port)
	if convErr != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid upstream port %q", port)
	}
	if err := validateUpstreamHost(host); err != nil {
		return "", err
	}

	if port == defaultDNSPort {
		if addr, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
			return addr.String(), nil
		}
		return strings.Trim(host, "[]"), nil
	}

	return net.JoinHostPort(host, port), nil
}

func validateUpstreamHost(host string) error {
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("empty upstream host")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.ContainsAny(host, " \t") {
		return fmt.Errorf("invalid upstream host %q", host)
	}
	return nil
}

// DialUpstreamAddress returns host:port suitable for network dial operations.
func DialUpstreamAddress(stored string) string {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return stored
	}

	host, port, err := net.SplitHostPort(stored)
	if err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port)
	}
	if addr, parseErr := netip.ParseAddr(stored); parseErr == nil {
		return net.JoinHostPort(addr.String(), defaultDNSPort)
	}
	return net.JoinHostPort(stored, defaultDNSPort)
}

// DisplayUpstreams strips implicit port 53 from upstream entries for API/UI responses.
func DisplayUpstreams(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		parsed, err := ParseUpstreamAddress(raw)
		if err != nil {
			out = append(out, strings.TrimSpace(raw))
			continue
		}
		out = append(out, parsed)
	}
	return out
}

// ValidatedUpstreams validates upstream entries and returns the storage form.
func (c Config) ValidatedUpstreams() ([]string, error) {
	out := make([]string, 0, len(c.Recursive.Upstreams))
	for _, part := range c.Recursive.Upstreams {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := ParseUpstreamAddress(part)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream %q: %w", part, err)
		}
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one upstream DNS server is required")
	}
	return out, nil
}
