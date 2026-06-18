package storage

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParseBindTTL parses a BIND-style TTL string (e.g. "3600", "5m", "1h", "1d2h")
// into seconds. The returned text preserves the normalized input for zone file output.
func ParseBindTTL(raw string) (seconds uint32, text string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, "", fmt.Errorf("TTL is required")
	}

	if isPlainTTLNumber(raw) {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n == 0 {
			return 0, "", fmt.Errorf("invalid TTL %q", raw)
		}
		return uint32(n), raw, nil
	}

	var total uint64
	rest := raw
	for rest != "" {
		i := 0
		for i < len(rest) && unicode.IsDigit(rune(rest[i])) {
			i++
		}
		if i == 0 {
			return 0, "", fmt.Errorf("invalid TTL %q", raw)
		}

		n, err := strconv.ParseUint(rest[:i], 10, 32)
		if err != nil {
			return 0, "", fmt.Errorf("invalid TTL %q", raw)
		}

		if i >= len(rest) {
			return 0, "", fmt.Errorf("invalid TTL %q: missing unit suffix", raw)
		}

		unit := rest[i]
		rest = rest[i+1:]
		switch unit {
		case 's':
			total += n
		case 'm':
			total += n * 60
		case 'h':
			total += n * 3600
		case 'd':
			total += n * 86400
		case 'w':
			total += n * 604800
		default:
			return 0, "", fmt.Errorf("invalid TTL unit %q in %q", string(unit), raw)
		}
	}

	if total == 0 {
		return 0, "", fmt.Errorf("invalid TTL %q", raw)
	}
	if total > uint64(^uint32(0)) {
		return 0, "", fmt.Errorf("TTL %q exceeds maximum", raw)
	}

	return uint32(total), strings.ToLower(raw), nil
}

func isPlainTTLNumber(raw string) bool {
	if raw == "" {
		return false
	}
	for _, r := range raw {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// ResolveRecordTTL returns parsed seconds and zone-file text from API input.
func ResolveRecordTTL(in RecordInput) (uint32, string, error) {
	if text := strings.TrimSpace(in.TTLText); text != "" {
		return ParseBindTTL(text)
	}
	if in.TTL > 0 {
		return in.TTL, strconv.FormatUint(uint64(in.TTL), 10), nil
	}
	return 300, "300", nil
}
