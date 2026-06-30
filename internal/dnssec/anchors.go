package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	mdns "github.com/miekg/dns"
)

// embeddedRootAnchors holds the IANA DNSSEC root trust anchor DNSKEY records.
// Sources: IANA Root Zone KSK 20326 and KSK 38696 (RSA/SHA-256, algorithm 8).
const embeddedRootAnchors = `
. 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
. 3600 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
`

var (
	anchorOnce sync.Once
	anchorErr  error
	rootKeys   []mdns.RR
)

// InitAnchors parses the embedded root trust anchors. Call once at process startup.
func InitAnchors() error {
	return InitAnchorsWithCustom(nil)
}

// InitAnchorsWithCustom parses embedded IANA anchors plus optional custom trust anchor records.
func InitAnchorsWithCustom(customLines []string) error {
	anchorOnce.Do(func() {
		rootKeys, anchorErr = loadAnchors(customLines)
	})
	return anchorErr
}

// ApplyCustomAnchors reloads embedded and custom root trust anchors at runtime.
func ApplyCustomAnchors(customLines []string) error {
	keys, err := loadAnchors(customLines)
	if err != nil {
		return err
	}
	rootKeys = keys
	anchorErr = nil
	return nil
}

func loadAnchors(customLines []string) ([]mdns.RR, error) {
	keys, err := parseAnchorRecords(embeddedRootAnchors)
	if err != nil {
		return nil, err
	}
	for _, line := range customLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rr, err := mdns.NewRR(line)
		if err != nil {
			return nil, fmt.Errorf("parse custom root anchor %q: %w", line, err)
		}
		switch anchor := rr.(type) {
		case *mdns.DNSKEY:
			if anchor.Flags&mdns.SEP == 0 {
				return nil, fmt.Errorf("custom root anchor DNSKEY is not a KSK: %s", line)
			}
			keys = appendAnchorIfMissing(keys, anchor)
		case *mdns.DS:
			keys = appendAnchorIfMissing(keys, anchor)
		default:
			return nil, fmt.Errorf("custom root anchor must be DNSKEY or DS: %s", line)
		}
	}
	return keys, nil
}

func appendAnchorIfMissing(keys []mdns.RR, rr mdns.RR) []mdns.RR {
	for _, existing := range keys {
		if anchorRecordsEqual(existing, rr) {
			return keys
		}
	}
	return append(keys, rr)
}

func anchorRecordsEqual(a, b mdns.RR) bool {
	switch left := a.(type) {
	case *mdns.DNSKEY:
		right, ok := b.(*mdns.DNSKEY)
		if !ok {
			return false
		}
		return left.KeyTag() == right.KeyTag() &&
			left.Algorithm == right.Algorithm &&
			left.Flags == right.Flags &&
			strings.EqualFold(left.PublicKey, right.PublicKey)
	case *mdns.DS:
		right, ok := b.(*mdns.DS)
		if !ok {
			return false
		}
		return left.KeyTag == right.KeyTag &&
			left.Algorithm == right.Algorithm &&
			left.DigestType == right.DigestType &&
			strings.EqualFold(left.Digest, right.Digest)
	default:
		return false
	}
}

// RootAnchors returns the initialized root DNSKEY trust anchors.
// InitAnchors must have completed successfully before calling this function.
func RootAnchors() []mdns.RR {
	if len(rootKeys) == 0 {
		return nil
	}
	out := make([]mdns.RR, len(rootKeys))
	copy(out, rootKeys)
	return out
}

// SetRootAnchorsForTest replaces root anchors for unit tests.
func SetRootAnchorsForTest(keys []mdns.RR) {
	rootKeys = make([]mdns.RR, len(keys))
	copy(rootKeys, keys)
	anchorErr = nil
}

// RestoreEmbeddedAnchorsForTest reloads the embedded IANA root KSK anchors after test overrides.
func RestoreEmbeddedAnchorsForTest() error {
	keys, err := parseAnchorRecords(embeddedRootAnchors)
	if err != nil {
		return err
	}
	rootKeys = keys
	anchorErr = nil
	return nil
}

func parseAnchorRecords(text string) ([]mdns.RR, error) {
	lines := strings.Split(text, "\n")
	out := make([]mdns.RR, 0, 2)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rr, err := mdns.NewRR(line)
		if err != nil {
			return nil, fmt.Errorf("parse root anchor %q: %w", line, err)
		}
		key, ok := rr.(*mdns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("root anchor is not a DNSKEY: %s", line)
		}
		if key.Flags&mdns.SEP == 0 {
			return nil, fmt.Errorf("root anchor %d is not a KSK", key.KeyTag())
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, errors.New("no root trust anchors configured")
	}
	return out, nil
}
