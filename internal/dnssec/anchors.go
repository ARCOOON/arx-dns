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
. 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RQDUxBdp3rR6C3eQegQJyNHCIX8nrLYFY7l120EXGvBYz18MUYpYSMqC0ijNUqZ0Lj1h9htSzwkKxbVZV0dy4OHfLm6YM9hObysgGpfqssGOoo+FLfW02G2vN45jmLEwQ=
. 3600 IN DNSKEY 257 3 8 AwEAAcHDEz45tLKYRSbdeNeRjRr70AAeMhhDRMX0xBFk98hHNbSEIG8O9XGSUYC1ymUxyLxgNkzZRueekGV1IFKTZTmO5I/K8XlOR7xXR71MZobJw/PGzbeMgjQ4RsogHAgMX5/Al1LK6o6MymoTZCaf2donCldicYIN3J7EZEpkV0E=
`

var (
	anchorOnce sync.Once
	anchorErr  error
	rootKeys   []mdns.RR
)

// InitAnchors parses the embedded root trust anchors. Call once at process startup.
func InitAnchors() error {
	anchorOnce.Do(func() {
		rootKeys, anchorErr = parseAnchorRecords(embeddedRootAnchors)
	})
	return anchorErr
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
