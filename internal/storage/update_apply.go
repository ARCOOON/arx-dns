package storage

import (
	"fmt"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"
)

// ApplyUpdateSection applies RFC 2136 update records from the Authority section to tree.
func ApplyUpdateSection(tree *radix.Tree, origin string, updates []mdns.RR) error {
	origin = NormalizeName(origin)
	for _, rr := range updates {
		if err := applyUpdateRR(tree, origin, rr); err != nil {
			return err
		}
	}
	return nil
}

func applyUpdateRR(tree *radix.Tree, origin string, rr mdns.RR) error {
	if rr == nil {
		return fmt.Errorf("nil update record")
	}

	hdr := rr.Header()
	name := NormalizeName(hdr.Name)
	if !isNameInZone(name, origin) {
		return ErrUpdateNotZone
	}

	if hdr.Rrtype == mdns.TypeSOA {
		return ErrUpdateRefused
	}

	switch {
	case hdr.Class == mdns.ClassINET:
		insertRR(tree, mdns.Copy(rr))
		return nil
	case hdr.Class == mdns.ClassNONE:
		if !removeMatchingRR(tree, name, hdr.Rrtype, rrDataValue(rr)) {
			return ErrUpdateNXRRSET
		}
		return nil
	case hdr.Class == mdns.ClassANY:
		if hdr.Rrtype == mdns.TypeANY {
			if !removeAllAtName(tree, name) {
				return ErrUpdateNXDOMAIN
			}
			return nil
		}
		if !removeRRset(tree, name, hdr.Rrtype) {
			return ErrUpdateNXRRSET
		}
		return nil
	default:
		return fmt.Errorf("unsupported update class %d", hdr.Class)
	}
}

// ApplyDynamicUpdateRRs atomically applies RFC 2136 update records and persists the zone.
func (m *Memory) ApplyDynamicUpdateRRs(zonesDir, origin string, view ZoneView, updates []mdns.RR) error {
	return m.ApplyDynamicUpdate(zonesDir, origin, view, func(tree *radix.Tree) error {
		return ApplyUpdateSection(tree, origin, updates)
	})
}
