package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// ZoneRecordEntry is a serializable DNS record returned by the management API.
type ZoneRecordEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

// ComputeRecordID returns a stable identifier for a zone record.
func ComputeRecordID(origin string, rr mdns.RR) string {
	if rr == nil {
		return ""
	}

	origin = NormalizeName(origin)
	hdr := rr.Header()
	name := relativeOwnerName(hdr.Name, origin)
	typ := mdns.Type(hdr.Rrtype).String()
	value := rrDataValue(rr)

	payload := name + "\x00" + typ + "\x00" + value
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:8])
}

// ListZoneRecordEntries returns every record in origin for view with stable IDs.
func (m *Memory) ListZoneRecordEntries(origin string, view ZoneView) ([]ZoneRecordEntry, error) {
	if m == nil {
		return nil, fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	if !m.ZoneExists(origin, view) {
		return nil, ErrZoneNotFound
	}

	rrs := m.ZoneRecords(origin, view)
	out := make([]ZoneRecordEntry, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		out = append(out, ZoneRecordEntry{
			ID:    ComputeRecordID(origin, rr),
			Name:  relativeOwnerName(hdr.Name, origin),
			Type:  mdns.Type(hdr.Rrtype).String(),
			TTL:   hdr.Ttl,
			Value: rrDataValue(rr),
		})
	}
	return out, nil
}

// DeleteZoneRecordByID removes a record identified by ComputeRecordID from the zone.
func (m *Memory) DeleteZoneRecordByID(zonesDir, origin string, view ZoneView, id string) error {
	if m == nil {
		return fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("record id is required")
	}

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return ErrZoneNotFound
	}

	rrs := collectZoneRecords(m.treeForView(view), origin)
	var match *ZoneRecordEntry
	for _, rr := range rrs {
		if ComputeRecordID(origin, rr) != id {
			continue
		}
		hdr := rr.Header()
		match = &ZoneRecordEntry{
			Name:  relativeOwnerName(hdr.Name, origin),
			Type:  mdns.Type(hdr.Rrtype).String(),
			Value: rrDataValue(rr),
		}
		break
	}
	if match == nil {
		return ErrRecordNotFound
	}

	qtype, err := parseRecordType(match.Type)
	if err != nil {
		return err
	}

	fqdn, err := qualifyRecordName(origin, match.Name)
	if err != nil {
		return err
	}

	tree := cloneTree(m.treeForView(view))
	if !removeMatchingRR(tree, fqdn, qtype, match.Value) {
		return ErrRecordNotFound
	}

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return err
	}
	if err := WriteZoneFile(path, origin, tree); err != nil {
		return fmt.Errorf("persist zone file: %w", err)
	}

	return nil
}
