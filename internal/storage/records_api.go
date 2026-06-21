package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	mdns "github.com/miekg/dns"
)

// ZoneRecordEntry is a serializable DNS record returned by the management API.
type ZoneRecordEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   string `json:"ttl"`
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
			TTL:   m.recordTTLText(origin, view, rr),
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
	var matchRR mdns.RR
	var match *ZoneRecordEntry
	for _, rr := range rrs {
		if ComputeRecordID(origin, rr) != id {
			continue
		}
		matchRR = rr
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
	if strings.EqualFold(match.Type, "SOA") {
		return ErrSOANotDeletable
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

	m.ttlHints.remove(origin, view, matchRR)

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return err
	}
	if err := WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view)); err != nil {
		return fmt.Errorf("persist zone file: %w", err)
	}

	return nil
}

func (m *Memory) recordTTLText(origin string, view ZoneView, rr mdns.RR) string {
	if text := m.ttlHints.get(origin, view, rr); text != "" {
		return text
	}
	return strconv.FormatUint(uint64(rr.Header().Ttl), 10)
}

// UpdateZoneRecordByID replaces a record identified by ComputeRecordID with new data.
func (m *Memory) UpdateZoneRecordByID(zonesDir, origin string, view ZoneView, id string, in RecordInput) (mdns.RR, error) {
	if m == nil {
		return nil, fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("record id is required")
	}

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return nil, ErrZoneNotFound
	}

	rrs := collectZoneRecords(m.treeForView(view), origin)
	var existingRR mdns.RR
	for _, existing := range rrs {
		if ComputeRecordID(origin, existing) != id {
			continue
		}
		existingRR = existing
		break
	}
	if existingRR == nil {
		return nil, ErrRecordNotFound
	}

	hdr := existingRR.Header()
	match := &ZoneRecordEntry{
		Name:  relativeOwnerName(hdr.Name, origin),
		Type:  mdns.Type(hdr.Rrtype).String(),
		Value: rrDataValue(existingRR),
	}

	if strings.EqualFold(strings.TrimSpace(in.Type), "SOA") {
		if err := preserveSOASerial(existingRR, &in); err != nil {
			return nil, err
		}
	}

	rr, err := BuildRecord(origin, in)
	if err != nil {
		return nil, err
	}

	qtype, err := parseRecordType(match.Type)
	if err != nil {
		return nil, err
	}

	fqdn, err := qualifyRecordName(origin, match.Name)
	if err != nil {
		return nil, err
	}

	tree := cloneTree(m.treeForView(view))
	if !removeMatchingRR(tree, fqdn, qtype, match.Value) {
		return nil, ErrRecordNotFound
	}

	m.ttlHints.remove(origin, view, existingRR)
	insertRR(tree, rr)
	m.ttlHints.set(origin, view, rr, in.TTLText)

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return nil, err
	}
	if err := WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view)); err != nil {
		return nil, fmt.Errorf("persist zone file: %w", err)
	}

	return rr, nil
}

func preserveSOASerial(existing mdns.RR, in *RecordInput) error {
	soa, ok := existing.(*mdns.SOA)
	if !ok {
		return fmt.Errorf("existing record is not SOA")
	}

	fields := strings.Fields(strings.TrimSpace(in.Value))
	if len(fields) < 7 {
		return fmt.Errorf("SOA value must be ns mbox serial refresh retry expire minimum")
	}

	fields[2] = strconv.FormatUint(uint64(soa.Serial), 10)
	in.Value = strings.Join(fields, " ")
	return nil
}
