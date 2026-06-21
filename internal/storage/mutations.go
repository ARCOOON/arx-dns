package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"
)

var (
	// ErrZoneNotFound indicates the requested zone is not loaded in the given view.
	ErrZoneNotFound = errors.New("zone not found")
	// ErrRecordNotFound indicates no matching record exists in the zone.
	ErrRecordNotFound = errors.New("record not found")
	// ErrSOANotDeletable indicates an attempt to remove the zone SOA record.
	ErrSOANotDeletable = errors.New("SOA record cannot be deleted, only modified")
)

// ListZones returns metadata for all registered zones across public and internal views.
func (m *Memory) ListZones() []ZoneInfo {
	if m == nil {
		return nil
	}

	records := m.listRegisteredZones()
	sort.Slice(records, func(i, j int) bool {
		if records[i].view == records[j].view {
			return records[i].origin < records[j].origin
		}
		return records[i].view < records[j].view
	})

	out := make([]ZoneInfo, 0, len(records))
	for _, rec := range records {
		tree := m.treeForView(rec.view)
		out = append(out, ZoneInfo{
			Origin:   rec.origin,
			View:     rec.view,
			FilePath: rec.filePath,
			Records:  countZoneRecords(tree, rec.origin),
		})
	}
	return out
}

// ZoneExists reports whether the zone apex is present in the given view.
func (m *Memory) ZoneExists(origin string, view ZoneView) bool {
	if m == nil {
		return false
	}
	origin = NormalizeName(origin)
	if _, ok := m.zoneRecord(origin, view); ok {
		return true
	}
	return zoneHasSOA(m.treeForView(view), origin)
}

// AddZoneRecord inserts a record into the in-memory tree and persists the zone file.
func (m *Memory) AddZoneRecord(zonesDir, origin string, view ZoneView, in RecordInput) (mdns.RR, error) {
	if m == nil {
		return nil, fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	rr, err := BuildRecord(origin, in)
	if err != nil {
		return nil, err
	}

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return nil, ErrZoneNotFound
	}

	tree := cloneTree(m.treeForView(view))
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

// DeleteZoneRecord removes a matching record from the in-memory tree and persists the zone file.
func (m *Memory) DeleteZoneRecord(zonesDir, origin string, view ZoneView, in RecordInput) error {
	if m == nil {
		return fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	fqdn, err := qualifyRecordName(origin, in.Name)
	if err != nil {
		return err
	}

	qtype, err := parseRecordType(in.Type)
	if err != nil {
		return err
	}
	if qtype == mdns.TypeSOA {
		return ErrSOANotDeletable
	}

	value := strings.TrimSpace(in.Value)
	if value == "" {
		return fmt.Errorf("record value is required")
	}

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return ErrZoneNotFound
	}

	tree := cloneTree(m.treeForView(view))
	if !removeMatchingRR(tree, fqdn, qtype, value) {
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
	if err := WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view)); err != nil {
		return fmt.Errorf("persist zone file: %w", err)
	}

	return nil
}

func (m *Memory) zoneExistsLocked(origin string, view ZoneView) bool {
	if _, ok := m.zoneRecord(origin, view); ok {
		return true
	}
	return zoneHasSOA(m.treeForView(view), origin)
}

func (m *Memory) zoneFilePath(zonesDir, origin string, view ZoneView) (string, error) {
	if rec, ok := m.zoneRecord(origin, view); ok && rec.filePath != "" {
		return rec.filePath, nil
	}

	apex := strings.TrimSuffix(NormalizeName(origin), ".")
	if apex == "" {
		return "", fmt.Errorf("invalid zone origin %q", origin)
	}

	name := apex + ".zone"
	if view == ViewInternal {
		return filepath.Join(zonesDir, internalViewDir, name), nil
	}
	return filepath.Join(zonesDir, name), nil
}

// WriteZoneFile serializes all records for origin from tree into a BIND zone file.
func WriteZoneFile(path, origin string, tree *radix.Tree, ttlHints map[string]string) error {
	origin = NormalizeName(origin)
	rrs := collectZoneRecords(tree, origin)

	sort.Slice(rrs, func(i, j int) bool {
		left := rrs[i].Header()
		right := rrs[j].Header()
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Rrtype != right.Rrtype {
			return left.Rrtype < right.Rrtype
		}
		return rrDataValue(rrs[i]) < rrDataValue(rrs[j])
	})

	defaultTTL := uint32(300)
	for _, rr := range rrs {
		if rr.Header().Rrtype == mdns.TypeSOA {
			if soa, ok := rr.(*mdns.SOA); ok && soa.Hdr.Ttl > 0 {
				defaultTTL = soa.Hdr.Ttl
			}
			break
		}
	}
	if defaultTTL == 0 {
		defaultTTL = 300
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("$ORIGIN %s\n", origin))
	b.WriteString(fmt.Sprintf("$TTL %d\n", defaultTTL))

	for _, rr := range rrs {
		line, err := formatZoneLine(rr, origin, ttlHints[ComputeRecordID(origin, rr)])
		if err != nil {
			return err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create zone directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write zone temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace zone file: %w", err)
	}
	return nil
}

func formatZoneLine(rr mdns.RR, origin, ttlText string) (string, error) {
	if rr == nil {
		return "", fmt.Errorf("nil record")
	}

	hdr := rr.Header()
	owner := relativeOwnerName(hdr.Name, origin)
	rdata := rrDataValue(rr)
	ttl := ttlText
	if ttl == "" {
		ttl = strconv.FormatUint(uint64(hdr.Ttl), 10)
	}

	if r3597, ok := rr.(*mdns.RFC3597); ok {
		typ := fmt.Sprintf("TYPE%d", r3597.Hdr.Rrtype)
		if rdata == "" {
			return "", fmt.Errorf("empty rdata for %s %s", owner, typ)
		}
		return fmt.Sprintf("%s %s IN %s %s", owner, ttl, typ, rdata), nil
	}

	typ := mdns.Type(hdr.Rrtype).String()
	if rdata == "" {
		return "", fmt.Errorf("empty rdata for %s %s", owner, typ)
	}

	if hdr.Rrtype == mdns.TypeSOA {
		soa, ok := rr.(*mdns.SOA)
		if !ok {
			return "", fmt.Errorf("invalid SOA record")
		}
		return fmt.Sprintf("%s %s IN SOA %s %s (\n\t%d ; serial\n\t%d ; refresh\n\t%d ; retry\n\t%d ; expire\n\t%d ; minimum\n\t)",
			owner,
			ttl,
			soa.Ns,
			soa.Mbox,
			soa.Serial,
			soa.Refresh,
			soa.Retry,
			soa.Expire,
			soa.Minttl,
		), nil
	}

	if txt, ok := rr.(*mdns.TXT); ok {
		rdata = formatTXTRdata(txt.Txt)
		if rdata == "" {
			return "", fmt.Errorf("empty rdata for %s TXT", owner)
		}
		return fmt.Sprintf("%s %s IN TXT %s", owner, ttl, rdata), nil
	}

	return fmt.Sprintf("%s %s IN %s %s", owner, ttl, typ, rdata), nil
}

func relativeOwnerName(name, origin string) string {
	name = NormalizeName(name)
	origin = NormalizeName(origin)
	if name == origin {
		return "@"
	}
	suffix := "." + strings.TrimSuffix(origin, ".") + "."
	if strings.HasSuffix(name, suffix) {
		return strings.TrimSuffix(name, suffix)
	}
	return name
}

// ApplyDynamicUpdate applies a callback against a cloned zone tree, atomically swaps the
// view, and persists the zone file. The callback must return storage-layer update errors
// (e.g. ErrUpdateNXRRSET) to signal RFC 2136 prerequisite or update failures.
func (m *Memory) ApplyDynamicUpdate(zonesDir, origin string, view ZoneView, apply func(tree *radix.Tree) error) error {
	if m == nil {
		return fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return ErrZoneNotFound
	}

	tree := cloneTree(m.treeForView(view))
	if err := apply(tree); err != nil {
		return err
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
	if err := WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view)); err != nil {
		return fmt.Errorf("persist zone file: %w", err)
	}
	return nil
}
