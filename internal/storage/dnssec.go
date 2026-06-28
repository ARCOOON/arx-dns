package storage

import (
	"fmt"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/dnssec"
)

// DNSSECManager orchestrates Auto-DNSSEC key storage and zone signing.
type DNSSECManager struct {
	store *dnssec.Store
}

// NewDNSSECManager creates an Auto-DNSSEC manager backed by store.
func NewDNSSECManager(store *dnssec.Store) *DNSSECManager {
	return &DNSSECManager{store: store}
}

// IsEnabled reports whether Auto-DNSSEC is active for origin/view.
func (m *DNSSECManager) IsEnabled(origin string, view ZoneView) bool {
	if m == nil || m.store == nil {
		return false
	}
	enabled, err := m.store.IsEnabled(origin, string(view))
	if err != nil {
		return false
	}
	return enabled
}

// ShouldSign reports whether origin/view has complete KSK/ZSK material in dnssec_keys
// and signing should run during zone persist.
func (m *DNSSECManager) ShouldSign(origin string, view ZoneView) bool {
	if m == nil || m.store == nil {
		return false
	}
	origin = NormalizeName(origin)
	if !m.IsEnabled(origin, view) {
		return false
	}
	_, _, err := m.store.LoadKeys(origin, string(view))
	return err == nil
}

// EnsureAndSignTree generates keys when missing, then signs the zone tree.
func (m *DNSSECManager) EnsureAndSignTree(tree *radix.Tree, origin string, view ZoneView) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("dnssec manager is nil")
	}
	origin = NormalizeName(origin)
	records := collectZoneRecords(tree, origin)
	ttl := zoneTTLFromRecords(records)

	if err := m.store.EnsureKeys(origin, string(view), ttl); err != nil {
		return err
	}
	return m.SignTree(tree, origin, view)
}

// SignTree re-signs origin in tree when Auto-DNSSEC is enabled.
func (m *DNSSECManager) SignTree(tree *radix.Tree, origin string, view ZoneView) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("dnssec manager is nil")
	}
	if !m.IsEnabled(origin, view) {
		return nil
	}

	origin = NormalizeName(origin)
	records := collectZoneRecords(tree, origin)
	ksk, zsk, err := m.store.LoadKeys(origin, string(view))
	if err != nil {
		return err
	}

	signed, err := dnssec.SignZone(origin, records, ksk, zsk)
	if err != nil {
		return err
	}
	return applySignedRecords(tree, origin, signed)
}

// Status returns DNSSEC status for origin/view.
func (m *DNSSECManager) Status(origin string, view ZoneView) (dnssec.Status, error) {
	if m == nil || m.store == nil {
		return dnssec.Status{}, fmt.Errorf("dnssec manager is nil")
	}
	return m.store.Status(origin, string(view))
}

// EnsureKeys generates KSK/ZSK when missing for origin/view.
func (m *DNSSECManager) EnsureKeys(origin string, view ZoneView, ttl uint32) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("dnssec manager is nil")
	}
	return m.store.EnsureKeys(NormalizeName(origin), string(view), ttl)
}

func (m *Memory) SetDNSSECManager(manager *DNSSECManager) {
	if m == nil {
		return
	}
	m.dnssec = manager
}

func (m *Memory) persistZoneFile(zonesDir, origin string, view ZoneView, tree *radix.Tree) error {
	if m == nil {
		return fmt.Errorf("memory store is nil")
	}

	origin = NormalizeName(origin)
	if m.dnssec != nil && m.dnssec.ShouldSign(origin, view) {
		if err := m.dnssec.SignTree(tree, origin, view); err != nil {
			return fmt.Errorf("dnssec sign zone: %w", err)
		}
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return err
	}
	return WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view))
}

func applySignedRecords(tree *radix.Tree, origin string, signed []mdns.RR) error {
	if tree == nil {
		return fmt.Errorf("tree is nil")
	}
	stripAllZoneRecords(tree, origin)
	for _, rr := range signed {
		insertRR(tree, rr)
	}
	return nil
}

func stripAllZoneRecords(tree *radix.Tree, origin string) {
	if tree == nil {
		return
	}

	var names []string
	tree.Walk(func(name string, val interface{}) bool {
		if isNameInZone(name, origin) {
			names = append(names, name)
		}
		return false
	})
	for _, name := range names {
		tree.Delete(name)
	}
}

func stripDNSSECRecords(tree *radix.Tree, origin string) {
	if tree == nil {
		return
	}

	var names []string
	tree.Walk(func(name string, val interface{}) bool {
		if isNameInZone(name, origin) {
			names = append(names, name)
		}
		return false
	})

	for _, name := range names {
		raw, ok := tree.Get(name)
		if !ok {
			continue
		}
		byType := raw.(map[uint16][]mdns.RR)
		delete(byType, mdns.TypeRRSIG)
		delete(byType, mdns.TypeNSEC)
		delete(byType, mdns.TypeDNSKEY)
		if len(byType) == 0 {
			tree.Delete(name)
		} else {
			tree.Insert(name, byType)
		}
	}
}

func zoneTTLFromRecords(records []mdns.RR) uint32 {
	for _, rr := range records {
		if rr.Header().Rrtype == mdns.TypeSOA {
			if soa, ok := rr.(*mdns.SOA); ok && soa.Hdr.Ttl > 0 {
				return soa.Hdr.Ttl
			}
		}
	}
	return 300
}

// DNSSEC returns the attached Auto-DNSSEC manager, if any.
func (m *Memory) DNSSEC() *DNSSECManager {
	if m == nil {
		return nil
	}
	return m.dnssec
}

// EnableDNSSEC generates keys, signs the zone, persists the zone file, and swaps the tree.
func (m *Memory) EnableDNSSEC(zonesDir, origin string, view ZoneView) (dnssec.Status, error) {
	if m == nil {
		return dnssec.Status{}, fmt.Errorf("memory store is nil")
	}
	if m.dnssec == nil {
		return dnssec.Status{}, fmt.Errorf("dnssec is not configured")
	}

	origin = NormalizeName(origin)

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return dnssec.Status{}, ErrZoneNotFound
	}

	records := collectZoneRecords(m.treeForView(view), origin)
	if err := m.dnssec.EnsureKeys(origin, view, zoneTTLFromRecords(records)); err != nil {
		return dnssec.Status{}, err
	}

	tree := cloneTree(m.treeForView(view))
	if err := m.persistZoneFile(zonesDir, origin, view, tree); err != nil {
		return dnssec.Status{}, fmt.Errorf("persist zone file: %w", err)
	}

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	return m.dnssec.Status(origin, view)
}

// DisableDNSSEC deletes signing keys, strips DNSSEC records from the zone, and persists the unsigned zone file.
func (m *Memory) DisableDNSSEC(zonesDir, origin string, view ZoneView) (dnssec.Status, error) {
	if m == nil {
		return dnssec.Status{}, fmt.Errorf("memory store is nil")
	}
	if m.dnssec == nil {
		return dnssec.Status{}, fmt.Errorf("dnssec is not configured")
	}

	origin = NormalizeName(origin)

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return dnssec.Status{}, ErrZoneNotFound
	}

	if err := m.dnssec.DeleteKeys(origin, view); err != nil {
		return dnssec.Status{}, err
	}

	tree := cloneTree(m.treeForView(view))
	stripDNSSECRecords(tree, origin)

	if err := m.persistUnsignedZoneFile(zonesDir, origin, view, tree); err != nil {
		return dnssec.Status{}, fmt.Errorf("persist zone file: %w", err)
	}

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	return dnssec.Status{
		Enabled: false,
		Zone:    origin,
		View:    string(view),
	}, nil
}

func (m *Memory) persistUnsignedZoneFile(zonesDir, origin string, view ZoneView, tree *radix.Tree) error {
	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return err
	}
	return WriteZoneFile(path, origin, tree, m.ttlHints.snapshot(origin, view))
}

// DeleteKeys removes stored KSK/ZSK material for origin/view.
func (m *DNSSECManager) DeleteKeys(origin string, view ZoneView) error {
	if m == nil || m.store == nil {
		return fmt.Errorf("dnssec manager is nil")
	}
	return m.store.DeleteKeys(NormalizeName(origin), string(view))
}

// DNSSECStatus returns the current Auto-DNSSEC status for a zone.
func (m *Memory) DNSSECStatus(origin string, view ZoneView) (dnssec.Status, error) {
	if m == nil {
		return dnssec.Status{}, fmt.Errorf("memory store is nil")
	}
	if m.dnssec == nil {
		return dnssec.Status{
			Enabled: false,
			Zone:    NormalizeName(origin),
			View:    string(view),
		}, nil
	}
	return m.dnssec.Status(origin, view)
}
