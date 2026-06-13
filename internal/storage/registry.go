package storage

import (
	"fmt"
	"sync"
)

// ZoneView identifies the split-DNS view that owns a zone.
type ZoneView string

const (
	// ViewPublic is the external authoritative view (zones directory root).
	ViewPublic ZoneView = "public"
	// ViewInternal is the trusted-client internal view (zones/internal/).
	ViewInternal ZoneView = "internal"
)

// ZoneInfo describes a loaded authoritative zone and its on-disk source file.
type ZoneInfo struct {
	Origin   string   `json:"origin"`
	View     ZoneView `json:"view"`
	FilePath string   `json:"file_path"`
	Records  int      `json:"records"`
}

type zoneRegistry struct {
	mu     sync.RWMutex
	byKey  map[string]zoneRecord
	origin map[string]struct{}
}

type zoneRecord struct {
	origin   string
	view     ZoneView
	filePath string
}

func newZoneRegistry() *zoneRegistry {
	return &zoneRegistry{
		byKey:  make(map[string]zoneRecord),
		origin: make(map[string]struct{}),
	}
}

func zoneRegistryKey(origin string, view ZoneView) string {
	return fmt.Sprintf("%s:%s", NormalizeName(origin), view)
}

// RegisterZone records the origin, view, and source file path for a loaded zone.
func (m *Memory) RegisterZone(origin string, view ZoneView, filePath string) {
	if m == nil {
		return
	}
	origin = NormalizeName(origin)
	m.registry.mu.Lock()
	defer m.registry.mu.Unlock()

	key := zoneRegistryKey(origin, view)
	m.registry.byKey[key] = zoneRecord{
		origin:   origin,
		view:     view,
		filePath: filePath,
	}
	m.registry.origin[origin] = struct{}{}
}

func (m *Memory) zoneRecord(origin string, view ZoneView) (zoneRecord, bool) {
	origin = NormalizeName(origin)
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()
	rec, ok := m.registry.byKey[zoneRegistryKey(origin, view)]
	return rec, ok
}

func (m *Memory) listRegisteredZones() []zoneRecord {
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()

	out := make([]zoneRecord, 0, len(m.registry.byKey))
	for _, rec := range m.registry.byKey {
		out = append(out, rec)
	}
	return out
}

// ParseZoneView converts a view name from API input into a ZoneView constant.
func ParseZoneView(raw string) (ZoneView, error) {
	switch raw {
	case "", string(ViewPublic):
		return ViewPublic, nil
	case string(ViewInternal):
		return ViewInternal, nil
	default:
		return "", fmt.Errorf("invalid view %q: must be public or internal", raw)
	}
}
