package storage

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armon/go-radix"
)

var (
	// ErrZoneAlreadyExists indicates the requested zone is already loaded in the given view.
	ErrZoneAlreadyExists = errors.New("zone already exists")
)

// CreateZone writes a new BIND zone file with a valid SOA record, loads it into memory,
// and registers the zone in the given view.
func (m *Memory) CreateZone(zonesDir, name string, view ZoneView) (ZoneInfo, error) {
	if m == nil {
		return ZoneInfo{}, fmt.Errorf("memory store is nil")
	}
	if err := ValidateZoneName(name); err != nil {
		return ZoneInfo{}, err
	}

	origin := NormalizeName(name)

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if m.zoneExistsLocked(origin, view) {
		return ZoneInfo{}, ErrZoneAlreadyExists
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return ZoneInfo{}, err
	}

	if err := writeInitialZoneFile(path, origin); err != nil {
		return ZoneInfo{}, err
	}

	tree := cloneTree(m.treeForView(view))
	if _, err := loadZoneFile(path, tree, slog.Default()); err != nil {
		_ = os.Remove(path)
		return ZoneInfo{}, fmt.Errorf("load created zone: %w", err)
	}

	m.registerZoneLocked(origin, view, path)

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	return ZoneInfo{
		Origin:   origin,
		View:     view,
		FilePath: path,
		Records:  countZoneRecords(tree, origin),
	}, nil
}

// DeleteZone removes all in-memory records for the zone, deletes the zone file from disk,
// and unregisters the zone from the given view.
func (m *Memory) DeleteZone(zonesDir, name string, view ZoneView) error {
	if m == nil {
		return fmt.Errorf("memory store is nil")
	}
	if err := ValidateZoneName(name); err != nil {
		return err
	}

	origin := NormalizeName(name)

	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if !m.zoneExistsLocked(origin, view) {
		return ErrZoneNotFound
	}

	path, err := m.zoneFilePath(zonesDir, origin, view)
	if err != nil {
		return err
	}

	tree := cloneTree(m.treeForView(view))
	removeZoneFromTree(tree, origin)

	if view == ViewInternal {
		m.SwapInternalTree(tree)
	} else {
		m.SwapPublicTree(tree)
	}

	m.unregisterZoneLocked(origin, view)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete zone file: %w", err)
	}

	return nil
}

func writeInitialZoneFile(path, origin string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create zone directory: %w", err)
	}

	content := formatInitialZoneFile(origin)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write zone temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace zone file: %w", err)
	}
	return nil
}

func formatInitialZoneFile(origin string) string {
	origin = NormalizeName(origin)
	apex := strings.TrimSuffix(origin, ".")
	serial := time.Now().UTC().Format("20060102") + "01"
	ns := fmt.Sprintf("ns1.%s.", apex)
	mbox := fmt.Sprintf("admin.%s.", apex)

	return fmt.Sprintf(`$ORIGIN %s
$TTL 3600
@       IN  SOA     %s %s (
                    %s ; serial
                    3600       ; refresh
                    600        ; retry
                    86400      ; expire
                    3600       ; minimum
                    )
`, origin, ns, mbox, serial)
}

func removeZoneFromTree(tree *radix.Tree, origin string) {
	if tree == nil {
		return
	}

	origin = NormalizeName(origin)
	var names []string
	tree.Walk(func(name string, _ interface{}) bool {
		if isNameInZone(name, origin) {
			names = append(names, name)
		}
		return false
	})
	for _, name := range names {
		tree.Delete(name)
	}
}

func (m *Memory) registerZoneLocked(origin string, view ZoneView, filePath string) {
	if m == nil || m.registry == nil {
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

func (m *Memory) unregisterZoneLocked(origin string, view ZoneView) {
	if m == nil || m.registry == nil {
		return
	}
	origin = NormalizeName(origin)
	m.registry.mu.Lock()
	defer m.registry.mu.Unlock()

	delete(m.registry.byKey, zoneRegistryKey(origin, view))

	for _, rec := range m.registry.byKey {
		if rec.origin == origin {
			return
		}
	}
	delete(m.registry.origin, origin)
}
