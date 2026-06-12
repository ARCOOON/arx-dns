package storage

import (
	"strings"
	"sync"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"
)

// LookupStatus describes the outcome of an authoritative lookup.
type LookupStatus int

const (
	// LookupNotFound means the name is not present in the zone.
	LookupNotFound LookupStatus = iota
	// LookupNodata means the name exists but has no records for the requested type.
	LookupNodata
	// LookupFound means matching records were returned.
	LookupFound
)

// Memory is a thread-safe in-memory authoritative zone store backed by a radix tree.
type Memory struct {
	mu   sync.RWMutex
	tree *radix.Tree
}

// NewMemory creates an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tree: radix.New(),
	}
}

// NormalizeName returns the FQDN in lowercase with a trailing dot.
func NormalizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// InsertRR adds a DNS resource record to the store.
func (m *Memory) InsertRR(rr mdns.RR) {
	if rr == nil {
		return
	}

	hdr := rr.Header()
	name := NormalizeName(hdr.Name)
	qtype := hdr.Rrtype

	m.mu.Lock()
	defer m.mu.Unlock()

	raw, ok := m.tree.Get(name)
	var byType map[uint16][]mdns.RR
	if ok {
		byType = raw.(map[uint16][]mdns.RR)
	} else {
		byType = make(map[uint16][]mdns.RR)
	}

	byType[qtype] = append(byType[qtype], rr)
	m.tree.Insert(name, byType)
}

// Lookup returns resource records for the given FQDN and query type.
func (m *Memory) Lookup(name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	name = NormalizeName(name)

	m.mu.RLock()
	defer m.mu.RUnlock()

	raw, ok := m.tree.Get(name)
	if !ok {
		return nil, LookupNotFound
	}

	byType := raw.(map[uint16][]mdns.RR)
	rrs, ok := byType[qtype]
	if !ok || len(rrs) == 0 {
		return nil, LookupNodata
	}

	out := make([]mdns.RR, len(rrs))
	copy(out, rrs)
	return out, LookupFound
}
