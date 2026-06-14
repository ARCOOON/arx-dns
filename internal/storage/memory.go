package storage

import (
	"strings"
	"sync"
	"sync/atomic"

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

// Memory is a thread-safe in-memory authoritative zone store backed by separate
// radix trees for public and internal split-DNS views. Lookups load the active
// tree pointer atomically for lock-free reads; reloads build new trees in the
// background and swap them in with atomic.Value.
type Memory struct {
	public   atomic.Value // holds *radix.Tree
	internal atomic.Value // holds *radix.Tree
	registry *zoneRegistry
	mutateMu sync.Mutex
}

// NewMemory creates an empty in-memory store with public and internal views.
func NewMemory() *Memory {
	m := &Memory{registry: newZoneRegistry()}
	m.public.Store(radix.New())
	m.internal.Store(radix.New())
	return m
}

// ResetRegistry clears zone metadata. It is called before a full directory reload.
func (m *Memory) ResetRegistry() {
	if m == nil || m.registry == nil {
		return
	}
	m.registry.mu.Lock()
	defer m.registry.mu.Unlock()
	m.registry.byKey = make(map[string]zoneRecord)
	m.registry.origin = make(map[string]struct{})
}

func (m *Memory) treeForView(view ZoneView) *radix.Tree {
	if view == ViewInternal {
		return m.internalTree()
	}
	return m.publicTree()
}

// SwapPublicTree atomically replaces the public-view radix tree.
func (m *Memory) SwapPublicTree(tree *radix.Tree) {
	if tree == nil {
		tree = radix.New()
	}
	m.public.Store(tree)
}

// SwapInternalTree atomically replaces the internal-view radix tree.
func (m *Memory) SwapInternalTree(tree *radix.Tree) {
	if tree == nil {
		tree = radix.New()
	}
	m.internal.Store(tree)
}

// SwapTree atomically replaces the public-view radix tree. It is kept for
// backward compatibility with callers that only manage the public view.
func (m *Memory) SwapTree(tree *radix.Tree) {
	m.SwapPublicTree(tree)
}

func (m *Memory) publicTree() *radix.Tree {
	return m.public.Load().(*radix.Tree)
}

func (m *Memory) internalTree() *radix.Tree {
	return m.internal.Load().(*radix.Tree)
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

// InsertRR adds a DNS resource record to the public view tree. It is intended
// for single-threaded initialization and tests; production reloads build fresh
// trees off the request path and swap them in atomically.
func (m *Memory) InsertRR(rr mdns.RR) {
	insertRR(m.publicTree(), rr)
}

// InsertInternalRR adds a DNS resource record to the internal view tree.
func (m *Memory) InsertInternalRR(rr mdns.RR) {
	insertRR(m.internalTree(), rr)
}

func insertRR(tree *radix.Tree, rr mdns.RR) {
	if rr == nil || tree == nil {
		return
	}

	hdr := rr.Header()
	name := NormalizeName(hdr.Name)
	qtype := hdr.Rrtype

	raw, ok := tree.Get(name)
	var byType map[uint16][]mdns.RR
	if ok {
		byType = raw.(map[uint16][]mdns.RR)
	} else {
		byType = make(map[uint16][]mdns.RR)
	}

	byType[qtype] = append(byType[qtype], rr)
	tree.Insert(name, byType)
}

// Lookup returns resource records from the public view for the given FQDN and type.
func (m *Memory) Lookup(name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	return lookupInTree(m.publicTree(), name, qtype)
}

// LookupPublic returns resource records from the public view.
func (m *Memory) LookupPublic(name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	return lookupInTree(m.publicTree(), name, qtype)
}

// LookupInternal returns resource records from the internal view.
func (m *Memory) LookupInternal(name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	return lookupInTree(m.internalTree(), name, qtype)
}

func lookupInTree(tree *radix.Tree, name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	name = NormalizeName(name)

	raw, ok := tree.Get(name)
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

// NameExistsPublic reports whether any resource records exist for name in the public view.
func (m *Memory) NameExistsPublic(name string) bool {
	return nameExistsInTree(m.publicTree(), name)
}

// NameExistsInternal reports whether any resource records exist for name in the internal view.
func (m *Memory) NameExistsInternal(name string) bool {
	return nameExistsInTree(m.internalTree(), name)
}

func nameExistsInTree(tree *radix.Tree, name string) bool {
	if tree == nil {
		return false
	}
	_, ok := tree.Get(NormalizeName(name))
	return ok
}

// LookupAllAtName returns every resource record stored at name in the public view.
func (m *Memory) LookupAllAtName(name string) ([]mdns.RR, LookupStatus) {
	return lookupAllAtName(m.publicTree(), name)
}

// LookupAllAtNameInternal returns every resource record stored at name in the internal view.
func (m *Memory) LookupAllAtNameInternal(name string) ([]mdns.RR, LookupStatus) {
	return lookupAllAtName(m.internalTree(), name)
}

func lookupAllAtName(tree *radix.Tree, name string) ([]mdns.RR, LookupStatus) {
	name = NormalizeName(name)

	raw, ok := tree.Get(name)
	if !ok {
		return nil, LookupNotFound
	}

	byType := raw.(map[uint16][]mdns.RR)
	var out []mdns.RR
	for _, rrs := range byType {
		for _, rr := range rrs {
			out = append(out, mdns.Copy(rr))
		}
	}
	if len(out) == 0 {
		return nil, LookupNodata
	}
	return out, LookupFound
}
