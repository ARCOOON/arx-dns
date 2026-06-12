package storage

import (
	"strings"
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

// Memory is a thread-safe in-memory authoritative zone store backed by a radix tree.
// Lookups load the active tree pointer atomically for lock-free reads; reloads build a
// new tree in the background and swap it in with atomic.Value.
type Memory struct {
	tree atomic.Value // holds *radix.Tree
}

// NewMemory creates an empty in-memory store.
func NewMemory() *Memory {
	m := &Memory{}
	m.tree.Store(radix.New())
	return m
}

// SwapTree atomically replaces the active radix tree. The previous tree remains
// readable by in-flight lookups until they finish.
func (m *Memory) SwapTree(tree *radix.Tree) {
	if tree == nil {
		tree = radix.New()
	}
	m.tree.Store(tree)
}

func (m *Memory) currentTree() *radix.Tree {
	return m.tree.Load().(*radix.Tree)
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

// InsertRR adds a DNS resource record to the active tree. It is intended for
// single-threaded initialization and tests; production reloads build a fresh tree
// off the request path and swap it in atomically.
func (m *Memory) InsertRR(rr mdns.RR) {
	insertRR(m.currentTree(), rr)
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

// Lookup returns resource records for the given FQDN and query type.
func (m *Memory) Lookup(name string, qtype uint16) ([]mdns.RR, LookupStatus) {
	name = NormalizeName(name)
	tree := m.currentTree()

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
