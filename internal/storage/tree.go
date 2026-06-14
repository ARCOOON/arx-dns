package storage

import (
	"strings"

	"github.com/armon/go-radix"
	mdns "github.com/miekg/dns"
)

func cloneTree(tree *radix.Tree) *radix.Tree {
	if tree == nil {
		return radix.New()
	}

	clone := radix.New()
	tree.Walk(func(key string, val interface{}) bool {
		byType := val.(map[uint16][]mdns.RR)
		newByType := make(map[uint16][]mdns.RR, len(byType))
		for qtype, rrs := range byType {
			copied := make([]mdns.RR, len(rrs))
			for i, rr := range rrs {
				copied[i] = mdns.Copy(rr)
			}
			newByType[qtype] = copied
		}
		clone.Insert(key, newByType)
		return false
	})
	return clone
}

func isNameInZone(name, origin string) bool {
	name = NormalizeName(name)
	origin = NormalizeName(origin)
	if name == origin {
		return true
	}
	suffix := "." + strings.TrimSuffix(origin, ".") + "."
	return strings.HasSuffix(name, suffix)
}

func collectZoneRecords(tree *radix.Tree, origin string) []mdns.RR {
	if tree == nil {
		return nil
	}

	var out []mdns.RR
	tree.Walk(func(name string, val interface{}) bool {
		if !isNameInZone(name, origin) {
			return false
		}
		byType := val.(map[uint16][]mdns.RR)
		for _, rrs := range byType {
			for _, rr := range rrs {
				out = append(out, mdns.Copy(rr))
			}
		}
		return false
	})
	return out
}

func countZoneRecords(tree *radix.Tree, origin string) int {
	return len(collectZoneRecords(tree, origin))
}

func zoneHasSOA(tree *radix.Tree, origin string) bool {
	_, status := lookupInTree(tree, origin, mdns.TypeSOA)
	return status == LookupFound
}

func removeMatchingRR(tree *radix.Tree, name string, qtype uint16, value string) bool {
	name = NormalizeName(name)
	raw, ok := tree.Get(name)
	if !ok {
		return false
	}

	byType := raw.(map[uint16][]mdns.RR)
	rrs, ok := byType[qtype]
	if !ok || len(rrs) == 0 {
		return false
	}

	wantValue := strings.TrimSpace(value)

	var kept []mdns.RR
	var removed bool
	for _, rr := range rrs {
		if recordValuesMatch(rr, wantValue) {
			removed = true
			continue
		}
		kept = append(kept, rr)
	}
	if !removed {
		return false
	}

	if len(kept) == 0 {
		delete(byType, qtype)
	} else {
		byType[qtype] = kept
	}

	if len(byType) == 0 {
		tree.Delete(name)
	} else {
		tree.Insert(name, byType)
	}
	return true
}

// removeRRset deletes all resource records of qtype at name. When qtype is TypeANY,
// every RRset at name is removed.
func removeRRset(tree *radix.Tree, name string, qtype uint16) bool {
	name = NormalizeName(name)
	raw, ok := tree.Get(name)
	if !ok {
		return false
	}

	byType := raw.(map[uint16][]mdns.RR)
	if qtype == mdns.TypeANY {
		tree.Delete(name)
		return true
	}

	if _, ok := byType[qtype]; !ok {
		return false
	}
	delete(byType, qtype)
	if len(byType) == 0 {
		tree.Delete(name)
	} else {
		tree.Insert(name, byType)
	}
	return true
}

// removeAllAtName deletes every resource record stored at name.
func removeAllAtName(tree *radix.Tree, name string) bool {
	name = NormalizeName(name)
	if _, ok := tree.Get(name); !ok {
		return false
	}
	tree.Delete(name)
	return true
}

// rrExists reports whether an exact RR (name, type, rdata) is present in tree.
func rrExists(tree *radix.Tree, rr mdns.RR) bool {
	if rr == nil || tree == nil {
		return false
	}
	hdr := rr.Header()
	rrs, status := lookupInTree(tree, hdr.Name, hdr.Rrtype)
	if status != LookupFound {
		return false
	}
	for _, candidate := range rrs {
		if mdns.IsDuplicate(candidate, rr) {
			return true
		}
	}
	return false
}

// rrsetExists reports whether at least one RR of qtype exists at name.
func rrsetExists(tree *radix.Tree, name string, qtype uint16) bool {
	_, status := lookupInTree(tree, name, qtype)
	return status == LookupFound
}
