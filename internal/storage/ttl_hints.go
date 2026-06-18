package storage

import (
	"sync"

	mdns "github.com/miekg/dns"
)

type ttlHintStore struct {
	mu    sync.RWMutex
	hints map[string]string
}

func newTTLHintStore() *ttlHintStore {
	return &ttlHintStore{hints: make(map[string]string)}
}

func ttlHintKey(origin string, view ZoneView, rr mdns.RR) string {
	return zoneRegistryKey(origin, view) + ":" + ComputeRecordID(origin, rr)
}

func (s *ttlHintStore) set(origin string, view ZoneView, rr mdns.RR, text string) {
	if s == nil || rr == nil || text == "" {
		return
	}
	key := ttlHintKey(origin, view, rr)
	s.mu.Lock()
	s.hints[key] = text
	s.mu.Unlock()
}

func (s *ttlHintStore) get(origin string, view ZoneView, rr mdns.RR) string {
	if s == nil || rr == nil {
		return ""
	}
	key := ttlHintKey(origin, view, rr)
	s.mu.RLock()
	text := s.hints[key]
	s.mu.RUnlock()
	return text
}

func (s *ttlHintStore) remove(origin string, view ZoneView, rr mdns.RR) {
	if s == nil || rr == nil {
		return
	}
	key := ttlHintKey(origin, view, rr)
	s.mu.Lock()
	delete(s.hints, key)
	s.mu.Unlock()
}

func (s *ttlHintStore) snapshot(origin string, view ZoneView) map[string]string {
	if s == nil {
		return nil
	}
	prefix := zoneRegistryKey(origin, view) + ":"
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string)
	for key, text := range s.hints {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			out[key[len(prefix):]] = text
		}
	}
	return out
}
