package dnsproc

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	defaultStartingRTTMs = 500
	rttFailurePenaltyMs  = 2000
	rttEWMAWeight        = 5 // alpha = 1/weight (0.2)
	rttCleanupInterval   = 5 * time.Minute
	rttEntryIdleTTL      = time.Hour
)

type rttEntry struct {
	rttEWMA  atomic.Uint64
	lastSeen atomic.Int64
}

// RTTRegistry tracks smoothed round-trip times for upstream nameserver IPs.
type RTTRegistry struct {
	entries  sync.Map
	stats    *telemetry.Stats
	tracked  atomic.Int64
	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	defaultRTT     *RTTRegistry
	defaultRTTOnce sync.Once
)

// NewRTTRegistry creates a registry and starts a background sweep for stale entries.
func NewRTTRegistry(stats *telemetry.Stats) *RTTRegistry {
	r := &RTTRegistry{
		stats:  stats,
		stopCh: make(chan struct{}),
	}
	go r.cleanupLoop()
	return r
}

// DefaultRTTRegistry returns the process-wide RTT registry, creating it on first use.
func DefaultRTTRegistry(stats *telemetry.Stats) *RTTRegistry {
	defaultRTTOnce.Do(func() {
		defaultRTT = NewRTTRegistry(stats)
	})
	return defaultRTT
}

// Close stops the background cleanup goroutine.
func (r *RTTRegistry) Close() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

// RecordSuccess updates the smoothed RTT for addr using an EWMA over duration.
func (r *RTTRegistry) RecordSuccess(addr netip.Addr, duration time.Duration) {
	if r == nil || !addr.IsValid() {
		return
	}
	ms := durationMilliseconds(duration)
	if ms == 0 {
		ms = 1
	}
	r.touch(addr, ms)
}

// RecordFailure applies a flat penalty sample for timeouts, SERVFAIL, or connection errors.
func (r *RTTRegistry) RecordFailure(addr netip.Addr) {
	if r == nil || !addr.IsValid() {
		return
	}
	r.touch(addr, rttFailurePenaltyMs)
}

// Latency returns the tracked RTT in milliseconds for server (host:port), or the default starting value.
func (r *RTTRegistry) Latency(server string) uint64 {
	if r == nil {
		return defaultStartingRTTMs
	}
	addr, ok := serverIP(server)
	if !ok {
		return defaultStartingRTTMs
	}
	val, ok := r.entries.Load(addr)
	if !ok {
		return defaultStartingRTTMs
	}
	ms := val.(*rttEntry).rttEWMA.Load()
	if ms == 0 {
		return defaultStartingRTTMs
	}
	return ms
}

// SortServers returns a copy of servers ordered by ascending tracked RTT.
func (r *RTTRegistry) SortServers(servers []string) []string {
	if len(servers) <= 1 {
		out := make([]string, len(servers))
		copy(out, servers)
		return out
	}

	type ranked struct {
		server string
		rtt    uint64
	}
	rankedServers := make([]ranked, len(servers))
	for i, server := range servers {
		rankedServers[i] = ranked{server: server, rtt: r.Latency(server)}
	}

	sort.SliceStable(rankedServers, func(i, j int) bool {
		if rankedServers[i].rtt == rankedServers[j].rtt {
			return rankedServers[i].server < rankedServers[j].server
		}
		return rankedServers[i].rtt < rankedServers[j].rtt
	})

	out := make([]string, len(servers))
	for i, item := range rankedServers {
		out[i] = item.server
	}
	return out
}

func (r *RTTRegistry) touch(addr netip.Addr, sampleMs uint64) {
	now := time.Now().UnixNano()
	val, loaded := r.entries.Load(addr)
	if !loaded {
		entry := &rttEntry{}
		entry.rttEWMA.Store(sampleMs)
		entry.lastSeen.Store(now)
		val, loaded = r.entries.LoadOrStore(addr, entry)
		if !loaded {
			r.incTracked()
		}
	}

	e := val.(*rttEntry)
	e.lastSeen.Store(now)
	e.updateEWMA(sampleMs)
}

func (e *rttEntry) updateEWMA(sampleMs uint64) {
	for {
		old := e.rttEWMA.Load()
		var next uint64
		if old == 0 {
			next = sampleMs
		} else {
			next = (sampleMs + (rttEWMAWeight-1)*old) / rttEWMAWeight
		}
		if e.rttEWMA.CompareAndSwap(old, next) {
			return
		}
	}
}

func (r *RTTRegistry) incTracked() {
	r.tracked.Add(1)
	if r.stats != nil {
		r.stats.SetRTTTrackedIPs(uint64(r.tracked.Load()))
	}
}

func (r *RTTRegistry) decTracked() {
	r.tracked.Add(-1)
	if r.stats != nil {
		r.stats.SetRTTTrackedIPs(uint64(r.tracked.Load()))
	}
}

func (r *RTTRegistry) cleanupLoop() {
	ticker := time.NewTicker(rttCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

func (r *RTTRegistry) sweep() {
	cutoff := time.Now().Add(-rttEntryIdleTTL).UnixNano()
	r.entries.Range(func(key, value any) bool {
		e := value.(*rttEntry)
		if e.lastSeen.Load() < cutoff {
			r.entries.Delete(key)
			r.decTracked()
		}
		return true
	})
}

func serverIP(server string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return netip.Addr{}, false
	}
	if host[0] == '[' {
		host = host[1 : len(host)-1]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func durationMilliseconds(d time.Duration) uint64 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}
