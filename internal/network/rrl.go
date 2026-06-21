package network

import (
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"golang.org/x/time/rate"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	rrlCleanupInterval = 5 * time.Minute
	rrlEntryIdleTTL    = 10 * time.Minute
)

type rrlEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

// RateLimiter applies per-client-IP token-bucket limits to inbound DNS traffic.
type RateLimiter struct {
	enabled bool
	limit   rate.Limit
	burst   int
	stats   *telemetry.Stats

	entries sync.Map

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewRateLimiter builds a rate limiter from configuration. When disabled, Allow
// always returns true and no background cleanup goroutine is started.
func NewRateLimiter(cfg config.RateLimitConfig, stats *telemetry.Stats) *RateLimiter {
	r := &RateLimiter{
		enabled: cfg.Enabled,
		limit:   rate.Limit(cfg.RequestsPerSecond),
		burst:   cfg.Burst,
		stats:   stats,
		stopCh:  make(chan struct{}),
	}
	if r.enabled {
		go r.cleanupLoop()
	}
	return r
}

// Allow reports whether a request from addr may proceed. When the limit is
// exceeded the packet must be dropped silently and rrl_dropped is incremented.
func (r *RateLimiter) Allow(addr netip.Addr) bool {
	if !r.enabled || !addr.IsValid() {
		return true
	}

	now := time.Now()
	val, loaded := r.entries.Load(addr)
	if !loaded {
		entry := &rrlEntry{
			limiter: rate.NewLimiter(r.limit, r.burst),
		}
		entry.lastSeen.Store(now.UnixNano())
		val, loaded = r.entries.LoadOrStore(addr, entry)
	}

	e := val.(*rrlEntry)
	e.lastSeen.Store(now.UnixNano())

	if e.limiter.Allow() {
		return true
	}

	if r.stats != nil {
		r.stats.IncRRLDropped()
	}
	return false
}

// Close stops the background cleanup goroutine.
func (r *RateLimiter) Close() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

// Reconfigure updates rate limiting parameters without restarting listeners.
func (r *RateLimiter) Reconfigure(cfg config.RateLimitConfig) {
	if r == nil {
		return
	}
	r.enabled = cfg.Enabled
	if cfg.RequestsPerSecond > 0 {
		r.limit = rate.Limit(cfg.RequestsPerSecond)
	}
	if cfg.Burst > 0 {
		r.burst = cfg.Burst
	}
}

func (r *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rrlCleanupInterval)
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

func (r *RateLimiter) sweep() {
	cutoff := time.Now().Add(-rrlEntryIdleTTL).UnixNano()
	r.entries.Range(func(key, value any) bool {
		e := value.(*rrlEntry)
		if e.lastSeen.Load() < cutoff {
			r.entries.Delete(key)
		}
		return true
	})
}
