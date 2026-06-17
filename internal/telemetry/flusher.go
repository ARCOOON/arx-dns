package telemetry

import (
	"context"
	"log/slog"
	"time"
)

type counterState struct {
	queries         uint64
	cacheHits       uint64
	dropped         uint64
	dnssecFails     uint64
	localQueries    uint64
	upstreamQueries uint64
}

// Flusher samples in-memory counters and persists 60-second deltas to state.db.
type Flusher struct {
	stats  *Stats
	db     *DB
	logger *slog.Logger
	prev   counterState
}

// NewFlusher creates a telemetry flusher bound to the shared stats instance.
func NewFlusher(stats *Stats, db *DB, logger *slog.Logger) *Flusher {
	if logger == nil {
		logger = slog.Default()
	}

	return &Flusher{
		stats:  stats,
		db:     db,
		logger: logger,
	}
}

// StartWorkers launches the 60-second rollup flusher and hourly retention cleanup.
// Workers stop when ctx is canceled and perform a final flush before returning.
func StartWorkers(ctx context.Context, stats *Stats, db *DB, logger *slog.Logger) {
	if stats == nil || db == nil {
		return
	}

	flusher := NewFlusher(stats, db, logger)

	go flusher.run(ctx)
	go runRetention(ctx, db, logger)
}

func (f *Flusher) run(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	f.seedPrevious()

	for {
		select {
		case <-ctx.Done():
			f.flush()
			return
		case <-ticker.C:
			f.flush()
		}
	}
}

func (f *Flusher) seedPrevious() {
	snap := f.stats.Snapshot()
	f.prev = counterState{
		queries:         snap.TotalQueries,
		cacheHits:       snap.CacheHits,
		dropped:         snap.DroppedPackets,
		dnssecFails:     snap.DNSSECValidationsFailed,
		localQueries:    snap.LocalQueries,
		upstreamQueries: snap.UpstreamQueries,
	}
}

// Flush persists the current counter deltas immediately.
func (f *Flusher) Flush() {
	f.flush()
}

func (f *Flusher) flush() {
	snap := f.stats.Snapshot()
	delta := counterState{
		queries:         counterDelta(snap.TotalQueries, f.prev.queries),
		cacheHits:       counterDelta(snap.CacheHits, f.prev.cacheHits),
		dropped:         counterDelta(snap.DroppedPackets, f.prev.dropped),
		dnssecFails:     counterDelta(snap.DNSSECValidationsFailed, f.prev.dnssecFails),
		localQueries:    counterDelta(snap.LocalQueries, f.prev.localQueries),
		upstreamQueries: counterDelta(snap.UpstreamQueries, f.prev.upstreamQueries),
	}

	if err := f.db.InsertRollup(
		time.Now().UTC(),
		delta.queries,
		delta.cacheHits,
		delta.dropped,
		delta.dnssecFails,
		delta.localQueries,
		delta.upstreamQueries,
	); err != nil {
		f.logger.Warn("telemetry rollup flush failed", "error", err)
		return
	}

	f.prev = counterState{
		queries:         snap.TotalQueries,
		cacheHits:       snap.CacheHits,
		dropped:         snap.DroppedPackets,
		dnssecFails:     snap.DNSSECValidationsFailed,
		localQueries:    snap.LocalQueries,
		upstreamQueries: snap.UpstreamQueries,
	}
}

func counterDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func runRetention(ctx context.Context, db *DB, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()

	purge := func() {
		rows, err := db.PurgeOldMetrics()
		if err != nil {
			logger.Warn("telemetry retention cleanup failed", "error", err)
			return
		}
		if rows > 0 {
			logger.Info("telemetry retention cleanup completed", "deleted_rows", rows)
		}
	}

	purge()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}
