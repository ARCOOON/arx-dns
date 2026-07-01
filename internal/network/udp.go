package network

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
	"github.com/panjf2000/gnet/v2"
)

// UDPReactor serves DNS over UDP using a gnet event-driven reactor.
type UDPReactor struct {
	reactor
	stats *telemetry.Stats
	proc  *dnsproc.Processor
	rrl   *RateLimiter
}

// NewUDPReactor creates a UDP reactor for the given configuration.
func NewUDPReactor(cfg Config, logger *slog.Logger, stats *telemetry.Stats, proc *dnsproc.Processor, rrl *RateLimiter) *UDPReactor {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &UDPReactor{
		reactor: reactor{
			cfg:    cfg,
			logger: logger,
			proto:  "udp",
		},
		stats: stats,
		proc:  proc,
		rrl:   rrl,
	}
}

// Run starts the UDP reactor until ctx is canceled.
func (r *UDPReactor) Run(ctx context.Context) error {
	r.ctx = ctx
	return runReactor(ctx, r.cfg, "udp", r, r.logger, r.gnetOptions()...)
}

func (r *UDPReactor) OnTraffic(c gnet.Conn) gnet.Action {
	payload, err := c.Next(-1)
	if err != nil || len(payload) == 0 {
		if err != nil {
			r.logger.Debug("udp read failed", "error", err)
			r.stats.IncDropped()
		}
		return gnet.None
	}

	client := ClientIPFromAddr(c.RemoteAddr())
	if r.rrl != nil && !r.rrl.Allow(client) {
		return gnet.None
	}

	response, err := r.proc.Response(client, payload)
	if errors.Is(err, dnsproc.ErrPolicyDrop) {
		return gnet.None
	}
	if err != nil {
		r.logger.Debug("udp parse failed", "error", err, "bytes", len(payload))
		r.stats.IncParseError()
		return gnet.None
	}

	if _, err := c.Write(response); err != nil {
		r.logger.Warn("udp write failed", "error", err)
		r.stats.IncWriteError()
		return gnet.None
	}

	r.stats.IncUDPQuery()
	recordAnswer(r.stats, response)
	return gnet.None
}
