package network

import (
	"context"
	"encoding/binary"
	"log/slog"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxDNSMessageSize = 65535
	tcpLengthPrefix   = 2
)

// TCPReactor serves DNS over TCP using a gnet event-driven reactor.
type TCPReactor struct {
	reactor
	stats *telemetry.Stats
}

// NewTCPReactor creates a TCP reactor for the given configuration.
func NewTCPReactor(cfg Config, logger *slog.Logger, stats *telemetry.Stats) *TCPReactor {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TCPReactor{
		reactor: reactor{
			cfg:    cfg,
			logger: logger,
			proto:  "tcp",
		},
		stats: stats,
	}
}

// Run starts the TCP reactor until ctx is canceled.
func (r *TCPReactor) Run(ctx context.Context) error {
	r.ctx = ctx
	return runReactor(ctx, r.cfg, "tcp", r, r.logger, r.gnetOptions()...)
}

func (r *TCPReactor) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	return nil, gnet.None
}

func (r *TCPReactor) OnTraffic(c gnet.Conn) gnet.Action {
	for {
		buffered := c.InboundBuffered()
		if buffered < tcpLengthPrefix {
			return gnet.None
		}

		header, err := c.Peek(tcpLengthPrefix)
		if err != nil {
			r.logger.Debug("tcp header peek failed", "error", err)
			r.stats.IncDropped()
			return gnet.Close
		}

		msgLen := int(binary.BigEndian.Uint16(header))
		if msgLen < 1 || msgLen > maxDNSMessageSize {
			r.logger.Debug("tcp invalid message length", "bytes", msgLen)
			r.stats.IncDropped()
			return gnet.Close
		}

		frameLen := tcpLengthPrefix + msgLen
		if buffered < frameLen {
			return gnet.None
		}

		frame, err := c.Peek(frameLen)
		if err != nil {
			r.logger.Debug("tcp frame peek failed", "error", err)
			r.stats.IncDropped()
			return gnet.Close
		}

		payload := frame[tcpLengthPrefix:frameLen]
		if _, err := c.Discard(frameLen); err != nil {
			r.logger.Debug("tcp frame discard failed", "error", err)
			r.stats.IncDropped()
			return gnet.Close
		}

		response, err := dnsproc.RefusedResponse(payload)
		if err != nil {
			r.logger.Debug("tcp parse failed", "error", err, "bytes", len(payload))
			r.stats.IncParseError()
			continue
		}

		out := make([]byte, tcpLengthPrefix+len(response))
		binary.BigEndian.PutUint16(out[:tcpLengthPrefix], uint16(len(response)))
		copy(out[tcpLengthPrefix:], response)

		if _, err := c.Write(out); err != nil {
			r.logger.Warn("tcp write failed", "error", err)
			r.stats.IncWriteError()
			return gnet.Close
		}

		r.stats.IncTCPQuery()
		r.stats.IncRefusedAnswer()
	}
}
