package network

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxDNSMessageSize = 65535
	tcpLengthPrefix   = 2

	tcpKeepAlive    = 3 * time.Minute
	tcpKeepInterval = 30 * time.Second
	tcpKeepCount    = 3
	tcpReadTimeout  = 3 * time.Second
	tcpTimeoutTick  = 500 * time.Millisecond
)

type tcpConnState struct {
	deadline time.Time
}

// TCPReactor serves DNS over TCP using a gnet event-driven reactor.
type TCPReactor struct {
	reactor
	stats *telemetry.Stats
	proc  *dnsproc.Processor
	conns sync.Map
}

// NewTCPReactor creates a TCP reactor for the given configuration.
func NewTCPReactor(cfg Config, logger *slog.Logger, stats *telemetry.Stats, proc *dnsproc.Processor) *TCPReactor {
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
		proc:  proc,
	}
}

// Run starts the TCP reactor until ctx is canceled.
func (r *TCPReactor) Run(ctx context.Context) error {
	r.ctx = ctx
	return runReactor(ctx, r.cfg, "tcp", r, r.logger, r.gnetOptions()...)
}

func (r *TCPReactor) gnetOptions() []gnet.Option {
	opts := r.reactor.gnetOptions()
	return append(opts,
		gnet.WithTCPKeepAlive(tcpKeepAlive),
		gnet.WithTCPKeepInterval(tcpKeepInterval),
		gnet.WithTCPKeepCount(tcpKeepCount),
		gnet.WithTicker(true),
	)
}

func (r *TCPReactor) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	state := &tcpConnState{deadline: time.Now().Add(tcpReadTimeout)}
	c.SetContext(state)
	r.conns.Store(c, state)
	return nil, gnet.None
}

func (r *TCPReactor) OnClose(c gnet.Conn, _ error) (action gnet.Action) {
	r.conns.Delete(c)
	return gnet.None
}

func (r *TCPReactor) OnTick() (delay time.Duration, action gnet.Action) {
	now := time.Now()
	r.conns.Range(func(key, value any) bool {
		c, ok := key.(gnet.Conn)
		if !ok {
			return true
		}
		state, ok := value.(*tcpConnState)
		if !ok {
			return true
		}
		if now.After(state.deadline) {
			r.stats.IncTCPTimeout()
			_ = c.Close()
			r.conns.Delete(c)
		}
		return true
	})
	return tcpTimeoutTick, gnet.None
}

func (r *TCPReactor) OnTraffic(c gnet.Conn) gnet.Action {
	state, ok := c.Context().(*tcpConnState)
	if !ok {
		state = &tcpConnState{deadline: time.Now().Add(tcpReadTimeout)}
		c.SetContext(state)
		r.conns.Store(c, state)
	}

	if time.Now().After(state.deadline) {
		r.stats.IncTCPTimeout()
		return gnet.Close
	}

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

		client := ClientIPFromAddr(c.RemoteAddr())
		response, err := r.proc.ResponseTCP(client, payload)
		if err != nil {
			r.logger.Debug("tcp parse failed", "error", err, "bytes", len(payload))
			r.stats.IncParseError()
			state.deadline = time.Now().Add(tcpReadTimeout)
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
		recordAnswer(r.stats, response)
		state.deadline = time.Now().Add(tcpReadTimeout)
	}
}
