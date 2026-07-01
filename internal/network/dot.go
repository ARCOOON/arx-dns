package network

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

// DoTServer serves DNS-over-TLS (RFC 7858) using length-prefixed TCP framing (RFC 1035).
type DoTServer struct {
	addr   string
	tlsCfg *tls.Config
	logger *slog.Logger
	stats  *telemetry.Stats
	proc   *dnsproc.Processor
	rrl    *RateLimiter
	ln     net.Listener
}

// NewDoTServer creates a DNS-over-TLS listener on addr.
func NewDoTServer(addr string, tlsCfg *tls.Config, logger *slog.Logger, stats *telemetry.Stats, proc *dnsproc.Processor, rrl *RateLimiter) *DoTServer {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}

	dotTLS := tlsCfg.Clone()
	dotTLS.NextProtos = []string{"dot"}

	return &DoTServer{
		addr:   addr,
		tlsCfg: dotTLS,
		logger: logger,
		stats:  stats,
		proc:   proc,
		rrl:    rrl,
	}
}

// Run accepts TLS connections and serves DNS until ctx is canceled.
func (s *DoTServer) Run(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.addr, s.tlsCfg)
	if err != nil {
		return err
	}
	s.ln = ln
	s.logger.Info("dot listener started", "address", s.addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.Debug("dot accept failed", "error", err)
			continue
		}

		go s.serveConn(conn)
	}
}

func (s *DoTServer) serveConn(conn net.Conn) {
	defer conn.Close()

	deadline := time.Now().Add(tcpReadTimeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			s.stats.IncDropped()
			return
		}

		var lenBuf [tcpLengthPrefix]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if err != io.EOF && !isNetClosed(err) {
				s.logger.Debug("dot length read failed", "error", err)
			}
			if err == io.EOF || isTimeout(err) {
				s.stats.IncTCPTimeout()
			}
			return
		}

		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen < 1 || msgLen > maxDNSMessageSize {
			s.logger.Debug("dot invalid message length", "bytes", msgLen)
			s.stats.IncDropped()
			return
		}

		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			if isTimeout(err) {
				s.stats.IncTCPTimeout()
			} else {
				s.logger.Debug("dot payload read failed", "error", err)
				s.stats.IncDropped()
			}
			return
		}

		client := ClientIPFromAddr(conn.RemoteAddr())
		if s.rrl != nil && !s.rrl.Allow(client) {
			deadline = time.Now().Add(tcpReadTimeout)
			continue
		}

		isXfer := dnsproc.IsZoneTransferQuery(payload)
		writeTimeout := tcpReadTimeout
		if isXfer {
			writeTimeout = tcpXferTimeout
			deadline = time.Now().Add(tcpXferTimeout)
		}

		var lastResponse []byte
		err := s.proc.HandleTCP(client, payload, func(data []byte) error {
			lastResponse = data
			out := make([]byte, tcpLengthPrefix+len(data))
			binary.BigEndian.PutUint16(out[:tcpLengthPrefix], uint16(len(data)))
			copy(out[tcpLengthPrefix:], data)

			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				s.stats.IncWriteError()
				return err
			}
			if _, err := conn.Write(out); err != nil {
				s.logger.Warn("dot write failed", "error", err)
				s.stats.IncWriteError()
				return err
			}
			if isXfer {
				deadline = time.Now().Add(tcpXferTimeout)
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, dnsproc.ErrPolicyDrop) {
				deadline = time.Now().Add(tcpReadTimeout)
				continue
			}
			s.logger.Debug("dot query failed", "error", err, "bytes", len(payload))
			if !isXfer {
				s.stats.IncParseError()
			}
			return
		}

		s.stats.IncDoTQuery()
		if !isXfer && lastResponse != nil {
			recordAnswer(s.stats, lastResponse)
		}
		deadline = time.Now().Add(tcpReadTimeout)
		if isXfer {
			deadline = time.Now().Add(tcpXferTimeout)
		}
	}
}

func isNetClosed(err error) bool {
	if err == nil {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err.Error() == "use of closed network connection"
	}
	return false
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
