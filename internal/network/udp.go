package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

const maxUDPPayload = 65535

// UDPListener serves DNS over UDP with kernel-level SO_REUSEPORT load balancing.
type UDPListener struct {
	cfg    Config
	logger *slog.Logger

	mu    sync.Mutex
	conns []net.PacketConn
	wg    sync.WaitGroup
}

// NewUDPListener creates a UDP listener for the given configuration.
func NewUDPListener(cfg Config, logger *slog.Logger) *UDPListener {
	if logger == nil {
		logger = slog.Default()
	}
	return &UDPListener{cfg: cfg, logger: logger}
}

// Run binds SO_REUSEPORT sockets and processes packets until ctx is canceled.
func (l *UDPListener) Run(ctx context.Context) error {
	sockets := l.cfg.socketCount()
	conns := make([]net.PacketConn, 0, sockets)

	for i := 0; i < sockets; i++ {
		conn, err := listenPacket(ctx, "udp", l.cfg.Address)
		if err != nil {
			closePacketConns(conns)
			return fmt.Errorf("udp listen socket %d: %w", i, err)
		}
		conns = append(conns, conn)
	}

	l.mu.Lock()
	l.conns = conns
	l.mu.Unlock()

	for _, conn := range conns {
		l.wg.Add(1)
		go func(c net.PacketConn) {
			defer l.wg.Done()
			l.serve(ctx, c)
		}(conn)
	}

	<-ctx.Done()
	l.shutdown()
	l.wg.Wait()
	return ctx.Err()
}

func (l *UDPListener) serve(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, maxUDPPayload)

	for {
		if ctx.Err() != nil {
			return
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.logger.Warn("udp read failed", "error", err)
			continue
		}

		l.logger.Info("udp request received", "bytes", n)
	}
}

func (l *UDPListener) shutdown() {
	l.mu.Lock()
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	closePacketConns(conns)
}

func closePacketConns(conns []net.PacketConn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}
