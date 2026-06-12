package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

const (
	maxDNSMessageSize = 65535
	tcpLengthPrefix   = 2
)

// TCPListener serves DNS over TCP (RFC 1035 length-prefixed framing).
type TCPListener struct {
	cfg    Config
	logger *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
	wg        sync.WaitGroup
}

// NewTCPListener creates a TCP listener for the given configuration.
func NewTCPListener(cfg Config, logger *slog.Logger) *TCPListener {
	if logger == nil {
		logger = slog.Default()
	}
	return &TCPListener{cfg: cfg, logger: logger}
}

// Run binds SO_REUSEPORT listeners and accepts connections until ctx is canceled.
func (l *TCPListener) Run(ctx context.Context) error {
	sockets := l.cfg.socketCount()
	listeners := make([]net.Listener, 0, sockets)

	for i := 0; i < sockets; i++ {
		ln, err := listenTCP(ctx, "tcp", l.cfg.Address)
		if err != nil {
			closeTCPListeners(listeners)
			return fmt.Errorf("tcp listen socket %d: %w", i, err)
		}
		listeners = append(listeners, ln)
	}

	l.mu.Lock()
	l.listeners = listeners
	l.mu.Unlock()

	for _, ln := range listeners {
		l.wg.Add(1)
		go func(listener net.Listener) {
			defer l.wg.Done()
			l.accept(ctx, listener)
		}(ln)
	}

	<-ctx.Done()
	l.shutdown()
	l.wg.Wait()
	return ctx.Err()
}

func (l *TCPListener) accept(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.logger.Warn("tcp accept failed", "error", err)
			continue
		}

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			l.handleConn(c)
		}(conn)
	}
}

func (l *TCPListener) handleConn(conn net.Conn) {
	defer conn.Close()

	var lengthPrefix [tcpLengthPrefix]byte
	if _, err := io.ReadFull(conn, lengthPrefix[:]); err != nil {
		if err != io.EOF {
			l.logger.Warn("tcp length read failed", "error", err)
		}
		return
	}

	msgLen := int(binary.BigEndian.Uint16(lengthPrefix[:]))
	if msgLen < 1 || msgLen > maxDNSMessageSize {
		l.logger.Warn("tcp invalid message length", "bytes", msgLen)
		return
	}

	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		l.logger.Warn("tcp payload read failed", "error", err, "expected_bytes", msgLen)
		return
	}

	l.logger.Info("tcp request received", "bytes", msgLen)
}

func (l *TCPListener) shutdown() {
	l.mu.Lock()
	listeners := l.listeners
	l.listeners = nil
	l.mu.Unlock()
	closeTCPListeners(listeners)
}

func closeTCPListeners(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}
