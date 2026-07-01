package network

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	dohPath             = "/dns-query"
	dnsMessageMediaType = "application/dns-message"
	maxDoHBodySize      = 65535
)

// DoHServer serves DNS-over-HTTPS (RFC 8484) over TLS.
type DoHServer struct {
	addr   string
	tlsCfg *tls.Config
	logger *slog.Logger
	stats  *telemetry.Stats
	proc   *dnsproc.Processor
	rrl    *RateLimiter
	server *http.Server
}

// NewDoHServer creates a DNS-over-HTTPS listener on addr.
func NewDoHServer(addr string, tlsCfg *tls.Config, logger *slog.Logger, stats *telemetry.Stats, proc *dnsproc.Processor, rrl *RateLimiter) *DoHServer {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}

	dohTLS := tlsCfg.Clone()
	dohTLS.NextProtos = []string{"h2", "http/1.1"}

	mux := http.NewServeMux()
	srv := &DoHServer{
		addr:   addr,
		tlsCfg: dohTLS,
		logger: logger,
		stats:  stats,
		proc:   proc,
	}
	mux.HandleFunc(dohPath, srv.handleDNSQuery)
	srv.rrl = rrl
	srv.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: dohTLS,
	}

	return srv
}

// Run starts the HTTPS server until ctx is canceled.
func (s *DoHServer) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, s.tlsCfg)
	s.logger.Info("doh listener started", "address", s.addr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("doh shutdown failed", "error", err)
		}
	}()

	err = s.server.Serve(tlsLn)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (s *DoHServer) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDoHGet(w, r)
	case http.MethodPost:
		s.handleDoHPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *DoHServer) handleDoHGet(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("dns"))
	if raw == "" {
		http.Error(w, "missing dns query parameter", http.StatusBadRequest)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		http.Error(w, "invalid dns parameter encoding", http.StatusBadRequest)
		return
	}

	s.writeDNSResponse(w, r, payload)
}

func (s *DoHServer) handleDoHPost(w http.ResponseWriter, r *http.Request) {
	mediaType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if mediaType != dnsMessageMediaType {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	payload, err := io.ReadAll(io.LimitReader(r.Body, maxDoHBodySize+1))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if len(payload) == 0 || len(payload) > maxDoHBodySize {
		http.Error(w, "invalid dns message size", http.StatusBadRequest)
		return
	}

	s.writeDNSResponse(w, r, payload)
}

func (s *DoHServer) writeDNSResponse(w http.ResponseWriter, r *http.Request, payload []byte) {
	client := clientIPFromHTTPRequest(r)
	if s.rrl != nil && !s.rrl.Allow(client) {
		return
	}

	response, err := s.proc.ResponseTCP(client, payload)
	if errors.Is(err, dnsproc.ErrPolicyDrop) {
		return
	}
	if err != nil {
		s.logger.Debug("doh parse failed", "error", err, "bytes", len(payload))
		s.stats.IncParseError()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", dnsMessageMediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		s.logger.Warn("doh write failed", "error", err)
		s.stats.IncWriteError()
		return
	}

	s.stats.IncDoHQuery()
	recordAnswer(s.stats, response)
}

func clientIPFromHTTPRequest(r *http.Request) netip.Addr {
	if r == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ClientIPFromAddr(&net.TCPAddr{IP: ip})
		}
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}
