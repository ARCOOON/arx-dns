package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const shutdownTimeout = 10 * time.Second

// Server exposes a lightweight HTTP API for health checks, telemetry, zone management,
// and optionally the embedded management WebUI when built with -tags webui.
type Server struct {
	cfg         config.Config
	stats       *telemetry.Stats
	telemetryDB *telemetry.DB
	store       *storage.Memory
	notifier    dnsproc.ZoneChangeNotifier
	logger      *slog.Logger
	server      *http.Server
}

// New creates a management API server bound to cfg.API.Listen.
func New(cfg config.Config, stats *telemetry.Stats, telemetryDB *telemetry.DB, store *storage.Memory, notifier dnsproc.ZoneChangeNotifier, logger *slog.Logger) *Server {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:         cfg,
		stats:       stats,
		telemetryDB: telemetryDB,
		store:       store,
		notifier:    notifier,
		logger:      logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /metrics", telemetry.MetricsHandler(stats))

	auth := bearerAuth(cfg.API.AuthToken)
	mux.Handle("GET /api/v1/stats", auth(http.HandlerFunc(s.handleStats)))
	mux.Handle("GET /api/v1/stats/history", auth(http.HandlerFunc(s.handleStatsHistory)))
	mux.Handle("GET /api/v1/zones", auth(http.HandlerFunc(s.handleListZones)))
	mux.Handle("GET /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleListZoneRecords)))
	mux.Handle("POST /api/v1/zones/reload", auth(http.HandlerFunc(s.handleZonesReload)))
	mux.Handle("POST /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleCreateRecord)))
	mux.Handle("DELETE /api/v1/zones/{zone}/records/{id}", auth(http.HandlerFunc(s.handleDeleteRecord)))
	mux.Handle("DELETE /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleDeleteRecord)))

	mux.HandleFunc("GET /{$}", handleWebUI)
	mux.HandleFunc("GET /{path...}", handleWebUI)

	s.server = &http.Server{
		Addr:    cfg.API.Listen,
		Handler: auditMiddleware(logger)(mux),
	}

	return s
}

// Handler returns the HTTP handler for testing and embedding.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// Run starts the HTTP API until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	tlsEnabled := s.cfg.APITLSEnabled()
	s.logger.Info("management api listener started",
		"address", s.cfg.API.Listen,
		"tls", tlsEnabled,
	)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("management api shutdown failed", "error", err)
		}
	}()

	var err error
	if tlsEnabled {
		err = s.server.ListenAndServeTLS(s.cfg.API.TLSCert, s.cfg.API.TLSKey)
	} else {
		err = s.server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func bearerAuth(token string) func(http.Handler) http.Handler {
	expected := []byte(token)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(raw, "Bearer ") {
				writeJSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			provided := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
			if subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
				writeJSONError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleZonesReload(w http.ResponseWriter, _ *http.Request) {
	s.logger.Info("zone reload triggered", "directory", s.cfg.Zones.Directory, "trigger", "api")
	storage.LoadZones(s.cfg.Zones, s.store, s.logger)
	if s.notifier != nil {
		s.notifier.NotifyZones(dnsproc.ZoneOrigins(s.store.ListZones()))
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "zones reloaded",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
