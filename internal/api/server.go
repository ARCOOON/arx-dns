package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/firewall"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const shutdownTimeout = 10 * time.Second

// Server exposes a lightweight HTTP API for health checks, telemetry, zone management,
// and optionally the embedded management WebUI when built with -tags webui.
type Server struct {
	cfg         config.Config
	cfgMu       sync.RWMutex
	configPath  string
	runtime     RuntimeConfigurator
	stats       *telemetry.Stats
	telemetryDB *telemetry.DB
	store       *storage.Memory
	firewall    *firewall.Engine
	queryACL    *dnsproc.QueryAccessChecker
	notifier    dnsproc.ZoneChangeNotifier
	logger      *slog.Logger
	server      *http.Server
}

// New creates a management API server bound to cfg.API.Listen.
func New(cfg config.Config, configPath string, stats *telemetry.Stats, telemetryDB *telemetry.DB, store *storage.Memory, fw *firewall.Engine, queryACL *dnsproc.QueryAccessChecker, notifier dnsproc.ZoneChangeNotifier, runtime RuntimeConfigurator, logger *slog.Logger) *Server {
	if stats == nil {
		stats = telemetry.New()
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:         cfg,
		configPath:  configPath,
		runtime:     runtime,
		stats:       stats,
		telemetryDB: telemetryDB,
		store:       store,
		firewall:    fw,
		queryACL:    queryACL,
		notifier:    notifier,
		logger:      logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /metrics", telemetry.MetricsHandler(stats))

	auth := bearerAuth(cfg.API.AuthToken)
	mux.Handle("GET /api/v1/stats", auth(http.HandlerFunc(s.handleStats)))
	mux.Handle("GET /api/v1/stats/history", auth(http.HandlerFunc(s.handleStatsHistory)))
	mux.Handle("GET /api/v1/firewall/status", auth(http.HandlerFunc(s.handleFirewallStatus)))
	mux.Handle("GET /api/v1/firewall/sources", auth(http.HandlerFunc(s.handleListBlocklistSources)))
	mux.Handle("POST /api/v1/firewall/sources", auth(http.HandlerFunc(s.handleCreateBlocklistSource)))
	mux.Handle("DELETE /api/v1/firewall/sources/{id}", auth(http.HandlerFunc(s.handleDeleteBlocklistSource)))
	mux.Handle("PATCH /api/v1/firewall/sources/{id}", auth(http.HandlerFunc(s.handlePatchBlocklistSource)))
	mux.Handle("POST /api/v1/firewall/sync", auth(http.HandlerFunc(s.handleFirewallSync)))
	mux.Handle("GET /api/v1/firewall/custom", auth(http.HandlerFunc(s.handleListCustomBlocklist)))
	mux.Handle("POST /api/v1/firewall/custom", auth(http.HandlerFunc(s.handleCreateCustomBlocklist)))
	mux.Handle("DELETE /api/v1/firewall/custom/{id}", auth(http.HandlerFunc(s.handleDeleteCustomBlocklist)))
	mux.Handle("GET /api/v1/settings/acl", auth(http.HandlerFunc(s.handleListACLRules)))
	mux.Handle("POST /api/v1/settings/acl", auth(http.HandlerFunc(s.handleCreateACLRule)))
	mux.Handle("PUT /api/v1/settings/acl/{id}", auth(http.HandlerFunc(s.handleUpdateACLRule)))
	mux.Handle("DELETE /api/v1/settings/acl/{id}", auth(http.HandlerFunc(s.handleDeleteACLRule)))
	mux.Handle("GET /api/v1/zones", auth(http.HandlerFunc(s.handleListZones)))
	mux.Handle("POST /api/v1/zones", auth(http.HandlerFunc(s.handleCreateZone)))
	mux.Handle("DELETE /api/v1/zones/{zone}", auth(http.HandlerFunc(s.handleDeleteZone)))
	mux.Handle("GET /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleListZoneRecords)))
	mux.Handle("GET /api/v1/zones/{zone}/dnssec", auth(http.HandlerFunc(s.handleGetZoneDNSSEC)))
	mux.Handle("POST /api/v1/zones/{zone}/dnssec/enable", auth(http.HandlerFunc(s.handleEnableZoneDNSSEC)))
	mux.Handle("POST /api/v1/zones/{zone}/dnssec/disable", auth(http.HandlerFunc(s.handleDisableZoneDNSSEC)))
	mux.Handle("POST /api/v1/zones/reload", auth(http.HandlerFunc(s.handleZonesReload)))
	mux.Handle("POST /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleCreateRecord)))
	mux.Handle("PUT /api/v1/zones/{zone}/records/{id}", auth(http.HandlerFunc(s.handleUpdateRecord)))
	mux.Handle("DELETE /api/v1/zones/{zone}/records/{id}", auth(http.HandlerFunc(s.handleDeleteRecord)))
	mux.Handle("DELETE /api/v1/zones/{zone}/records", auth(http.HandlerFunc(s.handleDeleteRecord)))
	mux.Handle("GET /api/v1/logs/history", auth(http.HandlerFunc(s.handleLogsHistory)))
	mux.Handle("GET /api/v1/logs/stream", bearerAuthOrQueryToken(cfg.API.AuthToken)(http.HandlerFunc(s.handleLogsStream)))
	mux.Handle("GET /api/v1/logs/config", auth(http.HandlerFunc(s.handleLogsConfigGet)))
	mux.Handle("PUT /api/v1/logs/config", auth(http.HandlerFunc(s.handleLogsConfigPut)))
	mux.Handle("GET /api/v1/config", auth(http.HandlerFunc(s.handleConfigGet)))
	mux.Handle("PUT /api/v1/config", auth(http.HandlerFunc(s.handleConfigPut)))
	mux.Handle("GET /api/v1/config/acl", auth(http.HandlerFunc(s.handleACLConfigGet)))
	mux.Handle("PUT /api/v1/config/acl", auth(http.HandlerFunc(s.handleACLConfigPut)))
	mux.Handle("GET /api/v1/config/rpz", auth(http.HandlerFunc(s.handleRPZConfigGet)))
	mux.Handle("PUT /api/v1/config/rpz", auth(http.HandlerFunc(s.handleRPZConfigPut)))
	mux.Handle("GET /api/v1/audit", auth(http.HandlerFunc(s.handleAuditList)))

	mux.HandleFunc("GET /{$}", handleWebUI)
	mux.HandleFunc("GET /{path...}", handleWebUI)

	s.server = &http.Server{
		Addr:    cfg.API.Listen,
		Handler: auditMiddleware(logger, telemetryDB)(mux),
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
