package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func auditMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost && r.Method != http.MethodDelete {
				next.ServeHTTP(w, r)
				return
			}

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			success := rec.status >= http.StatusOK && rec.status < http.StatusBadRequest
			logger.Info("api audit",
				"client_ip", clientIP(r),
				"zone", strings.TrimSpace(r.PathValue("zone")),
				"action", auditAction(r),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"success", success,
			)
		})
	}
}

func auditAction(r *http.Request) string {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/firewall/sync"):
		return "sync_blocklists"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/firewall/sources"):
		return "create_blocklist_source"
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/firewall/sources/"):
		return "delete_blocklist_source"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/records"):
		return "create_record"
	case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/records"):
		return "delete_record"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reload"):
		return "reload_zones"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/zones"):
		return "create_zone"
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/zones/") && !strings.Contains(r.URL.Path, "/records"):
		return "delete_zone"
	default:
		return strings.ToLower(r.Method) + " " + r.URL.Path
	}
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
