package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid limit parameter")
			return
		}
		limit = parsed
	}

	logs, err := s.telemetryDB.ListAuditLogs(limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}
	if logs == nil {
		logs = []telemetry.AuditLog{}
	}

	writeJSON(w, http.StatusOK, telemetry.AuditResponse{Logs: logs})
}

func auditMiddleware(logger *slog.Logger, db *telemetry.DB) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldAuditRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			recordType := ""
			if shouldInspectBody(r) {
				recordType = extractRecordType(readAndRestoreBody(r))
			}

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			success := rec.status >= http.StatusOK && rec.status < http.StatusBadRequest
			action := auditAction(r)
			target := auditTarget(r)
			details := auditDetails(r, rec.status, success, recordType)

			logger.Info("api audit",
				"client_ip", clientIP(r),
				"zone", target,
				"action", action,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"success", success,
			)

			if db != nil {
				if err := db.InsertAuditLog(clientIP(r), action, target, details, r.Method, r.URL.Path, rec.status, success); err != nil {
					logger.Warn("failed to persist audit log", "error", err)
				}
			}
		})
	}
}

func shouldAuditRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/api/v1/")
}

func auditAction(r *http.Request) string {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/firewall/sync"):
		return "sync_blocklists"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/firewall/sources"):
		return "create_blocklist_source"
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/firewall/sources/"):
		return "delete_blocklist_source"
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v1/firewall/sources/"):
		return "update_blocklist_source"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/records"):
		return "create_record"
	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/records"):
		return "update_record"
	case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/records"):
		return "delete_record"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reload"):
		return "reload_zones"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/zones"):
		return "create_zone"
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/zones/") && !strings.Contains(r.URL.Path, "/records"):
		return "delete_zone"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/settings/acl"):
		return "create_acl_rule"
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/settings/acl/"):
		return "update_acl_rule"
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/settings/acl/"):
		return "delete_acl_rule"
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/config":
		return "update_config"
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/logs/config":
		return "update_log_config"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dnssec/enable"):
		return "enable_dnssec"
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dnssec/disable"):
		return "disable_dnssec"
	default:
		return strings.ToLower(r.Method) + " " + r.URL.Path
	}
}

func auditTarget(r *http.Request) string {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if zone != "" {
		return zone
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id != "" {
		return id
	}
	return ""
}

func auditDetails(r *http.Request, status int, success bool, recordType string) string {
	details := fmt.Sprintf("method=%s path=%s status=%d success=%t", r.Method, r.URL.Path, status, success)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType != "" {
		details += " type=" + recordType
	}
	return details
}

func shouldInspectBody(r *http.Request) bool {
	if r == nil || r.Body == nil {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut:
	default:
		return false
	}
	return strings.Contains(r.URL.Path, "/records")
}

func readAndRestoreBody(r *http.Request) []byte {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body
}

func extractRecordType(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var payload struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(payload.Type))
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
