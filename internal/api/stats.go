package api

import (
	"net/http"
	"strings"
)

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.stats.Snapshot())
}

func (s *Server) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "telemetry database is not available")
		return
	}

	window := strings.TrimSpace(r.URL.Query().Get("range"))
	if window == "" {
		window = strings.TrimSpace(r.URL.Query().Get("window"))
	}
	if window == "" {
		window = "1h"
	}

	history, err := s.telemetryDB.QueryHistory(window)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, history)
}
