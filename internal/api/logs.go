package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/logger"
)

type logsHistoryResponse struct {
	Lines []string `json:"lines"`
}

type logsConfigResponse struct {
	Level    string                `json:"level"`
	Rotation logger.RotationConfig `json:"rotation"`
}

type logsConfigUpdateRequest struct {
	Level    string                `json:"level"`
	Rotation logger.RotationConfig `json:"rotation"`
}

func (s *Server) handleLogsHistory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, logsHistoryResponse{
		Lines: logger.History(),
	})
}

func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming is not supported by this server")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := logger.Subscribe()
	defer logger.Unsubscribe(ch)

	ctx := r.Context()
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-ctx.Done():
			return
		case line, open := <-ch:
			if !open {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleLogsConfigGet(w http.ResponseWriter, _ *http.Request) {
	cfg := logger.CurrentConfig()
	writeJSON(w, http.StatusOK, logsConfigResponse{
		Level:    cfg.Level,
		Rotation: cfg.Rotation,
	})
}

func (s *Server) handleLogsConfigPut(w http.ResponseWriter, r *http.Request) {
	var in logsConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	cfg := logger.Config{
		Level:    in.Level,
		Rotation: in.Rotation,
	}

	var dbErr error
	if s.telemetryDB != nil {
		dbErr = logger.UpdateConfig(s.telemetryDB.Main(), cfg)
	} else {
		dbErr = logger.UpdateConfig(nil, cfg)
	}
	if dbErr != nil {
		writeJSONError(w, http.StatusBadRequest, dbErr.Error())
		return
	}

	updated := logger.CurrentConfig()
	writeJSON(w, http.StatusOK, logsConfigResponse{
		Level:    updated.Level,
		Rotation: updated.Rotation,
	})
}

// bearerAuthOrQueryToken authenticates Bearer headers or ?token= for EventSource.
func bearerAuthOrQueryToken(token string) func(http.Handler) http.Handler {
	headerAuth := bearerAuth(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
				headerAuth(next).ServeHTTP(w, r)
				return
			}
			queryToken := strings.TrimSpace(r.URL.Query().Get("token"))
			if queryToken == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}
			r.Header.Set("Authorization", "Bearer "+queryToken)
			headerAuth(next).ServeHTTP(w, r)
		})
	}
}
