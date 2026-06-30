package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// RuntimeConfigurator applies non-critical configuration changes without a process restart.
type RuntimeConfigurator interface {
	Apply(cfg config.Config) error
}

type configUpdateResponse struct {
	Success         bool `json:"success"`
	RequiresRestart bool `json:"requires_restart"`
}

func (s *Server) currentConfig() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Server) setConfig(cfg config.Config) {
	s.cfgMu.Lock()
	s.cfg = cfg
	s.cfgMu.Unlock()
}

func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.currentConfig().ForAPIResponse())
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	if s.configPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "configuration path is not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var incoming config.Config
	if err := json.Unmarshal(body, &incoming); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	current := s.currentConfig()
	merged := config.MergeWithCurrent(current, incoming)

	prepared, err := config.PrepareForApply(merged)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	requiresRestart := config.RequiresRestart(current, prepared)

	if err := config.Write(s.configPath, prepared); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write configuration file")
		return
	}

	s.setConfig(prepared)

	if !requiresRestart && s.runtime != nil {
		if err := s.runtime.Apply(prepared); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, configUpdateResponse{
		Success:         true,
		RequiresRestart: requiresRestart,
	})
}
