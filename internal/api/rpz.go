package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// rpzPolicyPayload is one RPZ policy in REST form (domain maps to TOML pattern).
type rpzPolicyPayload struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
}

// rpzConfigPayload is the REST representation of the [rpz] configuration section.
type rpzConfigPayload struct {
	Enabled  bool               `json:"enabled"`
	Policies []rpzPolicyPayload `json:"policies"`
}

func rpzConfigFrom(cfg config.RPZConfig) rpzConfigPayload {
	policies := make([]rpzPolicyPayload, 0, len(cfg.Policies))
	for _, policy := range cfg.Policies {
		policies = append(policies, rpzPolicyPayload{
			Domain: policy.Pattern,
			Action: policy.Action,
			Target: policy.Target,
		})
	}
	if policies == nil {
		policies = []rpzPolicyPayload{}
	}
	return rpzConfigPayload{
		Enabled:  cfg.Enabled,
		Policies: policies,
	}
}

func (p rpzConfigPayload) toConfig() config.RPZConfig {
	policies := make([]config.RPZPolicyConfig, 0, len(p.Policies))
	for _, policy := range p.Policies {
		policies = append(policies, config.RPZPolicyConfig{
			Pattern: policy.Domain,
			Action:  policy.Action,
			Target:  policy.Target,
		})
	}
	return config.RPZConfig{
		Enabled:  p.Enabled,
		Policies: policies,
	}
}

func (s *Server) handleRPZConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, rpzConfigFrom(s.currentConfig().RPZ))
}

func (s *Server) handleRPZConfigPut(w http.ResponseWriter, r *http.Request) {
	if s.configPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "configuration path is not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var incoming rpzConfigPayload
	if err := json.Unmarshal(body, &incoming); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	current := s.currentConfig()
	merged := current
	merged.RPZ = incoming.toConfig()

	prepared, err := config.PrepareForApply(merged)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := config.Write(s.configPath, prepared); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write configuration file")
		return
	}

	s.setConfig(prepared)

	if s.runtime != nil {
		if err := s.runtime.Apply(prepared); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, configUpdateResponse{
		Success:         true,
		RequiresRestart: false,
	})
}
