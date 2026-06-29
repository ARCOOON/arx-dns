package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ARCOOON/arx-dns/internal/config"
)

// aclConfigPayload is the REST representation of the [acl] configuration section.
type aclConfigPayload struct {
	MatchLists     map[string][]string             `json:"match_lists"`
	AllowQuery     []string                        `json:"allow_query"`
	AllowRecursion []string                        `json:"allow_recursion"`
	AllowTransfer  []string                        `json:"allow_transfer"`
	Zones          map[string]zoneACLConfigPayload `json:"zones,omitempty"`
}

type zoneACLConfigPayload struct {
	AllowQuery     []string `json:"allow_query,omitempty"`
	AllowRecursion []string `json:"allow_recursion,omitempty"`
	AllowTransfer  []string `json:"allow_transfer,omitempty"`
}

func aclConfigFrom(cfg config.ACLConfig) aclConfigPayload {
	lists := cfg.Lists
	if lists == nil {
		lists = map[string][]string{}
	}
	zones := make(map[string]zoneACLConfigPayload, len(cfg.Zones))
	for apex, zoneCfg := range cfg.Zones {
		zones[apex] = zoneACLConfigPayload{
			AllowQuery:     append([]string(nil), zoneCfg.AllowQuery...),
			AllowRecursion: append([]string(nil), zoneCfg.AllowRecursion...),
			AllowTransfer:  append([]string(nil), zoneCfg.AllowTransfer...),
		}
	}
	return aclConfigPayload{
		MatchLists:     lists,
		AllowQuery:     append([]string(nil), cfg.AllowQuery...),
		AllowRecursion: append([]string(nil), cfg.AllowRecursion...),
		AllowTransfer:  append([]string(nil), cfg.AllowTransfer...),
		Zones:          zones,
	}
}

func (p aclConfigPayload) toConfig(current config.ACLConfig) config.ACLConfig {
	out := config.ACLConfig{
		Lists:          p.MatchLists,
		AllowQuery:     append([]string(nil), p.AllowQuery...),
		AllowRecursion: append([]string(nil), p.AllowRecursion...),
		AllowTransfer:  append([]string(nil), p.AllowTransfer...),
	}
	if p.MatchLists == nil {
		out.Lists = map[string][]string{}
	}
	if p.Zones != nil {
		out.Zones = make(map[string]config.ZoneACLConfig, len(p.Zones))
		for apex, zoneCfg := range p.Zones {
			out.Zones[apex] = config.ZoneACLConfig{
				AllowQuery:     append([]string(nil), zoneCfg.AllowQuery...),
				AllowRecursion: append([]string(nil), zoneCfg.AllowRecursion...),
				AllowTransfer:  append([]string(nil), zoneCfg.AllowTransfer...),
			}
		}
	} else {
		out.Zones = current.Zones
	}
	return out
}

func (s *Server) handleACLConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, aclConfigFrom(s.currentConfig().ACL))
}

func (s *Server) handleACLConfigPut(w http.ResponseWriter, r *http.Request) {
	if s.configPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "configuration path is not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var incoming aclConfigPayload
	if err := json.Unmarshal(body, &incoming); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	current := s.currentConfig()
	merged := current
	merged.ACL = incoming.toConfig(current.ACL)

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
