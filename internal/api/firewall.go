package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/firewall"
)

type firewallStatusResponse struct {
	BlockedDomainsCount int `json:"blocked_domains_count"`
}

type blocklistSourcesResponse struct {
	Sources []firewall.BlocklistSource `json:"sources"`
}

type createBlocklistSourceRequest struct {
	URL string `json:"url"`
}

type blocklistMutationResponse struct {
	Status  string                    `json:"status"`
	Message string                    `json:"message"`
	Source  *firewall.BlocklistSource `json:"source,omitempty"`
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	count := 0
	if s.firewall != nil {
		count = s.firewall.BlockedDomainsCount()
	}
	writeJSON(w, http.StatusOK, firewallStatusResponse{BlockedDomainsCount: count})
}

func (s *Server) handleListBlocklistSources(w http.ResponseWriter, _ *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	sources, err := firewall.ListBlocklistSources(s.telemetryDB.Main())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list blocklist sources")
		return
	}
	if sources == nil {
		sources = []firewall.BlocklistSource{}
	}

	writeJSON(w, http.StatusOK, blocklistSourcesResponse{Sources: sources})
}

func (s *Server) handleCreateBlocklistSource(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var in createBlocklistSourceRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	source, err := firewall.InsertBlocklistSource(s.telemetryDB.Main(), in.URL)
	if err != nil {
		switch {
		case errors.Is(err, firewall.ErrInvalidSourceURL):
			writeJSONError(w, http.StatusBadRequest, "invalid blocklist source URL")
		case errors.Is(err, firewall.ErrSourceAlreadyExists):
			writeJSONError(w, http.StatusConflict, "blocklist source already exists")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to create blocklist source")
		}
		return
	}

	writeJSON(w, http.StatusCreated, blocklistMutationResponse{
		Status:  "ok",
		Message: "blocklist source created",
		Source:  &source,
	})
}

func (s *Server) handleDeleteBlocklistSource(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid blocklist source id")
		return
	}

	if err := firewall.DeleteBlocklistSource(s.telemetryDB.Main(), id); err != nil {
		switch {
		case errors.Is(err, firewall.ErrSourceNotFound):
			writeJSONError(w, http.StatusNotFound, "blocklist source not found")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to delete blocklist source")
		}
		return
	}

	writeJSON(w, http.StatusOK, blocklistMutationResponse{
		Status:  "ok",
		Message: "blocklist source deleted",
	})
}

func (s *Server) handleFirewallSync(w http.ResponseWriter, _ *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	if !firewall.StartBlocklistSync(
		s.telemetryDB.Main(),
		s.cfg.Firewall.BlocklistsDirectory,
		s.firewall,
		s.logger,
	) {
		writeJSONError(w, http.StatusConflict, "blocklist sync already in progress")
		return
	}

	s.logger.Info("blocklist sync triggered",
		"directory", s.cfg.Firewall.BlocklistsDirectory,
		"trigger", "api",
	)

	writeJSON(w, http.StatusAccepted, blocklistMutationResponse{
		Status:  "ok",
		Message: "blocklist sync started",
	})
}
