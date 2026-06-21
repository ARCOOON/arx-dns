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
	BlockedDomainsCount int  `json:"blocked_domains_count"`
	SyncInProgress      bool `json:"sync_in_progress"`
}

type blocklistSourcesResponse struct {
	Sources []firewall.BlocklistSource `json:"sources"`
}

type createBlocklistSourceRequest struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

type patchBlocklistSourceRequest struct {
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
}

type blocklistMutationResponse struct {
	Status  string                         `json:"status"`
	Message string                         `json:"message"`
	Source  *firewall.BlocklistSource      `json:"source,omitempty"`
	Entry   *firewall.CustomBlocklistEntry `json:"entry,omitempty"`
}

type customBlocklistResponse struct {
	Domains []firewall.CustomBlocklistEntry `json:"domains"`
}

type createCustomBlocklistRequest struct {
	Domain string `json:"domain"`
}

func (s *Server) reloadFirewallBlocklists() {
	if s.firewall == nil || s.telemetryDB == nil {
		return
	}
	firewall.LoadFromDirWithDB(s.cfg.Firewall.BlocklistsDirectory, s.telemetryDB.Main(), s.firewall, s.logger)
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	count := 0
	if s.firewall != nil {
		count = s.firewall.BlockedDomainsCount()
	}
	writeJSON(w, http.StatusOK, firewallStatusResponse{
		BlockedDomainsCount: count,
		SyncInProgress:      firewall.SyncInProgress(),
	})
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

	source, err := firewall.InsertBlocklistSource(s.telemetryDB.Main(), in.URL, in.Description)
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

func (s *Server) handlePatchBlocklistSource(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid blocklist source id")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var in patchBlocklistSourceRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}
	if in.Enabled == nil && in.Description == nil {
		writeJSONError(w, http.StatusBadRequest, "at least one of enabled or description is required")
		return
	}

	source, err := firewall.UpdateBlocklistSource(s.telemetryDB.Main(), id, firewall.UpdateBlocklistSourceInput{
		Enabled:     in.Enabled,
		Description: in.Description,
	})
	if err != nil {
		switch {
		case errors.Is(err, firewall.ErrSourceNotFound):
			writeJSONError(w, http.StatusNotFound, "blocklist source not found")
		default:
			if strings.Contains(err.Error(), "no fields to update") {
				writeJSONError(w, http.StatusBadRequest, "at least one of enabled or description is required")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to update blocklist source")
		}
		return
	}

	s.reloadFirewallBlocklists()

	writeJSON(w, http.StatusOK, blocklistMutationResponse{
		Status:  "ok",
		Message: "blocklist source updated",
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

func (s *Server) handleListCustomBlocklist(w http.ResponseWriter, _ *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	domains, err := firewall.ListCustomBlocklistDomains(s.telemetryDB.Main())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list custom blocklist domains")
		return
	}
	if domains == nil {
		domains = []firewall.CustomBlocklistEntry{}
	}

	writeJSON(w, http.StatusOK, customBlocklistResponse{Domains: domains})
}

func (s *Server) handleCreateCustomBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var in createCustomBlocklistRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	entry, err := firewall.InsertCustomBlocklistDomain(s.telemetryDB.Main(), in.Domain)
	if err != nil {
		switch {
		case errors.Is(err, firewall.ErrInvalidCustomDomain):
			writeJSONError(w, http.StatusBadRequest, "invalid custom blocklist domain")
		case errors.Is(err, firewall.ErrCustomDomainAlreadyExists):
			writeJSONError(w, http.StatusConflict, "custom blocklist domain already exists")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to create custom blocklist domain")
		}
		return
	}

	s.reloadFirewallBlocklists()

	writeJSON(w, http.StatusCreated, blocklistMutationResponse{
		Status:  "ok",
		Message: "custom blocklist domain created",
		Entry:   &entry,
	})
}

func (s *Server) handleDeleteCustomBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid custom blocklist domain id")
		return
	}

	if err := firewall.DeleteCustomBlocklistDomain(s.telemetryDB.Main(), id); err != nil {
		switch {
		case errors.Is(err, firewall.ErrCustomDomainNotFound):
			writeJSONError(w, http.StatusNotFound, "custom blocklist domain not found")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to delete custom blocklist domain")
		}
		return
	}

	s.reloadFirewallBlocklists()

	writeJSON(w, http.StatusOK, blocklistMutationResponse{
		Status:  "ok",
		Message: "custom blocklist domain deleted",
	})
}
