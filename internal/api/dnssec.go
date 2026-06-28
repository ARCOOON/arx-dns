package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/dnssec"
	"github.com/ARCOOON/arx-dns/internal/storage"
)

type dnssecStatusResponse struct {
	Enabled   bool   `json:"enabled"`
	Zone      string `json:"zone"`
	View      string `json:"view"`
	Algorithm uint8  `json:"algorithm,omitempty"`
	KSKTag    uint16 `json:"ksk_tag,omitempty"`
	ZSKTag    uint16 `json:"zsk_tag,omitempty"`
	DS        string `json:"ds,omitempty"`
}

type dnssecZoneRequest struct {
	View string `json:"view,omitempty"`
}

func (s *Server) handleGetZoneDNSSEC(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if err := storage.ValidateZoneName(zone); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	view, err := storage.ParseZoneView(r.URL.Query().Get("view"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !s.store.ZoneExists(zone, view) {
		writeJSONError(w, http.StatusNotFound, "zone not found")
		return
	}

	status, err := s.store.DNSSECStatus(zone, view)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, toDNSSECResponse(status))
}

func (s *Server) handleEnableZoneDNSSEC(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if err := storage.ValidateZoneName(zone); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var in dnssecZoneRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
			return
		}
	}

	view, err := storage.ParseZoneView(in.View)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, err := s.store.EnableDNSSEC(s.cfg.Zones.Directory, zone, view)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrZoneNotFound):
			writeJSONError(w, http.StatusNotFound, "zone not found")
		case strings.Contains(err.Error(), "dnssec is not configured"):
			writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if s.notifier != nil {
		s.notifier.NotifyZone(storage.NormalizeName(zone))
	}

	writeJSON(w, http.StatusOK, toDNSSECResponse(status))
}

func (s *Server) handleDisableZoneDNSSEC(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if err := storage.ValidateZoneName(zone); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var in dnssecZoneRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
			return
		}
	}

	view, err := storage.ParseZoneView(in.View)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, err := s.store.DisableDNSSEC(s.cfg.Zones.Directory, zone, view)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrZoneNotFound):
			writeJSONError(w, http.StatusNotFound, "zone not found")
		case strings.Contains(err.Error(), "dnssec is not configured"):
			writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if s.notifier != nil {
		s.notifier.NotifyZone(storage.NormalizeName(zone))
	}

	writeJSON(w, http.StatusOK, toDNSSECResponse(status))
}

func toDNSSECResponse(status dnssec.Status) dnssecStatusResponse {
	return dnssecStatusResponse{
		Enabled:   status.Enabled,
		Zone:      status.Zone,
		View:      status.View,
		Algorithm: status.Algorithm,
		KSKTag:    status.KSKTag,
		ZSKTag:    status.ZSKTag,
		DS:        status.DS,
	}
}
