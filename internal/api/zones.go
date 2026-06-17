package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

type zonesListResponse struct {
	Zones []storage.ZoneInfo `json:"zones"`
}

type zoneRecordsResponse struct {
	Zone    string                    `json:"zone"`
	View    storage.ZoneView          `json:"view"`
	Records []storage.ZoneRecordEntry `json:"records"`
}

type recordResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
}

func (s *Server) handleListZones(w http.ResponseWriter, _ *http.Request) {
	zones := s.store.ListZones()
	writeJSON(w, http.StatusOK, zonesListResponse{Zones: zones})
}

func (s *Server) handleListZoneRecords(w http.ResponseWriter, r *http.Request) {
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

	records, err := s.store.ListZoneRecordEntries(zone, view)
	if err != nil {
		if errors.Is(err, storage.ErrZoneNotFound) {
			writeJSONError(w, http.StatusNotFound, "zone not found")
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, zoneRecordsResponse{
		Zone:    storage.NormalizeName(zone),
		View:    view,
		Records: records,
	})
}

func (s *Server) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if err := storage.ValidateZoneName(zone); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	in, err := decodeRecordInput(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	view, err := storage.ParseZoneView(in.View)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	rr, err := s.store.AddZoneRecord(s.cfg.Zones.Directory, zone, view, in)
	if err != nil {
		if errors.Is(err, storage.ErrZoneNotFound) {
			writeJSONError(w, http.StatusNotFound, "zone not found")
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	hdr := rr.Header()
	if s.notifier != nil {
		s.notifier.NotifyZone(zone)
	}
	writeJSON(w, http.StatusCreated, recordResponse{
		Status:  "created",
		Message: "record added",
		Name:    hdr.Name,
		Type:    strings.ToUpper(strings.TrimSpace(in.Type)),
	})
}

func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimSpace(r.PathValue("zone"))
	if err := storage.ValidateZoneName(zone); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	recordID := strings.TrimSpace(r.PathValue("id"))
	if recordID != "" {
		s.handleDeleteRecordByID(w, r, zone, recordID)
		return
	}

	in, err := decodeRecordInput(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	view, err := storage.ParseZoneView(in.View)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	err = s.store.DeleteZoneRecord(s.cfg.Zones.Directory, zone, view, in)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrZoneNotFound):
			writeJSONError(w, http.StatusNotFound, "zone not found")
		case errors.Is(err, storage.ErrRecordNotFound):
			writeJSONError(w, http.StatusNotFound, "record not found")
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if s.notifier != nil {
		s.notifier.NotifyZone(zone)
	}

	writeJSON(w, http.StatusOK, recordResponse{
		Status:  "deleted",
		Message: "record removed",
		Name:    in.Name,
		Type:    strings.ToUpper(strings.TrimSpace(in.Type)),
	})
}

func (s *Server) handleDeleteRecordByID(w http.ResponseWriter, r *http.Request, zone, recordID string) {
	view, err := storage.ParseZoneView(r.URL.Query().Get("view"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	err = s.store.DeleteZoneRecordByID(s.cfg.Zones.Directory, zone, view, recordID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrZoneNotFound):
			writeJSONError(w, http.StatusNotFound, "zone not found")
		case errors.Is(err, storage.ErrRecordNotFound):
			writeJSONError(w, http.StatusNotFound, "record not found")
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if s.notifier != nil {
		s.notifier.NotifyZone(zone)
	}

	writeJSON(w, http.StatusOK, recordResponse{
		Status:  "deleted",
		Message: "record removed",
	})
}

func decodeRecordInput(body io.Reader) (storage.RecordInput, error) {
	var in storage.RecordInput
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		return storage.RecordInput{}, errors.New("malformed JSON payload")
	}
	if strings.TrimSpace(in.Name) == "" {
		return storage.RecordInput{}, errors.New("record name is required")
	}
	if strings.TrimSpace(in.Type) == "" {
		return storage.RecordInput{}, errors.New("record type is required")
	}
	return in, nil
}
