package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/acl"
)

type aclRulesResponse struct {
	Rules []acl.Rule `json:"rules"`
}

type createACLRuleRequest struct {
	Subnet      string `json:"subnet"`
	Description string `json:"description,omitempty"`
}

type aclMutationResponse struct {
	Status  string    `json:"status"`
	Message string    `json:"message"`
	Rule    *acl.Rule `json:"rule,omitempty"`
}

func (s *Server) reloadQueryACL() {
	if s.queryACL == nil {
		return
	}
	if err := s.queryACL.Reload(); err != nil {
		s.logger.Warn("failed to reload query access ACL", "error", err)
	}
}

func (s *Server) handleListACLRules(w http.ResponseWriter, _ *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	rules, err := acl.ListRules(s.telemetryDB.Main())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list acl rules")
		return
	}
	if rules == nil {
		rules = []acl.Rule{}
	}

	writeJSON(w, http.StatusOK, aclRulesResponse{Rules: rules})
}

func (s *Server) handleCreateACLRule(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var in createACLRuleRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON payload")
		return
	}

	rule, err := acl.InsertRule(s.telemetryDB.Main(), in.Subnet, in.Description)
	if err != nil {
		switch {
		case errors.Is(err, acl.ErrInvalidSubnet):
			writeJSONError(w, http.StatusBadRequest, "invalid subnet; use an IP address or CIDR notation")
		case errors.Is(err, acl.ErrRuleAlreadyExists):
			writeJSONError(w, http.StatusConflict, "acl rule already exists")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to create acl rule")
		}
		return
	}

	s.reloadQueryACL()

	writeJSON(w, http.StatusCreated, aclMutationResponse{
		Status:  "ok",
		Message: "acl rule created",
		Rule:    &rule,
	})
}

func (s *Server) handleDeleteACLRule(w http.ResponseWriter, r *http.Request) {
	if s.telemetryDB == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid acl rule id")
		return
	}

	if err := acl.DeleteRule(s.telemetryDB.Main(), id); err != nil {
		switch {
		case errors.Is(err, acl.ErrRuleNotFound):
			writeJSONError(w, http.StatusNotFound, "acl rule not found")
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to delete acl rule")
		}
		return
	}

	s.reloadQueryACL()

	writeJSON(w, http.StatusOK, aclMutationResponse{
		Status:  "ok",
		Message: "acl rule deleted",
	})
}
