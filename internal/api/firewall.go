package api

import (
	"net/http"
)

type firewallStatusResponse struct {
	BlockedDomainsCount int `json:"blocked_domains_count"`
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	count := 0
	if s.firewall != nil {
		count = s.firewall.BlockedDomainsCount()
	}
	writeJSON(w, http.StatusOK, firewallStatusResponse{BlockedDomainsCount: count})
}
