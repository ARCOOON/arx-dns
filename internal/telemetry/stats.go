package telemetry

import (
	"encoding/json"
	"sync/atomic"
)

// Stats holds lock-free operational counters for future JSON API exposure.
type Stats struct {
	totalQueries            atomic.Uint64
	udpQueries              atomic.Uint64
	tcpQueries              atomic.Uint64
	dotQueries              atomic.Uint64
	dohQueries              atomic.Uint64
	droppedPackets          atomic.Uint64
	parseErrors             atomic.Uint64
	writeErrors             atomic.Uint64
	refusedAnswers          atomic.Uint64
	authoritativeAnswers    atomic.Uint64
	nxdomainAnswers         atomic.Uint64
	forwardedQueries        atomic.Uint64
	upstreamFailures        atomic.Uint64
	cacheHits               atomic.Uint64
	cacheMisses             atomic.Uint64
	negativeCacheHits       atomic.Uint64
	aclRejected             atomic.Uint64
	truncatedResponses      atomic.Uint64
	tcpTimeouts             atomic.Uint64
	firewallBlocked         atomic.Uint64
	dnssecValidationsPassed atomic.Uint64
	dnssecValidationsFailed atomic.Uint64
	rrlDropped              atomic.Uint64
}

// New creates an initialized Stats instance.
func New() *Stats {
	return &Stats{}
}

// Snapshot is a point-in-time view of operational counters.
type Snapshot struct {
	TotalQueries            uint64 `json:"total_queries"`
	UDPQueries              uint64 `json:"udp_queries"`
	TCPQueries              uint64 `json:"tcp_queries"`
	DoTQueries              uint64 `json:"dot_queries"`
	DoHQueries              uint64 `json:"doh_queries"`
	DroppedPackets          uint64 `json:"dropped_packets"`
	ParseErrors             uint64 `json:"parse_errors"`
	WriteErrors             uint64 `json:"write_errors"`
	RefusedAnswers          uint64 `json:"refused_answers"`
	AuthoritativeAnswers    uint64 `json:"authoritative_answers"`
	NXDomainAnswers         uint64 `json:"nxdomain_answers"`
	ForwardedQueries        uint64 `json:"forwarded_queries"`
	UpstreamFailures        uint64 `json:"upstream_failures"`
	CacheHits               uint64 `json:"cache_hits"`
	CacheMisses             uint64 `json:"cache_misses"`
	NegativeCacheHits       uint64 `json:"negative_cache_hits"`
	ACLRejected             uint64 `json:"acl_rejected"`
	TruncatedResponses      uint64 `json:"truncated_responses"`
	TCPTimeouts             uint64 `json:"tcp_timeouts"`
	FirewallBlocked         uint64 `json:"firewall_blocked"`
	DNSSECValidationsPassed uint64 `json:"dnssec_validations_passed"`
	DNSSECValidationsFailed uint64 `json:"dnssec_validations_failed"`
	RRLDropped              uint64 `json:"rrl_dropped"`
}

// Snapshot returns the current counter values.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		TotalQueries:            s.totalQueries.Load(),
		UDPQueries:              s.udpQueries.Load(),
		TCPQueries:              s.tcpQueries.Load(),
		DoTQueries:              s.dotQueries.Load(),
		DoHQueries:              s.dohQueries.Load(),
		DroppedPackets:          s.droppedPackets.Load(),
		ParseErrors:             s.parseErrors.Load(),
		WriteErrors:             s.writeErrors.Load(),
		RefusedAnswers:          s.refusedAnswers.Load(),
		AuthoritativeAnswers:    s.authoritativeAnswers.Load(),
		NXDomainAnswers:         s.nxdomainAnswers.Load(),
		ForwardedQueries:        s.forwardedQueries.Load(),
		UpstreamFailures:        s.upstreamFailures.Load(),
		CacheHits:               s.cacheHits.Load(),
		CacheMisses:             s.cacheMisses.Load(),
		NegativeCacheHits:       s.negativeCacheHits.Load(),
		ACLRejected:             s.aclRejected.Load(),
		TruncatedResponses:      s.truncatedResponses.Load(),
		TCPTimeouts:             s.tcpTimeouts.Load(),
		FirewallBlocked:         s.firewallBlocked.Load(),
		DNSSECValidationsPassed: s.dnssecValidationsPassed.Load(),
		DNSSECValidationsFailed: s.dnssecValidationsFailed.Load(),
		RRLDropped:              s.rrlDropped.Load(),
	}
}

// MarshalJSON serializes the current snapshot.
func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Snapshot())
}

func (s *Stats) IncTotalQuery() {
	s.totalQueries.Add(1)
}

func (s *Stats) IncUDPQuery() {
	s.udpQueries.Add(1)
	s.IncTotalQuery()
}

func (s *Stats) IncTCPQuery() {
	s.tcpQueries.Add(1)
	s.IncTotalQuery()
}

func (s *Stats) IncDoTQuery() {
	s.dotQueries.Add(1)
	s.IncTotalQuery()
}

func (s *Stats) IncDoHQuery() {
	s.dohQueries.Add(1)
	s.IncTotalQuery()
}

func (s *Stats) IncDropped() {
	s.droppedPackets.Add(1)
}

func (s *Stats) IncParseError() {
	s.parseErrors.Add(1)
	s.IncDropped()
}

func (s *Stats) IncWriteError() {
	s.writeErrors.Add(1)
	s.IncDropped()
}

func (s *Stats) IncRefusedAnswer() {
	s.refusedAnswers.Add(1)
}

func (s *Stats) IncAuthoritativeAnswer() {
	s.authoritativeAnswers.Add(1)
}

func (s *Stats) IncNXDomainAnswer() {
	s.nxdomainAnswers.Add(1)
}

func (s *Stats) IncForwardedQuery() {
	s.forwardedQueries.Add(1)
}

func (s *Stats) IncUpstreamFailure() {
	s.upstreamFailures.Add(1)
}

func (s *Stats) IncCacheHit() {
	s.cacheHits.Add(1)
}

func (s *Stats) IncCacheMiss() {
	s.cacheMisses.Add(1)
}

func (s *Stats) IncNegativeCacheHit() {
	s.negativeCacheHits.Add(1)
}

func (s *Stats) IncACLRejected() {
	s.aclRejected.Add(1)
}

func (s *Stats) IncTruncatedResponse() {
	s.truncatedResponses.Add(1)
}

func (s *Stats) IncTCPTimeout() {
	s.tcpTimeouts.Add(1)
}

func (s *Stats) IncFirewallBlocked() {
	s.firewallBlocked.Add(1)
}

func (s *Stats) IncDNSSECValidationPassed() {
	s.dnssecValidationsPassed.Add(1)
}

func (s *Stats) IncDNSSECValidationFailed() {
	s.dnssecValidationsFailed.Add(1)
}

func (s *Stats) IncRRLDropped() {
	s.rrlDropped.Add(1)
}
