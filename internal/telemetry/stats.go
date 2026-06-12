package telemetry

import (
	"encoding/json"
	"sync/atomic"
)

// Stats holds lock-free operational counters for future JSON API exposure.
type Stats struct {
	totalQueries         atomic.Uint64
	udpQueries           atomic.Uint64
	tcpQueries           atomic.Uint64
	droppedPackets       atomic.Uint64
	parseErrors          atomic.Uint64
	writeErrors          atomic.Uint64
	refusedAnswers       atomic.Uint64
	authoritativeAnswers atomic.Uint64
	nxdomainAnswers      atomic.Uint64
}

// New creates an initialized Stats instance.
func New() *Stats {
	return &Stats{}
}

// Snapshot is a point-in-time view of operational counters.
type Snapshot struct {
	TotalQueries         uint64 `json:"total_queries"`
	UDPQueries           uint64 `json:"udp_queries"`
	TCPQueries           uint64 `json:"tcp_queries"`
	DroppedPackets       uint64 `json:"dropped_packets"`
	ParseErrors          uint64 `json:"parse_errors"`
	WriteErrors          uint64 `json:"write_errors"`
	RefusedAnswers       uint64 `json:"refused_answers"`
	AuthoritativeAnswers uint64 `json:"authoritative_answers"`
	NXDomainAnswers      uint64 `json:"nxdomain_answers"`
}

// Snapshot returns the current counter values.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		TotalQueries:         s.totalQueries.Load(),
		UDPQueries:           s.udpQueries.Load(),
		TCPQueries:           s.tcpQueries.Load(),
		DroppedPackets:       s.droppedPackets.Load(),
		ParseErrors:          s.parseErrors.Load(),
		WriteErrors:          s.writeErrors.Load(),
		RefusedAnswers:       s.refusedAnswers.Load(),
		AuthoritativeAnswers: s.authoritativeAnswers.Load(),
		NXDomainAnswers:      s.nxdomainAnswers.Load(),
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
