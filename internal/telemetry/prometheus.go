package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsNamespace = "arxdns"

type counterSpec struct {
	name string
	help string
	load func(Snapshot) float64
}

// StatsCollector exposes lock-free Stats counters to Prometheus on scrape.
type StatsCollector struct {
	stats      *Stats
	descs      map[string]*prometheus.Desc
	specs      []counterSpec
	gaugeSpecs []counterSpec
}

// NewStatsCollector returns a Prometheus collector that reads atomic counters
// from stats only when Prometheus scrapes the /metrics endpoint.
func NewStatsCollector(stats *Stats) *StatsCollector {
	if stats == nil {
		stats = New()
	}

	specs := []counterSpec{
		{name: "queries_total", help: "Total number of DNS queries processed.", load: func(s Snapshot) float64 { return float64(s.TotalQueries) }},
		{name: "udp_queries_total", help: "Total number of DNS queries received over UDP.", load: func(s Snapshot) float64 { return float64(s.UDPQueries) }},
		{name: "tcp_queries_total", help: "Total number of DNS queries received over TCP.", load: func(s Snapshot) float64 { return float64(s.TCPQueries) }},
		{name: "dot_queries_total", help: "Total number of DNS queries received over DNS-over-TLS.", load: func(s Snapshot) float64 { return float64(s.DoTQueries) }},
		{name: "doh_queries_total", help: "Total number of DNS queries received over DNS-over-HTTPS.", load: func(s Snapshot) float64 { return float64(s.DoHQueries) }},
		{name: "dropped_packets_total", help: "Total number of dropped packets (parse failures, invalid frames, write errors).", load: func(s Snapshot) float64 { return float64(s.DroppedPackets) }},
		{name: "parse_errors_total", help: "Total number of DNS message parse failures.", load: func(s Snapshot) float64 { return float64(s.ParseErrors) }},
		{name: "write_errors_total", help: "Total number of DNS response write failures.", load: func(s Snapshot) float64 { return float64(s.WriteErrors) }},
		{name: "refused_answers_total", help: "Total number of REFUSED DNS responses sent.", load: func(s Snapshot) float64 { return float64(s.RefusedAnswers) }},
		{name: "authoritative_answers_total", help: "Total number of authoritative NOERROR or NODATA responses sent.", load: func(s Snapshot) float64 { return float64(s.AuthoritativeAnswers) }},
		{name: "nxdomain_answers_total", help: "Total number of NXDOMAIN DNS responses sent.", load: func(s Snapshot) float64 { return float64(s.NXDomainAnswers) }},
		{name: "forwarded_queries_total", help: "Total number of recursive queries forwarded upstream.", load: func(s Snapshot) float64 { return float64(s.ForwardedQueries) }},
		{name: "local_queries_total", help: "Total number of queries answered locally (cache, zone data, or AD optimization).", load: func(s Snapshot) float64 { return float64(s.LocalQueries) }},
		{name: "upstream_queries_total", help: "Total number of recursive queries handed off to a forwarder or iterative resolver.", load: func(s Snapshot) float64 { return float64(s.UpstreamQueries) }},
		{name: "upstream_failures_total", help: "Total number of recursive queries where all upstreams failed.", load: func(s Snapshot) float64 { return float64(s.UpstreamFailures) }},
		{name: "cache_hits_total", help: "Total number of forwarded queries served from the response cache.", load: func(s Snapshot) float64 { return float64(s.CacheHits) }},
		{name: "cache_misses_total", help: "Total number of forwarded queries that missed the response cache.", load: func(s Snapshot) float64 { return float64(s.CacheMisses) }},
		{name: "negative_cache_hits_total", help: "Total number of forwarded NXDOMAIN or NODATA answers served from the response cache.", load: func(s Snapshot) float64 { return float64(s.NegativeCacheHits) }},
		{name: "acl_rejected_total", help: "Total number of recursive queries denied because the client IP is untrusted.", load: func(s Snapshot) float64 { return float64(s.ACLRejected) }},
		{name: "refused_queries_total", help: "Total number of DNS queries refused by the query access ACL.", load: func(s Snapshot) float64 { return float64(s.RefusedQueries) }},
		{name: "truncated_responses_total", help: "Total number of UDP responses truncated with the TC bit set.", load: func(s Snapshot) float64 { return float64(s.TruncatedResponses) }},
		{name: "tcp_timeouts_total", help: "Total number of TCP connections closed due to read-frame timeout.", load: func(s Snapshot) float64 { return float64(s.TCPTimeouts) }},
		{name: "firewall_blocked_total", help: "Total number of queries blocked by the DNS firewall blocklist engine.", load: func(s Snapshot) float64 { return float64(s.FirewallBlocked) }},
		{name: "rpz_matched_total", help: "Total number of queries matched by the Response Policy Zone engine.", load: func(s Snapshot) float64 { return float64(s.RPZMatched) }},
		{name: "dnssec_validations_passed_total", help: "Total number of forwarded upstream responses that passed DNSSEC signature verification.", load: func(s Snapshot) float64 { return float64(s.DNSSECValidationsPassed) }},
		{name: "dnssec_validations_failed_total", help: "Total number of forwarded upstream responses rejected as BOGUS after DNSSEC checks.", load: func(s Snapshot) float64 { return float64(s.DNSSECValidationsFailed) }},
		{name: "rrl_dropped_total", help: "Total number of DNS queries silently dropped by response rate limiting.", load: func(s Snapshot) float64 { return float64(s.RRLDropped) }},
		{name: "cookies_verified_total", help: "Total number of DNS queries with a valid client and server cookie pair.", load: func(s Snapshot) float64 { return float64(s.CookiesVerified) }},
		{name: "cookies_rejected_total", help: "Total number of DNS queries rejected with BADCOOKIE due to an invalid server cookie.", load: func(s Snapshot) float64 { return float64(s.CookiesRejected) }},
		{name: "ecs_queries_forwarded_total", help: "Total number of recursive queries forwarded upstream with an EDNS Client Subnet option.", load: func(s Snapshot) float64 { return float64(s.ECSQueriesForwarded) }},
		{name: "xfr_completed_total", help: "Total number of completed AXFR or IXFR-downgraded zone transfers.", load: func(s Snapshot) float64 { return float64(s.XFRCompleted) }},
		{name: "xfr_refused_total", help: "Total number of refused or unauthorized zone transfer attempts.", load: func(s Snapshot) float64 { return float64(s.XFRRefused) }},
		{name: "notify_sent_total", help: "Total number of RFC 1996 NOTIFY messages sent to slaves.", load: func(s Snapshot) float64 { return float64(s.NotifySent) }},
		{name: "notify_failed_total", help: "Total number of failed NOTIFY delivery attempts.", load: func(s Snapshot) float64 { return float64(s.NotifyFailed) }},
		{name: "qname_min_fallbacks_total", help: "Total number of iterative queries that fell back from QNAME minimization to the full QNAME.", load: func(s Snapshot) float64 { return float64(s.QNameMinFallbacks) }},
	}

	gaugeSpecs := []counterSpec{
		{name: "rtt_tracked_ips", help: "Current number of upstream nameserver IPs tracked in the RTT registry.", load: func(s Snapshot) float64 { return float64(s.RTTTrackedIPs) }},
	}

	descs := make(map[string]*prometheus.Desc, len(specs)+len(gaugeSpecs))
	for _, spec := range specs {
		descs[spec.name] = prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "", spec.name),
			spec.help,
			nil,
			nil,
		)
	}
	for _, spec := range gaugeSpecs {
		descs[spec.name] = prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "", spec.name),
			spec.help,
			nil,
			nil,
		)
	}

	return &StatsCollector{
		stats:      stats,
		descs:      descs,
		specs:      specs,
		gaugeSpecs: gaugeSpecs,
	}
}

// Describe implements prometheus.Collector.
func (c *StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, spec := range c.specs {
		ch <- c.descs[spec.name]
	}
	for _, spec := range c.gaugeSpecs {
		ch <- c.descs[spec.name]
	}
}

// Collect implements prometheus.Collector. Counter values are read from atomic
// storage only at scrape time so the DNS hot path stays lock-free.
func (c *StatsCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.stats.Snapshot()
	for _, spec := range c.specs {
		ch <- prometheus.MustNewConstMetric(
			c.descs[spec.name],
			prometheus.CounterValue,
			spec.load(snap),
		)
	}
	for _, spec := range c.gaugeSpecs {
		ch <- prometheus.MustNewConstMetric(
			c.descs[spec.name],
			prometheus.GaugeValue,
			spec.load(snap),
		)
	}
}

// MetricsHandler returns an HTTP handler that serves Prometheus metrics for stats.
func MetricsHandler(stats *Stats) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStatsCollector(stats))
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
