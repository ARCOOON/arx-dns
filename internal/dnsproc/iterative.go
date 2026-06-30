package dnsproc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	defaultIterativeTimeout = 2 * time.Second
	maxIterativeDepth       = 15
)

// ErrIterativeDepthExceeded is returned when iterative resolution exceeds the depth limit.
var ErrIterativeDepthExceeded = errors.New("iterative resolution depth exceeded")

// IterativeResolver resolves queries by walking delegations from root hints with RD=0.
type IterativeResolver struct {
	rootHints         []string
	client            *mdns.Client
	stats             *telemetry.Stats
	rtt               *RTTRegistry
	dnssecValidation  bool
	qnameMinimization bool
	maxDepth          int
	logger            *slog.Logger
}

// NewIterativeFromConfig builds an iterative resolver using dynamically loaded root hints.
func NewIterativeFromConfig(cfg config.Config, rootHints []string, stats *telemetry.Stats, logger *slog.Logger) (*IterativeResolver, error) {
	hints, err := NormalizeUpstreams(rootHints)
	if err != nil {
		return nil, fmt.Errorf("root hints: %w", err)
	}
	r := NewIterativeResolver(hints, stats, logger)
	r.dnssecValidation = cfg.Security.DNSSECValidation
	r.qnameMinimization = cfg.Resolver.QNameMinimization
	return r, nil
}

// NewIterativeResolver creates an iterative resolver using the given root hint addresses.
func NewIterativeResolver(rootHints []string, stats *telemetry.Stats, logger *slog.Logger) *IterativeResolver {
	addrs := make([]string, len(rootHints))
	copy(addrs, rootHints)

	return &IterativeResolver{
		rootHints: addrs,
		client: &mdns.Client{
			Net:     "udp",
			UDPSize: defaultClientUDPSize,
			Timeout: defaultIterativeTimeout,
		},
		stats:    stats,
		rtt:      DefaultRTTRegistry(stats),
		maxDepth: maxIterativeDepth,
		logger:   logger,
	}
}

// SetDNSSECValidation enables or disables the EDNS DO bit on iterative queries.
func (r *IterativeResolver) SetDNSSECValidation(enabled bool) {
	if r != nil {
		r.dnssecValidation = enabled
	}
}

// ECSCacheContext returns an empty ECS context; iterative resolution does not forward ECS.
func (r *IterativeResolver) ECSCacheContext(_ netip.Addr) storage.ECSContext {
	return storage.ECSContext{}
}

// Exchange resolves req iteratively from a random root hint server.
func (r *IterativeResolver) Exchange(req *mdns.Msg, _ netip.Addr) (*mdns.Msg, error) {
	if r == nil || len(r.rootHints) == 0 {
		return nil, errors.New("iterative resolver is not configured")
	}
	if req == nil || len(req.Question) == 0 {
		return nil, errors.New("query has no question section")
	}

	q := req.Question[0]
	if r.stats != nil {
		r.stats.IncForwardedQuery()
	}

	minLabels := 0
	if r.qnameMinimization {
		minLabels = 1
	}

	resp, err := r.resolve(q.Name, q.Qtype, q.Qclass, r.pickRoot(), 0, minLabels)
	if err != nil {
		if r.stats != nil {
			r.stats.IncUpstreamFailure()
		}
		return nil, err
	}
	return resp, nil
}

func (r *IterativeResolver) resolve(name string, qtype, qclass uint16, servers []string, depth int, minLabels int) (*mdns.Msg, error) {
	if depth >= r.maxDepth {
		return nil, ErrIterativeDepthExceeded
	}
	if len(servers) == 0 {
		return nil, errors.New("no nameservers available for iterative query")
	}

	current := mdns.Fqdn(name)
	for cnameSteps := 0; cnameSteps < maxCNAMEChainDepth; cnameSteps++ {
		queryName, queryType, minimized := r.delegationQueryParams(current, qtype, minLabels)
		if r.logger != nil {
			r.logger.Debug("iterative delegation step",
				"depth", depth,
				"target_qname", current,
				"query_qname", queryName,
				"query_qtype", mdns.TypeToString[queryType],
				"qname_minimized", minimized,
				"nameservers", servers,
			)
		}
		req := r.buildQuery(queryName, queryType, qclass)
		resp, err := r.queryDelegation(req, current, qtype, qclass, servers, minimized)
		if err != nil {
			return nil, err
		}

		if final, ok := r.responseMatchesQuery(resp, current, qtype); ok {
			return final, nil
		}

		if r.isNegative(resp) {
			return resp, nil
		}

		if target, ok := r.cnameTarget(resp, current); ok {
			current = mdns.Fqdn(target)
			servers = r.pickRoot()
			if r.qnameMinimization {
				minLabels = 1
			} else {
				minLabels = 0
			}
			continue
		}

		nsHosts := r.referralNS(resp)
		if len(nsHosts) == 0 {
			return nil, fmt.Errorf("no answer or referral from nameservers %v", servers)
		}

		next := r.glueAddrs(resp, nsHosts)
		if len(next) == 0 {
			next, err = r.resolveGlue(nsHosts, depth+1)
			if err != nil {
				return nil, err
			}
		}
		next = r.sortServers(next)

		nextMinLabels := minLabels
		if minimized {
			nextMinLabels = minLabels + 1
		}
		return r.resolve(current, qtype, qclass, next, depth+1, nextMinLabels)
	}

	return nil, ErrIterativeDepthExceeded
}

// delegationQueryParams returns the QNAME and QTYPE for a delegation-walk query.
// When QNAME minimization is active and minLabels reveals fewer labels than the
// target name, the query uses QTYPE NS per RFC 7816.
func (r *IterativeResolver) delegationQueryParams(target string, qtype uint16, minLabels int) (string, uint16, bool) {
	target = mdns.Fqdn(target)
	if !r.qnameMinimization || minLabels <= 0 {
		return target, qtype, false
	}

	total := qnameLabelCount(target)
	if minLabels >= total {
		return target, qtype, false
	}

	return minimizedQName(target, minLabels), mdns.TypeNS, true
}

func qnameLabelCount(fqdn string) int {
	return len(mdns.SplitDomainName(mdns.Fqdn(fqdn)))
}

func minimizedQName(fqdn string, labelCount int) string {
	labels := mdns.SplitDomainName(mdns.Fqdn(fqdn))
	if labelCount <= 0 || labelCount >= len(labels) {
		return mdns.Fqdn(fqdn)
	}
	start := len(labels) - labelCount
	return mdns.Fqdn(strings.Join(labels[start:], "."))
}

func (r *IterativeResolver) queryDelegation(req *mdns.Msg, fullName string, qtype, qclass uint16, servers []string, minimized bool) (*mdns.Msg, error) {
	resp, lastServer, err := r.queryServers(req, servers)
	if !minimized {
		return resp, err
	}
	if err != nil || needsQNameMinFallback(resp) {
		if r.stats != nil {
			r.stats.IncQNameMinFallback()
		}
		if r.logger != nil {
			reason := "servfail_or_refused"
			if err != nil {
				reason = "timeout_or_error"
			}
			minimizedQNAME := ""
			if req != nil && len(req.Question) > 0 {
				minimizedQNAME = req.Question[0].Name
			}
			r.logger.Warn("qname minimization fallback to full qname",
				"full_qname", mdns.Fqdn(fullName),
				"minimized_qname", minimizedQNAME,
				"server", lastServer,
				"reason", reason,
				"error", err,
				"rcode", dnsRcodeString(resp),
			)
		}
		fullReq := r.buildQuery(mdns.Fqdn(fullName), qtype, qclass)
		return r.queryServersResponse(fullReq, servers)
	}
	return resp, nil
}

func needsQNameMinFallback(resp *mdns.Msg) bool {
	if resp == nil {
		return false
	}
	return resp.Rcode == mdns.RcodeServerFailure || resp.Rcode == mdns.RcodeRefused
}

func (r *IterativeResolver) buildQuery(name string, qtype, qclass uint16) *mdns.Msg {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), qtype)
	msg.Question[0].Qclass = qclass
	msg.RecursionDesired = false

	if r.dnssecValidation {
		msg.SetEdns0(mdns.DefaultMsgSize, true)
	} else {
		msg.SetEdns0(mdns.DefaultMsgSize, false)
	}
	return msg
}

func (r *IterativeResolver) queryServersResponse(req *mdns.Msg, servers []string) (*mdns.Msg, error) {
	resp, _, err := r.queryServers(req, servers)
	return resp, err
}

func (r *IterativeResolver) queryServers(req *mdns.Msg, servers []string) (*mdns.Msg, string, error) {
	var lastErr error
	var lastServer string
	qname, qtypeStr := iterativeQueryLabels(req)

	for _, server := range r.sortServers(servers) {
		lastServer = server
		dialAddr := config.DialUpstreamAddress(server)
		ip, hasIP := serverIP(dialAddr)
		start := time.Now()
		resp, _, err := r.client.Exchange(req, dialAddr)
		elapsed := time.Since(start)

		if r.logger != nil {
			r.logger.Debug("iterative nameserver exchange",
				"server", server,
				"qname", qname,
				"qtype", qtypeStr,
				"transport", r.client.Net,
				"latency", elapsed,
				"error", err,
				"rcode", dnsRcodeString(resp),
			)
		}

		if err != nil {
			if hasIP {
				r.rtt.RecordFailure(ip)
			}
			lastErr = err
			continue
		}
		if resp == nil {
			if hasIP {
				r.rtt.RecordFailure(ip)
			}
			lastErr = errors.New("empty response from nameserver")
			continue
		}
		if resp.Rcode == mdns.RcodeServerFailure {
			if hasIP {
				r.rtt.RecordFailure(ip)
			}
			lastErr = fmt.Errorf("nameserver %s returned SERVFAIL", server)
			continue
		}

		if hasIP {
			r.rtt.RecordSuccess(ip, elapsed)
		}
		return resp, server, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all nameserver queries failed")
	}
	return nil, lastServer, lastErr
}

func iterativeQueryLabels(req *mdns.Msg) (string, string) {
	if req == nil || len(req.Question) == 0 {
		return "", ""
	}
	q := req.Question[0]
	return q.Name, mdns.TypeToString[q.Qtype]
}

func dnsRcodeString(resp *mdns.Msg) string {
	if resp == nil {
		return ""
	}
	if name, ok := mdns.RcodeToString[resp.Rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", resp.Rcode)
}

func (r *IterativeResolver) pickRoot() []string {
	return r.sortServers(r.rootHints)
}

func (r *IterativeResolver) sortServers(servers []string) []string {
	if r == nil || r.rtt == nil || len(servers) <= 1 {
		out := make([]string, len(servers))
		copy(out, servers)
		return out
	}
	return r.rtt.SortServers(servers)
}

func (r *IterativeResolver) responseMatchesQuery(resp *mdns.Msg, qname string, qtype uint16) (*mdns.Msg, bool) {
	if resp == nil || resp.Rcode != mdns.RcodeSuccess {
		return nil, false
	}

	qname = mdns.CanonicalName(qname)
	matched := make([]mdns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		h := rr.Header()
		if mdns.CanonicalName(h.Name) == qname && h.Rrtype == qtype {
			matched = append(matched, rr)
		}
	}
	if len(matched) == 0 {
		return nil, false
	}

	out := &mdns.Msg{
		MsgHdr: resp.MsgHdr,
		Answer: matched,
		Ns:     resp.Ns,
		Extra:  resp.Extra,
	}
	out.Rcode = mdns.RcodeSuccess
	return out, true
}

func (r *IterativeResolver) isNegative(resp *mdns.Msg) bool {
	if resp == nil {
		return false
	}
	if resp.Rcode == mdns.RcodeNameError {
		return true
	}
	if resp.Rcode == mdns.RcodeSuccess && len(resp.Answer) == 0 {
		for _, rr := range resp.Ns {
			if _, ok := rr.(*mdns.SOA); ok {
				return true
			}
		}
	}
	return false
}

func (r *IterativeResolver) cnameTarget(resp *mdns.Msg, qname string) (string, bool) {
	qname = mdns.CanonicalName(qname)
	for _, rr := range resp.Answer {
		cname, ok := rr.(*mdns.CNAME)
		if !ok {
			continue
		}
		if mdns.CanonicalName(cname.Hdr.Name) == qname {
			return cname.Target, true
		}
	}
	return "", false
}

func (r *IterativeResolver) referralNS(resp *mdns.Msg) []string {
	if resp == nil {
		return nil
	}
	out := make([]string, 0, len(resp.Ns)+len(resp.Answer))
	seen := make(map[string]struct{})
	appendNS := func(rr mdns.RR) {
		ns, ok := rr.(*mdns.NS)
		if !ok {
			return
		}
		name := mdns.CanonicalName(ns.Ns)
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, ns.Ns)
	}
	for _, rr := range resp.Ns {
		appendNS(rr)
	}
	for _, rr := range resp.Answer {
		appendNS(rr)
	}
	return out
}

func (r *IterativeResolver) glueAddrs(resp *mdns.Msg, nsHosts []string) []string {
	if resp == nil || len(nsHosts) == 0 {
		return nil
	}

	want := make(map[string]struct{}, len(nsHosts))
	for _, host := range nsHosts {
		want[mdns.CanonicalName(host)] = struct{}{}
	}

	out := make([]string, 0, len(nsHosts))
	seen := make(map[string]struct{}, len(nsHosts))
	for _, rr := range resp.Extra {
		h := rr.Header()
		if _, ok := want[mdns.CanonicalName(h.Name)]; !ok {
			continue
		}

		var ip net.IP
		switch v := rr.(type) {
		case *mdns.A:
			ip = v.A
		case *mdns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if ip == nil {
			continue
		}

		addr := net.JoinHostPort(ip.String(), "53")
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func (r *IterativeResolver) resolveGlue(nsHosts []string, depth int) ([]string, error) {
	out := make([]string, 0, len(nsHosts))
	seen := make(map[string]struct{}, len(nsHosts))

	for _, host := range nsHosts {
		addrs, err := r.resolveNameserverHost(host, depth)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("failed to resolve glue for nameservers %v", nsHosts)
	}
	return out, nil
}

func (r *IterativeResolver) resolveNameserverHost(host string, depth int) ([]string, error) {
	minLabels := 0
	if r.qnameMinimization {
		minLabels = 1
	}

	resp, err := r.resolve(host, mdns.TypeA, mdns.ClassINET, r.pickRoot(), depth, minLabels)
	if err == nil && resp != nil && resp.Rcode == mdns.RcodeSuccess {
		if addrs := r.extractAddressTargets(resp); len(addrs) > 0 {
			return addrs, nil
		}
	}

	resp, err = r.resolve(host, mdns.TypeAAAA, mdns.ClassINET, r.pickRoot(), depth, minLabels)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("nameserver %s address lookup failed", host)
	}
	addrs := r.extractAddressTargets(resp)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("nameserver %s has no address records", host)
	}
	return addrs, nil
}

func (r *IterativeResolver) extractAddressTargets(resp *mdns.Msg) []string {
	out := make([]string, 0, len(resp.Answer))
	seen := make(map[string]struct{}, len(resp.Answer))
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *mdns.A:
			ip = v.A
		case *mdns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if ip == nil {
			continue
		}
		addr := net.JoinHostPort(ip.String(), "53")
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}
