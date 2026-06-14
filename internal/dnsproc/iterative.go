package dnsproc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
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
	rootHints        []string
	client           *mdns.Client
	stats            *telemetry.Stats
	dnssecValidation bool
	maxDepth         int
}

// NewIterativeFromConfig builds an iterative resolver from application configuration.
func NewIterativeFromConfig(cfg config.Config, stats *telemetry.Stats) (*IterativeResolver, error) {
	hints, err := cfg.NormalizedRootHints()
	if err != nil {
		return nil, err
	}
	r := NewIterativeResolver(hints, stats)
	r.dnssecValidation = cfg.Security.DNSSECValidation
	return r, nil
}

// NewIterativeResolver creates an iterative resolver using the given root hint addresses.
func NewIterativeResolver(rootHints []string, stats *telemetry.Stats) *IterativeResolver {
	addrs := make([]string, len(rootHints))
	copy(addrs, rootHints)

	return &IterativeResolver{
		rootHints: addrs,
		client: &mdns.Client{
			Net:     "udp",
			Timeout: defaultIterativeTimeout,
		},
		stats:    stats,
		maxDepth: maxIterativeDepth,
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

	resp, err := r.resolve(q.Name, q.Qtype, q.Qclass, r.pickRoot(), 0)
	if err != nil {
		if r.stats != nil {
			r.stats.IncUpstreamFailure()
		}
		return nil, err
	}
	return resp, nil
}

func (r *IterativeResolver) resolve(name string, qtype, qclass uint16, servers []string, depth int) (*mdns.Msg, error) {
	if depth >= r.maxDepth {
		return nil, ErrIterativeDepthExceeded
	}
	if len(servers) == 0 {
		return nil, errors.New("no nameservers available for iterative query")
	}

	current := mdns.Fqdn(name)
	for cnameSteps := 0; cnameSteps < maxCNAMEChainDepth; cnameSteps++ {
		req := r.buildQuery(current, qtype, qclass)
		resp, err := r.queryServers(req, servers)
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
		return r.resolve(current, qtype, qclass, next, depth+1)
	}

	return nil, ErrIterativeDepthExceeded
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

func (r *IterativeResolver) queryServers(req *mdns.Msg, servers []string) (*mdns.Msg, error) {
	var lastErr error
	for _, server := range servers {
		resp, _, err := r.client.Exchange(req, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil {
			return resp, nil
		}
		lastErr = errors.New("empty response from nameserver")
	}
	if lastErr == nil {
		lastErr = errors.New("all nameserver queries failed")
	}
	return nil, lastErr
}

func (r *IterativeResolver) pickRoot() []string {
	if len(r.rootHints) == 1 {
		return []string{r.rootHints[0]}
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.rootHints))))
	if err != nil {
		return []string{r.rootHints[0]}
	}
	return []string{r.rootHints[idx.Int64()]}
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
	out := make([]string, 0, len(resp.Ns))
	for _, rr := range resp.Ns {
		ns, ok := rr.(*mdns.NS)
		if !ok {
			continue
		}
		out = append(out, ns.Ns)
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
	resp, err := r.resolve(host, mdns.TypeA, mdns.ClassINET, r.pickRoot(), depth)
	if err == nil && resp != nil && resp.Rcode == mdns.RcodeSuccess {
		if addrs := r.extractAddressTargets(resp); len(addrs) > 0 {
			return addrs, nil
		}
	}

	resp, err = r.resolve(host, mdns.TypeAAAA, mdns.ClassINET, r.pickRoot(), depth)
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
