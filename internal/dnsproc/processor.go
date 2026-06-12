package dnsproc

import (
	"net/netip"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	maxMessageSize     = 65535
	dnsHeaderSize      = 12
	maxCNAMEChainDepth = 8
)

// Processor resolves authoritative DNS queries against an in-memory zone store and
// forwards unresolved recursive queries to upstream resolvers when configured.
type Processor struct {
	store     *storage.Memory
	forwarder *Forwarder
	cache     *storage.ResponseCache
	stats     *telemetry.Stats
	acl       TrustedChecker
}

// New creates a DNS processor backed by the given storage engine.
func New(store *storage.Memory, forwarder *Forwarder, cache *storage.ResponseCache, stats *telemetry.Stats, acl TrustedChecker) *Processor {
	return &Processor{
		store:     store,
		forwarder: forwarder,
		cache:     cache,
		stats:     stats,
		acl:       acl,
	}
}

// Response parses a DNS query payload from client and returns an authoritative answer,
// a forwarded recursive answer, or an appropriate error code.
func (p *Processor) Response(client netip.Addr, payload []byte) ([]byte, error) {
	if len(payload) < dnsHeaderSize || len(payload) > maxMessageSize {
		return nil, mdns.ErrBuf
	}

	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}

	if len(req.Question) == 0 {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Authoritative = true
		resp.Rcode = mdns.RcodeFormatError
		return resp.Pack()
	}

	trusted := p.clientTrusted(client)
	q := req.Question[0]
	records, rcode, needsForward := p.resolveQuestion(q, trusted)

	if needsForward && req.RecursionDesired {
		if !trusted {
			return p.refusedResponse(req)
		}
		if p.forwarder != nil {
			return p.forwardQuery(req)
		}
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Rcode = rcode
	resp.Answer = records
	return resp.Pack()
}

func (p *Processor) clientTrusted(client netip.Addr) bool {
	if p.acl == nil {
		return true
	}
	return p.acl.Trusted(client)
}

func (p *Processor) refusedResponse(req *mdns.Msg) ([]byte, error) {
	if p.stats != nil {
		p.stats.IncACLRejected()
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Authoritative = false
	resp.Rcode = mdns.RcodeRefused
	return resp.Pack()
}

func (p *Processor) forwardQuery(req *mdns.Msg) ([]byte, error) {
	key := storage.QuestionKey(req.Question[0])

	if p.cache != nil {
		if cached, ok := p.cache.Get(key); ok {
			if p.stats != nil {
				p.stats.IncCacheHit()
			}
			cached.SetReply(req)
			cached.RecursionAvailable = true
			return cached.Pack()
		}
		if p.stats != nil {
			p.stats.IncCacheMiss()
		}
	}

	resp, err := p.forwarder.Exchange(req)
	if err != nil {
		fallback := new(mdns.Msg)
		fallback.SetReply(req)
		fallback.RecursionAvailable = true
		fallback.Authoritative = false
		fallback.Rcode = mdns.RcodeServerFailure
		return fallback.Pack()
	}

	if p.cache != nil {
		p.cache.Set(key, resp)
	}

	resp.SetReply(req)
	resp.RecursionAvailable = true
	return resp.Pack()
}

func (p *Processor) resolveQuestion(q mdns.Question, trusted bool) (records []mdns.RR, rcode int, needsForward bool) {
	switch q.Qtype {
	case mdns.TypeA, mdns.TypeAAAA:
		records, rcode = p.resolveAddress(q.Name, q.Qtype, trusted)
		needsForward = rcode == mdns.RcodeNameError
	default:
		var status storage.LookupStatus
		records, status = p.authoritativeLookup(q.Name, q.Qtype, trusted)
		switch status {
		case storage.LookupFound:
			rcode = mdns.RcodeSuccess
		case storage.LookupNodata:
			rcode = mdns.RcodeSuccess
		default:
			rcode = mdns.RcodeNameError
			needsForward = true
		}
	}
	return records, rcode, needsForward
}

func (p *Processor) authoritativeLookup(name string, qtype uint16, trusted bool) ([]mdns.RR, storage.LookupStatus) {
	if trusted {
		records, status := p.store.LookupInternal(name, qtype)
		if status != storage.LookupNotFound {
			return records, status
		}
	}
	return p.store.LookupPublic(name, qtype)
}

// resolveAddress returns A or AAAA records, following CNAME chains when needed.
func (p *Processor) resolveAddress(name string, qtype uint16, trusted bool) ([]mdns.RR, int) {
	records, status := p.authoritativeLookup(name, qtype, trusted)
	switch status {
	case storage.LookupFound:
		return records, mdns.RcodeSuccess
	case storage.LookupNotFound:
		return nil, mdns.RcodeNameError
	}

	return p.followCNAMEChain(name, qtype, trusted)
}

// followCNAMEChain walks CNAME aliases until the requested address type is found,
// the chain ends, or a loop/depth limit is hit. Each lookup loads the active radix
// tree pointer atomically, so concurrent callers need no locks.
func (p *Processor) followCNAMEChain(startName string, qtype uint16, trusted bool) ([]mdns.RR, int) {
	answer := make([]mdns.RR, 0, 4)
	visited := make(map[string]struct{}, maxCNAMEChainDepth)
	current := storage.NormalizeName(startName)

	for depth := 0; depth < maxCNAMEChainDepth; depth++ {
		if _, seen := visited[current]; seen {
			return answer, mdns.RcodeServerFailure
		}
		visited[current] = struct{}{}

		records, status := p.authoritativeLookup(current, qtype, trusted)
		switch status {
		case storage.LookupFound:
			return append(answer, records...), mdns.RcodeSuccess
		case storage.LookupNotFound:
			if len(answer) > 0 {
				return answer, mdns.RcodeSuccess
			}
			return nil, mdns.RcodeNameError
		}

		cnames, status := p.authoritativeLookup(current, mdns.TypeCNAME, trusted)
		if status != storage.LookupFound {
			return answer, mdns.RcodeSuccess
		}

		cname, ok := cnames[0].(*mdns.CNAME)
		if !ok {
			return answer, mdns.RcodeServerFailure
		}

		answer = append(answer, cnames[0])
		current = storage.NormalizeName(cname.Target)
	}

	return answer, mdns.RcodeServerFailure
}

// RcodeFromPayload unpacks a serialized DNS response and returns its RCODE.
func RcodeFromPayload(payload []byte) (int, error) {
	msg := new(mdns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return 0, err
	}
	return msg.Rcode, nil
}
