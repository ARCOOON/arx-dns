package dnsproc

import (
	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

const (
	maxMessageSize     = 65535
	dnsHeaderSize      = 12
	maxCNAMEChainDepth = 8
)

// Processor resolves authoritative DNS queries against an in-memory zone store.
type Processor struct {
	store *storage.Memory
}

// New creates a DNS processor backed by the given storage engine.
func New(store *storage.Memory) *Processor {
	return &Processor{store: store}
}

// Response parses a DNS query payload and returns an authoritative answer or NXDOMAIN.
func (p *Processor) Response(payload []byte) ([]byte, error) {
	if len(payload) < dnsHeaderSize || len(payload) > maxMessageSize {
		return nil, mdns.ErrBuf
	}

	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	if len(req.Question) == 0 {
		resp.Rcode = mdns.RcodeFormatError
		return resp.Pack()
	}

	q := req.Question[0]

	var records []mdns.RR
	var rcode int

	switch q.Qtype {
	case mdns.TypeA, mdns.TypeAAAA:
		records, rcode = p.resolveAddress(q.Name, q.Qtype)
	default:
		var status storage.LookupStatus
		records, status = p.store.Lookup(q.Name, q.Qtype)
		switch status {
		case storage.LookupFound:
			rcode = mdns.RcodeSuccess
		case storage.LookupNodata:
			rcode = mdns.RcodeSuccess
		default:
			rcode = mdns.RcodeNameError
		}
	}

	resp.Rcode = rcode
	resp.Answer = records
	return resp.Pack()
}

// resolveAddress returns A or AAAA records, following CNAME chains when needed.
func (p *Processor) resolveAddress(name string, qtype uint16) ([]mdns.RR, int) {
	records, status := p.store.Lookup(name, qtype)
	switch status {
	case storage.LookupFound:
		return records, mdns.RcodeSuccess
	case storage.LookupNotFound:
		return nil, mdns.RcodeNameError
	}

	return p.followCNAMEChain(name, qtype)
}

// followCNAMEChain walks CNAME aliases until the requested address type is found,
// the chain ends, or a loop/depth limit is hit. Each store.Lookup loads the
// active radix tree pointer atomically, so concurrent callers need no locks.
func (p *Processor) followCNAMEChain(startName string, qtype uint16) ([]mdns.RR, int) {
	answer := make([]mdns.RR, 0, 4)
	visited := make(map[string]struct{}, maxCNAMEChainDepth)
	current := storage.NormalizeName(startName)

	for depth := 0; depth < maxCNAMEChainDepth; depth++ {
		if _, seen := visited[current]; seen {
			return answer, mdns.RcodeServerFailure
		}
		visited[current] = struct{}{}

		records, status := p.store.Lookup(current, qtype)
		switch status {
		case storage.LookupFound:
			return append(answer, records...), mdns.RcodeSuccess
		case storage.LookupNotFound:
			if len(answer) > 0 {
				return answer, mdns.RcodeSuccess
			}
			return nil, mdns.RcodeNameError
		}

		cnames, status := p.store.Lookup(current, mdns.TypeCNAME)
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
