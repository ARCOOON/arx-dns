package dnsproc

import (
	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

const (
	maxMessageSize = 65535
	dnsHeaderSize  = 12
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
	records, status := p.store.Lookup(q.Name, q.Qtype)

	switch status {
	case storage.LookupFound:
		resp.Rcode = mdns.RcodeSuccess
		resp.Answer = records
	case storage.LookupNodata:
		resp.Rcode = mdns.RcodeSuccess
	default:
		resp.Rcode = mdns.RcodeNameError
	}

	return resp.Pack()
}

// RcodeFromPayload unpacks a serialized DNS response and returns its RCODE.
func RcodeFromPayload(payload []byte) (int, error) {
	msg := new(mdns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return 0, err
	}
	return msg.Rcode, nil
}
