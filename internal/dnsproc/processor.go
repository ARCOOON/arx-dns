package dnsproc

import (
	mdns "github.com/miekg/dns"
)

const (
	maxMessageSize = 65535
	dnsHeaderSize  = 12
)

// RefusedResponse parses a DNS query payload and returns a serialized REFUSED response.
func RefusedResponse(payload []byte) ([]byte, error) {
	if len(payload) < dnsHeaderSize || len(payload) > maxMessageSize {
		return nil, mdns.ErrBuf
	}

	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Rcode = mdns.RcodeRefused

	return resp.Pack()
}
