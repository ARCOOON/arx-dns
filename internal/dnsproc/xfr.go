package dnsproc

import (
	"net/netip"
	"sort"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

const maxRecordsPerXferMessage = 100

// IsZoneTransferQuery reports whether payload is an AXFR or IXFR query.
func IsZoneTransferQuery(payload []byte) bool {
	if len(payload) < dnsHeaderSize {
		return false
	}
	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return false
	}
	if len(req.Question) == 0 {
		return false
	}
	qtype := req.Question[0].Qtype
	return qtype == mdns.TypeAXFR || qtype == mdns.TypeIXFR
}

// TCPFrameWriter writes one RFC 1035 length-prefixed DNS message on a TCP connection.
type TCPFrameWriter func(payload []byte) error

// HandleTCP processes a DNS query received over TCP (or TLS). Zone transfers stream
// multiple response frames through writeFrame; ordinary queries write a single frame.
func (p *Processor) HandleTCP(client netip.Addr, payload []byte, writeFrame TCPFrameWriter) error {
	if len(payload) < dnsHeaderSize || len(payload) > maxMessageSize {
		return mdns.ErrBuf
	}

	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return err
	}

	cookieCtx := p.parseRequestCookie(req, client)
	if cookieCtx.rejectBadCookie {
		resp, err := p.badCookieResponse(req, client, cookieCtx, false)
		if err != nil {
			return err
		}
		return writeFrame(resp)
	}

	if req.Opcode == mdns.OpcodeUpdate {
		resp, err := p.handleDynamicUpdate(client, req, payload, false, cookieCtx)
		if err != nil {
			return err
		}
		return writeFrame(resp)
	}

	if len(req.Question) == 0 {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Authoritative = true
		resp.Rcode = mdns.RcodeFormatError
		packed, err := p.packResponse(resp, req, false, client, cookieCtx)
		if err != nil {
			return err
		}
		return writeFrame(packed)
	}

	q := req.Question[0]
	if q.Qtype == mdns.TypeAXFR || q.Qtype == mdns.TypeIXFR {
		return p.streamZoneTransfer(client, req, writeFrame, cookieCtx)
	}

	respPayload, err := p.buildResponse(client, payload, false)
	if err != nil {
		return err
	}
	return writeFrame(respPayload)
}

func (p *Processor) xfrRefusedResponse(req *mdns.Msg, client netip.Addr, cookieCtx cookieContext, limitUDP bool) ([]byte, error) {
	if p.stats != nil {
		p.stats.IncACLRejected()
		p.stats.IncXFRRefused()
	}
	return p.refusedResponse(req, limitUDP, client, cookieCtx)
}

func (p *Processor) streamZoneTransfer(client netip.Addr, req *mdns.Msg, writeFrame TCPFrameWriter, cookieCtx cookieContext) error {
	if !p.xfrEnabled {
		resp, err := p.xfrRefusedResponse(req, client, cookieCtx, false)
		if err != nil {
			return err
		}
		return writeFrame(resp)
	}

	if !p.transferAllowed(client, "") {
		resp, err := p.xfrRefusedResponse(req, client, cookieCtx, false)
		if err != nil {
			return err
		}
		return writeFrame(resp)
	}

	view := p.selectView(client, req)
	origin, xferView, ok := p.resolveXferZone(req.Question[0].Name, view)
	if !ok {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Rcode = mdns.RcodeNotAuth
		packed, err := p.packResponse(resp, req, false, client, cookieCtx)
		if err != nil {
			return err
		}
		if p.stats != nil {
			p.stats.IncXFRRefused()
		}
		return writeFrame(packed)
	}

	if !p.transferAllowed(client, origin) {
		resp, err := p.xfrRefusedResponse(req, client, cookieCtx, false)
		if err != nil {
			return err
		}
		return writeFrame(resp)
	}

	records := p.store.ZoneRecords(origin, xferView)
	soa := findSOARecord(records, origin)
	if soa == nil {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Rcode = mdns.RcodeNotAuth
		packed, err := p.packResponse(resp, req, false, client, cookieCtx)
		if err != nil {
			return err
		}
		if p.stats != nil {
			p.stats.IncXFRRefused()
		}
		return writeFrame(packed)
	}

	others := make([]mdns.RR, 0, len(records))
	for _, rr := range records {
		if mdns.IsDuplicate(rr, soa) {
			continue
		}
		others = append(others, rr)
	}

	soaCopy := mdns.Copy(soa)
	if err := p.writeXferMessage(req, client, cookieCtx, []mdns.RR{soaCopy}, writeFrame); err != nil {
		return err
	}

	for start := 0; start < len(others); start += maxRecordsPerXferMessage {
		end := start + maxRecordsPerXferMessage
		if end > len(others) {
			end = len(others)
		}
		batch := make([]mdns.RR, end-start)
		for i, rr := range others[start:end] {
			batch[i] = mdns.Copy(rr)
		}
		if err := p.writeXferMessage(req, client, cookieCtx, batch, writeFrame); err != nil {
			return err
		}
	}

	if err := p.writeXferMessage(req, client, cookieCtx, []mdns.RR{mdns.Copy(soa)}, writeFrame); err != nil {
		return err
	}

	if p.stats != nil {
		p.stats.IncXFRCompleted()
	}
	if p.logger != nil {
		p.logger.Info("zone transfer completed",
			"client", client.String(),
			"zone", origin,
			"view", xferView,
			"qtype", mdns.TypeToString[req.Question[0].Qtype],
			"records", len(records),
		)
	}
	return nil
}

func (p *Processor) writeXferMessage(req *mdns.Msg, client netip.Addr, cookieCtx cookieContext, answers []mdns.RR, writeFrame TCPFrameWriter) error {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = mdns.RcodeSuccess
	resp.Answer = answers
	packed, err := p.packResponse(resp, req, false, client, cookieCtx)
	if err != nil {
		return err
	}
	return writeFrame(packed)
}

func (p *Processor) transferAllowed(client netip.Addr, zoneApex string) bool {
	if p.policyEngine != nil {
		return p.policyEngine.AllowTransfer(client, zoneApex)
	}
	if p.xfrACL == nil {
		return false
	}
	return p.xfrACL.Trusted(client)
}

func (p *Processor) resolveXferZone(qname string, view storage.ZoneView) (origin string, zoneView storage.ZoneView, ok bool) {
	qname = storage.NormalizeName(qname)
	labels := splitDNSLabels(qname)
	for i := len(labels) - 1; i >= 0; i-- {
		apex := strings.Join(labels[i:], ".") + "."
		if view == storage.ViewInternal && p.store.ZoneExists(apex, storage.ViewInternal) {
			return apex, storage.ViewInternal, true
		}
		if p.store.ZoneExists(apex, storage.ViewPublic) {
			return apex, storage.ViewPublic, true
		}
	}
	return "", "", false
}

func findSOARecord(records []mdns.RR, origin string) mdns.RR {
	origin = storage.NormalizeName(origin)
	for _, rr := range records {
		if rr.Header().Rrtype != mdns.TypeSOA {
			continue
		}
		if storage.NormalizeName(rr.Header().Name) == origin {
			return rr
		}
	}
	for _, rr := range records {
		if rr.Header().Rrtype == mdns.TypeSOA {
			return rr
		}
	}
	return nil
}

// ZoneOrigins returns unique zone apex names from ZoneInfo entries.
func ZoneOrigins(zones []storage.ZoneInfo) []string {
	seen := make(map[string]struct{}, len(zones))
	for _, z := range zones {
		origin := storage.NormalizeName(z.Origin)
		if origin == "." {
			continue
		}
		seen[origin] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for origin := range seen {
		out = append(out, origin)
	}
	sort.Strings(out)
	return out
}
