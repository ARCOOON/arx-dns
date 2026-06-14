package dnsproc

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

type tsigContext struct {
	keyName    string
	algorithm  string
	requestMAC string
}

func (p *Processor) handleDynamicUpdate(client netip.Addr, req *mdns.Msg, payload []byte, limitUDP bool, cookieCtx cookieContext) ([]byte, error) {
	tsigCtx, err := p.verifyUpdateTSIG(payload, req)
	if err != nil {
		if p.logger != nil {
			p.logger.Warn("dynamic update rejected: invalid or missing TSIG",
				"client", client.String(),
				"error", err,
			)
		}
		return p.updateRefusedResponse(req, limitUDP, client, cookieCtx)
	}

	if len(req.Question) != 1 {
		return p.updateFormatErrorResponse(req, limitUDP, client, cookieCtx, tsigCtx)
	}

	q := req.Question[0]
	origin := storage.NormalizeName(q.Name)
	if q.Qtype != mdns.TypeSOA {
		return p.updateFormatErrorResponse(req, limitUDP, client, cookieCtx, tsigCtx)
	}
	if q.Qclass != mdns.ClassINET && q.Qclass != mdns.ClassANY {
		return p.updateFormatErrorResponse(req, limitUDP, client, cookieCtx, tsigCtx)
	}

	trusted := p.clientTrusted(client)
	view, err := p.resolveUpdateView(origin, trusted)
	if err != nil {
		rcode := mdns.RcodeNotAuth
		if errors.Is(err, storage.ErrZoneNotFound) {
			rcode = mdns.RcodeNotZone
		}
		return p.updateResponse(req, rcode, limitUDP, client, cookieCtx, tsigCtx)
	}

	if err := p.checkPrerequisites(req.Answer, origin, view); err != nil {
		rcode := updateErrorToRcode(err)
		return p.updateResponse(req, rcode, limitUDP, client, cookieCtx, tsigCtx)
	}

	if len(req.Ns) == 0 {
		return p.updateResponse(req, mdns.RcodeSuccess, limitUDP, client, cookieCtx, tsigCtx)
	}

	if err := p.store.ApplyDynamicUpdateRRs(p.zonesDir, origin, view, req.Ns); err != nil {
		rcode := updateErrorToRcode(err)
		if p.logger != nil && rcode == mdns.RcodeServerFailure {
			p.logger.Error("dynamic update failed",
				"client", client.String(),
				"zone", origin,
				"error", err,
			)
		}
		return p.updateResponse(req, rcode, limitUDP, client, cookieCtx, tsigCtx)
	}

	if p.logger != nil {
		p.logger.Info("dynamic update applied",
			"client", client.String(),
			"zone", origin,
			"view", view,
			"prerequisites", len(req.Answer),
			"updates", len(req.Ns),
		)
	}

	return p.updateResponse(req, mdns.RcodeSuccess, limitUDP, client, cookieCtx, tsigCtx)
}

func (p *Processor) verifyUpdateTSIG(payload []byte, req *mdns.Msg) (tsigContext, error) {
	var ctx tsigContext
	if len(p.tsigSecrets) == 0 {
		return ctx, errors.New("no TSIG keys configured")
	}

	tsig := req.IsTsig()
	if tsig == nil {
		return ctx, errors.New("missing TSIG record")
	}

	keyName := mdns.CanonicalName(tsig.Hdr.Name)
	secret, ok := p.tsigSecrets[keyName]
	if !ok {
		return ctx, mdns.ErrSecret
	}

	if err := mdns.TsigVerify(payload, secret, "", false); err != nil {
		return ctx, err
	}

	ctx.keyName = keyName
	ctx.algorithm = tsig.Algorithm
	ctx.requestMAC = tsig.MAC
	return ctx, nil
}

func (p *Processor) resolveUpdateView(origin string, trusted bool) (storage.ZoneView, error) {
	_ = trusted
	origin = storage.NormalizeName(origin)
	if p.store.ZoneExists(origin, storage.ViewPublic) {
		return storage.ViewPublic, nil
	}
	if p.store.ZoneExists(origin, storage.ViewInternal) {
		return storage.ViewInternal, nil
	}
	return "", storage.ErrZoneNotFound
}

func (p *Processor) checkPrerequisites(prereqs []mdns.RR, origin string, view storage.ZoneView) error {
	for _, rr := range prereqs {
		if err := p.checkPrerequisite(rr, origin, view); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) checkPrerequisite(rr mdns.RR, origin string, view storage.ZoneView) error {
	if rr == nil {
		return fmt.Errorf("nil prerequisite")
	}

	hdr := rr.Header()
	name := storage.NormalizeName(hdr.Name)
	if !isNameInUpdateZone(name, origin) {
		return storage.ErrUpdateNotZone
	}

	switch {
	case hdr.Rrtype == mdns.TypeANY && hdr.Class == mdns.ClassANY:
		if !p.nameExistsInView(name, view) {
			return storage.ErrUpdateNXDOMAIN
		}
	case hdr.Rrtype == mdns.TypeANY && hdr.Class == mdns.ClassNONE:
		if p.nameExistsInView(name, view) {
			return storage.ErrUpdateYXDOMAIN
		}
	case hdr.Class == mdns.ClassANY:
		if !p.rrsetExistsInView(name, hdr.Rrtype, view) {
			return storage.ErrUpdateNXRRSET
		}
	case hdr.Class == mdns.ClassNONE:
		if p.rrsetExistsInView(name, hdr.Rrtype, view) {
			return storage.ErrUpdateYXRRSET
		}
	default:
		if !p.rrExistsInView(rr, view) {
			return storage.ErrUpdateNXRRSET
		}
	}
	return nil
}

func (p *Processor) nameExistsInView(name string, view storage.ZoneView) bool {
	if view == storage.ViewInternal {
		return p.store.NameExistsInternal(name)
	}
	return p.store.NameExistsPublic(name)
}

func (p *Processor) rrsetExistsInView(name string, qtype uint16, view storage.ZoneView) bool {
	var status storage.LookupStatus
	if view == storage.ViewInternal {
		_, status = p.store.LookupInternal(name, qtype)
	} else {
		_, status = p.store.LookupPublic(name, qtype)
	}
	return status == storage.LookupFound
}

func (p *Processor) rrExistsInView(rr mdns.RR, view storage.ZoneView) bool {
	hdr := rr.Header()
	var records []mdns.RR
	var status storage.LookupStatus
	if view == storage.ViewInternal {
		records, status = p.store.LookupInternal(hdr.Name, hdr.Rrtype)
	} else {
		records, status = p.store.LookupPublic(hdr.Name, hdr.Rrtype)
	}
	if status != storage.LookupFound {
		return false
	}
	for _, candidate := range records {
		if mdns.IsDuplicate(candidate, rr) {
			return true
		}
	}
	return false
}

func isNameInUpdateZone(name, origin string) bool {
	name = storage.NormalizeName(name)
	origin = storage.NormalizeName(origin)
	if name == origin {
		return true
	}
	suffix := "." + strings.TrimSuffix(origin, ".") + "."
	return strings.HasSuffix(name, suffix)
}

func updateErrorToRcode(err error) int {
	switch {
	case errors.Is(err, storage.ErrUpdateNXRRSET):
		return mdns.RcodeNXRrset
	case errors.Is(err, storage.ErrUpdateYXRRSET):
		return mdns.RcodeYXRrset
	case errors.Is(err, storage.ErrUpdateNXDOMAIN):
		return mdns.RcodeNameError
	case errors.Is(err, storage.ErrUpdateYXDOMAIN):
		return mdns.RcodeYXDomain
	case errors.Is(err, storage.ErrUpdateNotZone):
		return mdns.RcodeNotZone
	case errors.Is(err, storage.ErrUpdateRefused):
		return mdns.RcodeRefused
	case errors.Is(err, storage.ErrZoneNotFound):
		return mdns.RcodeNotAuth
	default:
		return mdns.RcodeServerFailure
	}
}

func (p *Processor) updateRefusedResponse(req *mdns.Msg, limitUDP bool, client netip.Addr, cookieCtx cookieContext) ([]byte, error) {
	if p.stats != nil {
		p.stats.IncRefusedAnswer()
	}
	return p.updateResponse(req, mdns.RcodeRefused, limitUDP, client, cookieCtx, tsigContext{})
}

func (p *Processor) updateFormatErrorResponse(req *mdns.Msg, limitUDP bool, client netip.Addr, cookieCtx cookieContext, tsigCtx tsigContext) ([]byte, error) {
	return p.updateResponse(req, mdns.RcodeFormatError, limitUDP, client, cookieCtx, tsigCtx)
}

func (p *Processor) updateResponse(req *mdns.Msg, rcode int, limitUDP bool, client netip.Addr, cookieCtx cookieContext, tsigCtx tsigContext) ([]byte, error) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = rcode
	resp.Answer = nil
	resp.Ns = nil

	if tsigCtx.keyName != "" && rcode != mdns.RcodeFormatError {
		resp.SetTsig(tsigCtx.keyName, tsigCtx.algorithm, 300, time.Now().Unix())
		secret := p.tsigSecrets[tsigCtx.keyName]
		if secret != "" {
			if opt := req.IsEdns0(); opt != nil {
				resp.SetEdns0(opt.UDPSize(), opt.Do())
				p.attachResponseCookie(resp, client, cookieCtx)
			}
			resp.Compress = true
			signed, _, err := mdns.TsigGenerate(resp, secret, tsigCtx.requestMAC, false)
			if err != nil {
				if p.logger != nil {
					p.logger.Error("failed to sign dynamic update response", "error", err)
				}
				return p.packResponse(resp, req, limitUDP, client, cookieCtx)
			}
			return signed, nil
		}
	}

	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}
