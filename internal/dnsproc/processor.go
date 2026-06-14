package dnsproc

import (
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/firewall"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

const (
	maxMessageSize     = 65535
	dnsHeaderSize      = 12
	maxCNAMEChainDepth = 8
	clientCookieLen    = 8
	serverCookieLen    = 8
)

// CookieHandler generates and verifies RFC 7873 server cookies.
type CookieHandler interface {
	ServerCookie(client netip.Addr, clientCookie [8]byte, dst []byte)
	Verify(client netip.Addr, clientCookie [8]byte, serverCookie []byte) bool
}

// Processor resolves authoritative DNS queries against an in-memory zone store and
// forwards unresolved recursive queries to upstream resolvers when configured.
type Processor struct {
	store            *storage.Memory
	forwarder        *Forwarder
	cache            *storage.ResponseCache
	stats            *telemetry.Stats
	acl              TrustedChecker
	firewall         *firewall.Engine
	dnssecValidation bool
	validator        *DNSSECValidator
	cookies          CookieHandler
	tsigSecrets      map[string]string
	zonesDir         string
	logger           *slog.Logger
}

// New creates a DNS processor backed by the given storage engine.
func New(store *storage.Memory, forwarder *Forwarder, cache *storage.ResponseCache, stats *telemetry.Stats, acl TrustedChecker, fw *firewall.Engine, dnssecValidation bool, cookies CookieHandler, tsigSecrets map[string]string, zonesDir string, logger *slog.Logger) *Processor {
	p := &Processor{
		store:            store,
		forwarder:        forwarder,
		cache:            cache,
		stats:            stats,
		acl:              acl,
		firewall:         fw,
		dnssecValidation: dnssecValidation,
		cookies:          cookies,
		tsigSecrets:      tsigSecrets,
		zonesDir:         zonesDir,
		logger:           logger,
	}
	if dnssecValidation && forwarder != nil {
		p.validator = NewDNSSECValidator(forwarder, stats, logger)
	}
	return p
}

// Response parses a UDP DNS query and returns a response with EDNS0 truncation when needed.
func (p *Processor) Response(client netip.Addr, payload []byte) ([]byte, error) {
	return p.buildResponse(client, payload, true)
}

// ResponseTCP parses a TCP DNS query and returns a full response without UDP size truncation.
func (p *Processor) ResponseTCP(client netip.Addr, payload []byte) ([]byte, error) {
	return p.buildResponse(client, payload, false)
}

func (p *Processor) buildResponse(client netip.Addr, payload []byte, limitUDP bool) ([]byte, error) {
	if len(payload) < dnsHeaderSize || len(payload) > maxMessageSize {
		return nil, mdns.ErrBuf
	}

	req := new(mdns.Msg)
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}

	cookieCtx := p.parseRequestCookie(req, client)
	if cookieCtx.rejectBadCookie {
		return p.badCookieResponse(req, client, cookieCtx, limitUDP)
	}

	if req.Opcode == mdns.OpcodeUpdate {
		return p.handleDynamicUpdate(client, req, payload, limitUDP, cookieCtx)
	}

	if len(req.Question) == 0 {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Authoritative = true
		resp.Rcode = mdns.RcodeFormatError
		return p.packResponse(resp, req, limitUDP, client, cookieCtx)
	}

	trusted := p.clientTrusted(client)
	q := req.Question[0]

	if p.firewall != nil && p.firewall.Blocked(q.Name) {
		return p.blockedResponse(req, q, limitUDP, client, cookieCtx)
	}

	records, rcode, needsForward := p.resolveQuestion(q, trusted)

	if needsForward && req.RecursionDesired {
		if !trusted {
			return p.refusedResponse(req, limitUDP, client, cookieCtx)
		}
		if p.forwarder != nil {
			return p.forwardQuery(req, client, limitUDP, cookieCtx)
		}
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Rcode = rcode
	resp.Answer = records
	if q.Qtype == mdns.TypeANY && rcode == mdns.RcodeSuccess {
		resp.Truncated = true
	}
	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}

func (p *Processor) clientTrusted(client netip.Addr) bool {
	if p.acl == nil {
		return true
	}
	return p.acl.Trusted(client)
}

func (p *Processor) blockedResponse(req *mdns.Msg, q mdns.Question, limitUDP bool, client netip.Addr, cookieCtx cookieContext) ([]byte, error) {
	if p.stats != nil {
		p.stats.IncFirewallBlocked()
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	switch p.firewall.Action() {
	case firewall.BlockActionZeroIP:
		switch q.Qtype {
		case mdns.TypeA:
			resp.Rcode = mdns.RcodeSuccess
			resp.Answer = []mdns.RR{&mdns.A{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("0.0.0.0"),
			}}
		case mdns.TypeAAAA:
			resp.Rcode = mdns.RcodeSuccess
			resp.Answer = []mdns.RR{&mdns.AAAA{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypeAAAA,
					Class:  mdns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP("::"),
			}}
		default:
			resp.Rcode = mdns.RcodeNameError
		}
	default:
		resp.Rcode = mdns.RcodeNameError
	}

	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}

func (p *Processor) refusedResponse(req *mdns.Msg, limitUDP bool, client netip.Addr, cookieCtx cookieContext) ([]byte, error) {
	if p.stats != nil {
		p.stats.IncACLRejected()
	}

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Authoritative = false
	resp.Rcode = mdns.RcodeRefused
	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}

func (p *Processor) forwardQuery(req *mdns.Msg, client netip.Addr, limitUDP bool, cookieCtx cookieContext) ([]byte, error) {
	ecsCtx := storage.ECSContext{}
	if p.forwarder != nil {
		ecsCtx = p.forwarder.ECSCacheContext(client)
	}
	key := storage.CacheKey(req.Question[0], req, ecsCtx)

	if p.cache != nil {
		if cached, ok := p.cache.Get(key); ok {
			if p.stats != nil {
				p.stats.IncCacheHit()
				if storage.IsNegativeResponse(cached) {
					p.stats.IncNegativeCacheHit()
				}
			}
			cached.SetReply(req)
			cached.RecursionAvailable = true
			return p.packResponse(cached, req, limitUDP, client, cookieCtx)
		}
		if p.stats != nil {
			p.stats.IncCacheMiss()
		}
	}

	resp, err := p.forwarder.Exchange(req, client)
	if err != nil {
		fallback := new(mdns.Msg)
		fallback.SetReply(req)
		fallback.RecursionAvailable = true
		fallback.Authoritative = false
		fallback.Rcode = mdns.RcodeServerFailure
		return p.packResponse(fallback, req, limitUDP, client, cookieCtx)
	}

	if p.dnssecValidation && p.validator != nil {
		authenticated, valErr := p.validator.Validate(resp)
		if valErr != nil {
			if p.stats != nil {
				p.stats.IncDNSSECValidationFailed()
			}
			if p.logger != nil {
				q := req.Question[0]
				p.logger.Warn("dnssec validation failed, dropping upstream response",
					"qname", q.Name,
					"qtype", mdns.TypeToString[q.Qtype],
					"error", valErr,
				)
			}
			fallback := new(mdns.Msg)
			fallback.SetReply(req)
			fallback.RecursionAvailable = true
			fallback.Authoritative = false
			fallback.Rcode = mdns.RcodeServerFailure
			return p.packResponse(fallback, req, limitUDP, client, cookieCtx)
		}
		if authenticated {
			resp.AuthenticatedData = true
		}
	}

	if p.cache != nil {
		p.cache.Set(key, resp)
	}

	resp.SetReply(req)
	resp.RecursionAvailable = true
	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}

type cookieContext struct {
	hasClientCookie bool
	hasServerCookie bool
	clientCookie    [clientCookieLen]byte
	serverCookie    []byte
	rejectBadCookie bool
}

func (p *Processor) parseRequestCookie(req *mdns.Msg, client netip.Addr) cookieContext {
	var ctx cookieContext
	if p.cookies == nil {
		return ctx
	}

	opt := req.IsEdns0()
	if opt == nil {
		return ctx
	}

	for _, option := range opt.Option {
		cookieOpt, ok := option.(*mdns.EDNS0_COOKIE)
		if !ok {
			continue
		}

		raw, err := hex.DecodeString(cookieOpt.Cookie)
		if err != nil || len(raw) < clientCookieLen {
			return ctx
		}

		copy(ctx.clientCookie[:], raw[:clientCookieLen])
		ctx.hasClientCookie = true
		if len(raw) > clientCookieLen {
			ctx.serverCookie = raw[clientCookieLen:]
			ctx.hasServerCookie = true
		}
		break
	}

	if ctx.hasClientCookie && ctx.hasServerCookie {
		if p.cookies.Verify(client, ctx.clientCookie, ctx.serverCookie) {
			if p.stats != nil {
				p.stats.IncCookiesVerified()
			}
		} else {
			ctx.rejectBadCookie = true
			if p.stats != nil {
				p.stats.IncCookiesRejected()
			}
		}
	}

	return ctx
}

func (p *Processor) attachResponseCookie(resp *mdns.Msg, client netip.Addr, cookieCtx cookieContext) {
	if p.cookies == nil || !cookieCtx.hasClientCookie {
		return
	}

	opt := resp.IsEdns0()
	if opt == nil {
		return
	}

	var serverCookie [serverCookieLen]byte
	p.cookies.ServerCookie(client, cookieCtx.clientCookie, serverCookie[:])

	cookieData := make([]byte, clientCookieLen+serverCookieLen)
	copy(cookieData[:clientCookieLen], cookieCtx.clientCookie[:])
	copy(cookieData[clientCookieLen:], serverCookie[:])

	filtered := opt.Option[:0]
	for _, option := range opt.Option {
		if _, isCookie := option.(*mdns.EDNS0_COOKIE); isCookie {
			continue
		}
		filtered = append(filtered, option)
	}
	filtered = append(filtered, &mdns.EDNS0_COOKIE{
		Code:   mdns.EDNS0COOKIE,
		Cookie: hex.EncodeToString(cookieData),
	})
	opt.Option = filtered
}

func (p *Processor) badCookieResponse(req *mdns.Msg, client netip.Addr, cookieCtx cookieContext, limitUDP bool) ([]byte, error) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Authoritative = false
	resp.SetRcode(req, mdns.RcodeBadCookie)
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil
	return p.packResponse(resp, req, limitUDP, client, cookieCtx)
}

// packResponse appends an EDNS0 OPT record when the request carried one, truncates UDP
// responses to the negotiated payload size (512 bytes when EDNS0 is absent), sets TC
// when records are omitted, and enables RFC 1035 name compression before serialization.
func (p *Processor) packResponse(resp, req *mdns.Msg, limitUDP bool, client netip.Addr, cookieCtx cookieContext) ([]byte, error) {
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
		p.attachResponseCookie(resp, client, cookieCtx)
	}

	if limitUDP {
		maxSize := mdns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			maxSize = int(opt.UDPSize())
		}
		resp.Truncate(maxSize)
		if resp.Truncated && p.stats != nil {
			p.stats.IncTruncatedResponse()
		}
	}

	resp.Compress = true
	return resp.Pack()
}

func (p *Processor) resolveQuestion(q mdns.Question, trusted bool) (records []mdns.RR, rcode int, needsForward bool) {
	switch q.Qtype {
	case mdns.TypeA, mdns.TypeAAAA:
		records, rcode = p.resolveAddress(q.Name, q.Qtype, trusted)
		needsForward = rcode == mdns.RcodeNameError
	case mdns.TypeANY:
		records, rcode, needsForward = p.resolveANY(q.Name, trusted)
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

// resolveANY implements RFC 8482 mitigation for QTYPE ANY (255). Instead of
// returning every RRset at the name, the server answers with a single synthesized
// HINFO record and sets the TC bit to discourage amplification.
func (p *Processor) resolveANY(name string, trusted bool) ([]mdns.RR, int, bool) {
	if !p.nameExistsInZone(name, trusted) {
		return nil, mdns.RcodeNameError, true
	}

	if soa := p.lookupZoneSOA(name, trusted); soa != nil {
		return []mdns.RR{mdns.Copy(soa)}, mdns.RcodeSuccess, false
	}

	hinfo := &mdns.HINFO{
		Hdr: mdns.RR_Header{
			Name:   storage.NormalizeName(name),
			Rrtype: mdns.TypeHINFO,
			Class:  mdns.ClassINET,
			Ttl:    300,
		},
		Cpu: "RFC8482",
		Os:  "https://datatracker.ietf.org/doc/html/rfc8482",
	}
	return []mdns.RR{hinfo}, mdns.RcodeSuccess, false
}

func (p *Processor) nameExistsInZone(name string, trusted bool) bool {
	if trusted && p.store.NameExistsInternal(name) {
		return true
	}
	return p.store.NameExistsPublic(name)
}

func (p *Processor) lookupZoneSOA(name string, trusted bool) mdns.RR {
	labels := splitDNSLabels(storage.NormalizeName(name))
	for i := len(labels) - 1; i >= 0; i-- {
		apex := strings.Join(labels[i:], ".") + "."
		records, status := p.authoritativeLookup(apex, mdns.TypeSOA, trusted)
		if status == storage.LookupFound && len(records) > 0 {
			return records[0]
		}
	}
	return nil
}

func splitDNSLabels(fqdn string) []string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == "" {
		return nil
	}
	return strings.Split(fqdn, ".")
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
