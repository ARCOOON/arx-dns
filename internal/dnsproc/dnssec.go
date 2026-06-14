package dnsproc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

// ErrDNSSECValidationFailed indicates upstream data failed cryptographic DNSSEC checks.
var ErrDNSSECValidationFailed = errors.New("dnssec validation failed")

// DNSSECValidator verifies RRSIG records in upstream responses using DNSKEY material.
type DNSSECValidator struct {
	forwarder *Forwarder
	stats     *telemetry.Stats
	logger    *slog.Logger
}

// NewDNSSECValidator builds a validator that reuses the upstream forwarder for DNSKEY lookups.
func NewDNSSECValidator(forwarder *Forwarder, stats *telemetry.Stats, logger *slog.Logger) *DNSSECValidator {
	return &DNSSECValidator{
		forwarder: forwarder,
		stats:     stats,
		logger:    logger,
	}
}

// Validate inspects resp for RRSIG records and cryptographically verifies each signature.
// When no RRSIG records are present, validation is skipped and authenticated is false.
// When verification succeeds, authenticated is true. A non-nil error means BOGUS data.
func (v *DNSSECValidator) Validate(resp *mdns.Msg) (authenticated bool, err error) {
	if v == nil || resp == nil {
		return false, nil
	}

	rrsigs := collectRRSIGs(resp)
	if len(rrsigs) == 0 {
		return false, nil
	}

	for _, sig := range rrsigs {
		rrset := collectRRSet(resp, sig)
		if len(rrset) == 0 {
			return false, fmt.Errorf("%w: no records for rrsig type %s owner %s",
				ErrDNSSECValidationFailed,
				mdns.TypeToString[sig.TypeCovered],
				sig.Hdr.Name,
			)
		}

		if err := v.verifySignature(sig, rrset); err != nil {
			return false, err
		}
	}

	if v.stats != nil {
		v.stats.IncDNSSECValidationPassed()
	}
	return true, nil
}

func (v *DNSSECValidator) verifySignature(sig *mdns.RRSIG, rrset []mdns.RR) error {
	now := uint32(time.Now().Unix())
	if now < sig.Inception || now > sig.Expiration {
		return fmt.Errorf("%w: signature outside validity period for %s",
			ErrDNSSECValidationFailed, sig.Hdr.Name)
	}

	keys, err := v.fetchDNSKEYs(sig.SignerName)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDNSSECValidationFailed, err)
	}

	var lastErr error
	for _, rr := range keys {
		key, ok := rr.(*mdns.DNSKEY)
		if !ok {
			continue
		}
		if sig.KeyTag != key.KeyTag() {
			continue
		}
		if err := sig.Verify(key, rrset); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrDNSSECValidationFailed, lastErr)
	}
	return fmt.Errorf("%w: no matching dnskey for key tag %d zone %s",
		ErrDNSSECValidationFailed, sig.KeyTag, sig.SignerName)
}

func (v *DNSSECValidator) fetchDNSKEYs(zone string) ([]mdns.RR, error) {
	if v.forwarder == nil {
		return nil, errors.New("forwarder is not configured")
	}

	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(zone), mdns.TypeDNSKEY)
	req.RecursionDesired = true

	resp, err := v.forwarder.Exchange(req, netip.Addr{})
	if err != nil {
		return nil, fmt.Errorf("dnskey lookup: %w", err)
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("dnskey lookup rcode %s", mdns.RcodeToString[resp.Rcode])
	}

	keys := make([]mdns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == mdns.TypeDNSKEY {
			keys = append(keys, rr)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("dnskey lookup returned no DNSKEY records")
	}
	return keys, nil
}

func collectRRSIGs(msg *mdns.Msg) []*mdns.RRSIG {
	sections := [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra}
	out := make([]*mdns.RRSIG, 0)

	for _, section := range sections {
		for _, rr := range section {
			sig, ok := rr.(*mdns.RRSIG)
			if ok {
				out = append(out, sig)
			}
		}
	}
	return out
}

func collectRRSet(msg *mdns.Msg, sig *mdns.RRSIG) []mdns.RR {
	sections := [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra}
	out := make([]mdns.RR, 0)

	for _, section := range sections {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == mdns.TypeRRSIG {
				continue
			}
			if h.Rrtype == sig.TypeCovered &&
				h.Class == sig.Hdr.Class &&
				mdns.CanonicalName(h.Name) == mdns.CanonicalName(sig.Hdr.Name) {
				out = append(out, rr)
			}
		}
	}
	return out
}
