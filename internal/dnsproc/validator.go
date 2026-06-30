package dnsproc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ARCOOON/arx-dns/internal/dnssec"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

// ErrDNSSECValidationFailed indicates upstream data failed cryptographic DNSSEC checks.
var ErrDNSSECValidationFailed = errors.New("dnssec validation failed")

// DNSSECValidator verifies RRSIG records and establishes a chain of trust from root anchors.
type DNSSECValidator struct {
	resolver ExchangeResolver
	stats    *telemetry.Stats
	logger   *slog.Logger
}

// NewDNSSECValidator builds a validator that reuses the configured resolver for chain lookups.
func NewDNSSECValidator(resolver ExchangeResolver, stats *telemetry.Stats, logger *slog.Logger) *DNSSECValidator {
	return &DNSSECValidator{
		resolver: resolver,
		stats:    stats,
		logger:   logger,
	}
}

// Validate inspects resp for RRSIG records, walks the chain of trust from root anchors,
// and cryptographically verifies each signature.
// When no RRSIG records are present the zone is treated as INSECURE (authenticated=false, no error).
// A non-nil error indicates BOGUS data per RFC 4035.
func (v *DNSSECValidator) Validate(resp *mdns.Msg) (authenticated bool, err error) {
	if v == nil || resp == nil {
		return false, nil
	}

	rrsigs := collectRRSIGs(resp)
	if len(rrsigs) == 0 {
		return false, nil
	}

	trustedZones := make(map[string][]mdns.RR)
	for _, sig := range rrsigs {
		zone := mdns.CanonicalName(sig.SignerName)
		if _, ok := trustedZones[zone]; ok {
			continue
		}
		keys, err := v.establishTrust(zone)
		if err != nil {
			return false, err
		}
		trustedZones[zone] = keys
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
		zone := mdns.CanonicalName(sig.SignerName)
		keys := trustedZones[zone]
		if err := Validate(rrset, []mdns.RR{sig}, keys); err != nil {
			return false, err
		}
	}

	if v.stats != nil {
		v.stats.IncDNSSECValidationPassed()
	}
	return true, nil
}

// Validate performs cryptographic verification of RRSIG records against an RRset using DNSKEY material.
func Validate(rrset []mdns.RR, sigs []mdns.RR, keys []mdns.RR) error {
	if len(rrset) == 0 {
		return fmt.Errorf("%w: empty rrset", ErrDNSSECValidationFailed)
	}
	if len(sigs) == 0 {
		return fmt.Errorf("%w: no rrsig records", ErrDNSSECValidationFailed)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no dnskey records", ErrDNSSECValidationFailed)
	}

	now := uint32(time.Now().Unix())
	for _, sigRR := range sigs {
		sig, ok := sigRR.(*mdns.RRSIG)
		if !ok {
			return fmt.Errorf("%w: non-rrsig in sigs slice", ErrDNSSECValidationFailed)
		}
		if now < sig.Inception || now > sig.Expiration {
			return fmt.Errorf("%w: signature outside validity period for %s",
				ErrDNSSECValidationFailed, sig.Hdr.Name)
		}

		var lastErr error
		verified := false
		for _, keyRR := range keys {
			key, ok := keyRR.(*mdns.DNSKEY)
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
			verified = true
			break
		}
		if !verified {
			if lastErr != nil {
				return fmt.Errorf("%w: %v", ErrDNSSECValidationFailed, lastErr)
			}
			return fmt.Errorf("%w: no matching dnskey for key tag %d signer %s",
				ErrDNSSECValidationFailed, sig.KeyTag, sig.SignerName)
		}
	}
	return nil
}

func (v *DNSSECValidator) establishTrust(signerZone string) ([]mdns.RR, error) {
	signerZone = mdns.CanonicalName(signerZone)

	parentKeys, err := v.validateRootZone()
	if err != nil {
		return nil, err
	}
	if signerZone == "." {
		return parentKeys, nil
	}

	for _, zone := range zoneCutPath(signerZone) {
		keys, err := v.validateZoneDelegation(zone, parentKeys)
		if err != nil {
			return nil, err
		}
		parentKeys = keys
	}
	return parentKeys, nil
}

// validateRootZone fetches the live root DNSKEY RRset, verifies its RRSIG with the
// zone ZSK, confirms embedded KSK trust anchors are present, and returns the full RRset.
func (v *DNSSECValidator) validateRootZone() ([]mdns.RR, error) {
	anchors := dnssec.RootAnchors()
	if len(anchors) == 0 {
		return nil, fmt.Errorf("%w: root anchors are not initialized", ErrDNSSECValidationFailed)
	}

	dnskeys, dnskeySigs, err := v.fetchSignedRRSet(".", mdns.TypeDNSKEY)
	if err != nil {
		return nil, fmt.Errorf("%w: root dnskey lookup: %v", ErrDNSSECValidationFailed, err)
	}
	if len(dnskeys) == 0 {
		return nil, fmt.Errorf("%w: no root dnskey records", ErrDNSSECValidationFailed)
	}
	if err := Validate(dnskeys, dnskeySigs, dnskeys); err != nil {
		return nil, fmt.Errorf("%w: root dnskey signature: %v", ErrDNSSECValidationFailed, err)
	}
	if !anchorsMatchRootTrust(anchors, dnskeys) {
		return nil, fmt.Errorf("%w: root dnskey set does not contain trust anchor", ErrDNSSECValidationFailed)
	}
	return dnskeys, nil
}

func (v *DNSSECValidator) validateZoneDelegation(zone string, parentKeys []mdns.RR) ([]mdns.RR, error) {
	zone = mdns.CanonicalName(zone)

	// Step 1: verify the DS RRset using the parent's validated DNSKEY RRset (ZSK signs DS).
	dsRecords, dsSigs, err := v.fetchSignedRRSet(zone, mdns.TypeDS)
	if err != nil {
		return nil, fmt.Errorf("%w: ds lookup %s: %v", ErrDNSSECValidationFailed, zone, err)
	}
	if len(dsRecords) == 0 {
		return nil, fmt.Errorf("%w: no ds records for zone %s", ErrDNSSECValidationFailed, zone)
	}
	if err := Validate(dsRecords, dsSigs, parentKeys); err != nil {
		return nil, fmt.Errorf("%w: ds signature for %s: %v", ErrDNSSECValidationFailed, zone, err)
	}

	// Step 2: fetch child DNSKEY RRset and verify its RRSIG (ZSK signs DNSKEY).
	dnskeys, dnskeySigs, err := v.fetchSignedRRSet(zone, mdns.TypeDNSKEY)
	if err != nil {
		return nil, fmt.Errorf("%w: dnskey lookup %s: %v", ErrDNSSECValidationFailed, zone, err)
	}
	if len(dnskeys) == 0 {
		return nil, fmt.Errorf("%w: no dnskey records for zone %s", ErrDNSSECValidationFailed, zone)
	}
	if err := Validate(dnskeys, dnskeySigs, dnskeys); err != nil {
		return nil, fmt.Errorf("%w: dnskey signature for %s: %v", ErrDNSSECValidationFailed, zone, err)
	}

	// Step 3: confirm DS digest matches a KSK in the validated DNSKEY RRset.
	if !dsMatchesKSK(dsRecords, dnskeys) {
		return nil, fmt.Errorf("%w: ds digest mismatch for zone %s", ErrDNSSECValidationFailed, zone)
	}

	return dnskeys, nil
}

func (v *DNSSECValidator) fetchSignedRRSet(name string, qtype uint16) (rrset []mdns.RR, sigs []mdns.RR, err error) {
	if v.resolver == nil {
		return nil, nil, errors.New("resolver is not configured")
	}

	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), qtype)
	req.RecursionDesired = true

	resp, err := v.resolver.Exchange(req, netip.Addr{})
	if err != nil {
		return nil, nil, fmt.Errorf("exchange: %w", err)
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, nil, fmt.Errorf("rcode %s", mdns.RcodeToString[resp.Rcode])
	}

	sections := [][]mdns.RR{resp.Answer, resp.Ns, resp.Extra}
	for _, section := range sections {
		for _, rr := range section {
			switch h := rr.Header(); {
			case h.Rrtype == qtype && mdns.CanonicalName(h.Name) == mdns.CanonicalName(name):
				rrset = append(rrset, rr)
			case h.Rrtype == mdns.TypeRRSIG:
				if sig, ok := rr.(*mdns.RRSIG); ok && sig.TypeCovered == qtype &&
					mdns.CanonicalName(sig.Hdr.Name) == mdns.CanonicalName(name) {
					sigs = append(sigs, rr)
				}
			}
		}
	}
	return rrset, sigs, nil
}

func anchorsMatchRootTrust(anchors, dnskeys []mdns.RR) bool {
	dsRecords := make([]mdns.RR, 0, len(anchors))
	for _, anchorRR := range anchors {
		if ds, ok := anchorRR.(*mdns.DS); ok {
			dsRecords = append(dsRecords, ds)
		}
	}
	if len(dsRecords) > 0 && dsMatchesKSK(dsRecords, dnskeys) {
		return true
	}
	return anchorsPresentInDNSKEYs(anchors, dnskeys)
}

func anchorsPresentInDNSKEYs(anchors, dnskeys []mdns.RR) bool {
	for _, anchorRR := range anchors {
		anchor, ok := anchorRR.(*mdns.DNSKEY)
		if !ok {
			continue
		}
		for _, keyRR := range dnskeys {
			key, ok := keyRR.(*mdns.DNSKEY)
			if !ok {
				continue
			}
			if anchor.KeyTag() == key.KeyTag() &&
				anchor.Algorithm == key.Algorithm &&
				anchor.Flags == key.Flags &&
				anchor.Protocol == key.Protocol &&
				strings.EqualFold(anchor.PublicKey, key.PublicKey) {
				return true
			}
		}
	}
	return false
}

func dsMatchesKSK(dsRecords []mdns.RR, dnskeys []mdns.RR) bool {
	ksks := make([]*mdns.DNSKEY, 0, len(dnskeys))
	for _, rr := range dnskeys {
		key, ok := rr.(*mdns.DNSKEY)
		if !ok {
			continue
		}
		if key.Flags&mdns.SEP != 0 {
			ksks = append(ksks, key)
		}
	}
	if len(ksks) == 0 {
		return false
	}

	for _, dsRR := range dsRecords {
		ds, ok := dsRR.(*mdns.DS)
		if !ok {
			continue
		}
		for _, ksk := range ksks {
			computed := ksk.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if computed.KeyTag == ds.KeyTag &&
				computed.Algorithm == ds.Algorithm &&
				computed.DigestType == ds.DigestType &&
				strings.EqualFold(computed.Digest, ds.Digest) {
				return true
			}
		}
	}
	return false
}

func zoneCutPath(signerZone string) []string {
	signerZone = mdns.CanonicalName(signerZone)
	if signerZone == "." {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(signerZone, "."), ".")
	cuts := make([]string, len(parts))
	for i := 0; i < len(parts); i++ {
		idx := len(parts) - 1 - i
		cuts[i] = strings.Join(parts[idx:], ".") + "."
	}
	return cuts
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
