package dnssec

import (
	"crypto"
	"fmt"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	defaultSignatureLifetime = 30 * 24 * time.Hour
	defaultInceptionSkew     = time.Hour
)

type rrsetKey struct {
	name   string
	rrtype uint16
}

// SignZone signs every RRset in records, injects DNSKEY records at the apex,
// and generates an NSEC chain for authenticated denial of existence.
func SignZone(origin string, records []mdns.RR, ksk, zsk *KeyMaterial) ([]mdns.RR, error) {
	if ksk == nil || zsk == nil || ksk.DNSKEY == nil || zsk.DNSKEY == nil {
		return nil, fmt.Errorf("ksk and zsk are required")
	}

	origin = mdns.CanonicalName(origin)
	unsigned := filterUnsignedRecords(records)
	if len(unsigned) == 0 {
		return nil, fmt.Errorf("zone %s has no records to sign", origin)
	}

	ttl := zoneTTL(unsigned)
	now := time.Now().UTC()
	inception := uint32(now.Add(-defaultInceptionSkew).Unix())
	expiration := uint32(now.Add(defaultSignatureLifetime).Unix())

	kskRR := mdns.Copy(ksk.DNSKEY).(*mdns.DNSKEY)
	zskRR := mdns.Copy(zsk.DNSKEY).(*mdns.DNSKEY)
	kskRR.Hdr.Ttl = ttl
	zskRR.Hdr.Ttl = ttl

	unsigned = ensureUniqueApexSOA(unsigned, origin)
	unsigned = bumpSOASerial(unsigned, origin)

	typesAtName := collectTypesAtName(unsigned)
	if typesAtName[origin] == nil {
		typesAtName[origin] = make(map[uint16]struct{})
	}
	typesAtName[origin][mdns.TypeDNSKEY] = struct{}{}
	nsecRecords := buildNSECChain(origin, typesAtName, ttl)

	signed := make([]mdns.RR, 0, len(unsigned)+len(nsecRecords)+32)
	signed = append(signed, unsigned...)
	signed = append(signed, kskRR, zskRR)
	signed = append(signed, nsecRecords...)

	rrsets := groupRRsets(signed)
	for _, rrset := range rrsets {
		if len(rrset) == 0 {
			continue
		}
		hdr := rrset[0].Header()
		if hdr.Rrtype == mdns.TypeRRSIG {
			continue
		}

		signerKey := zsk
		if hdr.Rrtype == mdns.TypeDNSKEY {
			signerKey = ksk
		}

		signer, ok := signerKey.Private.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key for %s is not a signer", signerKey.KeyType)
		}

		sig, err := signRRset(signer, signerKey.DNSKEY, rrset, origin, ttl, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("sign %s %s: %w", hdr.Name, mdns.Type(hdr.Rrtype), err)
		}
		signed = append(signed, sig)
	}

	sortSignedRecords(signed)
	return signed, nil
}

func filterUnsignedRecords(records []mdns.RR) []mdns.RR {
	out := make([]mdns.RR, 0, len(records))
	for _, rr := range records {
		if rr == nil {
			continue
		}
		switch rr.Header().Rrtype {
		case mdns.TypeRRSIG, mdns.TypeNSEC, mdns.TypeDNSKEY:
			continue
		}
		out = append(out, mdns.Copy(rr))
	}
	return out
}

func zoneTTL(records []mdns.RR) uint32 {
	for _, rr := range records {
		if rr.Header().Rrtype == mdns.TypeSOA {
			if soa, ok := rr.(*mdns.SOA); ok && soa.Hdr.Ttl > 0 {
				return soa.Hdr.Ttl
			}
		}
	}
	return 300
}

// ensureUniqueApexSOA keeps a single apex SOA and drops duplicate copies.
func ensureUniqueApexSOA(records []mdns.RR, origin string) []mdns.RR {
	origin = mdns.CanonicalName(origin)
	out := make([]mdns.RR, 0, len(records))
	var apexSOA mdns.RR

	for _, rr := range records {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == mdns.TypeSOA && mdns.CanonicalName(rr.Header().Name) == origin {
			if apexSOA == nil {
				apexSOA = mdns.Copy(rr)
			}
			continue
		}
		out = append(out, mdns.Copy(rr))
	}

	if apexSOA != nil {
		out = append(out, apexSOA)
	}
	return out
}

func bumpSOASerial(records []mdns.RR, origin string) []mdns.RR {
	origin = mdns.CanonicalName(origin)
	out := make([]mdns.RR, 0, len(records))
	var bumped bool

	for _, rr := range records {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == mdns.TypeSOA && mdns.CanonicalName(rr.Header().Name) == origin {
			if bumped {
				continue
			}
			soa, ok := mdns.Copy(rr).(*mdns.SOA)
			if !ok {
				out = append(out, mdns.Copy(rr))
				bumped = true
				continue
			}
			soa.Serial++
			out = append(out, soa)
			bumped = true
			continue
		}
		out = append(out, mdns.Copy(rr))
	}
	return out
}

func collectTypesAtName(records []mdns.RR) map[string]map[uint16]struct{} {
	typesAtName := make(map[string]map[uint16]struct{})
	for _, rr := range records {
		name := mdns.CanonicalName(rr.Header().Name)
		if typesAtName[name] == nil {
			typesAtName[name] = make(map[uint16]struct{})
		}
		typesAtName[name][rr.Header().Rrtype] = struct{}{}
		typesAtName[name][mdns.TypeRRSIG] = struct{}{}
		typesAtName[name][mdns.TypeNSEC] = struct{}{}
	}
	return typesAtName
}

func buildNSECChain(origin string, typesAtName map[string]map[uint16]struct{}, ttl uint32) []mdns.RR {
	names := make([]string, 0, len(typesAtName))
	for name := range typesAtName {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return mdns.CompareDomainName(names[i], names[j]) == -1
	})
	if len(names) == 0 {
		return nil
	}

	out := make([]mdns.RR, 0, len(names))
	for i, name := range names {
		next := names[(i+1)%len(names)]
		types := make([]uint16, 0, len(typesAtName[name]))
		for qtype := range typesAtName[name] {
			types = append(types, qtype)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		out = append(out, &mdns.NSEC{
			Hdr: mdns.RR_Header{
				Name:   name,
				Rrtype: mdns.TypeNSEC,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			NextDomain: next,
			TypeBitMap: types,
		})
	}
	_ = origin
	return out
}

func groupRRsets(records []mdns.RR) [][]mdns.RR {
	order := make([]rrsetKey, 0)
	sets := make(map[rrsetKey][]mdns.RR)

	for _, rr := range records {
		if rr == nil || rr.Header().Rrtype == mdns.TypeRRSIG {
			continue
		}
		key := rrsetKey{
			name:   mdns.CanonicalName(rr.Header().Name),
			rrtype: rr.Header().Rrtype,
		}
		if _, ok := sets[key]; !ok {
			order = append(order, key)
		}
		sets[key] = append(sets[key], mdns.Copy(rr))
	}

	sort.Slice(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return mdns.CompareDomainName(order[i].name, order[j].name) == -1
		}
		return order[i].rrtype < order[j].rrtype
	})

	out := make([][]mdns.RR, 0, len(order))
	for _, key := range order {
		rrset := sets[key]
		sort.Slice(rrset, func(i, j int) bool {
			return rrsetCanonicalLess(rrset[i], rrset[j])
		})
		out = append(out, rrset)
	}
	return out
}

func signRRset(
	signer crypto.Signer,
	dnskey *mdns.DNSKEY,
	rrset []mdns.RR,
	origin string,
	ttl, inception, expiration uint32,
) (*mdns.RRSIG, error) {
	if len(rrset) == 0 {
		return nil, fmt.Errorf("empty rrset")
	}

	hdr := rrset[0].Header()
	sig := &mdns.RRSIG{
		Hdr: mdns.RR_Header{
			Name:   hdr.Name,
			Rrtype: mdns.TypeRRSIG,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   dnskey.Algorithm,
		Labels:      ownerLabelCount(hdr.Name),
		OrigTtl:     hdr.Ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  origin,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		return nil, err
	}
	return sig, nil
}

func ownerLabelCount(name string) uint8 {
	name = strings.TrimSuffix(mdns.CanonicalName(name), ".")
	if name == "" {
		return 0
	}
	return uint8(strings.Count(name, ".") + 1)
}

func rrsetCanonicalLess(left, right mdns.RR) bool {
	return left.String() < right.String()
}

func sortSignedRecords(records []mdns.RR) {
	sort.Slice(records, func(i, j int) bool {
		left := records[i].Header()
		right := records[j].Header()
		if left.Name != right.Name {
			return mdns.CompareDomainName(left.Name, right.Name) == -1
		}
		if left.Rrtype != right.Rrtype {
			return left.Rrtype < right.Rrtype
		}
		return rrsetCanonicalLess(records[i], records[j])
	})
}
