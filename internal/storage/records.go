package storage

import (
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// RecordInput is the JSON payload for creating or deleting a DNS record via the API.
type RecordInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
	View  string `json:"view,omitempty"`
}

// BuildRecord constructs a dns.RR from zone-relative API input.
func BuildRecord(zoneOrigin string, in RecordInput) (mdns.RR, error) {
	fqdn, err := qualifyRecordName(zoneOrigin, in.Name)
	if err != nil {
		return nil, err
	}

	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	if typ == "" {
		return nil, fmt.Errorf("record type is required")
	}

	value := strings.TrimSpace(in.Value)
	if value == "" {
		return nil, fmt.Errorf("record value is required")
	}

	ttl := in.TTL
	if ttl == 0 {
		ttl = 300
	}

	line := fmt.Sprintf("%s %d IN %s %s", fqdn, ttl, typ, value)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("invalid record: %w", err)
	}
	return rr, nil
}

func qualifyRecordName(zoneOrigin, name string) (string, error) {
	zoneOrigin = NormalizeName(zoneOrigin)
	if zoneOrigin == "." {
		return "", fmt.Errorf("invalid zone origin")
	}

	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return zoneOrigin, nil
	}
	if strings.HasSuffix(name, ".") {
		return NormalizeName(name), nil
	}

	apex := strings.TrimSuffix(zoneOrigin, ".")
	return NormalizeName(name + "." + apex), nil
}

func parseRecordType(typeName string) (uint16, error) {
	typeName = strings.ToUpper(strings.TrimSpace(typeName))
	if typeName == "" {
		return 0, fmt.Errorf("record type is required")
	}
	qtype, ok := mdns.StringToType[typeName]
	if !ok {
		return 0, fmt.Errorf("unsupported record type %q", typeName)
	}
	return qtype, nil
}

func rrDataValue(rr mdns.RR) string {
	if rr == nil {
		return ""
	}

	switch typed := rr.(type) {
	case *mdns.A:
		return typed.A.String()
	case *mdns.AAAA:
		return typed.AAAA.String()
	case *mdns.CNAME:
		return typed.Target
	case *mdns.TXT:
		if len(typed.Txt) == 0 {
			return ""
		}
		return strings.Join(typed.Txt, " ")
	case *mdns.NS:
		return typed.Ns
	case *mdns.MX:
		return fmt.Sprintf("%d %s", typed.Preference, typed.Mx)
	case *mdns.PTR:
		return typed.Ptr
	case *mdns.SRV:
		return fmt.Sprintf("%d %d %d %s", typed.Priority, typed.Weight, typed.Port, typed.Target)
	default:
		fields := strings.Fields(rr.String())
		if len(fields) < 5 {
			return ""
		}
		return strings.Join(fields[4:], " ")
	}
}
