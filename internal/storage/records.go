package storage

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

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

	switch typ {
	case "MX":
		return buildMXRecord(fqdn, ttl, value)
	case "TXT":
		return buildTXTRecord(fqdn, ttl, value)
	case "SRV":
		return buildSRVRecord(fqdn, ttl, value)
	default:
		line := fmt.Sprintf("%s %d IN %s %s", fqdn, ttl, typ, value)
		rr, err := mdns.NewRR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid record: %w", err)
		}
		return rr, nil
	}
}

func buildMXRecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	preference, exchanger, err := parseMXValue(value)
	if err != nil {
		return nil, err
	}

	return &mdns.MX{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypeMX,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Preference: preference,
		Mx:         exchanger,
	}, nil
}

func buildTXTRecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	chunks, err := parseTXTValue(value)
	if err != nil {
		return nil, err
	}

	return &mdns.TXT{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypeTXT,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Txt: chunks,
	}, nil
}

func buildSRVRecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	priority, weight, port, target, err := parseSRVValue(value)
	if err != nil {
		return nil, err
	}

	return &mdns.SRV{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypeSRV,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Priority: priority,
		Weight:   weight,
		Port:     port,
		Target:   target,
	}, nil
}

func parseMXValue(value string) (uint16, string, error) {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return 0, "", fmt.Errorf("MX value must be preference and hostname (e.g. \"10 mail.example.com\")")
	}

	pref64, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("invalid MX preference %q", fields[0])
	}

	exchanger, err := qualifyHostTarget(fields[1])
	if err != nil {
		return 0, "", fmt.Errorf("invalid MX exchanger: %w", err)
	}

	return uint16(pref64), exchanger, nil
}

func parseSRVValue(value string) (uint16, uint16, uint16, string, error) {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return 0, 0, 0, "", fmt.Errorf("SRV value must be priority weight port target (e.g. \"10 5 5060 sip.example.com\")")
	}

	priority, err := parseSRVField(fields[0], "priority")
	if err != nil {
		return 0, 0, 0, "", err
	}
	weight, err := parseSRVField(fields[1], "weight")
	if err != nil {
		return 0, 0, 0, "", err
	}
	port, err := parseSRVField(fields[2], "port")
	if err != nil {
		return 0, 0, 0, "", err
	}
	if port == 0 {
		return 0, 0, 0, "", fmt.Errorf("invalid SRV port: must be between 1 and 65535")
	}

	target, err := qualifyHostTarget(fields[3])
	if err != nil {
		return 0, 0, 0, "", fmt.Errorf("invalid SRV target: %w", err)
	}

	return priority, weight, port, target, nil
}

func parseSRVField(raw, field string) (uint16, error) {
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid SRV %s %q", field, raw)
	}
	return uint16(n), nil
}

func parseTXTValue(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("TXT value is required")
	}

	if strings.HasPrefix(value, `"`) {
		chunks, err := splitQuotedTXT(value)
		if err != nil {
			return nil, err
		}
		if len(chunks) == 0 {
			return nil, fmt.Errorf("TXT value is required")
		}
		for _, chunk := range chunks {
			if err := validateTXTChunk(chunk); err != nil {
				return nil, err
			}
		}
		return chunks, nil
	}

	if err := validateTXTChunk(value); err != nil {
		return nil, err
	}
	return []string{value}, nil
}

func splitQuotedTXT(value string) ([]string, error) {
	var chunks []string
	rest := strings.TrimSpace(value)

	for rest != "" {
		if !strings.HasPrefix(rest, `"`) {
			return nil, fmt.Errorf("TXT value contains unquoted segments; wrap each chunk in double quotes")
		}

		rest = rest[1:]
		var chunk strings.Builder
		escaped := false
		consumed := 1

		for i, r := range rest {
			consumed = i + 1
			if escaped {
				chunk.WriteRune(r)
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				consumed = i + 1
				goto doneChunk
			}
			chunk.WriteRune(r)
		}
		return nil, fmt.Errorf("TXT value has unterminated quoted string")

	doneChunk:
		chunks = append(chunks, chunk.String())
		rest = strings.TrimSpace(rest[consumed:])
	}

	return chunks, nil
}

func validateTXTChunk(chunk string) error {
	if chunk == "" {
		return fmt.Errorf("TXT chunk must not be empty")
	}
	if len(chunk) > 255 {
		return fmt.Errorf("TXT chunk exceeds 255 octets")
	}
	if !utf8.ValidString(chunk) {
		return fmt.Errorf("TXT chunk must be valid UTF-8")
	}
	return nil
}

func qualifyHostTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("hostname is required")
	}
	if strings.ContainsAny(raw, " \t/\\") {
		return "", fmt.Errorf("hostname contains invalid characters")
	}
	return NormalizeName(raw), nil
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

func formatTXTRdata(chunks []string) string {
	if len(chunks) == 0 {
		return ""
	}
	parts := make([]string, len(chunks))
	for i, chunk := range chunks {
		parts[i] = `"` + escapeTXTChunk(chunk) + `"`
	}
	return strings.Join(parts, " ")
}

func escapeTXTChunk(chunk string) string {
	var b strings.Builder
	for _, r := range chunk {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
