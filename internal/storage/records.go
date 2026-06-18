package storage

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	mdns "github.com/miekg/dns"
)

// RecordInput is the JSON payload for creating or deleting a DNS record via the API.
type RecordInput struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     uint32 `json:"-"`
	TTLText string `json:"-"`
	Value   string `json:"value"`
	View    string `json:"view,omitempty"`
}

// UnmarshalJSON accepts ttl as a BIND string ("1h", "5m") or a plain number.
func (in *RecordInput) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name  string          `json:"name"`
		Type  string          `json:"type"`
		Value string          `json:"value"`
		TTL   json.RawMessage `json:"ttl"`
		View  string          `json:"view,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	in.Name = raw.Name
	in.Type = raw.Type
	in.Value = raw.Value
	in.View = raw.View
	in.TTL = 0
	in.TTLText = ""

	if len(raw.TTL) == 0 {
		return nil
	}

	var ttlNumber uint32
	if err := json.Unmarshal(raw.TTL, &ttlNumber); err == nil {
		in.TTL = ttlNumber
		return nil
	}

	var ttlString string
	if err := json.Unmarshal(raw.TTL, &ttlString); err != nil {
		return fmt.Errorf("ttl must be a number or BIND TTL string")
	}
	in.TTLText = strings.TrimSpace(ttlString)
	return nil
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

	ttl, ttlText, err := ResolveRecordTTL(in)
	if err != nil {
		return nil, err
	}
	in.TTL = ttl
	in.TTLText = ttlText

	switch typ {
	case "MX":
		return buildMXRecord(fqdn, ttl, value)
	case "TXT":
		return buildTXTRecord(fqdn, ttl, value)
	case "SRV":
		return buildSRVRecord(fqdn, ttl, value)
	case "NS":
		return buildNSRecord(fqdn, ttl, value)
	case "SOA":
		return buildSOARecord(fqdn, ttl, value)
	case "PTR":
		return buildPTRRecord(fqdn, ttl, value)
	case "CAA":
		return buildCAARecord(fqdn, ttl, value)
	case "SVCB", "HTTPS":
		return buildSVCBRecord(fqdn, ttl, typ, value)
	default:
		if isRFC3597TypeName(typ) {
			if !strings.HasPrefix(typ, "TYPE") {
				typ = "TYPE" + typ
			}
			return buildRFC3597Record(fqdn, ttl, typ, value)
		}
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

func buildNSRecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	target, err := qualifyHostTarget(value)
	if err != nil {
		return nil, fmt.Errorf("invalid NS target: %w", err)
	}

	return &mdns.NS{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypeNS,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Ns: target,
	}, nil
}

func buildSOARecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	ns, mbox, serial, refresh, retry, expire, minimum, err := parseSOAValue(value)
	if err != nil {
		return nil, err
	}

	return &mdns.SOA{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypeSOA,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      ns,
		Mbox:    mbox,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minttl:  minimum,
	}, nil
}

func buildPTRRecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	target, err := qualifyHostTarget(value)
	if err != nil {
		return nil, fmt.Errorf("invalid PTR target: %w", err)
	}

	return &mdns.PTR{
		Hdr: mdns.RR_Header{
			Name:   owner,
			Rrtype: mdns.TypePTR,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: target,
	}, nil
}

func buildCAARecord(owner string, ttl uint32, value string) (mdns.RR, error) {
	line := fmt.Sprintf("%s %d IN CAA %s", owner, ttl, value)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("invalid CAA record: %w", err)
	}
	return rr, nil
}

func buildSVCBRecord(owner string, ttl uint32, typ, value string) (mdns.RR, error) {
	line := fmt.Sprintf("%s %d IN %s %s", owner, ttl, typ, value)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("invalid %s record: %w", typ, err)
	}
	return rr, nil
}

func isRFC3597TypeName(typ string) bool {
	if strings.HasPrefix(typ, "TYPE") {
		return true
	}
	if _, known := mdns.StringToType[typ]; known {
		return false
	}
	_, err := strconv.ParseUint(typ, 10, 16)
	return err == nil
}

// parseRFC3597Value normalizes API and BIND generic RDATA into \# <length> <hex> form
// and validates that the declared length matches the decoded hex payload.
func parseRFC3597Value(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("RFC 3597 value is required")
	}

	raw := value
	if strings.HasPrefix(raw, `\#`) {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, `\#`))
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", fmt.Errorf("RFC 3597 value is required")
	}

	var (
		declaredLen int
		hexPayload  string
	)

	if len(fields) == 1 {
		hexPayload = strings.ToLower(fields[0])
		if len(hexPayload)%2 != 0 {
			return "", fmt.Errorf("RFC 3597 hex data must have an even number of digits")
		}
		declaredLen = len(hexPayload) / 2
	} else {
		lengthField, err := strconv.Atoi(fields[0])
		if err != nil || lengthField < 0 || lengthField > 65535 {
			return "", fmt.Errorf("RFC 3597 length must be an integer between 0 and 65535")
		}
		declaredLen = lengthField
		hexPayload = strings.ToLower(strings.Join(fields[1:], ""))
	}

	if hexPayload == "" {
		if declaredLen != 0 {
			return "", fmt.Errorf("RFC 3597 hex data is required")
		}
		return `\# 0`, nil
	}

	if len(hexPayload)%2 != 0 {
		return "", fmt.Errorf("RFC 3597 hex data must have an even number of digits")
	}
	if _, err := hex.DecodeString(hexPayload); err != nil {
		return "", fmt.Errorf("RFC 3597 hex data is invalid: %w", err)
	}
	actualLen := len(hexPayload) / 2
	if actualLen != declaredLen {
		return "", fmt.Errorf("RFC 3597 length %d does not match hex data (%d octets)", declaredLen, actualLen)
	}

	return fmt.Sprintf(`\# %d %s`, declaredLen, hexPayload), nil
}

func buildRFC3597Record(owner string, ttl uint32, typ string, value string) (mdns.RR, error) {
	num := strings.TrimPrefix(typ, "TYPE")
	if num == "" {
		return nil, fmt.Errorf("invalid record type %q", typ)
	}
	typeCode, err := strconv.ParseUint(num, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid record type %q", typ)
	}

	rdata, err := parseRFC3597Value(value)
	if err != nil {
		return nil, err
	}

	line := fmt.Sprintf("%s %d IN %s %s", owner, ttl, typ, rdata)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("invalid %s record: %w", typ, err)
	}
	if _, ok := rr.(*mdns.RFC3597); !ok {
		return nil, fmt.Errorf("%s did not produce an RFC 3597 record", typ)
	}
	if rr.Header().Rrtype != uint16(typeCode) {
		return nil, fmt.Errorf("record type mismatch for %s", typ)
	}
	return rr, nil
}

func parseSOAValue(value string) (ns, mbox string, serial, refresh, retry, expire, minimum uint32, err error) {
	fields := strings.Fields(value)
	if len(fields) < 7 {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("SOA value must be ns mbox serial refresh retry expire minimum")
	}

	ns, err = qualifyHostTarget(fields[0])
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("invalid SOA nameserver: %w", err)
	}
	mbox, err = qualifyHostTarget(fields[1])
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, fmt.Errorf("invalid SOA mailbox: %w", err)
	}

	serial, err = parseSOAField(fields[2], "serial")
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, err
	}
	refresh, err = parseSOAField(fields[3], "refresh")
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, err
	}
	retry, err = parseSOAField(fields[4], "retry")
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, err
	}
	expire, err = parseSOAField(fields[5], "expire")
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, err
	}
	minimum, err = parseSOAField(fields[6], "minimum")
	if err != nil {
		return "", "", 0, 0, 0, 0, 0, err
	}

	return ns, mbox, serial, refresh, retry, expire, minimum, nil
}

func parseSOAField(raw, field string) (uint32, error) {
	seconds, _, err := ParseBindTTL(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid SOA %s %q", field, raw)
	}
	return seconds, nil
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
	if strings.HasPrefix(typeName, "TYPE") {
		num := strings.TrimPrefix(typeName, "TYPE")
		if num == "" {
			return 0, fmt.Errorf("invalid record type %q", typeName)
		}
		n, err := strconv.ParseUint(num, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid record type %q", typeName)
		}
		return uint16(n), nil
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
	case *mdns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			typed.Ns, typed.Mbox, typed.Serial, typed.Refresh, typed.Retry, typed.Expire, typed.Minttl)
	case *mdns.CAA:
		return fmt.Sprintf("%d %s %s", typed.Flag, typed.Tag, formatCAAValue(typed.Value))
	case *mdns.RFC3597:
		return formatRFC3597Rdata(typed)
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

func formatCAAValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\"") {
		return `"` + escapeTXTChunk(value) + `"`
	}
	return value
}

func formatRFC3597Rdata(rr *mdns.RFC3597) string {
	if rr == nil {
		return ""
	}
	return fmt.Sprintf(`\# %d %s`, len(rr.Rdata)/2, rr.Rdata)
}

func recordValuesMatch(rr mdns.RR, want string) bool {
	got := rrDataValue(rr)
	if r3597, ok := rr.(*mdns.RFC3597); ok {
		wantNorm, err := parseRFC3597Value(want)
		if err == nil {
			return formatRFC3597Rdata(r3597) == wantNorm
		}
	}
	return got == want
}
