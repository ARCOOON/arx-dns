package acl

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	mdns "github.com/miekg/dns"
)

// ZoneView identifies a split-DNS view selected by the ACL engine.
type ZoneView string

const (
	ViewPublic   ZoneView = "public"
	ViewInternal ZoneView = "internal"
)

const (
	// KeywordAny matches every client address in a match list.
	KeywordAny = "any"
	// KeywordNone denies every client address in a match list.
	KeywordNone      = "none"
	keywordLocalhost = "localhost"
)

type entryKind int

const (
	entryIP entryKind = iota
	entryNamed
	entryAny
	entryNone
	entryLocalhost
)

// MatchEntry is one element of a BIND-style match list.
type MatchEntry struct {
	kind   entryKind
	prefix netip.Prefix
	name   string
}

// MatchList is an ordered set of match entries evaluated with OR semantics.
type MatchList struct {
	entries []MatchEntry
}

// PolicySet groups the three BIND ACL directives for one scope.
type PolicySet struct {
	AllowQuery     *MatchList
	AllowRecursion *MatchList
	AllowTransfer  *MatchList
}

// ViewRule selects a zone view for clients matching match_clients.
type ViewRule struct {
	Name         string
	MatchClients *MatchList
	UseECS       bool
}

// Engine evaluates BIND9-style ACLs and view selection at runtime.
type Engine struct {
	named           map[string]*MatchList
	global          PolicySet
	zones           map[string]PolicySet
	views           []ViewRule
	defaultView     ZoneView
	legacyRecursion *MatchList
}

// ACL wraps a single match list for direct Allow checks.
type ACL struct {
	list  *MatchList
	named map[string]*MatchList
}

// NewACL returns an ACL backed by list and optional named list registry.
func NewACL(list *MatchList, named map[string]*MatchList) *ACL {
	return &ACL{list: list, named: named}
}

// Allow reports whether ip matches the wrapped match list (OR semantics).
func (a *ACL) Allow(ip net.IP) bool {
	if a == nil || a.list == nil {
		return true
	}
	addr, ok := addrFromIP(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	return a.list.contains(addr, a.named)
}

// ParseMatchList builds a match list from string elements (IPs, CIDRs, keywords, named ACLs).
func ParseMatchList(elements []string) (*MatchList, error) {
	if len(elements) == 0 {
		return nil, nil
	}

	list := &MatchList{entries: make([]MatchEntry, 0, len(elements))}
	for _, raw := range elements {
		entry, err := parseMatchElement(raw)
		if err != nil {
			return nil, err
		}
		list.entries = append(list.entries, entry)
	}
	return list, nil
}

func parseMatchElement(raw string) (MatchEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return MatchEntry{}, fmt.Errorf("empty match list element")
	}

	lower := strings.ToLower(raw)
	switch lower {
	case KeywordAny:
		return MatchEntry{kind: entryAny}, nil
	case KeywordNone:
		return MatchEntry{kind: entryNone}, nil
	case keywordLocalhost:
		return MatchEntry{kind: entryLocalhost}, nil
	}

	if ip := net.ParseIP(raw); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return MatchEntry{}, fmt.Errorf("invalid ip %q", raw)
		}
		addr = addr.Unmap()
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		return MatchEntry{
			kind:   entryIP,
			prefix: netip.PrefixFrom(addr, bits).Masked(),
		}, nil
	}

	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return MatchEntry{
			kind:   entryIP,
			prefix: prefix.Masked(),
		}, nil
	}

	return MatchEntry{kind: entryNamed, name: lower}, nil
}

// BuildNamedLists parses configured named ACL definitions.
func BuildNamedLists(lists map[string][]string) (map[string]*MatchList, error) {
	out := make(map[string]*MatchList, len(lists))
	for name, elements := range lists {
		canonical := strings.ToLower(strings.TrimSpace(name))
		if canonical == "" {
			return nil, fmt.Errorf("acl named list name must not be empty")
		}
		list, err := ParseMatchList(elements)
		if err != nil {
			return nil, fmt.Errorf("acl list %q: %w", name, err)
		}
		if list == nil {
			list = &MatchList{}
		}
		out[canonical] = list
	}
	if err := resolveNamedReferences(out); err != nil {
		return nil, err
	}
	return out, nil
}

func resolveNamedReferences(named map[string]*MatchList) error {
	visiting := make(map[string]bool)
	visited := make(map[string]bool)

	var walk func(name string) error
	walk = func(name string) error {
		if visited[name] {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("circular acl reference involving %q", name)
		}
		list, ok := named[name]
		if !ok {
			return fmt.Errorf("undefined acl %q", name)
		}
		visiting[name] = true
		for _, entry := range list.entries {
			if entry.kind != entryNamed {
				continue
			}
			if err := walk(entry.name); err != nil {
				return err
			}
		}
		visiting[name] = false
		visited[name] = true
		return nil
	}

	for name := range named {
		if err := walk(name); err != nil {
			return err
		}
	}
	return nil
}

// NewEngine constructs a runtime ACL engine from parsed configuration.
func NewEngine(named map[string]*MatchList, global PolicySet, zones map[string]PolicySet, views []ViewRule, defaultView ZoneView, legacyRecursion *MatchList) *Engine {
	if named == nil {
		named = make(map[string]*MatchList)
	}
	if zones == nil {
		zones = make(map[string]PolicySet)
	}
	if defaultView == "" {
		defaultView = ViewPublic
	}
	return &Engine{
		named:           named,
		global:          global,
		zones:           zones,
		views:           views,
		defaultView:     defaultView,
		legacyRecursion: legacyRecursion,
	}
}

func (e *Engine) allow(list *MatchList, addr netip.Addr) bool {
	if e == nil {
		return true
	}
	if list == nil {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	return list.contains(addr.Unmap(), e.named)
}

// AllowQuery reports whether addr may send queries (global policy).
func (e *Engine) AllowQuery(addr netip.Addr) bool {
	return e.allow(e.global.AllowQuery, addr)
}

// AllowQueryZone reports whether addr may query the given authoritative zone apex.
func (e *Engine) AllowQueryZone(addr netip.Addr, zoneApex string) bool {
	if e == nil {
		return true
	}
	if !e.AllowQuery(addr) {
		return false
	}
	zoneApex = normalizeZoneName(zoneApex)
	if zoneApex == "." {
		return true
	}
	policy, ok := e.zones[zoneApex]
	if !ok || policy.AllowQuery == nil {
		return true
	}
	return e.allow(policy.AllowQuery, addr)
}

// AllowRecursion reports whether addr may use recursive resolution.
func (e *Engine) AllowRecursion(addr netip.Addr) bool {
	if e == nil {
		return true
	}
	if e.global.AllowRecursion != nil {
		return e.allow(e.global.AllowRecursion, addr)
	}
	if e.legacyRecursion != nil {
		return e.allow(e.legacyRecursion, addr)
	}
	return false
}

// AllowTransfer reports whether addr may request a zone transfer for zoneApex.
func (e *Engine) AllowTransfer(addr netip.Addr, zoneApex string) bool {
	if e == nil {
		return false
	}
	zoneApex = normalizeZoneName(zoneApex)
	if policy, ok := e.zones[zoneApex]; ok && policy.AllowTransfer != nil {
		return e.allow(policy.AllowTransfer, addr)
	}
	if e.global.AllowTransfer != nil {
		return e.allow(e.global.AllowTransfer, addr)
	}
	return false
}

// SelectView chooses the zone view for a client using configured view rules.
// When ECS is present in req, subnet address is used for rules with UseECS or when no rules match on client IP.
func (e *Engine) SelectView(client netip.Addr, req *mdns.Msg) ZoneView {
	if e == nil || len(e.views) == 0 {
		if e != nil && e.legacyRecursion != nil && e.allow(e.legacyRecursion, client) {
			return ViewInternal
		}
		return ViewPublic
	}

	ecsAddr, hasECS := ecsClientAddr(req)
	candidates := []netip.Addr{client}
	if hasECS {
		candidates = append([]netip.Addr{ecsAddr}, candidates...)
	}

	for _, rule := range e.views {
		addrs := candidates
		if !rule.UseECS {
			addrs = []netip.Addr{client}
		} else if hasECS {
			addrs = []netip.Addr{ecsAddr}
		}
		for _, addr := range addrs {
			if e.allow(rule.MatchClients, addr) {
				return parseViewName(rule.Name)
			}
		}
	}
	return e.defaultView
}

func parseViewName(name string) ZoneView {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case string(ViewInternal):
		return ViewInternal
	default:
		return ViewPublic
	}
}

func normalizeZoneName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func ecsClientAddr(req *mdns.Msg) (netip.Addr, bool) {
	subnet, ok := extractECSSubnet(req)
	if !ok || subnet.Address == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(subnet.Address)
	if !ok {
		return netip.Addr{}, false
	}
	if subnet.SourceNetmask > 0 {
		bits := int(subnet.SourceNetmask)
		if addr.Is4() {
			addr = netip.PrefixFrom(addr, bits).Masked().Addr()
		} else if addr.Is6() {
			addr = netip.PrefixFrom(addr, bits).Masked().Addr()
		}
	}
	return addr.Unmap(), true
}

func extractECSSubnet(req *mdns.Msg) (*mdns.EDNS0_SUBNET, bool) {
	if req == nil {
		return nil, false
	}
	opt := req.IsEdns0()
	if opt == nil {
		return nil, false
	}
	for _, option := range opt.Option {
		subnet, ok := option.(*mdns.EDNS0_SUBNET)
		if ok {
			return subnet, true
		}
	}
	return nil, false
}

func (ml *MatchList) contains(addr netip.Addr, named map[string]*MatchList) bool {
	if ml == nil {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range ml.entries {
		switch entry.kind {
		case entryAny:
			return true
		case entryNone:
			return false
		case entryLocalhost:
			if isLocalhost(addr) {
				return true
			}
		case entryIP:
			if entry.prefix.Contains(addr) {
				return true
			}
		case entryNamed:
			if ref, ok := named[entry.name]; ok && ref.contains(addr, named) {
				return true
			}
		}
	}
	return false
}

func isLocalhost(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	if addr.Is4() {
		return netip.MustParsePrefix("127.0.0.0/8").Contains(addr)
	}
	return false
}

func addrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(ip)
}

// ValidateNamedReferences ensures every named entry in list references a defined ACL.
func ValidateNamedReferences(list *MatchList, named map[string]*MatchList) error {
	if list == nil {
		return nil
	}
	for _, entry := range list.entries {
		if entry.kind != entryNamed {
			continue
		}
		if _, ok := named[entry.name]; !ok {
			return fmt.Errorf("undefined acl %q", entry.name)
		}
	}
	return nil
}
