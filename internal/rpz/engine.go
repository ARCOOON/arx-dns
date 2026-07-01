package rpz

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/armon/go-radix"
)

// Action selects how a matched query name is answered.
type Action string

const (
	// ActionNXDOMAIN returns RCODE NXDOMAIN.
	ActionNXDOMAIN Action = "NXDOMAIN"
	// ActionNODATA returns NOERROR with an empty answer section.
	ActionNODATA Action = "NODATA"
	// ActionDROP suppresses any DNS response for the query.
	ActionDROP Action = "DROP"
	// ActionCNAME returns a synthetic CNAME record pointing at target.
	ActionCNAME Action = "CNAME"
	// ActionA returns a synthetic A record with the IPv4 address in target.
	ActionA Action = "A"
	// ActionAAAA returns a synthetic AAAA record with the IPv6 address in target.
	ActionAAAA Action = "AAAA"
)

var (
	errUnknownAction      = errors.New("unknown rpz action")
	errEmptyPattern       = errors.New("rpz pattern must not be empty")
	errInvalidWildcard    = errors.New("rpz wildcard pattern must start with *.")
	errCNAMEWithoutTarget = errors.New("rpz CNAME action requires a target")
	errAWithoutTarget     = errors.New("rpz A action requires an IPv4 target")
	errAAAAWithoutTarget  = errors.New("rpz AAAA action requires an IPv6 target")
	errInvalidIPv4Target  = errors.New("rpz A action requires a valid IPv4 address")
	errInvalidIPv6Target  = errors.New("rpz AAAA action requires a valid IPv6 address")
)

type policyEntry struct {
	action Action
	target string
}

type policySnapshot struct {
	exact     map[string]policyEntry
	wildcards *radix.Tree
}

// Engine matches query names against exact and wildcard RPZ policies.
// Lookups load the active snapshot via atomic.Value without locks.
type Engine struct {
	enabled  bool
	snapshot atomic.Value // holds *policySnapshot
}

// New creates an empty RPZ engine. Policies are added with AddPolicy or ReplacePolicies.
func New() *Engine {
	e := &Engine{enabled: true}
	e.snapshot.Store(&policySnapshot{
		exact:     make(map[string]policyEntry),
		wildcards: radix.New(),
	})
	return e
}

// Enabled reports whether policy evaluation is active.
func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	return e.enabled
}

// SetEnabled toggles policy evaluation without clearing loaded policies.
func (e *Engine) SetEnabled(enabled bool) {
	if e == nil {
		return
	}
	e.enabled = enabled
}

// ParseAction validates an RPZ action string.
func ParseAction(raw string) (Action, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(ActionNXDOMAIN), "":
		return ActionNXDOMAIN, nil
	case string(ActionNODATA):
		return ActionNODATA, nil
	case string(ActionDROP):
		return ActionDROP, nil
	case string(ActionCNAME):
		return ActionCNAME, nil
	case string(ActionA):
		return ActionA, nil
	case string(ActionAAAA):
		return ActionAAAA, nil
	default:
		return "", fmt.Errorf("%w: %q", errUnknownAction, raw)
	}
}

// AddPolicy registers one policy pattern. Wildcard patterns use a *.prefix suffix form
// (for example *.example.com) and match subdomains only, not the apex itself.
func (e *Engine) AddPolicy(pattern string, action Action, target string) error {
	if e == nil {
		return errors.New("rpz engine is nil")
	}

	entry, reversedWildcard, err := parsePattern(pattern, action, target)
	if err != nil {
		return err
	}

	for {
		cur := e.snapshot.Load().(*policySnapshot)
		next := cloneSnapshot(cur)

		if reversedWildcard == "" {
			next.exact[normalizeName(pattern)] = entry
		} else {
			next.wildcards.Insert(reversedWildcard, entry)
		}

		if e.snapshot.CompareAndSwap(cur, next) {
			return nil
		}
	}
}

// ReplacePolicies atomically replaces all loaded policies.
func (e *Engine) ReplacePolicies(policies []Policy) error {
	if e == nil {
		return errors.New("rpz engine is nil")
	}

	exact := make(map[string]policyEntry, len(policies))
	wildcards := radix.New()

	for _, policy := range policies {
		entry, reversedWildcard, err := parsePattern(policy.Pattern, policy.Action, policy.Target)
		if err != nil {
			return err
		}
		if reversedWildcard == "" {
			exact[normalizeName(policy.Pattern)] = entry
			continue
		}
		wildcards.Insert(reversedWildcard, entry)
	}

	e.snapshot.Store(&policySnapshot{
		exact:     exact,
		wildcards: wildcards,
	})
	return nil
}

// Policy is one RPZ trigger pattern and its response action.
type Policy struct {
	Pattern string
	Action  Action
	Target  string
}

// PolicyCount returns the number of exact and wildcard policies currently loaded.
func (e *Engine) PolicyCount() int {
	if e == nil {
		return 0
	}
	snap := e.snapshot.Load().(*policySnapshot)
	return len(snap.exact) + snap.wildcards.Len()
}

// Evaluate returns the policy action for qname when a match exists.
func (e *Engine) Evaluate(qname string) (Action, string, bool) {
	if e == nil || !e.enabled {
		return "", "", false
	}

	name := normalizeName(qname)
	if name == "" {
		return "", "", false
	}

	snap := e.snapshot.Load().(*policySnapshot)
	if entry, ok := snap.exact[name]; ok {
		return entry.action, entry.target, true
	}

	reversed := reverseDomain(name)
	if reversed == "" {
		return "", "", false
	}

	prefix, raw, ok := snap.wildcards.LongestPrefix(reversed)
	if !ok || prefix == "" {
		return "", "", false
	}
	if len(reversed) == len(prefix) {
		return "", "", false
	}
	if reversed[len(prefix)] != '.' {
		return "", "", false
	}

	entry, ok := raw.(policyEntry)
	if !ok {
		return "", "", false
	}
	return entry.action, entry.target, true
}

func parsePattern(pattern string, action Action, target string) (policyEntry, string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return policyEntry{}, "", errEmptyPattern
	}

	action, err := ParseAction(string(action))
	if err != nil {
		return policyEntry{}, "", err
	}

	target, err = normalizeTarget(action, target)
	if err != nil {
		return policyEntry{}, "", err
	}

	entry := policyEntry{action: action, target: target}

	if strings.HasPrefix(pattern, "*.") {
		apex := normalizeName(strings.TrimPrefix(pattern, "*."))
		if apex == "" {
			return policyEntry{}, "", errInvalidWildcard
		}
		reversed := reverseDomain(apex)
		if reversed == "" {
			return policyEntry{}, "", errInvalidWildcard
		}
		return entry, reversed, nil
	}
	if strings.Contains(pattern, "*") {
		return policyEntry{}, "", errInvalidWildcard
	}

	return entry, "", nil
}

func cloneSnapshot(cur *policySnapshot) *policySnapshot {
	nextExact := make(map[string]policyEntry, len(cur.exact))
	for key, value := range cur.exact {
		nextExact[key] = value
	}

	nextWildcards := radix.New()
	cur.wildcards.Walk(func(key string, value interface{}) bool {
		nextWildcards.Insert(key, value)
		return false
	})

	return &policySnapshot{
		exact:     nextExact,
		wildcards: nextWildcards,
	}
}

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	return name
}

func normalizeTarget(action Action, target string) (string, error) {
	target = strings.TrimSpace(target)
	switch action {
	case ActionCNAME:
		target = normalizeName(target)
		if target == "" {
			return "", errCNAMEWithoutTarget
		}
		return target + ".", nil
	case ActionA:
		if target == "" {
			return "", errAWithoutTarget
		}
		ip := net.ParseIP(target)
		if ip == nil || ip.To4() == nil {
			return "", errInvalidIPv4Target
		}
		return ip.To4().String(), nil
	case ActionAAAA:
		if target == "" {
			return "", errAAAAWithoutTarget
		}
		ip := net.ParseIP(target)
		if ip == nil || ip.To4() != nil {
			return "", errInvalidIPv6Target
		}
		return ip.String(), nil
	default:
		if target != "" {
			return "", fmt.Errorf("rpz target is only valid for CNAME, A, and AAAA actions")
		}
		return "", nil
	}
}

func reverseDomain(name string) string {
	name = normalizeName(name)
	if name == "" {
		return ""
	}

	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}
