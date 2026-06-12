package firewall

import (
	"strings"
	"sync/atomic"

	"github.com/armon/go-radix"
)

// BlockAction selects how blocked queries are answered.
type BlockAction string

const (
	// BlockActionNXDOMAIN returns RCODE NXDOMAIN for blocked names.
	BlockActionNXDOMAIN BlockAction = "NXDOMAIN"
	// BlockActionZeroIP returns A/AAAA records pointing to 0.0.0.0 or ::.
	BlockActionZeroIP BlockAction = "ZEROIP"
)

// ParseBlockAction validates a CLI block-action value.
func ParseBlockAction(raw string) (BlockAction, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(BlockActionNXDOMAIN), "":
		return BlockActionNXDOMAIN, nil
	case string(BlockActionZeroIP):
		return BlockActionZeroIP, nil
	default:
		return "", errUnknownBlockAction
	}
}

// Engine matches query names against reversed-domain radix prefixes for
// subdomain-aware blocking. Lookups load the active tree via atomic.Value
// without locks; reloads build a fresh tree and swap it in atomically.
type Engine struct {
	tree   atomic.Value // holds *radix.Tree
	action BlockAction
}

// New creates an empty firewall engine with the given block action.
func New(action BlockAction) *Engine {
	e := &Engine{action: action}
	e.tree.Store(radix.New())
	return e
}

// Action returns the configured response action for blocked queries.
func (e *Engine) Action() BlockAction {
	return e.action
}

// SwapTree atomically replaces the blocklist radix tree.
func (e *Engine) SwapTree(tree *radix.Tree) {
	if tree == nil {
		tree = radix.New()
	}
	e.tree.Store(tree)
}

// Blocked reports whether name matches any loaded blocklist entry, including
// subdomains of a listed apex (e.g. blocking example.com also blocks ads.example.com).
func (e *Engine) Blocked(name string) bool {
	reversed := ReverseDomain(name)
	if reversed == "" {
		return false
	}

	tree := e.tree.Load().(*radix.Tree)
	prefix, _, ok := tree.LongestPrefix(reversed)
	if !ok || prefix == "" {
		return false
	}

	if len(prefix) == len(reversed) {
		return true
	}
	return reversed[len(prefix)] == '.'
}

// ReverseDomain converts an FQDN into reversed labels for radix prefix matching
// (example.com -> com.example, ads.example.com -> com.example.ads).
func ReverseDomain(name string) string {
	name = normalizeDomain(name)
	if name == "" {
		return ""
	}

	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	return name
}
