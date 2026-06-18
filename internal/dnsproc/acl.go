package dnsproc

import (
	"database/sql"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/ARCOOON/arx-dns/internal/acl"
)

type aclSnapshot struct {
	enforced bool
	prefixes []netip.Prefix
}

// QueryAccessChecker enforces IP/CIDR-based query access rules loaded from main.db.
// When no rules are configured, all clients are allowed.
type QueryAccessChecker struct {
	db   *sql.DB
	snap atomic.Value
}

// NewQueryAccessChecker loads ACL rules from the database and returns a checker.
func NewQueryAccessChecker(db *sql.DB) (*QueryAccessChecker, error) {
	checker := &QueryAccessChecker{db: db}
	if err := checker.Reload(); err != nil {
		return nil, err
	}
	return checker, nil
}

// Reload refreshes the in-memory prefix list from the database.
func (c *QueryAccessChecker) Reload() error {
	if c == nil {
		return fmt.Errorf("query access checker is nil")
	}
	if c.db == nil {
		c.snap.Store(aclSnapshot{})
		return nil
	}

	rules, err := acl.ListRules(c.db)
	if err != nil {
		return fmt.Errorf("reload query access rules: %w", err)
	}

	snap := aclSnapshot{
		enforced: len(rules) > 0,
		prefixes: make([]netip.Prefix, 0, len(rules)),
	}

	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Subnet)
		if err != nil {
			return fmt.Errorf("parse stored subnet %q: %w", rule.Subnet, err)
		}
		snap.prefixes = append(snap.prefixes, prefix.Masked())
	}

	c.snap.Store(snap)
	return nil
}

// Allowed reports whether the client address may send DNS queries.
// When no rules are configured, every address is allowed.
func (c *QueryAccessChecker) Allowed(addr netip.Addr) bool {
	if c == nil {
		return true
	}

	raw := c.snap.Load()
	snap, ok := raw.(aclSnapshot)
	if !ok || !snap.enforced {
		return true
	}
	if !addr.IsValid() {
		return false
	}

	addr = addr.Unmap()
	for _, prefix := range snap.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
