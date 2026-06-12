package dnsproc

import "net/netip"

// TrustedChecker reports whether a client address is allowed to use recursion.
type TrustedChecker interface {
	Trusted(addr netip.Addr) bool
}
