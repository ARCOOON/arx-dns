package dnsproc

import (
	"strings"

	"github.com/ARCOOON/arx-dns/internal/storage"
)

// activeDirectoryMarkers identify Windows Active Directory DNS suffixes. Upstream
// resolvers often time out on these; unanswered local lookups return NXDOMAIN immediately.
var activeDirectoryMarkers = []string{"_msdcs", "_ldap", "_sites"}

// isActiveDirectoryQuery reports whether name is an internal AD lookup pattern.
func isActiveDirectoryQuery(name string) bool {
	normalized := strings.ToLower(storage.NormalizeName(name))
	for _, marker := range activeDirectoryMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
