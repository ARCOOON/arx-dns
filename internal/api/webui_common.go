package api

import "strings"

func isReservedWebPath(path string) bool {
	switch {
	case path == "health",
		path == "metrics",
		strings.HasPrefix(path, "api/"):
		return true
	default:
		return false
	}
}
