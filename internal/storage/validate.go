package storage

import (
	"fmt"
	"strings"
	"unicode"
)

// ValidateZoneName ensures a zone URL parameter contains only safe FQDN characters
// and cannot be used for path traversal when resolving zone file paths.
func ValidateZoneName(zone string) error {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("zone name is required")
	}

	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return fmt.Errorf("invalid zone name")
	}
	if strings.Contains(zone, "..") {
		return fmt.Errorf("invalid zone name")
	}
	if strings.ContainsAny(zone, `/\`) {
		return fmt.Errorf("invalid zone name")
	}

	labels := strings.Split(zone, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("invalid zone name")
		}
		if len(label) > 63 {
			return fmt.Errorf("invalid zone name: label exceeds 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid zone name: label cannot start or end with hyphen")
		}
		for _, r := range label {
			if r == '-' {
				continue
			}
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return fmt.Errorf("invalid zone name: only alphanumeric characters, hyphens, and dots are allowed")
			}
		}
	}

	return nil
}
