package firewall

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CustomBlocklistEntry is one manually blocked domain stored in main.db.
type CustomBlocklistEntry struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	// ErrCustomDomainNotFound is returned when a custom blocklist entry ID does not exist.
	ErrCustomDomainNotFound = errors.New("custom blocklist domain not found")
	// ErrCustomDomainAlreadyExists is returned when the domain is already blocked manually.
	ErrCustomDomainAlreadyExists = errors.New("custom blocklist domain already exists")
	// ErrInvalidCustomDomain is returned when a domain name is empty or malformed.
	ErrInvalidCustomDomain = errors.New("invalid custom blocklist domain")
)

// ValidateCustomDomain normalizes and validates a manually blocked domain name.
func ValidateCustomDomain(raw string) (string, error) {
	domains := ParseBlocklistLine(raw)
	if len(domains) != 1 {
		return "", ErrInvalidCustomDomain
	}
	return domains[0], nil
}

// ListCustomBlocklistDomains returns all manually blocked domains ordered by ID.
func ListCustomBlocklistDomains(db *sql.DB) ([]CustomBlocklistEntry, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	const query = `
SELECT id, domain, created_at
FROM blocklist_custom
ORDER BY id ASC;
`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list custom blocklist domains: %w", err)
	}
	defer rows.Close()

	entries := make([]CustomBlocklistEntry, 0)
	for rows.Next() {
		var entry CustomBlocklistEntry
		var createdAt string
		if err := rows.Scan(&entry.ID, &entry.Domain, &createdAt); err != nil {
			return nil, fmt.Errorf("scan custom blocklist domain: %w", err)
		}
		ts, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			ts, err = time.Parse("2006-01-02 15:04:05", createdAt)
			if err != nil {
				return nil, fmt.Errorf("parse custom blocklist created_at %q: %w", createdAt, err)
			}
		}
		entry.CreatedAt = ts.UTC()
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom blocklist domains: %w", err)
	}

	return entries, nil
}

// InsertCustomBlocklistDomain registers a new manually blocked domain.
func InsertCustomBlocklistDomain(db *sql.DB, rawDomain string) (CustomBlocklistEntry, error) {
	if db == nil {
		return CustomBlocklistEntry{}, fmt.Errorf("database handle is nil")
	}

	domain, err := ValidateCustomDomain(rawDomain)
	if err != nil {
		return CustomBlocklistEntry{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	const query = `
INSERT INTO blocklist_custom (domain, created_at)
VALUES (?, ?)
RETURNING id, domain, created_at;
`

	var entry CustomBlocklistEntry
	var createdAt string
	if err := db.QueryRow(query, domain, now).Scan(&entry.ID, &entry.Domain, &createdAt); err != nil {
		if isUniqueConstraintError(err) {
			return CustomBlocklistEntry{}, ErrCustomDomainAlreadyExists
		}
		return CustomBlocklistEntry{}, fmt.Errorf("insert custom blocklist domain: %w", err)
	}

	ts, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		ts, err = time.Parse("2006-01-02 15:04:05", createdAt)
		if err != nil {
			return CustomBlocklistEntry{}, fmt.Errorf("parse custom blocklist created_at %q: %w", createdAt, err)
		}
	}
	entry.CreatedAt = ts.UTC()

	return entry, nil
}

// DeleteCustomBlocklistDomain removes a manually blocked domain by ID.
func DeleteCustomBlocklistDomain(db *sql.DB, id int64) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return ErrCustomDomainNotFound
	}

	const query = `DELETE FROM blocklist_custom WHERE id = ?;`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("delete custom blocklist domain: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete custom blocklist domain rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCustomDomainNotFound
	}

	return nil
}
