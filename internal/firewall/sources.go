package firewall

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// BlocklistSource is one remote blocklist feed configured in main.db.
type BlocklistSource struct {
	ID      int64  `json:"id"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

var (
	// ErrSourceNotFound is returned when a blocklist source ID does not exist.
	ErrSourceNotFound = errors.New("blocklist source not found")
	// ErrSourceAlreadyExists is returned when the URL is already registered.
	ErrSourceAlreadyExists = errors.New("blocklist source already exists")
	// ErrInvalidSourceURL is returned when a feed URL is empty or not HTTP(S).
	ErrInvalidSourceURL = errors.New("invalid blocklist source URL")
)

// ValidateSourceURL normalizes and validates a remote blocklist feed URL.
func ValidateSourceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrInvalidSourceURL
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ErrInvalidSourceURL
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", ErrInvalidSourceURL
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", ErrInvalidSourceURL
	}

	return raw, nil
}

// InsertBlocklistSource registers a new enabled remote blocklist feed.
func InsertBlocklistSource(db *sql.DB, sourceURL string) (BlocklistSource, error) {
	if db == nil {
		return BlocklistSource{}, fmt.Errorf("database handle is nil")
	}

	normalized, err := ValidateSourceURL(sourceURL)
	if err != nil {
		return BlocklistSource{}, err
	}

	const query = `
INSERT INTO blocklist_sources (url, enabled)
VALUES (?, 1)
RETURNING id, url, enabled;
`

	var source BlocklistSource
	var enabled int
	if err := db.QueryRow(query, normalized).Scan(&source.ID, &source.URL, &enabled); err != nil {
		if isUniqueConstraintError(err) {
			return BlocklistSource{}, ErrSourceAlreadyExists
		}
		return BlocklistSource{}, fmt.Errorf("insert blocklist source: %w", err)
	}
	source.Enabled = enabled != 0

	return source, nil
}

// ListBlocklistSources returns all configured remote blocklist feeds.
func ListBlocklistSources(db *sql.DB) ([]BlocklistSource, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	const query = `
SELECT id, url, enabled
FROM blocklist_sources
ORDER BY id ASC;
`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list blocklist sources: %w", err)
	}
	defer rows.Close()

	sources := make([]BlocklistSource, 0)
	for rows.Next() {
		var source BlocklistSource
		var enabled int
		if err := rows.Scan(&source.ID, &source.URL, &enabled); err != nil {
			return nil, fmt.Errorf("scan blocklist source: %w", err)
		}
		source.Enabled = enabled != 0
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocklist sources: %w", err)
	}

	return sources, nil
}

// ListEnabledBlocklistSources returns enabled remote blocklist feeds for sync.
func ListEnabledBlocklistSources(db *sql.DB) ([]BlocklistSource, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	const query = `
SELECT id, url, enabled
FROM blocklist_sources
WHERE enabled = 1
ORDER BY id ASC;
`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list enabled blocklist sources: %w", err)
	}
	defer rows.Close()

	sources := make([]BlocklistSource, 0)
	for rows.Next() {
		var source BlocklistSource
		var enabled int
		if err := rows.Scan(&source.ID, &source.URL, &enabled); err != nil {
			return nil, fmt.Errorf("scan enabled blocklist source: %w", err)
		}
		source.Enabled = enabled != 0
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enabled blocklist sources: %w", err)
	}

	return sources, nil
}

// DeleteBlocklistSource removes a remote blocklist feed by ID.
func DeleteBlocklistSource(db *sql.DB, id int64) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return ErrSourceNotFound
	}

	const query = `DELETE FROM blocklist_sources WHERE id = ?;`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("delete blocklist source: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete blocklist source rows affected: %w", err)
	}
	if rows == 0 {
		return ErrSourceNotFound
	}

	return nil
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed")
}
