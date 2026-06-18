package firewall

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// BlocklistSource is one remote blocklist feed configured in main.db.
type BlocklistSource struct {
	ID          int64      `json:"id"`
	URL         string     `json:"url"`
	Description string     `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	LastCount   int64      `json:"last_count"`
	LastSync    *time.Time `json:"last_sync,omitempty"`
}

// UpdateBlocklistSourceInput carries optional fields for PATCH updates.
type UpdateBlocklistSourceInput struct {
	Enabled     *bool
	Description *string
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
func InsertBlocklistSource(db *sql.DB, sourceURL, description string) (BlocklistSource, error) {
	if db == nil {
		return BlocklistSource{}, fmt.Errorf("database handle is nil")
	}

	normalized, err := ValidateSourceURL(sourceURL)
	if err != nil {
		return BlocklistSource{}, err
	}

	description = strings.TrimSpace(description)

	const query = `
INSERT INTO blocklist_sources (url, description, enabled)
VALUES (?, ?, 1)
RETURNING id, url, description, enabled, last_count, last_sync;
`

	var source BlocklistSource
	var enabled int
	var descriptionCol sql.NullString
	var lastSync sql.NullString
	if err := db.QueryRow(query, normalized, nullableDescription(description)).Scan(
		&source.ID,
		&source.URL,
		&descriptionCol,
		&enabled,
		&source.LastCount,
		&lastSync,
	); err != nil {
		if isUniqueConstraintError(err) {
			return BlocklistSource{}, ErrSourceAlreadyExists
		}
		return BlocklistSource{}, fmt.Errorf("insert blocklist source: %w", err)
	}
	source.Enabled = enabled != 0
	if descriptionCol.Valid {
		source.Description = strings.TrimSpace(descriptionCol.String)
	}
	if lastSync.Valid && strings.TrimSpace(lastSync.String) != "" {
		ts, err := parseSQLiteDateTime(lastSync.String)
		if err != nil {
			return BlocklistSource{}, err
		}
		source.LastSync = &ts
	}

	return source, nil
}

// ListBlocklistSources returns all configured remote blocklist feeds.
func ListBlocklistSources(db *sql.DB) ([]BlocklistSource, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	const query = `
SELECT id, url, description, enabled, last_count, last_sync
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
		source, err := scanBlocklistSource(rows.Scan)
		if err != nil {
			return nil, err
		}
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
SELECT id, url, description, enabled, last_count, last_sync
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
		source, err := scanBlocklistSource(rows.Scan)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enabled blocklist sources: %w", err)
	}

	return sources, nil
}

// UpdateBlocklistSource updates enabled state and/or description for one feed.
func UpdateBlocklistSource(db *sql.DB, id int64, in UpdateBlocklistSourceInput) (BlocklistSource, error) {
	if db == nil {
		return BlocklistSource{}, fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return BlocklistSource{}, ErrSourceNotFound
	}
	if in.Enabled == nil && in.Description == nil {
		return BlocklistSource{}, fmt.Errorf("no fields to update")
	}

	setClauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if in.Enabled != nil {
		enabled := 0
		if *in.Enabled {
			enabled = 1
		}
		setClauses = append(setClauses, "enabled = ?")
		args = append(args, enabled)
	}
	if in.Description != nil {
		setClauses = append(setClauses, "description = ?")
		args = append(args, nullableDescription(strings.TrimSpace(*in.Description)))
	}

	args = append(args, id)
	query := fmt.Sprintf(`
UPDATE blocklist_sources
SET %s
WHERE id = ?
RETURNING id, url, description, enabled, last_count, last_sync;
`, strings.Join(setClauses, ", "))

	var source BlocklistSource
	var enabled int
	var description sql.NullString
	var lastSync sql.NullString
	if err := db.QueryRow(query, args...).Scan(
		&source.ID,
		&source.URL,
		&description,
		&enabled,
		&source.LastCount,
		&lastSync,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BlocklistSource{}, ErrSourceNotFound
		}
		return BlocklistSource{}, fmt.Errorf("update blocklist source: %w", err)
	}

	source.Enabled = enabled != 0
	if description.Valid {
		source.Description = strings.TrimSpace(description.String)
	}
	if lastSync.Valid && strings.TrimSpace(lastSync.String) != "" {
		ts, err := parseSQLiteDateTime(lastSync.String)
		if err != nil {
			return BlocklistSource{}, err
		}
		source.LastSync = &ts
	}

	return source, nil
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

// UpdateBlocklistSourceStats persists domain count and sync timestamp for one feed.
func UpdateBlocklistSourceStats(db *sql.DB, id int64, domainCount int) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if id <= 0 {
		return ErrSourceNotFound
	}

	const query = `
UPDATE blocklist_sources
SET last_count = ?, last_sync = ?
WHERE id = ?;
`

	result, err := db.Exec(query, domainCount, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("update blocklist source stats: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update blocklist source stats rows affected: %w", err)
	}
	if rows == 0 {
		return ErrSourceNotFound
	}

	return nil
}

func scanBlocklistSource(scan func(dest ...any) error) (BlocklistSource, error) {
	var source BlocklistSource
	var enabled int
	var description sql.NullString
	var lastSync sql.NullString
	if err := scan(&source.ID, &source.URL, &description, &enabled, &source.LastCount, &lastSync); err != nil {
		return BlocklistSource{}, fmt.Errorf("scan blocklist source: %w", err)
	}
	source.Enabled = enabled != 0
	if description.Valid {
		source.Description = strings.TrimSpace(description.String)
	}
	if lastSync.Valid && strings.TrimSpace(lastSync.String) != "" {
		ts, err := parseSQLiteDateTime(lastSync.String)
		if err != nil {
			return BlocklistSource{}, err
		}
		source.LastSync = &ts
	}
	return source, nil
}

func parseSQLiteDateTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty datetime")
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), nil
	}
	if ts, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
		return ts.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unsupported datetime format %q", raw)
}

func nullableDescription(description string) any {
	if description == "" {
		return nil
	}
	return description
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed")
}
