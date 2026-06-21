package telemetry

import (
	"database/sql"
	"fmt"
	"time"
)

const defaultAuditLimit = 500

// AuditLog is one persisted management API audit record.
type AuditLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// AuditResponse is returned by GET /api/v1/audit.
type AuditResponse struct {
	Logs []AuditLog `json:"logs"`
}

// InsertAuditLog persists one audit event into main.db.
func (db *DB) InsertAuditLog(clientIP, action, target, details string, method string, path string, status int, success bool) error {
	if db == nil || db.main == nil {
		return fmt.Errorf("database unavailable")
	}

	const query = `
INSERT INTO audit_logs (timestamp, client_ip, action, target, details, method, path, status, success)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
`

	successInt := 0
	if success {
		successInt = 1
	}

	_, err := db.main.Exec(
		query,
		time.Now().UTC().Format(time.RFC3339),
		clientIP,
		action,
		target,
		details,
		method,
		path,
		status,
		successInt,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// ListAuditLogs returns the most recent audit records, newest first.
func (db *DB) ListAuditLogs(limit int) ([]AuditLog, error) {
	if db == nil || db.main == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > defaultAuditLimit {
		limit = defaultAuditLimit
	}

	const query = `
SELECT id, timestamp, client_ip, action, target, details
FROM audit_logs
ORDER BY id DESC
LIMIT ?;
`

	rows, err := db.main.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]AuditLog, 0)
	for rows.Next() {
		var (
			entry     AuditLog
			timestamp string
			target    sql.NullString
			details   sql.NullString
		)
		if err := rows.Scan(&entry.ID, &timestamp, &entry.ClientIP, &entry.Action, &target, &details); err != nil {
			return nil, fmt.Errorf("scan audit log row: %w", err)
		}
		ts, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			ts, err = time.Parse("2006-01-02 15:04:05", timestamp)
			if err != nil {
				return nil, fmt.Errorf("parse audit timestamp %q: %w", timestamp, err)
			}
		}
		entry.Timestamp = ts.UTC()
		if target.Valid {
			entry.Target = target.String
		}
		if details.Valid {
			entry.Details = details.String
		}
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit log rows: %w", err)
	}
	return logs, nil
}
