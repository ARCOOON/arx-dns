package telemetry

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultDataDir    = "./data"
	stateDBFilename   = "state.db"
	mainDBFilename    = "main.db"
	retentionDays     = 30
	flushInterval     = 60 * time.Second
	retentionInterval = time.Hour
)

// HistoryPoint is one aggregated bucket in a telemetry time series.
type HistoryPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	Queries         uint64    `json:"queries"`
	CacheHits       uint64    `json:"cache_hits"`
	Dropped         uint64    `json:"dropped"`
	DNSSECFails     uint64    `json:"dnssec_fails"`
	LocalQueries    uint64    `json:"local_queries"`
	UpstreamQueries uint64    `json:"upstream_queries"`
}

// HistoryResponse is returned by GET /api/v1/stats/history.
type HistoryResponse struct {
	Window      string         `json:"window"`
	Granularity string         `json:"granularity"`
	Points      []HistoryPoint `json:"points"`
}

// DB holds SQLite connection pools for telemetry state and future zone storage.
type DB struct {
	state *sql.DB
	main  *sql.DB
}

// OpenDB opens connection pools to data/state.db and data/main.db.
// Both databases use WAL journal mode and NORMAL synchronous for concurrent writes.
func OpenDB(dataDir string) (*DB, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory %q: %w", dataDir, err)
	}

	statePath := filepath.Join(dataDir, stateDBFilename)
	mainPath := filepath.Join(dataDir, mainDBFilename)

	stateDB, err := openSQLite(statePath)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}

	mainDB, err := openSQLite(mainPath)
	if err != nil {
		_ = stateDB.Close()
		return nil, fmt.Errorf("open main database: %w", err)
	}

	db := &DB{state: stateDB, main: mainDB}
	if err := db.initStateSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.initMainSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.migrateMetricsRollup(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func openSQLite(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	if err := applyPragmas(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func applyPragmas(conn *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
	}

	for _, pragma := range pragmas {
		if _, err := conn.Exec(pragma); err != nil {
			return fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	return nil
}

func (db *DB) initStateSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS metrics_rollup (
	timestamp DATETIME NOT NULL,
	queries INTEGER NOT NULL,
	cache_hits INTEGER NOT NULL,
	dropped INTEGER NOT NULL,
	dnssec_fails INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_rollup_timestamp ON metrics_rollup(timestamp);
`

	if _, err := db.state.Exec(schema); err != nil {
		return fmt.Errorf("initialize state schema: %w", err)
	}

	return nil
}

func (db *DB) initMainSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS blocklist_sources (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	url TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1
);
`

	if _, err := db.main.Exec(schema); err != nil {
		return fmt.Errorf("initialize main schema: %w", err)
	}

	return nil
}

func (db *DB) migrateMetricsRollup() error {
	columns, err := db.tableColumns("metrics_rollup")
	if err != nil {
		return err
	}

	alterations := []struct {
		name string
		ddl  string
	}{
		{
			name: "local_queries",
			ddl:  `ALTER TABLE metrics_rollup ADD COLUMN local_queries INTEGER NOT NULL DEFAULT 0;`,
		},
		{
			name: "upstream_queries",
			ddl:  `ALTER TABLE metrics_rollup ADD COLUMN upstream_queries INTEGER NOT NULL DEFAULT 0;`,
		},
	}

	for _, alteration := range alterations {
		if columns[alteration.name] {
			continue
		}
		if _, err := db.state.Exec(alteration.ddl); err != nil {
			return fmt.Errorf("migrate metrics_rollup column %s: %w", alteration.name, err)
		}
	}

	return nil
}

func (db *DB) tableColumns(table string) (map[string]bool, error) {
	rows, err := db.state.Query(`PRAGMA table_info(` + table + `);`)
	if err != nil {
		return nil, fmt.Errorf("pragma table_info %s: %w", table, err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &primaryKey); err != nil {
			return nil, fmt.Errorf("scan table_info row: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate table_info rows: %w", err)
	}

	return columns, nil
}

// State returns the telemetry state database handle.
func (db *DB) State() *sql.DB {
	return db.state
}

// Main returns the main application database handle (blocklist sources and future zone backend).
func (db *DB) Main() *sql.DB {
	return db.main
}

// InsertRollup persists one 60-second metrics delta row.
func (db *DB) InsertRollup(timestamp time.Time, queries, cacheHits, dropped, dnssecFails, localQueries, upstreamQueries uint64) error {
	const query = `
INSERT INTO metrics_rollup (timestamp, queries, cache_hits, dropped, dnssec_fails, local_queries, upstream_queries)
VALUES (?, ?, ?, ?, ?, ?, ?);
`

	_, err := db.state.Exec(
		query,
		timestamp.UTC().Format(time.RFC3339),
		queries,
		cacheHits,
		dropped,
		dnssecFails,
		localQueries,
		upstreamQueries,
	)
	if err != nil {
		return fmt.Errorf("insert metrics rollup: %w", err)
	}

	return nil
}

// PurgeOldMetrics deletes rollup rows older than the configured retention window.
func (db *DB) PurgeOldMetrics() (int64, error) {
	const query = `DELETE FROM metrics_rollup WHERE timestamp <= datetime('now', ?);`

	result, err := db.state.Exec(query, fmt.Sprintf("-%d days", retentionDays))
	if err != nil {
		return 0, fmt.Errorf("purge old metrics: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge rows affected: %w", err)
	}

	return rows, nil
}

// QueryHistory returns aggregated telemetry buckets for the requested window.
func (db *DB) QueryHistory(window string) (HistoryResponse, error) {
	switch window {
	case "5m":
		return db.queryHistory(window, "minute", `datetime('now', '-5 minutes')`, `strftime('%Y-%m-%d %H:%M:00', timestamp)`)
	case "1h":
		return db.queryHistory(window, "minute", `datetime('now', '-1 hour')`, `strftime('%Y-%m-%d %H:%M:00', timestamp)`)
	case "30d":
		return db.queryHistory(window, "day", `datetime('now', '-30 days')`, `strftime('%Y-%m-%d', timestamp)`)
	default:
		return HistoryResponse{}, fmt.Errorf("unsupported window %q", window)
	}
}

func (db *DB) queryHistory(window, granularity, sinceExpr, bucketExpr string) (HistoryResponse, error) {
	query := fmt.Sprintf(`
SELECT %s AS bucket,
       COALESCE(SUM(queries), 0) AS queries,
       COALESCE(SUM(cache_hits), 0) AS cache_hits,
       COALESCE(SUM(dropped), 0) AS dropped,
       COALESCE(SUM(dnssec_fails), 0) AS dnssec_fails,
       COALESCE(SUM(local_queries), 0) AS local_queries,
       COALESCE(SUM(upstream_queries), 0) AS upstream_queries
FROM metrics_rollup
WHERE timestamp >= %s
GROUP BY bucket
ORDER BY bucket ASC;
`, bucketExpr, sinceExpr)

	rows, err := db.state.Query(query)
	if err != nil {
		return HistoryResponse{}, fmt.Errorf("query history: %w", err)
	}
	defer rows.Close()

	points := make([]HistoryPoint, 0)
	for rows.Next() {
		var (
			bucket          string
			queries         uint64
			cacheHits       uint64
			dropped         uint64
			dnssecFails     uint64
			localQueries    uint64
			upstreamQueries uint64
		)

		if err := rows.Scan(&bucket, &queries, &cacheHits, &dropped, &dnssecFails, &localQueries, &upstreamQueries); err != nil {
			return HistoryResponse{}, fmt.Errorf("scan history row: %w", err)
		}

		ts, err := parseHistoryBucket(bucket, granularity)
		if err != nil {
			return HistoryResponse{}, err
		}

		points = append(points, HistoryPoint{
			Timestamp:       ts,
			Queries:         queries,
			CacheHits:       cacheHits,
			Dropped:         dropped,
			DNSSECFails:     dnssecFails,
			LocalQueries:    localQueries,
			UpstreamQueries: upstreamQueries,
		})
	}

	if err := rows.Err(); err != nil {
		return HistoryResponse{}, fmt.Errorf("iterate history rows: %w", err)
	}

	return HistoryResponse{
		Window:      window,
		Granularity: granularity,
		Points:      points,
	}, nil
}

func parseHistoryBucket(bucket, granularity string) (time.Time, error) {
	switch granularity {
	case "minute":
		ts, err := time.Parse("2006-01-02 15:04:05", bucket)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse minute bucket %q: %w", bucket, err)
		}
		return ts.UTC(), nil
	case "day":
		ts, err := time.Parse("2006-01-02", bucket)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse day bucket %q: %w", bucket, err)
		}
		return ts.UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported granularity %q", granularity)
	}
}

// Close closes both database connection pools.
func (db *DB) Close() error {
	if db == nil {
		return nil
	}

	var errs []error
	if db.state != nil {
		if err := db.state.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close state database: %w", err))
		}
	}
	if db.main != nil {
		if err := db.main.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close main database: %w", err))
		}
	}

	if len(errs) == 1 {
		return errs[0]
	}
	if len(errs) > 1 {
		return fmt.Errorf("close databases: %v", errs)
	}

	return nil
}
