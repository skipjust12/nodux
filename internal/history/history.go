// Package history is nodux's memory of what happened: every alert it
// sent, what the LLM layer cost, and periodic memory samples per
// container. It's a SQLite database (pure Go driver, no cgo) next to
// the state file. The digest, the LLM prompt ("this container crashed 5
// times this week") and the chat bot read from it.
package history

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	StateFiring   = "firing"
	StateResolved = "resolved"

	fileName = "history.db"

	// Memory samples are only needed for the digest's week-over-week
	// comparison; they're the bulk of the rows, so they go sooner.
	sampleRetention = 14 * 24 * time.Hour
)

// schema is applied in order; PRAGMA user_version records how far.
var schema = []string{
	`CREATE TABLE alerts (
		id           INTEGER PRIMARY KEY,
		ts           INTEGER NOT NULL, -- unix ms
		state        TEXT    NOT NULL, -- firing, resolved
		host         TEXT    NOT NULL DEFAULT '',
		detector     TEXT    NOT NULL,
		severity     TEXT    NOT NULL,
		subject      TEXT    NOT NULL DEFAULT '', -- container name, or a host resource
		is_container INTEGER NOT NULL DEFAULT 0,
		container_id TEXT    NOT NULL DEFAULT '',
		image        TEXT    NOT NULL DEFAULT '',
		message      TEXT    NOT NULL,
		analysis     TEXT    NOT NULL DEFAULT '',
		incident_id  INTEGER NOT NULL DEFAULT 0,
		episode      TEXT    NOT NULL DEFAULT '',
		exit_code    INTEGER
	);
	CREATE INDEX alerts_ts ON alerts (ts);
	CREATE INDEX alerts_subject ON alerts (subject, ts);
	CREATE TABLE llm_calls (
		id                 INTEGER PRIMARY KEY,
		ts                 INTEGER NOT NULL,
		run                TEXT    NOT NULL, -- one analysis or answer, possibly several calls
		purpose            TEXT    NOT NULL, -- incident, question, digest
		model              TEXT    NOT NULL,
		input_tokens       INTEGER NOT NULL,
		output_tokens      INTEGER NOT NULL,
		cache_read_tokens  INTEGER NOT NULL,
		cache_write_tokens INTEGER NOT NULL
	);
	CREATE INDEX llm_calls_ts ON llm_calls (ts);
	CREATE TABLE memory_samples (
		ts        INTEGER NOT NULL,
		container TEXT    NOT NULL,
		used      INTEGER NOT NULL,
		lim       INTEGER NOT NULL -- 0 = no limit
	);
	CREATE INDEX memory_samples_ts ON memory_samples (ts, container);`,
}

type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (or creates) history.db in dir.
func Open(dir string) (*Store, error) {
	path := filepath.Join(dir, fileName)
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// One connection: writes are tiny and rare, and SQLite serializes
	// writers anyway. This rules out SQLITE_BUSY between our own goroutines.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Alert messages and logs-derived analyses stay on this host.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		os.Chmod(p, 0o600)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(schema) {
		return fmt.Errorf("database schema version %d is newer than this nodux (%d); refusing to touch it", version, len(schema))
	}
	for i := version; i < len(schema); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(schema[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Alert is one alert or resolution as it was sent.
type Alert struct {
	Time        time.Time
	State       string // firing, resolved
	Host        string
	Detector    string
	Severity    string
	Subject     string // container name, or the resource of a host alert
	Container   bool
	ContainerID string
	Image       string
	Message     string
	Analysis    string
	IncidentID  int64
	Episode     string
	ExitCode    *int
}

// AlertFromIssue is the history row for an issue that was sent.
func AlertFromIssue(issue detector.Issue, analysis string) Alert {
	a := Alert{
		Time:        issue.DetectedAt,
		State:       StateFiring,
		Host:        issue.Host,
		Detector:    issue.Detector,
		Severity:    issue.Severity,
		Subject:     issue.Resource,
		ContainerID: issue.Container.ID,
		Image:       issue.Container.Image,
		Message:     issue.Message,
		Analysis:    analysis,
		IncidentID:  issue.IncidentID,
		Episode:     issue.Key,
	}
	if issue.Resolved {
		a.State = StateResolved
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	if c := issue.Container; c.Name != "" {
		a.Subject, a.Container = c.Name, true
		if c.ID != "" {
			code := c.ExitCode
			a.ExitCode = &code
		}
	}
	return a
}

func (s *Store) AddAlerts(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO alerts
		(ts, state, host, detector, severity, subject, is_container, container_id, image, message, analysis, incident_id, episode, exit_code)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range alerts {
		var exit any
		if a.ExitCode != nil {
			exit = *a.ExitCode
		}
		if _, err := stmt.ExecContext(ctx, a.Time.UnixMilli(), a.State, a.Host, a.Detector, a.Severity, a.Subject,
			a.Container, a.ContainerID, a.Image, a.Message, a.Analysis, a.IncidentID, a.Episode, exit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Query selects alerts. Zero fields don't filter.
type Query struct {
	Subject    string // container name or host resource
	Since      time.Time
	Until      time.Time
	FiringOnly bool
	Limit      int // newest first; 0 = all
}

// Alerts returns the alerts matching q, newest first.
func (s *Store) Alerts(ctx context.Context, q Query) ([]Alert, error) {
	var where []string
	var args []any
	if q.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, q.Subject)
	}
	if !q.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if !q.Until.IsZero() {
		where = append(where, "ts < ?")
		args = append(args, q.Until.UnixMilli())
	}
	if q.FiringOnly {
		where = append(where, "state = ?")
		args = append(args, StateFiring)
	}
	query := `SELECT ts, state, host, detector, severity, subject, is_container, container_id, image, message, analysis, incident_id, episode, exit_code FROM alerts`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY ts DESC, id DESC"
	if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", q.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var ts int64
		var exit sql.NullInt64
		if err := rows.Scan(&ts, &a.State, &a.Host, &a.Detector, &a.Severity, &a.Subject, &a.Container, &a.ContainerID,
			&a.Image, &a.Message, &a.Analysis, &a.IncidentID, &a.Episode, &exit); err != nil {
			return nil, err
		}
		a.Time = time.UnixMilli(ts)
		if exit.Valid {
			code := int(exit.Int64)
			a.ExitCode = &code
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// LLMCall is the token usage of one API call.
type LLMCall struct {
	Time       time.Time
	Run        string // groups the calls of one analysis or answer
	Purpose    string // incident, question, digest
	Model      string
	Input      int64 // uncached input tokens
	Output     int64
	CacheRead  int64
	CacheWrite int64
}

func (s *Store) AddLLMCall(ctx context.Context, c LLMCall) error {
	if c.Time.IsZero() {
		c.Time = s.now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO llm_calls
		(ts, run, purpose, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Time.UnixMilli(), c.Run, c.Purpose, c.Model, c.Input, c.Output, c.CacheRead, c.CacheWrite)
	return err
}

// LLMCalls returns the calls made in [since, until).
func (s *Store) LLMCalls(ctx context.Context, since, until time.Time) ([]LLMCall, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, run, purpose, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
		FROM llm_calls WHERE ts >= ? AND ts < ? ORDER BY ts`, since.UnixMilli(), until.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMCall
	for rows.Next() {
		var c LLMCall
		var ts int64
		if err := rows.Scan(&ts, &c.Run, &c.Purpose, &c.Model, &c.Input, &c.Output, &c.CacheRead, &c.CacheWrite); err != nil {
			return nil, err
		}
		c.Time = time.UnixMilli(ts)
		out = append(out, c)
	}
	return out, rows.Err()
}

// MemorySample is a container's memory working set at one point in time.
type MemorySample struct {
	Time      time.Time
	Container string
	Used      uint64
	Limit     uint64 // 0 = no limit
}

func (s *Store) AddMemorySamples(ctx context.Context, samples []MemorySample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO memory_samples (ts, container, used, lim) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, m := range samples {
		if _, err := stmt.ExecContext(ctx, m.Time.UnixMilli(), m.Container, int64(m.Used), int64(m.Limit)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MemorySamples returns the samples taken in [since, until), oldest
// first, by container name.
func (s *Store) MemorySamples(ctx context.Context, since, until time.Time) (map[string][]MemorySample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, container, used, lim FROM memory_samples
		WHERE ts >= ? AND ts < ? ORDER BY ts`, since.UnixMilli(), until.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]MemorySample)
	for rows.Next() {
		var m MemorySample
		var ts, used, lim int64
		if err := rows.Scan(&ts, &m.Container, &used, &lim); err != nil {
			return nil, err
		}
		m.Time, m.Used, m.Limit = time.UnixMilli(ts), uint64(used), uint64(lim)
		out[m.Container] = append(out[m.Container], m)
	}
	return out, rows.Err()
}

// Prune deletes alerts and LLM usage older than retention, and memory
// samples older than two weeks (or retention, if that's shorter).
func (s *Store) Prune(ctx context.Context, retention time.Duration) error {
	now := s.now()
	cutoff := now.Add(-retention).UnixMilli()
	samples := now.Add(-min(retention, sampleRetention)).UnixMilli()
	for _, q := range []struct {
		sql string
		ts  int64
	}{
		{`DELETE FROM alerts WHERE ts < ?`, cutoff},
		{`DELETE FROM llm_calls WHERE ts < ?`, cutoff},
		{`DELETE FROM memory_samples WHERE ts < ?`, samples},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.ts); err != nil {
			return err
		}
	}
	return nil
}
