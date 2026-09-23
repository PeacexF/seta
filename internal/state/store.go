// Package state persists findings across runs in SQLite and turns each run
// into a diff: new, persisting, resolved and regressed findings.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// migrations[i] upgrades the schema from version i to i+1. Released
// migrations must never change; add a new one instead.
var migrations = []string{
	`CREATE TABLE runs (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at   INTEGER NOT NULL, -- unix ms
		duration_ms  INTEGER NOT NULL,
		checks_run   INTEGER NOT NULL,
		findings     INTEGER NOT NULL,
		check_errors INTEGER NOT NULL
	);
	CREATE TABLE findings (
		fingerprint  TEXT PRIMARY KEY,
		check_id     TEXT NOT NULL,
		target       TEXT NOT NULL,
		subject      TEXT NOT NULL,
		severity     TEXT NOT NULL,
		title        TEXT NOT NULL,
		evidence     TEXT NOT NULL, -- JSON object
		remediation  TEXT NOT NULL,
		open         INTEGER NOT NULL,
		suppressed   INTEGER NOT NULL,
		missing_runs INTEGER NOT NULL, -- consecutive runs the finding was absent from
		first_seen   INTEGER NOT NULL,
		last_seen    INTEGER NOT NULL,
		resolved_at  INTEGER
	);
	CREATE TABLE events (
		run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
		fingerprint TEXT NOT NULL,
		kind        TEXT NOT NULL,
		severity    TEXT NOT NULL,
		PRIMARY KEY (run_id, fingerprint)
	);
	CREATE TABLE kv (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`,
}

// Open opens (creating if needed) and migrates the database at path.
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("state path %q must not contain ? or #", path)
	}
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writers anyway, and this avoids
	// SQLITE_BUSY between our own connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this version of seta supports (%d)", v, len(migrations))
	}
	for ; v < len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Get reads a value stored with Set; ok is false if there is none.
func (s *Store) Get(ctx context.Context, key string) (value string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (s *Store) Set(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE key = ?", key)
	return err
}

// Prune deletes runs (and their events) that started before cutoff, and
// resolved findings older than cutoff, which then count as new if they
// return. The latest run is always kept.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (runs int64, err error) {
	ms := cutoff.UnixMilli()
	res, err := s.db.ExecContext(ctx, "DELETE FROM runs WHERE started_at < ? AND id < (SELECT MAX(id) FROM runs)", ms)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM findings WHERE open = 0 AND resolved_at < ?", ms); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
