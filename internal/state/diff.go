package state

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

type Kind string

const (
	New        Kind = "new"
	Persisting Kind = "persisting"
	Resolved   Kind = "resolved"
	Regressed  Kind = "regressed"
)

func ParseKind(s string) (Kind, bool) {
	k := Kind(s)
	switch k {
	case New, Persisting, Resolved, Regressed:
		return k, true
	}
	return "", false
}

type Change struct {
	Kind    Kind         `json:"kind"`
	Finding core.Finding `json:"finding"`
	// Suppressed findings are tracked like any other but never notified.
	Suppressed bool      `json:"suppressed,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
}

// Diff is what one run changed. Changes are sorted by target, kind
// (new, regressed, resolved, persisting), severity and check ID.
type Diff struct {
	RunID    int64
	Started  time.Time
	Duration time.Duration
	Targets  []string
	Changes  []Change
	Errors   []engine.CheckError
	// Open counts unsuppressed findings that are open after this run.
	Open int
}

type Options struct {
	// ResolveAfter is how many consecutive runs a finding must be absent
	// from before it counts as resolved (minimum 1).
	ResolveAfter int
	// Canonical maps a recorded check ID to its current one, so state
	// survives check renames. Nil means IDs are used as recorded.
	Canonical func(id string) string
}

type row struct {
	fp          string
	f           core.Finding
	open        bool
	suppressed  bool
	missing     int
	firstSeen   int64
	lastSeen    int64
	resolvedAt  *int64
	dirty, gone bool
	oldFP       string
}

// Record stores a run and returns its diff. res must have its suppressions
// applied (config.Apply) and no baseline.
//
// A finding resolves only after being absent for ResolveAfter consecutive
// runs in which its check ran without error: a check error, or a check that
// was not selected, says nothing about the finding. Findings of targets no
// longer in res.Targets are forgotten without a "resolved" change.
func (s *Store) Record(ctx context.Context, res *engine.Result, opts Options) (*Diff, error) {
	resolveAfter := max(opts.ResolveAfter, 1)
	canonical := opts.Canonical
	if canonical == nil {
		canonical = func(id string) string { return id }
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := res.Started.Add(res.Duration).UnixMilli()
	r, err := tx.ExecContext(ctx, "INSERT INTO runs (started_at, duration_ms, checks_run, findings, check_errors) VALUES (?, ?, ?, ?, ?)",
		res.Started.UnixMilli(), res.Duration.Milliseconds(), res.Executions, len(res.Findings), len(res.Errors))
	if err != nil {
		return nil, err
	}
	d := &Diff{Started: res.Started, Duration: res.Duration, Errors: res.Errors}
	if d.RunID, err = r.LastInsertId(); err != nil {
		return nil, err
	}

	rows, err := loadRows(ctx, tx, canonical)
	if err != nil {
		return nil, err
	}

	targets := make(map[string]bool)
	for _, t := range res.Targets {
		targets[t.Name] = true
		d.Targets = append(d.Targets, t.Name)
	}
	ran := make(map[engine.Execution]bool)
	for _, e := range res.Ran {
		ran[e] = true
	}
	for _, e := range res.Errors {
		delete(ran, engine.Execution{Target: e.Target, CheckID: e.CheckID})
	}

	type present struct {
		f          core.Finding
		suppressed bool
	}
	var current []present
	for _, f := range res.Findings {
		current = append(current, present{f, false})
	}
	for _, sf := range res.Suppressed {
		current = append(current, present{sf.Finding, true})
	}
	seen := make(map[string]bool)
	for _, p := range current {
		fp := p.f.Fingerprint()
		seen[fp] = true
		rw := rows[fp]
		var kind Kind
		switch {
		case rw == nil:
			kind = New
			rw = &row{fp: fp, firstSeen: now}
			rows[fp] = rw
		case !rw.open:
			kind = Regressed
		case rw.suppressed && !p.suppressed:
			// The suppression expired or was removed: new to whoever reads alerts.
			kind = New
		default:
			kind = Persisting
		}
		rw.f, rw.open, rw.suppressed, rw.missing, rw.lastSeen, rw.resolvedAt, rw.dirty = p.f, true, p.suppressed, 0, now, nil, true
		d.Changes = append(d.Changes, Change{Kind: kind, Finding: p.f, Suppressed: p.suppressed, FirstSeen: time.UnixMilli(rw.firstSeen)})
	}

	for fp, rw := range rows {
		switch {
		case seen[fp]:
		case !targets[rw.f.Target]:
			rw.gone = true
		case rw.open && ran[engine.Execution{Target: rw.f.Target, CheckID: rw.f.CheckID}]:
			rw.missing++
			rw.dirty = true
			if rw.missing >= resolveAfter {
				rw.open, rw.missing, rw.resolvedAt = false, 0, &now
				d.Changes = append(d.Changes, Change{Kind: Resolved, Finding: rw.f, Suppressed: rw.suppressed, FirstSeen: time.UnixMilli(rw.firstSeen)})
			}
		}
		if rw.open && !rw.suppressed && !rw.gone {
			d.Open++
		}
	}

	if err := saveRows(ctx, tx, rows); err != nil {
		return nil, err
	}
	for _, c := range d.Changes {
		if c.Kind == Persisting {
			continue
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO events (run_id, fingerprint, kind, severity) VALUES (?, ?, ?, ?)",
			d.RunID, c.Finding.Fingerprint(), string(c.Kind), c.Finding.Severity.String()); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	slices.SortFunc(d.Changes, CompareChanges)
	return d, nil
}

var kindOrder = map[Kind]int{New: 0, Regressed: 1, Resolved: 2, Persisting: 3}

// CompareChanges orders changes like Diff.Changes.
func CompareChanges(a, b Change) int {
	return cmp.Or(
		strings.Compare(a.Finding.Target, b.Finding.Target),
		cmp.Compare(kindOrder[a.Kind], kindOrder[b.Kind]),
		engine.CompareFindings(a.Finding, b.Finding),
	)
}

func loadRows(ctx context.Context, tx *sql.Tx, canonical func(string) string) (map[string]*row, error) {
	rs, err := tx.QueryContext(ctx, `SELECT fingerprint, check_id, target, subject, severity, title, evidence, remediation,
		open, suppressed, missing_runs, first_seen, last_seen, resolved_at FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	rows := make(map[string]*row)
	for rs.Next() {
		rw := &row{}
		var sev, evidence string
		if err := rs.Scan(&rw.fp, &rw.f.CheckID, &rw.f.Target, &rw.f.Subject, &sev, &rw.f.Title, &evidence, &rw.f.Remediation,
			&rw.open, &rw.suppressed, &rw.missing, &rw.firstSeen, &rw.lastSeen, &rw.resolvedAt); err != nil {
			return nil, err
		}
		rw.f.Severity, _ = core.ParseSeverity(sev)
		_ = json.Unmarshal([]byte(evidence), &rw.f.Evidence)
		if id := canonical(rw.f.CheckID); id != rw.f.CheckID {
			rw.f.CheckID, rw.oldFP, rw.dirty = id, rw.fp, true
			rw.fp = rw.f.Fingerprint()
		}
		rows[rw.fp] = rw
	}
	return rows, rs.Err()
}

func saveRows(ctx context.Context, tx *sql.Tx, rows map[string]*row) error {
	for _, rw := range rows {
		if rw.oldFP != "" {
			if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE fingerprint = ?", rw.oldFP); err != nil {
				return err
			}
		}
		if rw.gone {
			if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE fingerprint = ?", rw.fp); err != nil {
				return err
			}
			continue
		}
		if !rw.dirty {
			continue
		}
		evidence, err := json.Marshal(rw.f.Evidence)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings (fingerprint, check_id, target, subject, severity, title, evidence,
			remediation, open, suppressed, missing_runs, first_seen, last_seen, resolved_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (fingerprint) DO UPDATE SET check_id = excluded.check_id, severity = excluded.severity,
				title = excluded.title, evidence = excluded.evidence, remediation = excluded.remediation, open = excluded.open,
				suppressed = excluded.suppressed, missing_runs = excluded.missing_runs, last_seen = excluded.last_seen,
				resolved_at = excluded.resolved_at`,
			rw.fp, rw.f.CheckID, rw.f.Target, rw.f.Subject, rw.f.Severity.String(), rw.f.Title, string(evidence),
			rw.f.Remediation, rw.open, rw.suppressed, rw.missing, rw.firstSeen, rw.lastSeen, rw.resolvedAt); err != nil {
			return err
		}
	}
	return nil
}
