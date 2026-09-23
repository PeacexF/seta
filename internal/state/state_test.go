package state

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// sim builds runs: each run checks spf and mx on a.test (and b.test when
// listed) and reports the findings given as "check@target" or
// "check@target/subject".
type sim struct {
	t     *testing.T
	s     *Store
	n     int
	opts  Options
	extra func(res *engine.Result)
}

func newSim(t *testing.T) *sim {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &sim{t: t, s: s, opts: Options{ResolveAfter: 2}}
}

func finding(spec string) core.Finding {
	check, where, _ := strings.Cut(spec, "@")
	target, subject, _ := strings.Cut(where, "/")
	return core.Finding{CheckID: "email." + check, Target: target, Subject: subject, Severity: core.SeverityHigh, Title: check,
		Evidence: map[string]string{"k": "v"}}
}

func (m *sim) result(targets []string, findings ...string) *engine.Result {
	res := &engine.Result{Started: t0.Add(time.Duration(m.n) * time.Hour), Duration: time.Second}
	for _, t := range targets {
		res.Targets = append(res.Targets, core.Target{Name: t})
		for _, c := range []string{"email.spf.missing", "email.mx.missing"} {
			res.Ran = append(res.Ran, engine.Execution{Target: t, CheckID: c})
		}
	}
	res.Executions = len(res.Ran)
	for _, f := range findings {
		res.Findings = append(res.Findings, finding(f))
	}
	return res
}

// run records a run and returns its changes as "kind check@target".
func (m *sim) run(res *engine.Result) string {
	m.t.Helper()
	m.n++
	if m.extra != nil {
		m.extra(res)
	}
	d, err := m.s.Record(context.Background(), res, m.opts)
	if err != nil {
		m.t.Fatal(err)
	}
	var out []string
	for _, c := range d.Changes {
		if c.Kind == Persisting {
			continue
		}
		s := fmt.Sprintf("%s %s@%s", c.Kind, strings.TrimPrefix(c.Finding.CheckID, "email."), c.Finding.Target)
		if c.Suppressed {
			s += " (suppressed)"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func expect(t *testing.T, step, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: changes = %q, want %q", step, got, want)
	}
}

var a = []string{"a.test"}

func TestLifecycle(t *testing.T) {
	m := newSim(t)
	expect(t, "first seen", m.run(m.result(a, "spf.missing@a.test")), "new spf.missing@a.test")
	expect(t, "still there", m.run(m.result(a, "spf.missing@a.test")), "")
	expect(t, "absent once", m.run(m.result(a)), "")
	expect(t, "absent twice", m.run(m.result(a)), "resolved spf.missing@a.test")
	expect(t, "stays resolved", m.run(m.result(a)), "")
	expect(t, "back", m.run(m.result(a, "spf.missing@a.test")), "regressed spf.missing@a.test")
	expect(t, "flap: absent", m.run(m.result(a)), "")
	expect(t, "flap: back", m.run(m.result(a, "spf.missing@a.test")), "")
	expect(t, "absent again", m.run(m.result(a)), "")
	expect(t, "count restarts after flap", m.run(m.result(a)), "resolved spf.missing@a.test")
}

func TestPersistingIsReported(t *testing.T) {
	m := newSim(t)
	m.run(m.result(a, "spf.missing@a.test"))
	d, err := m.s.Record(context.Background(), m.result(a, "spf.missing@a.test", "mx.missing@a.test"), m.opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changes) != 2 || d.Changes[0].Kind != New || d.Changes[1].Kind != Persisting || d.Open != 2 {
		t.Errorf("changes = %+v, open = %d", d.Changes, d.Open)
	}
	if !d.Changes[1].FirstSeen.Equal(t0.Add(time.Second)) {
		t.Errorf("first seen = %v", d.Changes[1].FirstSeen)
	}
}

func TestCheckErrorsNeverResolve(t *testing.T) {
	m := newSim(t)
	m.run(m.result(a, "spf.missing@a.test"))
	for i := range 5 {
		res := m.result(a)
		res.Errors = []engine.CheckError{{CheckID: "email.spf.missing", Target: "a.test", Err: errors.New("SERVFAIL")}}
		expect(t, fmt.Sprintf("error run %d", i), m.run(res), "")
	}
	// Errors don't count towards resolve_after either.
	expect(t, "first clean absence", m.run(m.result(a)), "")
	expect(t, "second clean absence", m.run(m.result(a)), "resolved spf.missing@a.test")
}

func TestUnselectedChecksNeverResolve(t *testing.T) {
	m := newSim(t)
	m.run(m.result(a, "spf.missing@a.test"))
	for range 3 {
		res := m.result(a)
		res.Ran = res.Ran[1:] // spf didn't run
		expect(t, "spf not run", m.run(res), "")
	}
}

func TestRemovedTargetsAreForgotten(t *testing.T) {
	m := newSim(t)
	m.run(m.result([]string{"a.test", "b.test"}, "spf.missing@a.test", "spf.missing@b.test"))
	expect(t, "b removed", m.run(m.result(a, "spf.missing@a.test")), "")
	expect(t, "b removed, again", m.run(m.result(a, "spf.missing@a.test")), "")
	expect(t, "b back", m.run(m.result([]string{"a.test", "b.test"}, "spf.missing@a.test", "spf.missing@b.test")), "new spf.missing@b.test")
}

func TestSuppressions(t *testing.T) {
	m := newSim(t)
	suppress := func(res *engine.Result) {
		for _, f := range res.Findings {
			res.Suppressed = append(res.Suppressed, engine.Suppressed{Finding: f, Reason: "known"})
		}
		res.Findings = nil
	}
	m.extra = suppress
	expect(t, "new but suppressed", m.run(m.result(a, "spf.missing@a.test")), "new spf.missing@a.test (suppressed)")
	expect(t, "suppressed persisting", m.run(m.result(a, "spf.missing@a.test")), "")
	m.extra = nil
	expect(t, "suppression expired", m.run(m.result(a, "spf.missing@a.test")), "new spf.missing@a.test")
	expect(t, "unsuppressed persisting", m.run(m.result(a, "spf.missing@a.test")), "")
	m.extra = suppress
	expect(t, "suppressed again", m.run(m.result(a, "spf.missing@a.test")), "")
	m.run(m.result(a))
	expect(t, "resolved while suppressed", m.run(m.result(a)), "resolved spf.missing@a.test (suppressed)")
}

func TestSubjectsAreSeparate(t *testing.T) {
	m := newSim(t)
	m.run(m.result(a, "mx.missing@a.test/mx1", "mx.missing@a.test/mx2"))
	m.run(m.result(a, "mx.missing@a.test/mx1"))
	expect(t, "mx2 gone", m.run(m.result(a, "mx.missing@a.test/mx1")), "resolved mx.missing@a.test")
}

func TestRenamedChecksKeepState(t *testing.T) {
	m := newSim(t)
	m.run(m.result(a, "spf.old@a.test"))
	m.opts.Canonical = func(id string) string { return strings.Replace(id, "old", "missing", 1) }
	expect(t, "after rename", m.run(m.result(a, "spf.missing@a.test")), "")
	expect(t, "renamed row resolves", m.run(m.result(a))+m.run(m.result(a)), "resolved spf.missing@a.test")
}

func TestPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	m := &sim{t: t, s: s, opts: Options{ResolveAfter: 1}}
	m.run(m.result(a, "spf.missing@a.test"))
	if err := s.Set(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m.s = s
	expect(t, "reopened", m.run(m.result(a)), "resolved spf.missing@a.test")
	if v, ok, err := s.Get(ctx, "k"); v != "v1" || !ok || err != nil {
		t.Errorf("kv = %q %v %v", v, ok, err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Error("deleted key still there")
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	s.db.Exec("PRAGMA user_version = 99")
	s.Close()
	if _, err := Open(context.Background(), path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("err = %v", err)
	}
}

func TestPrune(t *testing.T) {
	m := newSim(t)
	m.opts.ResolveAfter = 1
	m.run(m.result(a, "spf.missing@a.test"))
	m.run(m.result(a)) // resolves at t0+1h
	for range 3 {
		m.run(m.result(a))
	}
	ctx := context.Background()
	n, err := m.s.Prune(ctx, t0.Add(3*time.Hour))
	if err != nil || n != 3 {
		t.Fatalf("pruned %d runs, %v", n, err)
	}
	var runs, findings, events int
	m.s.db.QueryRow("SELECT COUNT(*) FROM runs").Scan(&runs)
	m.s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&findings)
	m.s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events)
	if runs != 2 || findings != 0 || events != 0 {
		t.Errorf("after prune: %d runs, %d findings, %d events", runs, findings, events)
	}
	// The latest run survives any cutoff.
	if n, _ := m.s.Prune(ctx, t0.Add(1000*time.Hour)); n != 1 {
		t.Errorf("pruned %d", n)
	}
	m.s.db.QueryRow("SELECT COUNT(*) FROM runs").Scan(&runs)
	if runs != 1 {
		t.Errorf("%d runs left", runs)
	}
	expect(t, "pruned finding returns as new", m.run(m.result(a, "spf.missing@a.test")), "new spf.missing@a.test")
}
