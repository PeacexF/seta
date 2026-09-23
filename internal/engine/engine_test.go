package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
)

// funcCheck adapts a function into a check with the given ID.
type funcCheck struct {
	id  string
	sev core.Severity
	run func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error)
}

func (c funcCheck) Meta() core.Meta {
	module, _, _ := strings.Cut(c.id, ".")
	sev := c.sev
	if sev == core.SeverityUnset {
		sev = core.SeverityMedium
	}
	return core.Meta{ID: c.id, Module: module, Title: "Title of " + c.id, Remediation: "Fix " + c.id, Severity: sev}
}

func (c funcCheck) Run(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	return c.run(ctx, env, t)
}

func findingCheck(id string, findings ...core.Finding) funcCheck {
	return funcCheck{id: id, run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		return findings, nil
	}}
}

func target(t *testing.T, name string) core.Target {
	t.Helper()
	tg, err := core.ParseDomain(name)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func newEngine() *Engine {
	return &Engine{Resolver: dnsx.NewFake(), CheckTimeout: time.Second}
}

func TestRunNormalizesFindings(t *testing.T) {
	e := newEngine()
	c := findingCheck("test.a.defaults", core.Finding{Subject: "s1"}, core.Finding{
		Subject: "s2", Severity: core.SeverityCritical, Title: "Custom", Remediation: "Custom fix",
	})
	res := e.Run(context.Background(), []Job{{Target: target(t, "example.test"), Checks: []core.Check{c}}})

	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res.Findings))
	}
	custom, defaults := res.Findings[0], res.Findings[1] // critical sorts first
	if defaults.CheckID != "test.a.defaults" || defaults.Target != "example.test" ||
		defaults.Severity != core.SeverityMedium || defaults.Title != "Title of test.a.defaults" ||
		defaults.Remediation != "Fix test.a.defaults" {
		t.Errorf("defaults not filled from meta: %+v", defaults)
	}
	if custom.Severity != core.SeverityCritical || custom.Title != "Custom" || custom.Remediation != "Custom fix" {
		t.Errorf("check-provided values overwritten: %+v", custom)
	}
}

func TestRunRejectsMalformedFindings(t *testing.T) {
	tests := map[string]core.Finding{
		"foreign check ID": {CheckID: "other.check.id"},
		"foreign target":   {Target: "other.test"},
		"invalid severity": {Severity: core.Severity(42)},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			res := newEngine().Run(context.Background(), []Job{{
				Target: target(t, "example.test"),
				Checks: []core.Check{findingCheck("test.a.b", f)},
			}})
			if len(res.Findings) != 0 || len(res.Errors) != 1 {
				t.Fatalf("want one check error and no findings, got %+v", res)
			}
		})
	}
	t.Run("duplicate subject", func(t *testing.T) {
		res := newEngine().Run(context.Background(), []Job{{
			Target: target(t, "example.test"),
			Checks: []core.Check{findingCheck("test.a.b", core.Finding{Subject: "x"}, core.Finding{Subject: "x"})},
		}})
		if len(res.Findings) != 0 || len(res.Errors) != 1 {
			t.Fatalf("want one check error and no findings, got %+v", res)
		}
	})
}

func TestErrorsAreSeparateFromFindings(t *testing.T) {
	fake := dnsx.NewFake()
	fake.SetError("example.test", dns.TypeMX, nil)
	e := &Engine{Resolver: fake}
	lookupMX := funcCheck{id: "test.dns.mx", run: func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		if _, err := env.Resolver.Lookup(ctx, t.Name, dns.TypeMX); err != nil {
			return nil, err
		}
		return []core.Finding{{}}, nil
	}}
	res := e.Run(context.Background(), []Job{{
		Target: target(t, "example.test"),
		Checks: []core.Check{lookupMX, findingCheck("test.other.ok", core.Finding{})},
	}})
	if len(res.Findings) != 1 || res.Findings[0].CheckID != "test.other.ok" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Errors) != 1 || res.Errors[0].CheckID != "test.dns.mx" ||
		!strings.Contains(res.Errors[0].Err.Error(), "SERVFAIL") {
		t.Fatalf("errors = %+v", res.Errors)
	}
	if res.Executions != 2 {
		t.Fatalf("executions = %d, want 2", res.Executions)
	}
}

func TestCheckTimeoutAbandonsStuckCheck(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := funcCheck{id: "test.slow.ignores_ctx", run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		<-release // ignores its context entirely
		return nil, nil
	}}
	e := &Engine{Resolver: dnsx.NewFake(), CheckTimeout: 50 * time.Millisecond}
	start := time.Now()
	res := e.Run(context.Background(), []Job{{Target: target(t, "example.test"), Checks: []core.Check{stuck}}})
	if time.Since(start) > time.Second {
		t.Fatalf("run waited for a stuck check: %v", time.Since(start))
	}
	if len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, ErrTimeout) {
		t.Fatalf("want timeout error, got %+v", res.Errors)
	}
}

func TestCheckTimeoutWrapsContextErrors(t *testing.T) {
	polite := funcCheck{id: "test.slow.honors_ctx", run: func(ctx context.Context, _ core.Env, _ core.Target) ([]core.Finding, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("lookup failed: %w", ctx.Err())
	}}
	e := &Engine{Resolver: dnsx.NewFake(), CheckTimeout: 20 * time.Millisecond}
	res := e.Run(context.Background(), []Job{{Target: target(t, "example.test"), Checks: []core.Check{polite}}})
	if len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, ErrTimeout) {
		t.Fatalf("want timeout error, got %+v", res.Errors)
	}
}

func TestPanickingCheckBecomesError(t *testing.T) {
	boom := funcCheck{id: "test.bad.panics", run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		panic("boom")
	}}
	res := newEngine().Run(context.Background(), []Job{{
		Target: target(t, "example.test"),
		Checks: []core.Check{boom, findingCheck("test.good.ok", core.Finding{})},
	}})
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Err.Error(), "panicked: boom") {
		t.Fatalf("errors = %+v", res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("other checks must still run, findings = %+v", res.Findings)
	}
}

func TestCanceledRunReportsErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := newEngine().Run(ctx, []Job{{Target: target(t, "example.test"), Checks: []core.Check{findingCheck("test.a.b", core.Finding{})}}})
	if len(res.Findings) != 0 || len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, context.Canceled) {
		t.Fatalf("got %+v", res)
	}
}

// concurrencyProbe records the peak number of simultaneous runs, overall and
// per target.
type concurrencyProbe struct {
	mu        sync.Mutex
	active    int
	peak      int
	perTarget map[string]int
	peakPer   int
}

func (p *concurrencyProbe) check(id string) funcCheck {
	return funcCheck{id: id, run: func(_ context.Context, _ core.Env, t core.Target) ([]core.Finding, error) {
		p.mu.Lock()
		p.active++
		p.perTarget[t.Name]++
		p.peak = max(p.peak, p.active)
		p.peakPer = max(p.peakPer, p.perTarget[t.Name])
		p.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		p.mu.Lock()
		p.active--
		p.perTarget[t.Name]--
		p.mu.Unlock()
		return nil, nil
	}}
}

func TestConcurrencyLimits(t *testing.T) {
	probe := &concurrencyProbe{perTarget: make(map[string]int)}
	var checks []core.Check
	for i := range 12 {
		checks = append(checks, probe.check(fmt.Sprintf("test.c.n%d", i)))
	}
	var jobs []Job
	for i := range 6 {
		jobs = append(jobs, Job{Target: target(t, fmt.Sprintf("t%d.test", i)), Checks: checks})
	}
	e := &Engine{Resolver: dnsx.NewFake(), Workers: 5, PerTarget: 2}
	res := e.Run(context.Background(), jobs)

	if res.Executions != 72 || len(res.Errors) != 0 {
		t.Fatalf("executions = %d, errors = %v", res.Executions, res.Errors)
	}
	if probe.peak > 5 {
		t.Errorf("global concurrency peaked at %d, limit 5", probe.peak)
	}
	if probe.peakPer > 2 {
		t.Errorf("per-target concurrency peaked at %d, limit 2", probe.peakPer)
	}
	if probe.peak < 2 {
		t.Errorf("checks did not run concurrently (peak %d)", probe.peak)
	}
}

func TestRunSharesCachedResolverWithinRun(t *testing.T) {
	var calls atomic.Int32
	counting := resolverFunc(func(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
		calls.Add(1)
		return &dnsx.Response{Name: name, Type: qtype}, nil
	})
	lookup := func(id string) funcCheck {
		return funcCheck{id: id, run: func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
			_, err := env.Resolver.Lookup(ctx, t.Name, dns.TypeTXT)
			return nil, err
		}}
	}
	e := &Engine{Resolver: counting}
	jobs := []Job{{Target: target(t, "example.test"), Checks: []core.Check{lookup("test.a.one"), lookup("test.a.two"), lookup("test.a.three")}}}
	e.Run(context.Background(), jobs)
	e.Run(context.Background(), jobs)
	if got := calls.Load(); got != 2 {
		t.Fatalf("underlying lookups = %d, want 1 per run", got)
	}
}

type resolverFunc func(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error)

func (f resolverFunc) Lookup(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	return f(ctx, name, qtype)
}

func TestResultsAreSorted(t *testing.T) {
	low := funcCheck{id: "test.z.low", sev: core.SeverityLow, run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		return []core.Finding{{Subject: "b"}, {Subject: "a"}}, nil
	}}
	high := funcCheck{id: "test.z.high", sev: core.SeverityHigh, run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		return []core.Finding{{}}, nil
	}}
	fail := funcCheck{id: "test.a.fail", run: func(context.Context, core.Env, core.Target) ([]core.Finding, error) {
		return nil, errors.New("nope")
	}}
	checks := []core.Check{low, high, fail}
	res := newEngine().Run(context.Background(), []Job{
		{Target: target(t, "b.test"), Checks: checks},
		{Target: target(t, "a.test"), Checks: checks},
	})
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Target+"/"+f.CheckID+"/"+f.Subject)
	}
	want := []string{
		"a.test/test.z.high/", "a.test/test.z.low/a", "a.test/test.z.low/b",
		"b.test/test.z.high/", "b.test/test.z.low/a", "b.test/test.z.low/b",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("finding order:\n got  %v\n want %v", got, want)
	}
	if len(res.Errors) != 2 || res.Errors[0].Target != "a.test" || res.Errors[1].Target != "b.test" {
		t.Fatalf("error order: %+v", res.Errors)
	}
	// Targets keep the order they were given in.
	if res.Targets[0].Name != "b.test" || res.Targets[1].Name != "a.test" {
		t.Fatalf("targets reordered: %v", res.Targets)
	}
}
