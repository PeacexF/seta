// Package checktest helps unit-test checks offline against zone fixtures.
package checktest

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/netx"
)

// ZonesDir is the absolute path of the shared zone fixtures in testdata/zones.
func ZonesDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "zones")
}

// Fixtures returns a fake resolver loaded with every shared zone fixture. It
// also answers the resolver check's canary queries, so it passes dnsx.Probe.
func Fixtures(tb testing.TB) *dnsx.Fake {
	tb.Helper()
	f, err := dnsx.LoadFakeDir(ZonesDir())
	if err != nil {
		tb.Fatalf("load zone fixtures: %v", err)
	}
	f.AddCanaries()
	return f
}

// Zone returns a fake resolver serving one inline zone.
func Zone(tb testing.TB, origin, zone string) *dnsx.Fake {
	tb.Helper()
	f := dnsx.NewFake()
	if err := f.AddZoneString(origin, zone); err != nil {
		tb.Fatalf("zone %s: %v", origin, err)
	}
	return f
}

type Env struct {
	Resolver dnsx.Resolver
	Net      netx.Options
	Now      func() time.Time
}

// Run executes one check against one domain through the engine, so findings
// are normalized and validated exactly as in a real run. It returns the
// findings, or the check error if the check could not reach a verdict.
func Run(tb testing.TB, c core.Check, r dnsx.Resolver, domain string) ([]core.Finding, error) {
	tb.Helper()
	return RunWith(tb, c, Env{Resolver: r}, Domain(tb, domain))
}

func RunWith(tb testing.TB, c core.Check, env Env, t core.Target) ([]core.Finding, error) {
	tb.Helper()
	e := &engine.Engine{Resolver: env.Resolver, Net: env.Net, Now: env.Now, CheckTimeout: 5 * time.Second}
	res := e.Run(context.Background(), []engine.Job{{Target: t, Checks: []core.Check{c}}})
	if len(res.Errors) > 0 {
		return nil, res.Errors[0].Err
	}
	return res.Findings, nil
}

func Domain(tb testing.TB, name string) core.Target {
	tb.Helper()
	t, err := core.ParseDomain(name)
	if err != nil {
		tb.Fatal(err)
	}
	return t
}
