// Package engine runs checks against targets with bounded concurrency and
// per-check timeouts, keeping check errors separate from findings.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
)

// Defaults for Engine fields left at their zero value.
const (
	DefaultWorkers      = 16
	DefaultPerTarget    = 4
	DefaultCheckTimeout = 15 * time.Second
)

// Engine executes checks. The zero value is not usable; set Resolver.
type Engine struct {
	// Resolver is wrapped in a fresh dnsx.Cache for every run.
	Resolver dnsx.Resolver
	Logger   *slog.Logger
	// Workers bounds how many checks run at once across all targets.
	Workers int
	// PerTarget bounds how many checks run at once against a single target,
	// so Seta never hammers one domain.
	PerTarget int
	// CheckTimeout bounds each check. A check that overruns is reported as a
	// check error and abandoned.
	CheckTimeout time.Duration
	// Now is used for timestamps; tests replace it. Defaults to time.Now.
	Now func() time.Time
}

// Job pairs a target with the checks to run against it. Callers decide which
// checks apply (selection patterns, active/passive) before calling Run.
type Job struct {
	Target core.Target
	Checks []core.Check
}

// Result is the outcome of one run.
type Result struct {
	Started  time.Time
	Duration time.Duration
	Targets  []core.Target
	// Executions is the number of (target, check) pairs that ran.
	Executions int
	// Findings are sorted by target, severity (highest first), check ID, subject.
	Findings []core.Finding
	// Errors are sorted by target and check ID.
	Errors []CheckError
}

// CheckError records a check that could not reach a verdict.
type CheckError struct {
	CheckID string
	Target  string
	Err     error
}

func (e CheckError) Error() string {
	return fmt.Sprintf("%s on %s: %v", e.CheckID, e.Target, e.Err)
}

// ErrTimeout is wrapped by errors for checks that exceeded CheckTimeout.
var ErrTimeout = errors.New("check timed out")

// Run executes every job and returns once all checks have finished, timed
// out, or ctx is done. It never returns partial per-check results: each
// check contributes either its findings or one CheckError.
func (e *Engine) Run(ctx context.Context, jobs []Job) *Result {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	logger := e.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	env := core.Env{
		Resolver: dnsx.NewCache(e.Resolver),
		Logger:   logger,
	}

	res := &Result{Started: now()}
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		global = make(chan struct{}, orDefault(e.Workers, DefaultWorkers))
	)
	for _, job := range jobs {
		res.Targets = append(res.Targets, job.Target)
		perTarget := make(chan struct{}, orDefault(e.PerTarget, DefaultPerTarget))
		for _, c := range job.Checks {
			res.Executions++
			wg.Go(func() {
				// Acquire the per-target slot first so a busy target doesn't
				// hold global slots while it waits.
				perTarget <- struct{}{}
				defer func() { <-perTarget }()
				global <- struct{}{}
				defer func() { <-global }()

				findings, err := e.runOne(ctx, env, c, job.Target)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					res.Errors = append(res.Errors, CheckError{CheckID: c.Meta().ID, Target: job.Target.Name, Err: err})
					return
				}
				res.Findings = append(res.Findings, findings...)
			})
		}
	}
	wg.Wait()
	res.Duration = now().Sub(res.Started)

	slices.SortFunc(res.Findings, compareFindings)
	slices.SortFunc(res.Errors, func(a, b CheckError) int {
		return cmp.Or(strings.Compare(a.Target, b.Target), strings.Compare(a.CheckID, b.CheckID))
	})
	return res
}

type outcome struct {
	findings []core.Finding
	err      error
}

// runOne runs a single check with its timeout, recovering panics, and
// normalizes the findings it returns.
func (e *Engine) runOne(ctx context.Context, env core.Env, c core.Check, t core.Target) ([]core.Finding, error) {
	meta := c.Meta()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("run canceled before check started: %w", err)
	}
	timeout := orDefault(e.CheckTimeout, DefaultCheckTimeout)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	env.Logger = env.Logger.With("check", meta.ID, "target", t.Name)
	start := time.Now()
	done := make(chan outcome, 1) // buffered: an abandoned check can still finish and exit
	go func() {
		defer func() {
			if p := recover(); p != nil {
				env.Logger.Error("check panicked", "panic", p, "stack", string(debug.Stack()))
				done <- outcome{err: fmt.Errorf("check panicked: %v", p)}
			}
		}()
		f, err := c.Run(cctx, env, t)
		done <- outcome{f, err}
	}()

	var o outcome
	select {
	case o = <-done:
	case <-cctx.Done():
		// Prefer a result that raced with the deadline.
		select {
		case o = <-done:
		default:
			if ctx.Err() != nil {
				o.err = fmt.Errorf("run canceled: %w", ctx.Err())
			} else {
				o.err = fmt.Errorf("%w after %s", ErrTimeout, timeout)
			}
		}
	}
	env.Logger.Debug("check finished", "duration", time.Since(start), "findings", len(o.findings), "error", o.err)
	if o.err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil && !errors.Is(o.err, ErrTimeout) {
			o.err = fmt.Errorf("%w after %s: %w", ErrTimeout, timeout, o.err)
		}
		return nil, o.err
	}
	return normalize(meta, t, o.findings)
}

// normalize fills defaults from the check's metadata and rejects findings
// that claim to come from another check or target.
func normalize(meta core.Meta, t core.Target, findings []core.Finding) ([]core.Finding, error) {
	out := make([]core.Finding, 0, len(findings))
	subjects := make(map[string]bool, len(findings))
	for _, f := range findings {
		if subjects[f.Subject] {
			return nil, fmt.Errorf("check returned more than one finding for subject %q", f.Subject)
		}
		subjects[f.Subject] = true
		if f.CheckID == "" {
			f.CheckID = meta.ID
		} else if f.CheckID != meta.ID {
			return nil, fmt.Errorf("check returned a finding for foreign check ID %q", f.CheckID)
		}
		if f.Target == "" {
			f.Target = t.Name
		} else if f.Target != t.Name {
			return nil, fmt.Errorf("check returned a finding for foreign target %q", f.Target)
		}
		if f.Severity == core.SeverityUnset {
			f.Severity = meta.Severity
		} else if !f.Severity.Valid() {
			return nil, fmt.Errorf("check returned a finding with invalid severity %d", int(f.Severity))
		}
		if f.Title == "" {
			f.Title = meta.Title
		}
		if f.Remediation == "" {
			f.Remediation = meta.Remediation
		}
		out = append(out, f)
	}
	return out, nil
}

func compareFindings(a, b core.Finding) int {
	return cmp.Or(
		strings.Compare(a.Target, b.Target),
		cmp.Compare(b.Severity, a.Severity),
		strings.Compare(a.CheckID, b.CheckID),
		strings.Compare(a.Subject, b.Subject),
	)
}

func orDefault[T cmp.Ordered](v, def T) T {
	var zero T
	if v <= zero {
		return def
	}
	return v
}
