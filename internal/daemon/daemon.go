// Package daemon runs a job on a cron schedule and reports its health over
// HTTP.
package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// Summary describes one completed run for logs and /healthz.
type Summary struct {
	RunID          int64         `json:"run_id"`
	Started        time.Time     `json:"started_at"`
	Duration       time.Duration `json:"-"`
	DurationMS     int64         `json:"duration_ms"`
	New            int           `json:"new"`
	Regressed      int           `json:"regressed"`
	Resolved       int           `json:"resolved"`
	Open           int           `json:"open_findings"`
	CheckErrors    int           `json:"check_errors"`
	NotifyFailures []string      `json:"notify_failures"`
}

type Daemon struct {
	Schedule cron.Schedule
	// Run performs one run. It must not record anything when ctx is
	// canceled before it finishes.
	Run    func(ctx context.Context) (Summary, error)
	Logger *slog.Logger
	// Grace is how long a run in progress may continue after shutdown is
	// requested before it is canceled.
	Grace time.Duration
	// StaleAfter: /healthz fails when no run has started for this long past
	// its scheduled time (a stuck run).
	StaleAfter time.Duration
	Now        func() time.Time
	// After replaces time.After in tests.
	After func(time.Duration) <-chan time.Time

	mu          sync.Mutex
	started     time.Time
	running     bool
	next        time.Time
	lastStarted time.Time
	last        *Summary // last successful run
	lastErr     string
}

// Serve runs once immediately, then on every scheduled time until ctx is
// done. Runs never overlap: the next time is computed after a run ends, so
// scheduled times that pass during a long run are skipped.
func (d *Daemon) Serve(ctx context.Context) error {
	d.mu.Lock()
	d.started = d.now()
	d.mu.Unlock()
	next := d.now()
	for {
		d.mu.Lock()
		d.next = next
		d.mu.Unlock()
		if wait := next.Sub(d.now()); wait > 0 {
			d.logger().Info("next run scheduled", "at", next.Format(time.RFC3339))
			select {
			case <-ctx.Done():
				return nil
			case <-d.after(wait):
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		d.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		now := d.now()
		next = d.Schedule.Next(now)
		if skipped := countBetween(d.Schedule, d.lastStart(), now); skipped > 0 {
			d.logger().Warn("run took longer than the schedule interval; skipped scheduled runs", "skipped", skipped)
		}
	}
}

func (d *Daemon) runOnce(ctx context.Context) {
	// Shutdown lets the current run finish (up to Grace) instead of
	// abandoning it half-way.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		d.logger().Info("shutting down after the current run", "grace", d.Grace)
		time.AfterFunc(d.Grace, cancel)
	})
	defer stop()

	d.mu.Lock()
	d.running = true
	d.lastStarted = d.now()
	d.mu.Unlock()

	sum, err := d.Run(runCtx)

	d.mu.Lock()
	defer d.mu.Unlock()
	d.running = false
	if err != nil {
		d.logger().Error("run failed", "error", err)
		d.lastErr = err.Error()
		return
	}
	d.lastErr = ""
	sum.DurationMS = sum.Duration.Milliseconds()
	if sum.NotifyFailures == nil {
		sum.NotifyFailures = []string{}
	}
	d.last = &sum
}

func (d *Daemon) lastStart() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastStarted
}

// countBetween counts scheduled times in (from, to).
func countBetween(s cron.Schedule, from, to time.Time) int {
	n := 0
	for t := s.Next(from); t.Before(to) && n < 1000; t = s.Next(t) {
		n++
	}
	return n
}

type health struct {
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	Running   bool      `json:"running"`
	NextRun   time.Time `json:"next_run"`
	LastRun   *Summary  `json:"last_run"`
	LastError string    `json:"last_error,omitempty"`
}

// Handler serves GET /healthz: 200 with status "ok" (or "starting" before
// the first run completes), 503 with "failing" when the last run failed
// and "stale" when runs stopped happening.
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		h := health{StartedAt: d.started, Running: d.running, NextRun: d.next, LastError: d.lastErr, Status: "ok"}
		if d.last != nil {
			last := *d.last
			h.LastRun = &last
		}
		d.mu.Unlock()

		code := http.StatusOK
		switch {
		case !h.NextRun.IsZero() && d.now().After(h.NextRun.Add(d.staleAfter())):
			h.Status, code = "stale", http.StatusServiceUnavailable
		case h.LastError != "":
			h.Status, code = "failing", http.StatusServiceUnavailable
		case h.LastRun == nil:
			h.Status = "starting"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(h)
	})
	return mux
}

func (d *Daemon) staleAfter() time.Duration {
	if d.StaleAfter > 0 {
		return d.StaleAfter
	}
	return time.Hour
}

func (d *Daemon) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Daemon) after(wait time.Duration) <-chan time.Time {
	if d.After != nil {
		return d.After(wait)
	}
	return time.After(wait)
}

func (d *Daemon) logger() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Logger
}
