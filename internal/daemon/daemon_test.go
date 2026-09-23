package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

// clock is a fake time source whose timers fire when the test advances it.
type clock struct {
	mu      sync.Mutex
	now     time.Time
	waiting chan time.Duration
	fire    chan time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), waiting: make(chan time.Duration), fire: make(chan time.Time)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	c.waiting <- d
	return c.fire
}

// advance waits for the daemon to start waiting, then moves time forward by
// the requested wait and fires the timer.
func (c *clock) advance(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.waiting:
		c.mu.Lock()
		c.now = c.now.Add(d)
		c.mu.Unlock()
		c.fire <- c.Now()
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never waited")
		return 0
	}
}

func hourly(t *testing.T) cron.Schedule {
	s, err := cron.ParseStandard("0 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSchedule(t *testing.T) {
	c := newClock()
	runs := make(chan time.Time, 10)
	d := &Daemon{
		Schedule: hourly(t),
		Now:      c.Now,
		After:    c.After,
		Run: func(ctx context.Context) (Summary, error) {
			runs <- c.Now()
			c.mu.Lock()
			c.now = c.now.Add(10 * time.Minute) // the run takes a while
			c.mu.Unlock()
			return Summary{RunID: int64(len(runs))}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Serve(ctx) }()

	start := <-runs
	if w := c.advance(t); w != 50*time.Minute {
		t.Errorf("waited %v after a 10m run, want 50m", w)
	}
	if second := <-runs; second.Sub(start) != time.Hour {
		t.Errorf("second run %v after the first", second.Sub(start))
	}
	<-c.waiting // waiting for the third run
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSkipsMissedTimesInsteadOfOverlapping(t *testing.T) {
	c := newClock()
	var n int
	d := &Daemon{
		Schedule: hourly(t),
		Now:      c.Now,
		After:    c.After,
		Run: func(ctx context.Context) (Summary, error) {
			n++
			c.mu.Lock()
			c.now = c.now.Add(150 * time.Minute)
			c.mu.Unlock()
			return Summary{}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Serve(ctx)
	if w := <-c.waiting; w != 30*time.Minute || n != 1 {
		t.Errorf("after a 2.5h run: waiting %v with %d runs; want the next whole hour", w, n)
	}
}

// blockingRun returns a run that signals started and returns when release
// is closed or its context ends, reporting the context error.
func blockingRun(started, release chan struct{}, runErr *error) func(ctx context.Context) (Summary, error) {
	return func(ctx context.Context) (Summary, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			*runErr = ctx.Err()
		}
		return Summary{}, nil
	}
}

func TestGracefulShutdown(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var runErr error
	d := &Daemon{Schedule: cron.Every(time.Hour), Grace: time.Hour, Run: blockingRun(started, release, &runErr)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Serve(ctx) }()
	<-started
	cancel()
	select {
	case <-done:
		t.Fatal("Serve returned before the run finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	if runErr != nil {
		t.Errorf("run was canceled within the grace period: %v", runErr)
	}
}

func TestShutdownCancelsAfterGrace(t *testing.T) {
	started := make(chan struct{})
	var runErr error
	d := &Daemon{Schedule: cron.Every(time.Hour), Grace: 10 * time.Millisecond, Run: blockingRun(started, make(chan struct{}), &runErr)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Serve(ctx) }()
	<-started
	cancel()
	<-done
	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("run not canceled after grace: %v", runErr)
	}
}

func TestHealth(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d := &Daemon{Now: func() time.Time { return now }}
	get := func() (int, health) {
		rec := httptest.NewRecorder()
		d.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		var h health
		json.Unmarshal(rec.Body.Bytes(), &h)
		return rec.Code, h
	}
	if code, h := get(); code != 200 || h.Status != "starting" {
		t.Errorf("before first run: %d %+v", code, h)
	}

	d.Run = func(context.Context) (Summary, error) { return Summary{RunID: 4, New: 2, Duration: time.Second}, nil }
	d.runOnce(context.Background())
	d.next = now.Add(time.Hour)
	if code, h := get(); code != 200 || h.Status != "ok" || h.LastRun.RunID != 4 || h.LastRun.DurationMS != 1000 {
		t.Errorf("after a run: %d %+v", code, h)
	}

	d.Run = func(context.Context) (Summary, error) { return Summary{}, errors.New("DNS check failed") }
	d.runOnce(context.Background())
	if code, h := get(); code != 503 || h.Status != "failing" || h.LastError != "DNS check failed" || h.LastRun.RunID != 4 {
		t.Errorf("after a failed run: %d %+v", code, h)
	}

	d.lastErr = ""
	now = now.Add(3 * time.Hour)
	if code, h := get(); code != 503 || h.Status != "stale" {
		t.Errorf("stuck: %d %+v", code, h)
	}
}
