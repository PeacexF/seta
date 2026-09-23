package dnsx

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingResolver counts calls and can block or fail on demand.
type countingResolver struct {
	next  Resolver
	calls atomic.Int32
	gate  chan struct{} // if set, each call waits for a receive-able value or ctx
	err   error
}

func (c *countingResolver) Lookup(ctx context.Context, name string, qtype uint16) (*Response, error) {
	c.calls.Add(1)
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return nil, &Error{Name: name, Type: qtype, Err: ctx.Err()}
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.next.Lookup(ctx, name, qtype)
}

func TestCacheDeduplicates(t *testing.T) {
	cr := &countingResolver{next: newTestFake(t)}
	c := NewCache(cr)
	ctx := context.Background()
	for _, name := range []string{"example.test", "EXAMPLE.TEST.", "example.test"} {
		if _, err := c.Lookup(ctx, name, dns.TypeMX); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Lookup(ctx, "example.test", dns.TypeTXT); err != nil {
		t.Fatal(err)
	}
	if got := cr.calls.Load(); got != 2 {
		t.Fatalf("underlying lookups = %d, want 2 (one MX, one TXT)", got)
	}
}

func TestCacheConcurrentCallersShareOneLookup(t *testing.T) {
	cr := &countingResolver{next: newTestFake(t), gate: make(chan struct{})}
	c := NewCache(cr)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := c.Lookup(context.Background(), "example.test", dns.TypeMX); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(20 * time.Millisecond) // let the callers pile up on the entry
	close(cr.gate)
	wg.Wait()
	if got := cr.calls.Load(); got != 1 {
		t.Fatalf("underlying lookups = %d, want 1", got)
	}
}

func TestCacheCachesQueryFailures(t *testing.T) {
	cr := &countingResolver{err: &Error{Name: "x.test.", Type: dns.TypeA, Rcode: dns.RcodeServerFailure}}
	c := NewCache(cr)
	for range 3 {
		if _, err := c.Lookup(context.Background(), "x.test", dns.TypeA); err == nil {
			t.Fatal("expected error")
		}
	}
	if got := cr.calls.Load(); got != 1 {
		t.Fatalf("underlying lookups = %d, want 1", got)
	}
}

func TestCacheDoesNotCacheCallerCancellation(t *testing.T) {
	cr := &countingResolver{next: newTestFake(t), gate: make(chan struct{}, 1)}
	c := NewCache(cr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Lookup(ctx, "example.test", dns.TypeMX); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	cr.gate <- struct{}{}
	resp, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
	if err != nil || len(resp.MX()) != 2 {
		t.Fatalf("second caller should retry and succeed, got %v, %v", resp, err)
	}
}

func TestCacheWaiterRetriesWhenLeaderIsCanceled(t *testing.T) {
	cr := &countingResolver{next: newTestFake(t), gate: make(chan struct{})}
	c := NewCache(cr)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error)
	go func() {
		_, err := c.Lookup(leaderCtx, "example.test", dns.TypeMX)
		leaderDone <- err
	}()
	for cr.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	waiterDone := make(chan error)
	go func() {
		_, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
		waiterDone <- err
	}()
	time.Sleep(10 * time.Millisecond)

	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader: want context.Canceled, got %v", err)
	}
	close(cr.gate)
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter should have retried and succeeded, got %v", err)
	}
}

func TestCacheWaiterHonorsOwnContext(t *testing.T) {
	cr := &countingResolver{next: newTestFake(t), gate: make(chan struct{})}
	defer close(cr.gate)
	c := NewCache(cr)
	go c.Lookup(context.Background(), "example.test", dns.TypeMX) //nolint:errcheck
	for cr.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Lookup(ctx, "example.test", dns.TypeMX); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}
