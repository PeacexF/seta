package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMemoizeRunsOnce(t *testing.T) {
	m := NewMemo()
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			v, err := Memoize(context.Background(), m, "k", func(context.Context) (int, error) {
				calls.Add(1)
				return 42, nil
			})
			if v != 42 || err != nil {
				t.Errorf("got %d, %v", v, err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("fn ran %d times", calls.Load())
	}
}

func TestMemoizeCachesErrorsButNotCancellation(t *testing.T) {
	m := NewMemo()
	boom := errors.New("boom")
	for range 2 {
		if _, err := Memoize(context.Background(), m, "err", func(context.Context) (int, error) { return 0, boom }); !errors.Is(err, boom) {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Memoize(ctx, m, "c", func(ctx context.Context) (int, error) { return 0, ctx.Err() }); err == nil {
		t.Fatal("want error")
	}
	v, err := Memoize(context.Background(), m, "c", func(context.Context) (int, error) { return 7, nil })
	if v != 7 || err != nil {
		t.Fatalf("canceled result was cached: %d %v", v, err)
	}
}
