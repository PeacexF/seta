package core

import (
	"context"
	"sync"
)

// Memo shares expensive per-run work (an SPF evaluation, an SMTP session)
// between the checks that need it. Like dnsx.Cache, a result produced while
// the computing check's context ended is discarded so the next caller retries.
type Memo struct {
	mu      sync.Mutex
	entries map[string]*memoEntry
}

type memoEntry struct {
	done  chan struct{}
	val   any
	err   error
	retry bool
}

func NewMemo() *Memo { return &Memo{entries: make(map[string]*memoEntry)} }

// Memoize returns the result of fn for key, running fn at most once per run.
func Memoize[T any](ctx context.Context, m *Memo, key string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	for {
		m.mu.Lock()
		e, ok := m.entries[key]
		if !ok {
			e = &memoEntry{done: make(chan struct{})}
			m.entries[key] = e
			m.mu.Unlock()
			m.fill(ctx, key, e, func(ctx context.Context) (any, error) { return fn(ctx) })
			if e.err != nil {
				return zero, e.err
			}
			return e.val.(T), nil
		}
		m.mu.Unlock()

		select {
		case <-e.done:
			if e.retry {
				continue
			}
			if e.err != nil {
				return zero, e.err
			}
			return e.val.(T), nil
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
}

func (m *Memo) fill(ctx context.Context, key string, e *memoEntry, fn func(context.Context) (any, error)) {
	defer close(e.done)
	defer func() {
		if e.retry {
			m.mu.Lock()
			delete(m.entries, key)
			m.mu.Unlock()
		}
	}()
	e.retry = true // stays set if fn panics
	e.val, e.err = fn(ctx)
	e.retry = e.err != nil && ctx.Err() != nil
}
