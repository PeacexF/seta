package dnsx

import (
	"context"
	"errors"
	"sync"
)

// Cache wraps a Resolver and remembers every answer for its lifetime. The
// engine creates one per run, so checks that query the same records (MX, TXT)
// share a single lookup and see consistent data.
//
// Failed lookups are cached too, so a timing-out name costs one timeout per
// run rather than one per check. The exception is a failure caused by the
// caller's own context ending: that says nothing about the query, so the next
// caller retries it.
type Cache struct {
	next Resolver

	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
}

type cacheKey struct {
	name   string
	qtype  uint16
	dnssec bool
}

type cacheEntry struct {
	done  chan struct{}
	resp  *Response
	err   error
	retry bool // leader's context ended; waiters should retry
}

// NewCache returns an empty cache in front of next.
func NewCache(next Resolver) *Cache {
	return &Cache{next: next, entries: make(map[cacheKey]*cacheEntry)}
}

func (c *Cache) Lookup(ctx context.Context, name string, qtype uint16) (*Response, error) {
	return c.lookup(ctx, cacheKey{CanonicalName(name), qtype, false})
}

// LookupDNSSEC fails when the wrapped resolver can't make DNSSEC queries.
func (c *Cache) LookupDNSSEC(ctx context.Context, name string, qtype uint16) (*Response, error) {
	return c.lookup(ctx, cacheKey{CanonicalName(name), qtype, true})
}

var errNoDNSSEC = errors.New("the resolver does not support DNSSEC queries")

func (c *Cache) lookup(ctx context.Context, key cacheKey) (*Response, error) {
	qtype := key.qtype
	for {
		c.mu.Lock()
		e, ok := c.entries[key]
		if !ok {
			e = &cacheEntry{done: make(chan struct{})}
			c.entries[key] = e
			c.mu.Unlock()
			c.fill(ctx, key, e)
			return e.resp, e.err
		}
		c.mu.Unlock()

		select {
		case <-e.done:
			if e.retry {
				continue
			}
			return e.resp, e.err
		case <-ctx.Done():
			return nil, &Error{Name: key.name, Type: qtype, Err: ctx.Err()}
		}
	}
}

func (c *Cache) fill(ctx context.Context, key cacheKey, e *cacheEntry) {
	defer close(e.done)
	defer func() {
		if e.retry {
			c.mu.Lock()
			delete(c.entries, key)
			c.mu.Unlock()
		}
	}()
	// Assume the worst until Lookup returns, so a panic in the resolver
	// releases waiters instead of leaving them blocked on done.
	e.retry = true
	if !key.dnssec {
		e.resp, e.err = c.next.Lookup(ctx, key.name, key.qtype)
	} else if sec, ok := c.next.(DNSSECResolver); ok {
		e.resp, e.err = sec.LookupDNSSEC(ctx, key.name, key.qtype)
	} else {
		e.err = &Error{Name: key.name, Type: key.qtype, Err: errNoDNSSEC}
	}
	e.retry = e.err != nil && ctx.Err() != nil
}
