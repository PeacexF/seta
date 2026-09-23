package spf

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/dnsx"
)

// RFC 7208 §4.6.4 limits.
const (
	MaxLookups     = 10
	MaxVoidLookups = 2
	MaxMXNames     = 10
)

// Work caps, far above the RFC limits, so a pathological tree can't turn one
// check into hundreds of queries.
const (
	maxDepth   = 10
	maxQueries = 100
)

// Fetch returns the SPF records published at domain. empty means the TXT
// query returned no answers at all, which makes it a void lookup.
func Fetch(ctx context.Context, r dnsx.Resolver, domain string) (records []string, empty bool, resp *dnsx.Response, err error) {
	resp, err = r.Lookup(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, false, nil, err
	}
	txts := resp.TXT()
	for _, txt := range txts {
		if IsSPF(txt) {
			records = append(records, txt)
		}
	}
	return records, len(txts) == 0, resp, nil
}

type Problem struct {
	Where string // "include:x", "redirect:x", or "" for the record itself
	Msg   string
}

type Evaluation struct {
	Lookups     int
	VoidLookups int
	// Cost lists the lookups each top-level term causes, recursively.
	Cost     []TermCost
	Voids    []string // queries that came back empty
	Problems []Problem
	// PermissiveIncludes are included records ending in +all, which make the
	// include match every sender.
	PermissiveIncludes []string
	// Effective is the "all" that applies after following redirects. Without
	// one, unmatched senders default to neutral.
	Effective    Mechanism
	HasEffective bool
	Unexpanded   []string // macro terms counted but not followed
	Incomplete   bool     // stopped at the work caps
}

type TermCost struct {
	Term    string
	Lookups int
}

// Evaluate walks rec and everything it includes or redirects to.
func Evaluate(ctx context.Context, r dnsx.Resolver, domain string, rec *Record) (*Evaluation, error) {
	w := &walker{r: r, ev: &Evaluation{}, stack: map[string]bool{dnsx.CanonicalName(domain): true}}
	if err := w.walk(ctx, domain, rec, "", 0, true); err != nil {
		return nil, err
	}
	return w.ev, nil
}

type walker struct {
	r       dnsx.Resolver
	ev      *Evaluation
	stack   map[string]bool
	queries int
}

func (w *walker) lookup(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	w.queries++
	return w.r.Lookup(ctx, name, qtype)
}

func (w *walker) stop() bool {
	if w.queries >= maxQueries || w.ev.Lookups > 5*MaxLookups {
		w.ev.Incomplete = true
		return true
	}
	return false
}

// walk visits rec. top is true for the target's own record and its redirect
// chain, whose "all" is the one that applies.
func (w *walker) walk(ctx context.Context, domain string, rec *Record, where string, depth int, top bool) error {
	w.prefetch(ctx, domain, rec)
	for _, m := range rec.Mechanisms {
		if !m.CountsLookup() {
			continue
		}
		term := m.String()
		if top && where == "" {
			w.ev.Cost = append(w.ev.Cost, TermCost{Term: term})
		}
		before := w.ev.Lookups
		if err := w.mechanism(ctx, domain, m, where, depth); err != nil {
			return err
		}
		if top && where == "" {
			w.ev.Cost[len(w.ev.Cost)-1].Lookups = w.ev.Lookups - before
		}
		if w.stop() {
			return nil
		}
	}

	if all, ok := rec.All(); ok {
		if top {
			w.ev.Effective, w.ev.HasEffective = all, true
		}
		return nil // redirect is ignored when "all" is present
	}
	if rec.Redirect == "" {
		return nil
	}
	w.ev.Lookups++
	if top && where == "" {
		w.ev.Cost = append(w.ev.Cost, TermCost{Term: "redirect=" + rec.Redirect, Lookups: 1})
	}
	before := w.ev.Lookups
	if HasMacro(rec.Redirect) {
		w.ev.Unexpanded = append(w.ev.Unexpanded, "redirect="+rec.Redirect)
		return nil
	}
	target := strings.TrimSuffix(strings.ToLower(rec.Redirect), ".")
	if err := w.follow(ctx, target, "redirect:"+target, depth, top); err != nil {
		return err
	}
	if top && where == "" {
		w.ev.Cost[len(w.ev.Cost)-1].Lookups += w.ev.Lookups - before
	}
	return nil
}

func (w *walker) mechanism(ctx context.Context, domain string, m Mechanism, where string, depth int) error {
	w.ev.Lookups++
	target := domain
	if m.Domain != "" {
		if HasMacro(m.Domain) {
			w.ev.Unexpanded = append(w.ev.Unexpanded, m.String())
			return nil
		}
		target = strings.TrimSuffix(strings.ToLower(m.Domain), ".")
	}

	switch m.Kind {
	case "include":
		return w.follow(ctx, target, "include:"+target, depth, false)

	case "a", "exists":
		empty := true
		qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
		if m.Kind == "exists" {
			qtypes = qtypes[:1] // exists only ever queries A
		}
		for _, qt := range qtypes {
			resp, err := w.lookup(ctx, target, qt)
			if err != nil {
				return err
			}
			if len(resp.Records()) > 0 {
				empty = false
			}
		}
		if empty {
			w.void(m.String())
		}

	case "mx":
		resp, err := w.lookup(ctx, target, dns.TypeMX)
		if err != nil {
			return err
		}
		n := len(resp.MX())
		if n == 0 {
			w.void(m.String())
		}
		if n > MaxMXNames {
			w.problem(where, fmt.Sprintf("%s: %s has %d MX records; SPF allows at most %d (permerror)", m, target, n, MaxMXNames))
		}
	}
	return nil
}

// follow evaluates the SPF record at target, reached via an include or
// redirect described by via.
func (w *walker) follow(ctx context.Context, target, via string, depth int, top bool) error {
	key := dnsx.CanonicalName(target)
	if w.stack[key] {
		w.problem(via, fmt.Sprintf("%s loops back to a record already being evaluated (permerror)", via))
		return nil
	}
	if depth+1 > maxDepth {
		w.ev.Incomplete = true
		return nil
	}
	w.queries++
	records, empty, _, err := Fetch(ctx, w.r, target)
	if err != nil {
		return err
	}
	switch {
	case len(records) == 0:
		if empty {
			w.void(via)
		}
		w.problem(via, fmt.Sprintf("%s has no SPF record, so every evaluation through it ends in permerror", target))
		return nil
	case len(records) > 1:
		w.problem(via, fmt.Sprintf("%s publishes %d SPF records (permerror)", target, len(records)))
		return nil
	}
	sub, err := Parse(records[0])
	if err != nil {
		w.problem(via, fmt.Sprintf("SPF record at %s is invalid: %v", target, err))
		return nil
	}
	if !top {
		if all, ok := sub.All(); ok && all.Qualifier == Pass {
			w.ev.PermissiveIncludes = append(w.ev.PermissiveIncludes, via)
		}
	}
	w.stack[key] = true
	defer delete(w.stack, key)
	return w.walk(ctx, target, sub, via, depth+1, top)
}

// prefetch issues the record's lookups concurrently. The walk itself stays
// sequential (counting depends on order), but with a caching resolver its
// latency then grows with include depth rather than include count.
func (w *walker) prefetch(ctx context.Context, domain string, rec *Record) {
	type query struct {
		name  string
		qtype uint16
	}
	var qs []query
	add := func(spec string, qtypes ...uint16) {
		if HasMacro(spec) {
			return
		}
		name := domain
		if spec != "" {
			name = spec
		}
		for _, t := range qtypes {
			qs = append(qs, query{name, t})
		}
	}
	for _, m := range rec.Mechanisms {
		switch m.Kind {
		case "include":
			add(m.Domain, dns.TypeTXT)
		case "a":
			add(m.Domain, dns.TypeA, dns.TypeAAAA)
		case "mx":
			add(m.Domain, dns.TypeMX)
		case "exists":
			add(m.Domain, dns.TypeA)
		}
	}
	if _, hasAll := rec.All(); !hasAll && rec.Redirect != "" {
		add(rec.Redirect, dns.TypeTXT)
	}
	if len(qs) < 2 || len(qs) > maxQueries-w.queries {
		return
	}
	var wg sync.WaitGroup
	for _, q := range qs {
		wg.Go(func() { w.r.Lookup(ctx, q.name, q.qtype) }) //nolint:errcheck // results land in the cache
	}
	wg.Wait()
}

func (w *walker) void(term string) {
	w.ev.VoidLookups++
	w.ev.Voids = append(w.ev.Voids, term)
}

func (w *walker) problem(where, msg string) {
	for _, p := range w.ev.Problems {
		if p.Where == where && p.Msg == msg {
			return
		}
	}
	w.ev.Problems = append(w.ev.Problems, Problem{Where: where, Msg: msg})
}
