// Package registry holds the set of available checks and selects them with
// glob patterns such as "email.*" and "!email.dnsbl.*".
package registry

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/PeacexF/seta/internal/core"
)

// Registry is a set of checks indexed by ID. It is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	checks  map[string]core.Check
	aliases map[string]string // former ID -> current ID
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		checks:  make(map[string]core.Check),
		aliases: make(map[string]string),
	}
}

// Default is the registry built-in checks add themselves to from init().
var Default = New()

// Register adds a check to the default registry and panics on invalid or
// duplicate metadata. It is meant to be called from init().
func Register(c core.Check) {
	if err := Default.Register(c); err != nil {
		panic(err)
	}
}

// Register adds a check after validating its metadata. IDs and aliases must
// be unique across the registry.
func (r *Registry) Register(c core.Check) error {
	m := c.Meta()
	if err := m.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.taken(m.ID) {
		return fmt.Errorf("check %s: ID already registered", m.ID)
	}
	for _, a := range m.Aliases {
		if r.taken(a) {
			return fmt.Errorf("check %s: alias %s already registered", m.ID, a)
		}
	}
	r.checks[m.ID] = c
	for _, a := range m.Aliases {
		r.aliases[a] = m.ID
	}
	return nil
}

func (r *Registry) taken(id string) bool {
	_, isCheck := r.checks[id]
	_, isAlias := r.aliases[id]
	return isCheck || isAlias
}

// Lookup finds a check by its ID or one of its former IDs.
func (r *Registry) Lookup(id string) (core.Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if canonical, ok := r.aliases[id]; ok {
		id = canonical
	}
	c, ok := r.checks[id]
	return c, ok
}

// All returns every registered check sorted by ID.
func (r *Registry) All() []core.Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]core.Check, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c)
	}
	sortByID(out)
	return out
}

// Select returns the checks matched by patterns, sorted by ID.
//
// A pattern is a check ID glob where "*" matches any run of characters
// (including dots) and "?" matches one character. A leading "!" excludes
// matches. Exclusions always win regardless of order; if there are no
// inclusion patterns, selection starts from all checks. A pattern without
// wildcards may also name a former ID (alias).
//
// An inclusion pattern that matches nothing is an error, so typos don't
// silently disable checks. Exclusions that match nothing are allowed.
func (r *Registry) Select(patterns []string) ([]core.Check, error) {
	var include, exclude []string
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if err := validatePattern(p); err != nil {
			return nil, err
		}
		if neg {
			exclude = append(exclude, p)
		} else {
			include = append(include, p)
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	selected := make(map[string]core.Check)
	if len(include) == 0 {
		maps.Copy(selected, r.checks)
	}
	for _, p := range include {
		n := 0
		for id, c := range r.checks {
			if r.matches(p, id) {
				selected[id] = c
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("check pattern %q matches no checks", p)
		}
	}
	for _, p := range exclude {
		for id := range selected {
			if r.matches(p, id) {
				delete(selected, id)
			}
		}
	}

	out := make([]core.Check, 0, len(selected))
	for _, c := range selected {
		out = append(out, c)
	}
	sortByID(out)
	return out, nil
}

func (r *Registry) matches(pattern, id string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		if canonical, ok := r.aliases[pattern]; ok {
			return canonical == id
		}
		return pattern == id
	}
	return Match(pattern, id)
}

func validatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("empty check pattern")
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '*' || c == '?') {
			return fmt.Errorf("invalid check pattern %q: unexpected character %q", p, c)
		}
	}
	return nil
}

// Match reports whether id matches the glob pattern, where "*" matches any
// sequence of characters and "?" matches exactly one.
func Match(pattern, id string) bool {
	// Iterative wildcard matching with single-star backtracking: linear in
	// practice and never exponential.
	p, s := 0, 0
	star, mark := -1, 0
	for s < len(id) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == id[s]):
			p++
			s++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, s
			p++
		case star >= 0:
			p = star + 1
			mark++
			s = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func sortByID(cs []core.Check) {
	slices.SortFunc(cs, func(a, b core.Check) int {
		return strings.Compare(a.Meta().ID, b.Meta().ID)
	})
}
