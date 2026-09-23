// Package checkdef lets a module define its checks as metadata plus a
// function.
package checkdef

import (
	"context"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/registry"
)

type Func func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error)

type check struct {
	meta core.Meta
	run  Func
}

func (c *check) Meta() core.Meta { return c.meta }

func (c *check) Run(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	return c.run(ctx, env, t)
}

// Set is one module's checks.
type Set struct {
	Module string
	checks []*check
}

// Define adds a check to the set and to the default registry. It is meant
// to be called from init() and panics on invalid metadata.
func (s *Set) Define(meta core.Meta, run Func) {
	meta.Module = s.Module
	c := &check{meta: meta, run: run}
	s.checks = append(s.checks, c)
	registry.Register(c)
}

func (s *Set) Checks() []core.Check {
	out := make([]core.Check, len(s.checks))
	for i, c := range s.checks {
		out[i] = c
	}
	return out
}

// Check returns the check with id, or nil.
func (s *Set) Check(id string) core.Check {
	for _, c := range s.checks {
		if c.meta.ID == id {
			return c
		}
	}
	return nil
}
