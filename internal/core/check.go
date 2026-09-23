// Package core defines the types shared by checks, the engine, and reporters:
// targets, checks, findings, severities, and fingerprints.
package core

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/PeacexF/seta/internal/dnsx"
)

// Mode says whether a check only reads public data or also talks to the
// target's services.
type Mode int

const (
	// Passive checks use DNS lookups and other public data only.
	Passive Mode = iota
	// Active checks open connections to the target's services and must be
	// explicitly enabled.
	Active
)

func (m Mode) String() string {
	switch m {
	case Passive:
		return "passive"
	case Active:
		return "active"
	}
	return fmt.Sprintf("mode(%d)", int(m))
}

func (m Mode) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// Check is a unit of logic that inspects a target and reports findings.
//
// Run returns an error only when the check could not reach a verdict (network
// failure, timeout, unexpected server response). An error is never a finding
// and never causes previously reported findings to be marked resolved.
type Check interface {
	Meta() Meta
	Run(ctx context.Context, env Env, t Target) ([]Finding, error)
}

// Meta describes a check. It is the single source for `seta checks list`,
// `seta checks explain`, and the generated check catalog.
type Meta struct {
	// ID is permanent: "<module>.<area>.<condition>", e.g. "email.dmarc.policy_none".
	ID string
	// Aliases are former IDs of this check, kept so that suppressions and
	// selections written against an old ID keep working after a rename.
	Aliases     []string
	Module      string
	Title       string
	Description string
	// Remediation is the default fix text for findings that don't set their own.
	Remediation string
	Mode        Mode
	Severity    Severity
	References  []string
}

var checkIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// ValidateCheckID reports whether id follows the "<module>.<area>.<condition>" format.
func ValidateCheckID(id string) error {
	if !checkIDPattern.MatchString(id) {
		return fmt.Errorf("invalid check ID %q: want <module>.<area>.<condition>, lowercase letters, digits and underscores", id)
	}
	return nil
}

// Validate checks that the metadata is complete and self-consistent.
func (m Meta) Validate() error {
	if err := ValidateCheckID(m.ID); err != nil {
		return err
	}
	if module, _, _ := strings.Cut(m.ID, "."); m.Module != module {
		return fmt.Errorf("check %s: module %q does not match ID prefix %q", m.ID, m.Module, module)
	}
	for _, a := range m.Aliases {
		if err := ValidateCheckID(a); err != nil {
			return fmt.Errorf("check %s: alias: %w", m.ID, err)
		}
		if a == m.ID {
			return fmt.Errorf("check %s: alias equals its own ID", m.ID)
		}
	}
	if m.Title == "" {
		return fmt.Errorf("check %s: missing title", m.ID)
	}
	if !m.Severity.Valid() {
		return fmt.Errorf("check %s: invalid default severity %v", m.ID, m.Severity)
	}
	if m.Mode != Passive && m.Mode != Active {
		return fmt.Errorf("check %s: invalid mode %v", m.ID, m.Mode)
	}
	return nil
}

// Env carries the shared services a check may use. Checks must not rely on
// any other global state, so they stay trivially testable with fakes.
type Env struct {
	// Resolver is shared by all checks in a run and caches responses, so
	// repeated lookups are cheap and consistent within the run.
	Resolver dnsx.Resolver
	Logger   *slog.Logger
}
