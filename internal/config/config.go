// Package config loads and validates seta.yaml.
package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/PeacexF/seta/internal/core"
)

// Version is the only config format version this build understands.
const Version = 1

// DefaultPath is where commands look for the config when -c is not given.
const DefaultPath = "seta.yaml"

// SchemaURL is the published JSON Schema for editors (yaml-language-server).
const SchemaURL = "https://raw.githubusercontent.com/PeacexF/seta/main/schema/config.v1.json"

type Config struct {
	Version  int      `yaml:"version"`
	Resolver Resolver `yaml:"resolver"`
	Defaults Defaults `yaml:"defaults"`
	Targets  []Target `yaml:"targets"`
	// SeverityOverrides is keyed by canonical check ID after loading.
	SeverityOverrides SeverityOverrides `yaml:"severity_overrides"`
	Suppressions      []Suppression     `yaml:"suppressions"`

	// Path is the file the config was loaded from, as given.
	Path string `yaml:"-"`
}

type Resolver struct {
	// Servers takes the same values as --resolver.
	Servers   []string `yaml:"servers"`
	Timeout   Duration `yaml:"timeout"`
	SkipCheck bool     `yaml:"skip_check"`
}

type Defaults struct {
	Checks       []string `yaml:"checks"`
	Active       bool     `yaml:"active"`
	CheckTimeout Duration `yaml:"check_timeout"`
}

type Target struct {
	// Domain is in canonical form after loading.
	Domain string `yaml:"domain"`
	// Checks replaces Defaults.Checks when set.
	Checks []string `yaml:"checks"`
	// Active overrides Defaults.Active when set.
	Active *bool `yaml:"active"`
	Email  Email `yaml:"email"`

	Line int `yaml:"-"`
}

type Email struct {
	DKIMSelectors []string `yaml:"dkim_selectors"`
	// ExpectedMX entries are host names, optionally with a leading "*."
	// matching exactly one label.
	ExpectedMX []string `yaml:"expected_mx"`
	DNSBLs     []string `yaml:"dnsbls"`
}

type Suppression struct {
	// Check is a check ID, former ID, or glob.
	Check string `yaml:"check"`
	// Target, Subject: empty matches any.
	Target  string `yaml:"target"`
	Subject string `yaml:"subject"`
	Reason  string `yaml:"reason"`
	Expires Date   `yaml:"expires"`

	Line int `yaml:"-"`
	ids  map[string]bool
}

// CheckPatterns returns the selection patterns that apply to t.
func (c *Config) CheckPatterns(t Target) []string {
	if t.Checks != nil {
		return t.Checks
	}
	return c.Defaults.Checks
}

// ActiveFor reports whether active checks are enabled for t.
func (c *Config) ActiveFor(t Target) bool {
	if t.Active != nil {
		return *t.Active
	}
	return c.Defaults.Active
}

func (s Suppression) Matches(f core.Finding) bool {
	return s.ids[f.CheckID] &&
		(s.Target == "" || s.Target == f.Target) &&
		(s.Subject == "" || s.Subject == f.Subject)
}

// Expired reports whether the suppression no longer applies: it stops
// applying at the start (UTC) of its expiry date.
func (s Suppression) Expired(now time.Time) bool {
	return !s.Expires.IsZero() && !now.Before(s.Expires.Time)
}

// Duration accepts Go duration strings such as "5s" or "1m30s". Bare numbers
// are rejected because their unit would be a guess.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if n.Kind != yaml.ScalarNode || err != nil {
		return typeError(n, "invalid duration %q: want a value with a unit, like 10s or 1m", n.Value)
	}
	if v < 0 {
		return typeError(n, "duration %q must not be negative", n.Value)
	}
	*d = Duration(v)
	return nil
}

type SeverityOverrides map[string]core.Severity

func (s *SeverityOverrides) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return typeError(n, "severity_overrides must map check IDs to severities")
	}
	m := make(SeverityOverrides, len(n.Content)/2)
	var errs []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		sev, err := core.ParseSeverity(v.Value)
		if v.Kind != yaml.ScalarNode || err != nil {
			errs = append(errs, fmt.Sprintf("line %d: invalid severity %q for %s: want info, low, medium, high or critical", v.Line, v.Value, k.Value))
			continue
		}
		m[k.Value] = sev
	}
	if errs != nil {
		return &yaml.TypeError{Errors: errs}
	}
	*s = m
	return nil
}

// Date is a calendar day written as YYYY-MM-DD, quoted or not.
type Date struct{ time.Time }

func (d *Date) UnmarshalYAML(n *yaml.Node) error {
	t, err := time.Parse(time.DateOnly, n.Value)
	if n.Kind != yaml.ScalarNode || err != nil {
		return typeError(n, "invalid date %q: want YYYY-MM-DD", n.Value)
	}
	d.Time = t
	return nil
}

// typeError reports a decoding problem so that yaml.v3 keeps collecting
// errors instead of stopping at the first one.
func typeError(n *yaml.Node, format string, args ...any) error {
	return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: ", n.Line) + fmt.Sprintf(format, args...)}}
}
