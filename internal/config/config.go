// Package config loads and validates seta.yaml.
package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"strconv"
	"strings"
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

	State    State      `yaml:"state"`
	Notify   []Notifier `yaml:"notify"`
	Schedule string     `yaml:"schedule"`

	// PluginsDir is searched for plugins before $PATH; relative to the
	// config file after loading.
	PluginsDir string `yaml:"plugins_dir"`
	// Plugins holds each plugin's settings, by plugin name.
	Plugins map[string]PluginConfig `yaml:"plugins"`

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
	// Plugins override the top-level plugin settings key by key.
	Plugins map[string]PluginConfig `yaml:"plugins"`

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

// SMTP connection security for email notifiers.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "tls"
	TLSNone     = "none"
)

// Defaults for the daemon settings.
const (
	DefaultStatePath    = "seta-state.db"
	DefaultResolveAfter = 2
	DefaultRetention    = Duration(90 * 24 * time.Hour)
	DefaultSchedule     = "0 */6 * * *"
)

type State struct {
	Path string `yaml:"path"`
	// ResolveAfter is how many consecutive runs a finding must be absent
	// from before it is reported resolved.
	ResolveAfter int      `yaml:"resolve_after"`
	Retention    Duration `yaml:"retention"`
}

// Notifier is one notification channel. Which fields apply depends on Type;
// loading rejects fields meant for other types.
type Notifier struct {
	Type string `yaml:"type"`
	// Name identifies the notifier in logs and 'seta notify test'; it
	// defaults to Type.
	Name        string   `yaml:"name"`
	On          []string `yaml:"on"`
	MinSeverity string   `yaml:"min_severity"`
	// Heartbeat sends an all-clear message when nothing was sent for this long.
	Heartbeat Duration `yaml:"heartbeat"`

	BotToken string `yaml:"bot_token"` // telegram
	ChatID   string `yaml:"chat_id"`   // telegram
	Webhook  string `yaml:"webhook"`   // discord, slack

	URL             string `yaml:"url"`               // webhook
	Secret          string `yaml:"secret"`            // webhook
	Format          string `yaml:"format"`            // webhook
	BlockPrivateIPs bool   `yaml:"block_private_ips"` // webhook

	// email
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	TLS      string   `yaml:"tls"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`

	Line int `yaml:"-"`
	// Severity is MinSeverity parsed; unset means all.
	Severity core.Severity `yaml:"-"`
}

// PluginConfig is a plugin's own settings, passed to it as JSON.
type PluginConfig map[string]any

// UnmarshalYAML converts the settings to JSON values itself, so that
// scalars reach the plugin as written: yaml.v3 would turn 2027-01-01 into a
// timestamp with a time of day.
func (c *PluginConfig) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		*c = PluginConfig{}
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return typeError(n, "plugin settings must be a mapping")
	}
	v, err := jsonValue(n)
	if err != nil {
		return err
	}
	*c = v.(map[string]any)
	return nil
}

func jsonValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.AliasNode:
		return jsonValue(n.Alias)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, typeError(k, "plugin setting names must be plain strings")
			}
			v, err := jsonValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := jsonValue(c)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	}
	switch n.ShortTag() {
	case "!!null":
		return nil, nil
	case "!!bool", "!!int", "!!float":
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		if f, ok := v.(float64); ok && (math.IsInf(f, 0) || math.IsNaN(f)) {
			return nil, typeError(n, "%s can't be passed to a plugin", n.Value)
		}
		return v, nil
	}
	return n.Value, nil
}

// PluginConfig returns each plugin's settings for t as JSON: the top-level
// settings with the target's merged over them.
func (c *Config) PluginConfig(t Target) map[string][]byte {
	out := make(map[string][]byte)
	for name, global := range c.Plugins {
		merged := PluginConfig{}
		maps.Copy(merged, global)
		maps.Copy(merged, t.Plugins[name])
		out[name], _ = json.Marshal(merged) // validated while loading
	}
	for name, own := range t.Plugins {
		if _, ok := out[name]; !ok {
			out[name], _ = json.Marshal(orEmpty(own))
		}
	}
	return out
}

func orEmpty(m PluginConfig) PluginConfig {
	if m == nil {
		return PluginConfig{}
	}
	return m
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

// Duration accepts Go duration strings such as "5s" or "1m30s", whole days
// ("90d"), "daily" and "weekly". Bare numbers are rejected because their
// unit would be a guess.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := parseDuration(n.Value)
	if n.Kind != yaml.ScalarNode || err != nil {
		return typeError(n, "invalid duration %q: want a value with a unit, like 10s, 1m or 7d", n.Value)
	}
	if v < 0 {
		return typeError(n, "duration %q must not be negative", n.Value)
	}
	*d = Duration(v)
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	switch s {
	case "daily":
		return 24 * time.Hour, nil
	case "weekly":
		return 7 * 24 * time.Hour, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
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
