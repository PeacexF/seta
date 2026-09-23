package registry

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/core"
)

type stubCheck struct{ meta core.Meta }

func (s stubCheck) Meta() core.Meta { return s.meta }
func (s stubCheck) Run(context.Context, core.Env, core.Target) ([]core.Finding, error) {
	return nil, nil
}

func stub(id string, aliases ...string) core.Check {
	module, _, _ := strings.Cut(id, ".")
	return stubCheck{core.Meta{ID: id, Module: module, Title: id, Severity: core.SeverityLow, Aliases: aliases}}
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r := New()
	for _, c := range []core.Check{
		stub("email.spf.missing"),
		stub("email.spf.lookup_limit"),
		stub("email.dmarc.missing"),
		stub("email.dmarc.policy_none", "email.dmarc.p_none"),
		stub("email.dnsbl.listed"),
		stub("tls.cert.expiring"),
	} {
		if err := r.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func ids(cs []core.Check) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Meta().ID)
	}
	return out
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, id string
		want        bool
	}{
		{"email.*", "email.spf.missing", true},
		{"email.spf.*", "email.spf.missing", true},
		{"email.spf.*", "email.dmarc.missing", false},
		{"*.missing", "email.dmarc.missing", true},
		{"*.missing", "email.dmarc.missing_x", false},
		{"email.*.missing", "email.spf.missing", true},
		{"email.*.missing", "email.missing", false},
		{"*", "anything.at.all", true},
		{"email.sp?.missing", "email.spf.missing", true},
		{"email.sp?.missing", "email.sp.missing", false},
		{"email.spf.missing", "email.spf.missing", true},
		{"email.spf", "email.spf.missing", false},
		{"**.*", "a.b.c", true},
		{"a*a*a*a*b", strings.Repeat("a", 100), false}, // must not blow up
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.id); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.id, got, tt.want)
		}
	}
}

func TestSelect(t *testing.T) {
	r := newTestRegistry(t)
	tests := []struct {
		patterns []string
		want     []string
	}{
		{nil, []string{"email.dmarc.missing", "email.dmarc.policy_none", "email.dnsbl.listed", "email.spf.lookup_limit", "email.spf.missing", "tls.cert.expiring"}},
		{[]string{"email.spf.*"}, []string{"email.spf.lookup_limit", "email.spf.missing"}},
		{[]string{"email.*", "!email.dnsbl.*"}, []string{"email.dmarc.missing", "email.dmarc.policy_none", "email.spf.lookup_limit", "email.spf.missing"}},
		// Exclusions win regardless of order.
		{[]string{"!email.dnsbl.*", "email.*"}, []string{"email.dmarc.missing", "email.dmarc.policy_none", "email.spf.lookup_limit", "email.spf.missing"}},
		// Only exclusions: start from everything.
		{[]string{"!email.*"}, []string{"tls.cert.expiring"}},
		{[]string{"*.missing", "tls.*"}, []string{"email.dmarc.missing", "email.spf.missing", "tls.cert.expiring"}},
		// Aliases resolve for exact patterns.
		{[]string{"email.dmarc.p_none"}, []string{"email.dmarc.policy_none"}},
		{[]string{"email.dmarc.*", "!email.dmarc.p_none"}, []string{"email.dmarc.missing"}},
		// Excluding something that matches nothing is fine.
		{[]string{"tls.*", "!http.*"}, []string{"tls.cert.expiring"}},
	}
	for _, tt := range tests {
		got, err := r.Select(tt.patterns)
		if err != nil {
			t.Errorf("Select(%q): %v", tt.patterns, err)
			continue
		}
		if !slices.Equal(ids(got), tt.want) {
			t.Errorf("Select(%q) = %v, want %v", tt.patterns, ids(got), tt.want)
		}
	}
}

func TestSelectErrors(t *testing.T) {
	r := newTestRegistry(t)
	for _, patterns := range [][]string{
		{"email.spf.mising"}, // typo matches nothing
		{"http.*"},
		{""},
		{"!"},
		{"Email.*"},
		{"email.[a-z].*"},
	} {
		if _, err := r.Select(patterns); err == nil {
			t.Errorf("Select(%q) should fail", patterns)
		}
	}
}

func TestRegisterRejectsDuplicatesAndInvalid(t *testing.T) {
	r := newTestRegistry(t)
	for name, c := range map[string]core.Check{
		"duplicate ID":          stub("email.spf.missing"),
		"ID taken by alias":     stub("email.dmarc.p_none"),
		"alias taken by ID":     stub("email.x.y", "email.spf.missing"),
		"alias taken by alias":  stub("email.x.z", "email.dmarc.p_none"),
		"invalid ID":            stub("email.spf"),
		"module does not match": stubCheck{core.Meta{ID: "a.b.c", Module: "x", Title: "t", Severity: core.SeverityLow}},
	} {
		if err := r.Register(c); err == nil {
			t.Errorf("%s: Register accepted %s", name, c.Meta().ID)
		}
	}
}

func TestLookup(t *testing.T) {
	r := newTestRegistry(t)
	for _, id := range []string{"email.dmarc.policy_none", "email.dmarc.p_none"} {
		c, ok := r.Lookup(id)
		if !ok || c.Meta().ID != "email.dmarc.policy_none" {
			t.Errorf("Lookup(%q) = %v, %v", id, c, ok)
		}
	}
	if _, ok := r.Lookup("email.nope.nope"); ok {
		t.Error("Lookup found a check that does not exist")
	}
}

func TestAllIsSorted(t *testing.T) {
	got := ids(newTestRegistry(t).All())
	if !slices.IsSorted(got) || len(got) != 6 {
		t.Fatalf("All() = %v", got)
	}
}
