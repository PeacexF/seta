package email

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
)

// fake serves several inline zones, keyed by origin.
func fake(t *testing.T, zones map[string]string) *dnsx.Fake {
	t.Helper()
	f := dnsx.NewFake()
	for origin, z := range zones {
		if err := f.AddZoneString(origin, z); err != nil {
			t.Fatalf("zone %s: %v", origin, err)
		}
	}
	return f
}

// results runs every email check whose ID starts with prefix and renders
// the outcome as sorted "id[subject]=severity" strings, or "id!error".
func results(t *testing.T, env checktest.Env, target core.Target, prefix string) []string {
	t.Helper()
	var out []string
	for _, c := range Checks() {
		id := c.Meta().ID
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		findings, err := checktest.RunWith(t, c, env, target)
		if err != nil {
			out = append(out, id+"!"+err.Error())
			continue
		}
		for _, f := range findings {
			s := id
			if f.Subject != "" {
				s += "[" + f.Subject + "]"
			}
			out = append(out, s+"="+f.Severity.String())
		}
	}
	slices.Sort(out)
	return out
}

func domain(t *testing.T, name string) core.Target { return checktest.Domain(t, name) }

func assertResults(t *testing.T, got []string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("results:\n got  %s\n want %s", fmtList(got), fmtList(want))
	}
}

// assertError checks that exactly the check with id failed with an error
// containing substr, and that it produced no findings.
func assertError(t *testing.T, got []string, id, substr string) {
	t.Helper()
	for _, g := range got {
		if strings.HasPrefix(g, id+"!") && strings.Contains(g, substr) {
			return
		}
	}
	t.Errorf("want %s to error with %q, got %s", id, substr, fmtList(got))
}

func fmtList(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%q", l)
}

func TestMetadata(t *testing.T) {
	for _, c := range Checks() {
		m := c.Meta()
		if m.Description == "" || m.Remediation == "" || len(m.References) == 0 {
			t.Errorf("%s: description, remediation and references are required", m.ID)
		}
	}
}
