package checktest

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/core"
)

// Results runs each check whose ID starts with prefix and lists outcomes as
// "id[subject]=severity" for findings and "id!error" for check errors.
func Results(tb testing.TB, checks []core.Check, env Env, target core.Target, prefix string) []string {
	tb.Helper()
	var out []string
	for _, c := range checks {
		id := c.Meta().ID
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		findings, err := RunWith(tb, c, env, target)
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

// Want compares Results output with want. An entry ending in "!" matches
// any error of that check; "id!text" matches an error containing text.
func Want(tb testing.TB, got []string, want ...string) {
	tb.Helper()
	got, want = slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	ok := len(got) == len(want)
	for i := 0; ok && i < len(got); i++ {
		w := want[i]
		if id, text, isErr := strings.Cut(w, "!"); isErr {
			ok = strings.HasPrefix(got[i], id+"!") && strings.Contains(got[i][len(id)+1:], text)
		} else {
			ok = got[i] == w
		}
	}
	if !ok {
		tb.Errorf("results:\n got  %s\n want %s", fmtList(got), fmtList(want))
	}
}

func fmtList(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%q", l)
}
