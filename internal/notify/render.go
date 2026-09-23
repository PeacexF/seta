package notify

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/PeacexF/seta/internal/state"
)

var kindLabels = map[state.Kind]struct{ emoji, label string }{
	state.New:        {"🔴", "NEW"},
	state.Regressed:  {"🟠", "REGRESSED"},
	state.Resolved:   {"✅", "RESOLVED"},
	state.Persisting: {"⚪", "STILL OPEN"},
}

// headline summarizes a message, e.g. "2 new · 1 resolved".
func headline(m *Message) string {
	switch m.Event {
	case EventTest:
		return "test message"
	case EventHeartbeat:
		return "all clear"
	}
	counts := map[state.Kind]int{}
	for _, c := range m.Changes {
		counts[c.Kind]++
	}
	var parts []string
	for _, k := range []state.Kind{state.New, state.Regressed, state.Resolved, state.Persisting} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(kindLabels[k].label)))
		}
	}
	return strings.Join(parts, " · ")
}

// bodyText is the plain text of heartbeat and test messages.
func bodyText(m *Message) string {
	if m.Event == EventTest {
		return fmt.Sprintf("Notifications to %q work.", m.Notifier)
	}
	return fmt.Sprintf("No changes to report. Watching %s; %s.", plural(len(m.Targets), "domain"), plural(m.Open, "open finding"))
}

func footerText(m *Message) string {
	parts := []string{plural(m.Open, "open finding")}
	if m.Errors > 0 {
		parts = append(parts, plural(m.Errors, "check error"))
	}
	return strings.Join(append(parts, fmt.Sprintf("run %d", m.RunID)), " · ")
}

// evidenceLines returns up to n "key: value" lines in key order.
func evidenceLines(c state.Change, n int) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(c.Finding.Evidence)) {
		if len(out) == n {
			break
		}
		out = append(out, k+": "+truncate(c.Finding.Evidence[k], 200))
	}
	return out
}

// block is one change as rendered text, grouped under a target heading.
type block struct {
	group, text string
}

// pack joins blocks into as few chunks of at most budget (in size units) as
// possible, repeating a group's heading when the group continues in the next
// chunk.
func pack(blocks []block, heading func(group string) string, budget int, size func(string) int) []string {
	var chunks []string
	var b strings.Builder
	group := ""
	for _, bl := range blocks {
		text := bl.text
		if bl.group != group {
			text = heading(bl.group) + text
		}
		if b.Len() > 0 && size(b.String())+size(text) > budget {
			chunks = append(chunks, b.String())
			b.Reset()
			text = heading(bl.group) + bl.text
		}
		b.WriteString(text)
		group = bl.group
	}
	if b.Len() > 0 || len(chunks) == 0 {
		chunks = append(chunks, b.String())
	}
	return chunks
}

// partLabel numbers chunks when a message needs more than one.
func partLabel(i, n int) string {
	if n == 1 {
		return ""
	}
	return fmt.Sprintf(" (%d/%d)", i+1, n)
}

// partReserve is room kept for partLabel.
const partReserve = len(" (99/99)")

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
