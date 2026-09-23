// Package report renders run results for humans and machines.
package report

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

// Options controls rendering.
type Options struct {
	// Color enables ANSI colors. Callers decide based on the output being a
	// terminal and NO_COLOR.
	Color bool
}

// Table writes a human-readable report grouped by target, highest severity
// first, followed by check errors and a one-line summary.
func Table(w io.Writer, res *engine.Result, opts Options) error {
	p := painter{on: opts.Color}
	var b strings.Builder

	idWidth := 0
	for _, f := range res.Findings {
		idWidth = max(idWidth, len(f.CheckID))
	}

	for i, t := range res.Targets {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(p.bold(t.Name) + "\n")
		n := 0
		for _, f := range res.Findings {
			if f.Target != t.Name {
				continue
			}
			n++
			writeFinding(&b, p, f, idWidth)
		}
		if n == 0 {
			if errs := errorsFor(res, t.Name); errs > 0 {
				b.WriteString("  " + p.yellow(fmt.Sprintf("no findings, but %s could not complete", plural(errs, "check"))) + "\n")
			} else {
				b.WriteString("  " + p.green("✓ no findings") + "\n")
			}
		}
	}

	if len(res.Errors) > 0 {
		b.WriteString("\n" + p.bold(fmt.Sprintf("Check errors (%d)", len(res.Errors))) + "\n")
		b.WriteString(p.dim("  These checks could not reach a verdict; they are not findings.") + "\n")
		for _, e := range res.Errors {
			fmt.Fprintf(&b, "  %s  %s  %v\n", e.Target, e.CheckID, e.Err)
		}
	}

	b.WriteString("\n" + summary(res) + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

const severityWidth = len("CRITICAL")

func writeFinding(b *strings.Builder, p painter, f core.Finding, idWidth int) {
	label := strings.ToUpper(f.Severity.String())
	title := f.Title
	if f.Subject != "" {
		title += " (" + f.Subject + ")"
	}
	fmt.Fprintf(b, "  %s  %s  %s\n",
		p.severity(f.Severity, pad(label, severityWidth)),
		pad(f.CheckID, idWidth),
		title)

	indent := strings.Repeat(" ", 2+severityWidth+2)
	for _, k := range slices.Sorted(maps.Keys(f.Evidence)) {
		b.WriteString(indent + p.dim(k+": "+f.Evidence[k]) + "\n")
	}
	if f.Remediation != "" {
		b.WriteString(indent + p.cyan("fix: ") + f.Remediation + "\n")
	}
}

func summary(res *engine.Result) string {
	counts := make(map[core.Severity]int)
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	var bySeverity []string
	for _, s := range slices.Backward(core.Severities()) {
		if n := counts[s]; n > 0 {
			bySeverity = append(bySeverity, fmt.Sprintf("%d %s", n, s))
		}
	}
	findings := plural(len(res.Findings), "finding")
	if len(bySeverity) > 0 {
		findings += " (" + strings.Join(bySeverity, ", ") + ")"
	}
	parts := []string{findings}
	if len(res.Errors) > 0 {
		parts = append(parts, plural(len(res.Errors), "check error"))
	}
	checks := plural(res.Executions, "check")
	if len(res.Targets) > 1 {
		checks += " on " + plural(len(res.Targets), "target")
	}
	parts = append(parts, checks, formatDuration(res.Duration))
	return strings.Join(parts, " · ")
}

func errorsFor(res *engine.Result, target string) int {
	n := 0
	for _, e := range res.Errors {
		if e.Target == target {
			n++
		}
	}
	return n
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// painter applies ANSI styles when enabled. Padding is always computed on the
// plain text before styling, so escape codes never break alignment.
type painter struct{ on bool }

func (p painter) style(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) bold(s string) string   { return p.style("1", s) }
func (p painter) dim(s string) string    { return p.style("2", s) }
func (p painter) green(s string) string  { return p.style("32", s) }
func (p painter) yellow(s string) string { return p.style("33", s) }
func (p painter) cyan(s string) string   { return p.style("36", s) }

func (p painter) severity(s core.Severity, text string) string {
	switch s {
	case core.SeverityCritical:
		return p.style("1;35", text)
	case core.SeverityHigh:
		return p.style("1;31", text)
	case core.SeverityMedium:
		return p.style("33", text)
	case core.SeverityLow:
		return p.style("36", text)
	default:
		return p.style("2", text)
	}
}
