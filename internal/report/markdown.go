package report

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

// Markdown writes a GitHub-flavored Markdown report for PR comments, job
// summaries and client reports.
func Markdown(w io.Writer, res *engine.Result, opts Options) error {
	var b strings.Builder
	b.WriteString("## Seta report\n\n")
	b.WriteString(summary(res) + "\n")

	for _, t := range res.Targets {
		fmt.Fprintf(&b, "\n### %s\n\n", mdText(t.Name))
		var fs []core.Finding
		for _, f := range res.Findings {
			if f.Target == t.Name {
				fs = append(fs, f)
			}
		}
		if len(fs) == 0 {
			switch errs, hidden := errorsFor(res, t.Name), hiddenFor(res, t.Name); {
			case errs > 0:
				fmt.Fprintf(&b, "No findings, but %s could not complete.\n", plural(errs, "check"))
			case hidden > 0:
				fmt.Fprintf(&b, "✅ No new findings (%d suppressed or in baseline).\n", hidden)
			default:
				b.WriteString("✅ No findings.\n")
			}
			continue
		}
		b.WriteString("| Severity | Check | Finding |\n|---|---|---|\n")
		for _, f := range fs {
			title := f.Title
			if f.Subject != "" {
				title += " (" + f.Subject + ")"
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdSeverity(f.Severity), mdCode(f.CheckID), mdText(title))
		}
		b.WriteString("\n<details><summary>Evidence and fixes</summary>\n\n")
		for _, f := range fs {
			fmt.Fprintf(&b, "**%s** %s", mdCode(f.CheckID), mdText(f.Title))
			if f.Subject != "" {
				fmt.Fprintf(&b, " (%s)", mdText(f.Subject))
			}
			b.WriteString("\n")
			for _, k := range slices.Sorted(maps.Keys(f.Evidence)) {
				fmt.Fprintf(&b, "- %s: %s\n", mdText(k), mdCode(f.Evidence[k]))
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, "- **Fix:** %s\n", mdText(f.Remediation))
			}
			b.WriteString("\n")
		}
		b.WriteString("</details>\n")
	}

	if len(res.Suppressed) > 0 {
		b.WriteString("\n### Suppressed\n\n| Target | Check | Reason | Expires |\n|---|---|---|---|\n")
		for _, s := range res.Suppressed {
			expires := "never"
			if !s.Expires.IsZero() {
				expires = s.Expires.Format("2006-01-02")
			}
			check := mdCode(s.CheckID)
			if s.Subject != "" {
				check += " (" + mdText(s.Subject) + ")"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdText(s.Target), check, mdText(s.Reason), expires)
		}
	}

	if len(res.Errors) > 0 {
		b.WriteString("\n### Check errors\n\nThese checks could not reach a verdict; they are not findings.\n\n")
		b.WriteString("| Target | Check | Error |\n|---|---|---|\n")
		for _, e := range res.Errors {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdText(e.Target), mdCode(e.CheckID), mdText(e.Err.Error()))
		}
	}

	if len(opts.Notes) > 0 {
		b.WriteString("\n")
		for _, n := range opts.Notes {
			b.WriteString("> " + mdText(n) + "\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdSeverity(s core.Severity) string {
	label := strings.ToUpper(s.String())
	if s >= core.SeverityHigh {
		return "**" + label + "**"
	}
	return label
}

var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", "&lt;", ">", "&gt;", "|", `\|`, "#", `\#`, "\n", " ",
)

// mdText escapes untrusted text (DNS records are attacker-controlled) so it
// can't inject links, HTML or table structure.
func mdText(s string) string { return mdEscaper.Replace(s) }

// mdCode renders s as a code span. Callers keep it out of table cells when s
// may contain "|", which GFM treats as a cell boundary even in code.
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || fence != "`" {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}
