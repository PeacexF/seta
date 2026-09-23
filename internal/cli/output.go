package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/baseline"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/report"
)

var formats = []string{"table", "json", "sarif", "markdown"}

// outputFlags control reporting and the exit code of scan and run.
type outputFlags struct {
	format   string
	output   string
	reports  []string
	failOn   string
	baseline string
	strict   bool
}

func (of *outputFlags) register(cmd *cobra.Command, defaultFailOn string) {
	f := cmd.Flags()
	f.StringVarP(&of.format, "format", "f", "table", "output format: "+strings.Join(formats, ", "))
	f.StringVarP(&of.output, "output", "o", "", "write the report to a file instead of stdout")
	f.StringArrayVar(&of.reports, "report", nil,
		"also write a report in another format, as FORMAT=PATH (repeatable), e.g. sarif=seta.sarif")
	f.StringVar(&of.failOn, "fail-on", defaultFailOn,
		"exit with code 1 if a finding is at or above this severity (info, low, medium, high, critical, or none)")
	f.StringVar(&of.baseline, "baseline", "", "report only findings not listed in this baseline file (see 'seta baseline')")
	f.BoolVar(&of.strict, "strict", false, "exit with code 3 if any check could not complete")
}

// session is a report in the making: validated flags, the open output and
// the baseline, all prepared before any check runs so mistakes fail fast.
type session struct {
	flags    outputFlags
	failOn   core.Severity // unset: never fail on findings
	out      io.Writer
	file     *os.File
	extra    []extraReport
	baseline *baseline.File
}

type extraReport struct {
	format string
	file   *os.File
}

func (a *App) openSession(cmd *cobra.Command, of outputFlags) (*session, error) {
	s := &session{flags: of, out: cmd.OutOrStdout()}
	if !slices.Contains(formats, of.format) {
		return nil, usageErr("unknown --format %q (want %s)", of.format, strings.Join(formats, ", "))
	}
	for _, r := range of.reports {
		format, path, ok := strings.Cut(r, "=")
		if !ok || path == "" || !slices.Contains(formats, format) {
			return nil, usageErr("invalid --report %q: want FORMAT=PATH with FORMAT one of %s", r, strings.Join(formats, ", "))
		}
	}
	if of.failOn != "none" {
		sev, err := core.ParseSeverity(of.failOn)
		if err != nil {
			return nil, usageErr("invalid --fail-on: %v, or none", err)
		}
		s.failOn = sev
	}
	if of.baseline != "" {
		b, err := baseline.Read(of.baseline)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, usageErr("baseline %s does not exist; create it with 'seta baseline -o %s'", of.baseline, of.baseline)
			}
			return nil, usageErr("%v", err)
		}
		s.baseline = b
	}
	if of.output != "" {
		f, err := os.Create(of.output)
		if err != nil {
			return nil, usageErr("%v", err)
		}
		s.file, s.out = f, f
	}
	for _, r := range of.reports {
		format, path, _ := strings.Cut(r, "=")
		f, err := os.Create(path)
		if err != nil {
			s.close()
			return nil, usageErr("%v", err)
		}
		s.extra = append(s.extra, extraReport{format, f})
	}
	return s, nil
}

// close removes the output files when the run fails before finish, so an
// empty report is never mistaken for a clean one.
func (s *session) close() {
	files := []*os.File{s.file}
	for _, r := range s.extra {
		files = append(files, r.file)
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		info, err := f.Stat()
		f.Close()
		if err == nil && info.Mode().IsRegular() {
			os.Remove(f.Name())
		}
	}
	s.file, s.extra = nil, nil
}

// finish applies the baseline, writes the report and turns the outcome into
// the exit code: findings at or above --fail-on win over --strict.
func (a *App) finish(s *session, res *engine.Result, notes []string, src *report.Source) error {
	defer s.close()
	if s.baseline != nil {
		if gone := s.baseline.Apply(res, a.canonicalID); gone == 1 {
			notes = append(notes, "1 finding in the baseline no longer occurs; regenerate it with 'seta baseline'.")
		} else if gone > 1 {
			notes = append(notes, fmt.Sprintf("%d findings in the baseline no longer occur; regenerate it with 'seta baseline'.", gone))
		}
	}
	opts := report.Options{Notes: notes, Source: src, Baseline: s.baseline != nil}
	for _, r := range s.extra {
		if err := writeReport(r.file, r.format, res, opts); err != nil {
			return err
		}
		if err := r.file.Close(); err != nil {
			return err
		}
	}
	s.extra = nil
	opts.Color = s.file == nil && a.useColor(s.out)
	if err := writeReport(s.out, s.flags.format, res, opts); err != nil {
		return err
	}
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		if err != nil {
			return err
		}
	}

	if s.failOn != core.SeverityUnset {
		n := 0
		for _, f := range res.Findings {
			if f.Severity >= s.failOn {
				n++
			}
		}
		if n > 0 {
			return &exitError{code: ExitFindings, err: fmt.Errorf("%s at or above --fail-on %s", plural(n, "finding"), s.failOn)}
		}
	}
	if s.flags.strict && len(res.Errors) > 0 {
		return &exitError{code: ExitCheckErrors, err: fmt.Errorf("%s could not complete (--strict)", plural(len(res.Errors), "check"))}
	}
	return nil
}

func writeReport(w io.Writer, format string, res *engine.Result, opts report.Options) error {
	switch format {
	case "json":
		return report.JSON(w, res)
	case "sarif":
		return report.SARIF(w, res, opts)
	case "markdown":
		return report.Markdown(w, res, opts)
	}
	return report.Table(w, res, opts)
}

// canonicalID maps a former check ID to the current one.
func (a *App) canonicalID(id string) string {
	if c, ok := a.Registry.Lookup(id); ok {
		return c.Meta().ID
	}
	return id
}

func usageErr(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}
