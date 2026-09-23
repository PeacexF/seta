package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/version"
)

// JSONSchema is bumped on any breaking change to the JSON output.
const JSONSchema = 1

type jsonReport struct {
	Schema     int              `json:"schema"`
	Tool       jsonTool         `json:"tool"`
	StartedAt  time.Time        `json:"started_at"`
	DurationMS int64            `json:"duration_ms"`
	Targets    []string         `json:"targets"`
	Summary    jsonSummary      `json:"summary"`
	Findings   []jsonFinding    `json:"findings"`
	Errors     []jsonError      `json:"errors"`
	Suppressed []jsonSuppressed `json:"suppressed"`
	Baselined  []jsonFinding    `json:"baselined"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonSummary struct {
	Findings    int            `json:"findings"`
	BySeverity  map[string]int `json:"by_severity"`
	CheckErrors int            `json:"check_errors"`
	ChecksRun   int            `json:"checks_run"`
	Suppressed  int            `json:"suppressed"`
	Baselined   int            `json:"baselined"`
}

type jsonFinding struct {
	Fingerprint string            `json:"fingerprint"`
	CheckID     string            `json:"check_id"`
	Target      string            `json:"target"`
	Subject     string            `json:"subject"`
	Severity    core.Severity     `json:"severity"`
	Title       string            `json:"title"`
	Evidence    map[string]string `json:"evidence"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
}

type jsonSuppressed struct {
	jsonFinding
	Suppression jsonSuppression `json:"suppression"`
}

type jsonSuppression struct {
	Reason string `json:"reason"`
	// Expires is a YYYY-MM-DD date, or null.
	Expires *string `json:"expires"`
}

type jsonError struct {
	CheckID string `json:"check_id"`
	Target  string `json:"target"`
	Error   string `json:"error"`
}

// JSON writes the versioned machine-readable report. Collections are always
// arrays or objects, never null, so consumers needn't special-case empties.
func JSON(w io.Writer, res *engine.Result) error {
	r := jsonReport{
		Schema:     JSONSchema,
		Tool:       jsonTool{Name: "seta", Version: version.Get().Version},
		StartedAt:  res.Started.UTC(),
		DurationMS: res.Duration.Milliseconds(),
		Targets:    []string{},
		Summary: jsonSummary{
			Findings:    len(res.Findings),
			BySeverity:  map[string]int{},
			CheckErrors: len(res.Errors),
			ChecksRun:   res.Executions,
			Suppressed:  len(res.Suppressed),
			Baselined:   len(res.Baselined),
		},
		Findings:   []jsonFinding{},
		Errors:     []jsonError{},
		Suppressed: []jsonSuppressed{},
		Baselined:  []jsonFinding{},
	}
	for _, s := range core.Severities() {
		r.Summary.BySeverity[s.String()] = 0
	}
	for _, t := range res.Targets {
		r.Targets = append(r.Targets, t.Name)
	}
	for _, f := range res.Findings {
		r.Summary.BySeverity[f.Severity.String()]++
		r.Findings = append(r.Findings, toJSON(f))
	}
	for _, e := range res.Errors {
		r.Errors = append(r.Errors, jsonError{CheckID: e.CheckID, Target: e.Target, Error: e.Err.Error()})
	}
	for _, s := range res.Suppressed {
		js := jsonSuppressed{jsonFinding: toJSON(s.Finding), Suppression: jsonSuppression{Reason: s.Reason}}
		if !s.Expires.IsZero() {
			d := s.Expires.Format(time.DateOnly)
			js.Suppression.Expires = &d
		}
		r.Suppressed = append(r.Suppressed, js)
	}
	for _, f := range res.Baselined {
		r.Baselined = append(r.Baselined, toJSON(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func toJSON(f core.Finding) jsonFinding {
	jf := jsonFinding{
		Fingerprint: f.Fingerprint(),
		CheckID:     f.CheckID,
		Target:      f.Target,
		Subject:     f.Subject,
		Severity:    f.Severity,
		Title:       f.Title,
		Evidence:    f.Evidence,
		Remediation: f.Remediation,
		References:  f.References,
	}
	if jf.Evidence == nil {
		jf.Evidence = map[string]string{}
	}
	if jf.References == nil {
		jf.References = []string{}
	}
	return jf
}
