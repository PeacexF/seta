package report

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/version"
)

// Source locates targets in the config file. SARIF consumers such as GitHub
// code scanning need a file location for every result; without a Source,
// results carry only a logical location (the domain).
type Source struct {
	// Path is relative to the repository root, e.g. "seta.yaml".
	Path        string
	TargetLines map[string]int
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	Help                 *sarifText     `json:"help,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConf  `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifRuleConf struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Level          string        `json:"level"`
	Message        sarifText     `json:"message"`
	AssociatedRule *sarifRuleRef `json:"associatedRule,omitempty"`
}

type sarifRuleRef struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	BaselineState       string             `json:"baselineState,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// sarifFingerprintKey versions the partial fingerprint so GitHub keeps
// tracking the same alert across runs even when the config line moves.
const sarifFingerprintKey = "setaFingerprint/v1"

// SARIF writes a SARIF 2.1.0 log. Suppressed findings carry a suppression and
// baselined ones baselineState "unchanged", so tools that understand SARIF
// can hide them; with opts.Baseline, the remaining findings are "new".
func SARIF(w io.Writer, res *engine.Result, opts Options) error {
	rules, index := sarifRules(res)
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "seta",
			Version:        version.Get().Version,
			InformationURI: "https://github.com/PeacexF/seta",
			Rules:          rules,
		}},
		Invocations: []sarifInvocation{{ExecutionSuccessful: true, Notifications: []sarifNotification{}}},
		Results:     []sarifResult{},
	}
	for _, e := range res.Errors {
		run.Invocations[0].Notifications = append(run.Invocations[0].Notifications, sarifNotification{
			Level:          "error",
			Message:        sarifText{Text: fmt.Sprintf("%s on %s could not complete: %v", e.CheckID, e.Target, e.Err)},
			AssociatedRule: &sarifRuleRef{ID: e.CheckID},
		})
	}
	for _, f := range res.Findings {
		r := sarifFinding(f, index, opts.Source)
		if opts.Baseline {
			r.BaselineState = "new"
		}
		run.Results = append(run.Results, r)
	}
	for _, f := range res.Baselined {
		r := sarifFinding(f, index, opts.Source)
		r.BaselineState = "unchanged"
		run.Results = append(run.Results, r)
	}
	for _, s := range res.Suppressed {
		r := sarifFinding(s.Finding, index, opts.Source)
		justification := s.Reason
		if !s.Expires.IsZero() {
			justification += " (until " + s.Expires.Format("2006-01-02") + ")"
		}
		r.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: justification}}
		run.Results = append(run.Results, r)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

// sarifRules describes every check that ran. GitHub takes an alert's
// severity from its rule, so a rule's level reflects the highest severity
// its findings were reported at (after overrides), not just the default.
func sarifRules(res *engine.Result) ([]sarifRule, map[string]int) {
	highest := make(map[string]core.Severity)
	note := func(f core.Finding) { highest[f.CheckID] = max(highest[f.CheckID], f.Severity) }
	for _, f := range res.Findings {
		note(f)
	}
	for _, f := range res.Baselined {
		note(f)
	}
	for _, s := range res.Suppressed {
		note(s.Finding)
	}

	metas := make(map[string]core.Meta, len(res.Checks))
	for _, m := range res.Checks {
		metas[m.ID] = m
	}
	for id := range highest {
		if _, ok := metas[id]; !ok {
			metas[id] = core.Meta{ID: id, Title: id, Severity: highest[id]}
		}
	}

	var rules []sarifRule
	index := make(map[string]int)
	for _, id := range slices.Sorted(maps.Keys(metas)) {
		m := metas[id]
		sev := max(m.Severity, highest[id])
		props := map[string]any{"tags": []string{"security", m.Module}, "precision": "high"}
		if m.Module == "" {
			props["tags"] = []string{"security"}
		}
		if s, ok := securitySeverity[sev]; ok {
			props["security-severity"] = s
		}
		r := sarifRule{
			ID:                   id,
			ShortDescription:     sarifText{Text: m.Title},
			DefaultConfiguration: sarifRuleConf{Level: sarifLevel(sev)},
			Properties:           props,
		}
		if m.Description != "" {
			r.FullDescription = &sarifText{Text: m.Description}
		}
		if m.Remediation != "" {
			r.Help = &sarifText{Text: m.Remediation}
		}
		if len(m.References) > 0 {
			r.HelpURI = m.References[0]
		}
		index[id] = len(rules)
		rules = append(rules, r)
	}
	return rules, index
}

// securitySeverity follows GitHub's CVSS-like bands: 9.0+ critical, 7.0+
// high, 4.0+ medium, above 0 low. Info findings get no score.
var securitySeverity = map[core.Severity]string{
	core.SeverityCritical: "9.5",
	core.SeverityHigh:     "8.0",
	core.SeverityMedium:   "5.5",
	core.SeverityLow:      "3.0",
}

func sarifLevel(s core.Severity) string {
	switch {
	case s >= core.SeverityHigh:
		return "error"
	case s == core.SeverityMedium:
		return "warning"
	}
	return "note"
}

func sarifFinding(f core.Finding, index map[string]int, src *Source) sarifResult {
	name := f.Target
	if f.Subject != "" {
		name += "/" + f.Subject
	}
	loc := sarifLocation{LogicalLocations: []sarifLogical{{Name: f.Target, FullyQualifiedName: name, Kind: "resource"}}}
	if src != nil {
		loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(src.Path)}}
		if line := src.TargetLines[f.Target]; line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
		}
	}

	msg := f.Title
	if f.Subject != "" {
		msg += " (" + f.Subject + ")"
	}
	msg += " on " + f.Target + "."
	for _, k := range slices.Sorted(maps.Keys(f.Evidence)) {
		msg += "\n" + k + ": " + f.Evidence[k]
	}
	if f.Remediation != "" {
		msg += "\nFix: " + f.Remediation
	}

	props := map[string]any{"severity": f.Severity.String(), "target": f.Target}
	if f.Subject != "" {
		props["subject"] = f.Subject
	}
	if len(f.Evidence) > 0 {
		props["evidence"] = f.Evidence
	}
	return sarifResult{
		RuleID:              f.CheckID,
		RuleIndex:           index[f.CheckID],
		Level:               sarifLevel(f.Severity),
		Message:             sarifText{Text: strings.TrimSpace(msg)},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{sarifFingerprintKey: f.Fingerprint()},
		Properties:          props,
	}
}
