package config

import (
	"slices"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

// Apply rewrites severities per SeverityOverrides and moves suppressed
// findings from res.Findings to res.Suppressed. Expired suppressions no
// longer apply; they are returned so the caller can warn about them.
func (c *Config) Apply(res *engine.Result, now time.Time) (expired []Suppression) {
	var active []Suppression
	for _, s := range c.Suppressions {
		if s.Expired(now) {
			expired = append(expired, s)
		} else {
			active = append(active, s)
		}
	}

	kept := res.Findings[:0]
	for _, f := range res.Findings {
		if sev, ok := c.SeverityOverrides[f.CheckID]; ok {
			f.Severity = sev
		}
		if s, ok := firstMatch(active, f); ok {
			res.Suppressed = append(res.Suppressed, engine.Suppressed{Finding: f, Reason: s.Reason, Expires: s.Expires.Time})
			continue
		}
		kept = append(kept, f)
	}
	res.Findings = kept
	slices.SortFunc(res.Findings, engine.CompareFindings)
	slices.SortFunc(res.Suppressed, func(a, b engine.Suppressed) int { return engine.CompareFindings(a.Finding, b.Finding) })
	return expired
}

func firstMatch(sups []Suppression, f core.Finding) (Suppression, bool) {
	for _, s := range sups {
		if s.Matches(f) {
			return s, true
		}
	}
	return Suppression{}, false
}
