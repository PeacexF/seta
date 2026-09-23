package baseline

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

func findings() []core.Finding {
	return []core.Finding{
		{CheckID: "email.spf.missing", Target: "b.test", Severity: core.SeverityHigh, Title: "No SPF record"},
		{CheckID: "email.mx.fcrdns", Target: "a.test", Subject: "mx2.a.test", Severity: core.SeverityLow, Title: "No FCrDNS"},
		{CheckID: "email.mx.fcrdns", Target: "a.test", Subject: "mx1.a.test", Severity: core.SeverityLow, Title: "No FCrDNS"},
	}
}

func TestRoundTripAndApply(t *testing.T) {
	var buf bytes.Buffer
	if err := New(findings()).Write(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Index(out, "mx1.a.test") > strings.Index(out, "mx2.a.test") || strings.Index(out, "mx2.a.test") > strings.Index(out, "b.test") {
		t.Errorf("entries not sorted:\n%s", out)
	}
	if !strings.Contains(out, `"version": 1`) || strings.Count(out, `"subject"`) != 2 {
		t.Errorf("unexpected file:\n%s", out)
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	res := &engine.Result{Findings: []core.Finding{
		{CheckID: "email.dmarc.missing", Target: "a.test", Severity: core.SeverityHigh},
		// Same identity, different severity and title: still known.
		{CheckID: "email.mx.fcrdns", Target: "a.test", Subject: "mx1.a.test", Severity: core.SeverityCritical, Title: "reworded"},
	}}
	gone := b.Apply(res, func(id string) string { return id })
	if len(res.Findings) != 1 || res.Findings[0].CheckID != "email.dmarc.missing" {
		t.Errorf("findings = %+v", res.Findings)
	}
	if len(res.Baselined) != 1 || gone != 2 {
		t.Errorf("baselined = %+v, gone = %d", res.Baselined, gone)
	}
}

func TestApplyFollowsRenames(t *testing.T) {
	b := &File{Version: 1, Findings: []Entry{{CheckID: "email.old.name", Target: "a.test"}}}
	res := &engine.Result{Findings: []core.Finding{{CheckID: "email.new.name", Target: "a.test"}}}
	b.Apply(res, func(id string) string { return strings.Replace(id, "old", "new", 1) })
	if len(res.Findings) != 0 || len(res.Baselined) != 1 {
		t.Errorf("renamed check not matched: %+v", res)
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"version":  `{"version": 2, "findings": []}`,
		"json":     `{"version": 1,`,
		"required": `{"version": 1, "findings": [{"check_id": "email.spf.missing"}]}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
