package report

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sampleResult() *engine.Result {
	return &engine.Result{
		Started:    time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		Duration:   1234 * time.Millisecond,
		Executions: 6,
		Targets: []core.Target{
			{Kind: core.KindDomain, Name: "broken.test"},
			{Kind: core.KindDomain, Name: "clean.test"},
			{Kind: core.KindDomain, Name: "flaky.test"},
		},
		Findings: []core.Finding{
			{
				CheckID: "email.spf.permissive_all", Target: "broken.test", Severity: core.SeverityCritical,
				Title:       "SPF record allows any sender",
				Evidence:    map[string]string{"record": "v=spf1 +all"},
				Remediation: "Replace +all with -all or ~all.",
				References:  []string{"https://www.rfc-editor.org/rfc/rfc7208#section-5.1"},
			},
			{
				CheckID: "email.mx.missing", Target: "broken.test", Severity: core.SeverityHigh,
				Title:       "No MX records",
				Evidence:    map[string]string{"mx_records": "none", "implicit_mx": "192.0.2.80"},
				Remediation: "Publish MX records.",
			},
			{
				CheckID: "email.mx.fcrdns", Target: "broken.test", Subject: "mx2.broken.test", Severity: core.SeverityLow,
				Title: "MX host lacks forward-confirmed reverse DNS",
			},
		},
		Errors: []engine.CheckError{
			{CheckID: "email.mx.missing", Target: "flaky.test", Err: errors.New("lookup MX flaky.test: server responded SERVFAIL")},
		},
	}
}

func TestTableGolden(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		res    *engine.Result
		opts   Options
	}{
		{"plain", "table.golden", sampleResult(), Options{}},
		{"color", "table_color.golden", sampleResult(), Options{Color: true, Notes: []string{"Active checks were not run."}}},
		{"empty", "table_empty.golden", &engine.Result{
			Duration: 80 * time.Millisecond, Executions: 1,
			Targets: []core.Target{{Kind: core.KindDomain, Name: "clean.test"}},
		}, Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Table(&buf, tt.res, tt.opts); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, filepath.Join("testdata", tt.golden), buf.Bytes())
		})
	}
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run 'go test ./internal/report -update' to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s (rerun with -update if intended)\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestJSONGolden(t *testing.T) {
	for name, res := range map[string]*engine.Result{
		"report.golden.json": sampleResult(),
		"empty.golden.json":  {Started: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), Targets: []core.Target{{Name: "clean.test"}}},
	} {
		var buf bytes.Buffer
		if err := JSON(&buf, res); err != nil {
			t.Fatal(err)
		}
		assertGolden(t, filepath.Join("testdata", name), buf.Bytes())
	}
}
