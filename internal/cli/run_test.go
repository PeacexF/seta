package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/checks/email"
	"github.com/PeacexF/seta/internal/dnsx"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seta.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// mxConfig declares one clean-looking target with an MX host it doesn't
// expect, and one without MX records.
const mxConfig = `version: 1
defaults:
  checks: ["email.mx.*", "!email.mx.fcrdns"]
targets:
  - domain: mx-ok.test
    email:
      expected_mx: [mx1.mx-ok.test]
  - domain: mx-none.test
`

func mxHarness() *harness { return &harness{checks: email.Checks()} }

func TestRun(t *testing.T) {
	path := writeConfig(t, mxConfig)
	code, out, errOut := mxHarness().run(t, "run", "-c", path)
	if code != ExitFindings || !strings.Contains(errOut, "2 findings at or above --fail-on low") {
		t.Fatalf("code %d, stderr: %s", code, errOut)
	}
	for _, want := range []string{
		"mx-ok.test\n  MEDIUM    email.mx.unexpected  Unexpected MX host (mx2.mx-ok.test)",
		"mx-none.test\n  HIGH      email.mx.missing     No MX records",
		"2 findings (1 high, 1 medium) · 6 checks on 2 targets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	if code, _, errOut := mxHarness().run(t, "run", "-c", path, "--fail-on", "high"); code != ExitFindings || !strings.Contains(errOut, "1 finding at or above") {
		t.Errorf("--fail-on high: code %d, %s", code, errOut)
	}
	if code, _, _ := mxHarness().run(t, "run", "-c", path, "--fail-on", "critical"); code != ExitOK {
		t.Errorf("--fail-on critical: code %d", code)
	}
	if code, _, errOut := mxHarness().run(t, "run", "-c", path, "--fail-on", "severe"); code != ExitUsage || !strings.Contains(errOut, "invalid --fail-on") {
		t.Errorf("bad --fail-on: code %d, %s", code, errOut)
	}
	if code, out, _ := mxHarness().run(t, "run", "-c", path, "--only", "email.mx.missing", "--fail-on", "none"); code != ExitOK ||
		strings.Contains(out, "unexpected") || !strings.Contains(out, "2 checks on 2 targets") {
		t.Errorf("--only: code %d\n%s", code, out)
	}
}

func TestRunSuppressionsAndOverrides(t *testing.T) {
	path := writeConfig(t, mxConfig+`severity_overrides:
  email.mx.unexpected: critical
suppressions:
  - check: email.mx.missing
    target: mx-none.test
    reason: parked domain
    expires: 2027-01-01
  - check: email.mx.unresolvable
    reason: expired exception
    expires: 2026-01-01
`)
	h := mxHarness()
	h.now = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	code, out, errOut := h.run(t, "run", "-c", path, "--fail-on", "high")
	if code != ExitFindings {
		t.Fatalf("code %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "CRITICAL  email.mx.unexpected") || !strings.Contains(out, "1 finding (1 critical) · 1 suppressed") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(errOut, "seta.yaml:16: suppression of email.mx.unresolvable expired on 2026-01-01") {
		t.Errorf("stderr:\n%s", errOut)
	}
}

func TestBaselineFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seta.yaml")
	bpath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(mxConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := mxHarness().run(t, "baseline", "-c", path, "-o", bpath)
	if code != ExitOK || !strings.Contains(errOut, "Wrote 2 findings to "+bpath) {
		t.Fatalf("baseline: code %d, %s", code, errOut)
	}

	code, out, errOut := mxHarness().run(t, "run", "-c", path, "--baseline", bpath)
	if code != ExitOK || !strings.Contains(out, "0 findings · 2 in baseline") {
		t.Fatalf("run with baseline: code %d, %s\n%s", code, errOut, out)
	}

	// A new problem fails; the known ones stay hidden.
	changed := strings.Replace(mxConfig, "[mx1.mx-ok.test]", "[mx1.mx-ok.test, mx3.mx-ok.test]", 1)
	if err := os.WriteFile(path, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = mxHarness().run(t, "run", "-c", path, "--baseline", bpath, "-f", "json")
	var r struct {
		Findings  []struct{ Subject string }
		Baselined []struct{ Subject string }
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if code != ExitFindings || len(r.Findings) != 1 || r.Findings[0].Subject != "mx3.mx-ok.test" || len(r.Baselined) != 2 {
		t.Errorf("code %d, %+v", code, r)
	}

	if code, _, errOut := mxHarness().run(t, "run", "-c", path, "--baseline", filepath.Join(dir, "nope.json")); code != ExitUsage ||
		!strings.Contains(errOut, "create it with 'seta baseline") {
		t.Errorf("missing baseline: code %d, %s", code, errOut)
	}
}

func TestBaselineNotesGoneFindings(t *testing.T) {
	dir := t.TempDir()
	bpath := filepath.Join(dir, "b.json")
	path := writeConfig(t, mxConfig)
	if code, _, _ := mxHarness().run(t, "baseline", "-c", path, "-o", bpath); code != ExitOK {
		t.Fatal(code)
	}
	fixed := strings.Replace(mxConfig, "[mx1.mx-ok.test]", "[\"*.mx-ok.test\"]", 1)
	path = writeConfig(t, fixed)
	_, out, _ := mxHarness().run(t, "run", "-c", path, "--baseline", bpath)
	if !strings.Contains(out, "1 finding in the baseline no longer occurs") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRunStrict(t *testing.T) {
	path := writeConfig(t, "version: 1\ntargets:\n  - domain: does-not-exist.test\n    checks: [email.mx.missing]\n")
	if code, _, _ := mxHarness().run(t, "run", "-c", path); code != ExitOK {
		t.Errorf("check errors without --strict: code %d", code)
	}
	code, _, errOut := mxHarness().run(t, "run", "-c", path, "--strict")
	if code != ExitCheckErrors || !strings.Contains(errOut, "1 check could not complete (--strict)") {
		t.Errorf("--strict: code %d, %s", code, errOut)
	}
}

func TestRunSARIF(t *testing.T) {
	path := writeConfig(t, mxConfig)
	code, out, _ := mxHarness().run(t, "run", "-c", path, "-f", "sarif", "--fail-on", "none")
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil || code != ExitOK {
		t.Fatalf("code %d, %v:\n%s", code, err, out)
	}
	lines := map[string]int{}
	for _, r := range log.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		if !strings.HasSuffix(loc.ArtifactLocation.URI, "/seta.yaml") || filepath.IsAbs(loc.ArtifactLocation.URI) {
			t.Errorf("uri = %q", loc.ArtifactLocation.URI)
		}
		lines[r.RuleID] = loc.Region.StartLine
	}
	if lines["email.mx.unexpected"] != 5 || lines["email.mx.missing"] != 8 {
		t.Errorf("result lines = %v", lines)
	}
}

func TestRunResolverFromConfig(t *testing.T) {
	path := writeConfig(t, "version: 1\nresolver:\n  servers: [dot]\n  timeout: 2s\ntargets:\n  - domain: mx-ok.test\n")
	h := &harness{}
	if code, _, errOut := h.run(t, "run", "-c", path); code != ExitOK {
		t.Fatalf("code %d, %s", code, errOut)
	}
	if !slices.Equal(h.specs[0], dnsx.Presets["dot"]) {
		t.Errorf("specs = %q", h.specs)
	}
	h = &harness{}
	h.run(t, "run", "-c", path, "--resolver", "doh")
	if !slices.Equal(h.specs[0], dnsx.Presets["doh"]) {
		t.Errorf("--resolver should win over the config: %q", h.specs)
	}
}

func TestRunConfigErrors(t *testing.T) {
	code, _, errOut := run(t, "run", "-c", filepath.Join(t.TempDir(), "seta.yaml"))
	if code != ExitUsage || !strings.Contains(errOut, "does not exist; create one with 'seta init'") {
		t.Errorf("missing config: code %d, %s", code, errOut)
	}
	path := writeConfig(t, "version: 1\ntargets:\n  - domain: mx-ok.test\n    bogus: 1\n")
	code, _, errOut = run(t, "run", "-c", path)
	if code != ExitUsage || errOut != path+":4:5: unknown setting \"bogus\"\n" {
		t.Errorf("invalid config: code %d, stderr %q", code, errOut)
	}
}

func TestConfigValidate(t *testing.T) {
	path := writeConfig(t, mxConfig)
	code, out, _ := mxHarness().run(t, "config", "validate", "-c", path)
	if code != ExitOK || out != path+" is valid: 2 targets, 6 checks per run.\n" {
		t.Errorf("code %d, %q", code, out)
	}
	path = writeConfig(t, "version: 1\ntargets:\n  - domain: bad domain\n  - domain: mx-ok.test\n    checks: [email.nope.*]\n")
	code, _, errOut := mxHarness().run(t, "config", "validate", "-c", path)
	if code != ExitUsage || strings.Count(errOut, "\n") != 2 || !strings.Contains(errOut, path+":5:14: check pattern") {
		t.Errorf("code %d, stderr:\n%s", code, errOut)
	}
}

func TestInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seta.yaml")
	code, _, errOut := mxHarness().run(t, "init", "--domain", "mx-ok.test,Example.COM", "-o", path)
	if code != ExitOK || !strings.Contains(errOut, "Wrote "+path+" for 2 domains") {
		t.Fatalf("code %d, %s", code, errOut)
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"$schema=https://", "  - domain: mx-ok.test\n", "  - domain: example.com\n", "active: false"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("config missing %q:\n%s", want, data)
		}
	}
	if code, _, _ := mxHarness().run(t, "config", "validate", "-c", path); code != ExitOK {
		t.Errorf("generated config does not validate")
	}
	if code, _, errOut := mxHarness().run(t, "init", "--domain", "a.test", "-o", path); code != ExitUsage || !strings.Contains(errOut, "--force") {
		t.Errorf("overwrite: code %d, %s", code, errOut)
	}
	if code, _, errOut := mxHarness().run(t, "init", "-o", filepath.Join(t.TempDir(), "x.yaml")); code != ExitUsage || !strings.Contains(errOut, "pass --domain") {
		t.Errorf("non-interactive without --domain: code %d, %s", code, errOut)
	}
}

func TestInitInteractive(t *testing.T) {
	answers := []string{"mx-ok.test, mx-none.test", "google s1", "", "y"}
	h := mxHarness()
	h.prompt = func(string) (string, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	path := filepath.Join(t.TempDir(), "seta.yaml")
	if code, _, errOut := h.run(t, "init", "-o", path); code != ExitOK {
		t.Fatalf("code %d, %s", code, errOut)
	}
	if len(h.questions) != 4 || !strings.Contains(h.questions[1], "DKIM selectors for mx-ok.test") {
		t.Errorf("questions: %q", h.questions)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `dkim_selectors: ["google", "s1"]`) || !strings.Contains(string(data), "active: true") ||
		strings.Count(string(data), "dkim_selectors:") != 2 {
		t.Errorf("config:\n%s", data)
	}
}

func TestRunExtraReports(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, mxConfig)
	sarif, md := filepath.Join(dir, "seta.sarif"), filepath.Join(dir, "summary.md")
	code, out, errOut := mxHarness().run(t, "run", "-c", path, "--fail-on", "none", "--report", "sarif="+sarif, "--report", "markdown="+md)
	if code != ExitOK || !strings.Contains(out, "email.mx.unexpected") {
		t.Fatalf("code %d, %s\n%s", code, errOut, out)
	}
	for file, want := range map[string]string{sarif: `"version": "2.1.0"`, md: "## Seta report"} {
		data, err := os.ReadFile(file)
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s: %v\n%s", file, err, data)
		}
	}
	for _, bad := range []string{"sarif", "xml=x", "sarif="} {
		if code, _, errOut := mxHarness().run(t, "run", "-c", path, "--report", bad); code != ExitUsage || !strings.Contains(errOut, "invalid --report") {
			t.Errorf("--report %q: code %d, %s", bad, code, errOut)
		}
	}
}

func TestFailedRunLeavesNoReports(t *testing.T) {
	dir := t.TempDir()
	sarif, out := filepath.Join(dir, "seta.sarif"), filepath.Join(dir, "out.txt")
	code, _, _ := run(t, "run", "-c", filepath.Join(dir, "missing.yaml"), "-o", out, "--report", "sarif="+sarif)
	if code != ExitUsage {
		t.Fatalf("code %d", code)
	}
	for _, f := range []string{sarif, out} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s left behind: %v", f, err)
		}
	}
}
