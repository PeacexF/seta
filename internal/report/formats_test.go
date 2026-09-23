package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

var testSource = &Source{Path: "seta.yaml", TargetLines: map[string]int{"broken.test": 4, "clean.test": 9}}

func TestSARIFGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleResult(), Options{Source: testSource, Baseline: true}); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, filepath.Join("testdata", "report.golden.sarif"), buf.Bytes())
}

func TestMarkdownGolden(t *testing.T) {
	res := sampleResult()
	res.Findings = append(res.Findings, core.Finding{
		CheckID: "email.spf.syntax", Target: "broken.test", Severity: core.SeverityHigh,
		Title:    "SPF record <b>is</b> [invalid](https://evil.test)",
		Evidence: map[string]string{"record": "v=spf1 a|b `x`"},
	})
	var buf bytes.Buffer
	if err := Markdown(&buf, res, Options{Notes: []string{"Active checks were not run."}}); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, filepath.Join("testdata", "report.golden.md"), buf.Bytes())
}

func compileSchema(t *testing.T, path, id string) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, name string, data []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("%s does not match the schema: %v", name, err)
	}
}

// TestSARIFSchema validates against the SARIF 2.1.0 schema GitHub code
// scanning uses, and checks GitHub's extra requirements.
func TestSARIFSchema(t *testing.T) {
	s := compileSchema(t, filepath.Join("testdata", "sarif-2.1.0.schema.json"), "https://json.schemastore.org/sarif-2.1.0.json")
	for name, opts := range map[string]Options{"with source": {Source: testSource}, "scan": {}} {
		var buf bytes.Buffer
		if err := SARIF(&buf, sampleResult(), opts); err != nil {
			t.Fatal(err)
		}
		validate(t, s, name, buf.Bytes())

		var log struct {
			Runs []struct {
				Tool struct {
					Driver struct{ Rules []struct{ ID string } }
				}
				Results []struct {
					RuleID    string
					RuleIndex int
					Locations []struct {
						PhysicalLocation *struct {
							ArtifactLocation struct{ URI string }
						}
					}
				}
			}
		}
		if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
			t.Fatal(err)
		}
		run := log.Runs[0]
		if len(run.Results) != 5 {
			t.Errorf("%s: %d results, want findings + baselined + suppressed = 5", name, len(run.Results))
		}
		for _, r := range run.Results {
			if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
				t.Errorf("%s: result %s points at rule %d", name, r.RuleID, r.RuleIndex)
			}
			if opts.Source != nil && (len(r.Locations) != 1 || r.Locations[0].PhysicalLocation == nil) {
				t.Errorf("%s: GitHub rejects results without a physical location: %+v", name, r)
			}
		}
	}
}

func TestJSONSchema(t *testing.T) {
	s := compileSchema(t, filepath.Join("..", "..", "schema", "report.v1.json"), "https://raw.githubusercontent.com/PeacexF/seta/main/schema/report.v1.json")
	for _, name := range []string{"report.golden.json", "empty.golden.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		validate(t, s, name, data)
	}
	res := &engine.Result{Findings: []core.Finding{{CheckID: "a.b.c", Target: "x.test", Severity: core.SeverityLow}}}
	res.Errors = []engine.CheckError{{CheckID: "a.b.c", Target: "y.test", Err: errors.New("boom")}}
	var buf bytes.Buffer
	if err := JSON(&buf, res); err != nil {
		t.Fatal(err)
	}
	validate(t, s, "minimal", buf.Bytes())
	if strings.Contains(buf.String(), "null,") {
		t.Errorf("unexpected null:\n%s", buf.String())
	}
}
