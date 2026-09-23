package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/checks/email"
	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/registry"
)

// harness runs the CLI with fake resolvers. Each resolver defaults to the
// honest zone fixtures; a test can make any of them lie.
type harness struct {
	checks           []core.Check // default: just email.mx.missing
	system, doh, dot dnsx.Resolver
	prompt           func(question string) (string, error)
	specs            [][]string // every spec list a resolver was built for
	questions        []string
	now              time.Time
}

func (h *harness) run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	reg := registry.New()
	checks := h.checks
	if checks == nil {
		checks = []core.Check{email.Check("email.mx.missing")}
	}
	for _, c := range checks {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	honest := checktest.Fixtures(t)
	pick := func(r dnsx.Resolver) dnsx.Resolver {
		if r == nil {
			return honest
		}
		return r
	}
	var out, errOut bytes.Buffer
	app := &App{
		Registry: reg,
		NewResolver: func(specs []string) (dnsx.Resolver, error) {
			h.specs = append(h.specs, specs)
			switch {
			case slices.Equal(specs, dnsx.Presets["doh"]):
				return pick(h.doh), nil
			case slices.Equal(specs, dnsx.Presets["dot"]):
				return pick(h.dot), nil
			}
			if _, err := dnsx.NewClient(specs, dnsx.Options{}); err != nil {
				return nil, err // keep real spec validation
			}
			return pick(h.system), nil
		},
		Stdout: &out,
		Stderr: &errOut,
	}
	if !h.now.IsZero() {
		app.Now = func() time.Time { return h.now }
	}
	if h.prompt != nil {
		app.Prompt = func(q string) (string, error) {
			h.questions = append(h.questions, q)
			return h.prompt(q)
		}
	}
	code = app.Run(context.Background(), args)
	return code, out.String(), errOut.String()
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return (&harness{}).run(t, args...)
}

// lyingResolver answers A queries honestly and blanks everything else, like
// the intercepting networks the resolver check exists for.
func lyingResolver(t *testing.T) dnsx.Resolver {
	honest := checktest.Fixtures(t)
	return resolverFunc(func(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
		if qtype == dns.TypeA {
			return honest.Lookup(ctx, name, qtype)
		}
		return &dnsx.Response{Name: dnsx.CanonicalName(name), Type: qtype}, nil
	})
}

type resolverFunc func(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error)

func (f resolverFunc) Lookup(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
	return f(ctx, name, qtype)
}

func yes(string) (string, error) { return "", nil }
func no(string) (string, error)  { return "n", nil }

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != ExitOK || !strings.HasPrefix(out, "seta ") || !strings.Contains(out, "go:") {
		t.Fatalf("code %d, output:\n%s", code, out)
	}
}

func TestChecksList(t *testing.T) {
	code, out, _ := run(t, "checks", "list")
	if code != ExitOK {
		t.Fatalf("code %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "ID") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if fields := strings.Fields(lines[1]); fields[0] != "email.mx.missing" || fields[1] != "passive" || fields[2] != "high" {
		t.Fatalf("unexpected row: %q", lines[1])
	}

	if code, out, _ := run(t, "checks", "list", "--module", "email"); code != ExitOK || !strings.Contains(out, "email.mx.missing") {
		t.Fatalf("--module email: code %d, output:\n%s", code, out)
	}
	if code, _, errOut := run(t, "checks", "list", "--module", "nope"); code != ExitUsage || !strings.Contains(errOut, "no checks in module") {
		t.Fatalf("--module nope: code %d, stderr: %s", code, errOut)
	}
}

func TestScanEndToEnd(t *testing.T) {
	code, out, errOut := run(t, "scan", "mx-ok.test", "MX-NONE.test.", "mx-none.test", "does-not-exist.test")
	if code != ExitOK {
		t.Fatalf("code %d, stderr: %s", code, errOut)
	}
	for _, want := range []string{
		"mx-ok.test\n  ✓ no findings",
		"mx-none.test\n  HIGH      email.mx.missing  No MX records",
		"implicit_mx: 192.0.2.80, 2001:db8::80",
		"does-not-exist.test  email.mx.missing  domain does-not-exist.test does not exist (NXDOMAIN)",
		"1 finding (1 high) · 1 check error · 3 checks on 3 targets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colors written to a non-terminal")
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"scan"}, "at least one domain"},
		{[]string{"scan", "https://example.com"}, "not a domain name"},
		{[]string{"scan", "--bogus", "example.com"}, "unknown flag"},
		{[]string{"version", "extra"}, "takes no arguments"},
		{[]string{"nope"}, "unknown command"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, tt.args...)
		if code != ExitUsage || !strings.Contains(errOut, tt.want) {
			t.Errorf("%q: code %d, stderr %q; want code %d containing %q", tt.args, code, errOut, ExitUsage, tt.want)
		}
	}
}

func TestResolverCheckNonInteractiveRefuses(t *testing.T) {
	h := &harness{system: lyingResolver(t)}
	code, out, errOut := h.run(t, "scan", "mx-ok.test")
	if code != ExitUsage || out != "" {
		t.Fatalf("code %d, stdout %q", code, out)
	}
	for _, want := range []string{
		"DNS check failed: the resolver (", "is returning incomplete answers",
		"MX lookups for gmail.com, outlook.com and yahoo.com returned no records",
		"intercepting or filtering DNS",
		"re-run with --resolver doh", "--skip-dns-check",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut)
		}
	}
}

func TestResolverCheckOffersDoH(t *testing.T) {
	h := &harness{system: lyingResolver(t), prompt: yes}
	code, out, errOut := h.run(t, "scan", "mx-ok.test")
	if code != ExitOK {
		t.Fatalf("code %d, stderr:\n%s", code, errOut)
	}
	if len(h.questions) != 1 || !strings.Contains(h.questions[0], "DNS over HTTPS") {
		t.Fatalf("questions = %q", h.questions)
	}
	if !strings.Contains(errOut, "Using DNS over HTTPS (https://1.1.1.1/dns-query, https://9.9.9.9/dns-query)") {
		t.Errorf("stderr:\n%s", errOut)
	}
	if !strings.Contains(out, "mx-ok.test\n  ✓ no findings") {
		t.Errorf("scan did not run through DoH:\n%s", out)
	}
}

func TestResolverCheckFallsBackToDoT(t *testing.T) {
	h := &harness{system: lyingResolver(t), doh: lyingResolver(t), prompt: yes}
	code, _, errOut := h.run(t, "scan", "mx-ok.test")
	if code != ExitOK {
		t.Fatalf("code %d, stderr:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "DNS over HTTPS did not work either") || !strings.Contains(errOut, "Using DNS over TLS") {
		t.Errorf("stderr:\n%s", errOut)
	}
}

func TestResolverCheckNothingWorks(t *testing.T) {
	h := &harness{system: lyingResolver(t), doh: lyingResolver(t), dot: lyingResolver(t), prompt: yes}
	code, out, errOut := h.run(t, "scan", "mx-ok.test")
	if code != ExitUsage || out != "" || !strings.Contains(errOut, "no working resolver") {
		t.Fatalf("code %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
}

func TestResolverCheckUserDeclines(t *testing.T) {
	h := &harness{system: lyingResolver(t), prompt: no}
	code, out, errOut := h.run(t, "scan", "mx-ok.test")
	if code != ExitUsage || out != "" || !strings.Contains(errOut, "scan aborted") {
		t.Fatalf("code %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
}

func TestResolverCheckExplicitEncryptedResolverFailsWithoutAsking(t *testing.T) {
	h := &harness{doh: lyingResolver(t), prompt: yes}
	code, _, errOut := h.run(t, "scan", "--resolver", "doh", "mx-ok.test")
	if code != ExitUsage || len(h.questions) != 0 || !strings.Contains(errOut, "cannot scan without a working resolver") {
		t.Fatalf("code %d, questions %q, stderr:\n%s", code, h.questions, errOut)
	}
}

func TestSkipDNSCheck(t *testing.T) {
	h := &harness{system: lyingResolver(t)}
	code, out, errOut := h.run(t, "scan", "--skip-dns-check", "mx-ok.test")
	if code != ExitOK || strings.Contains(errOut, "DNS check failed") {
		t.Fatalf("code %d, stderr:\n%s", code, errOut)
	}
	// This is exactly the false positive the check exists to prevent.
	if !strings.Contains(out, "email.mx.missing") {
		t.Errorf("expected the lying resolver's false finding:\n%s", out)
	}
}

func TestResolverFlag(t *testing.T) {
	h := &harness{}
	if code, _, errOut := h.run(t, "scan", "--resolver", "9.9.9.9,tls://1.1.1.1", "mx-ok.test"); code != ExitOK {
		t.Fatalf("code %d, stderr:\n%s", code, errOut)
	}
	if len(h.specs) != 1 || !slices.Equal(h.specs[0], []string{"9.9.9.9", "tls://1.1.1.1"}) {
		t.Fatalf("resolver built for %q", h.specs)
	}

	h = &harness{}
	if code, _, _ := h.run(t, "scan", "--resolver", "dot", "mx-ok.test"); code != ExitOK || !slices.Equal(h.specs[0], dnsx.Presets["dot"]) {
		t.Fatalf("dot preset: code %d, specs %q", code, h.specs)
	}

	for _, bad := range []string{"udp://1.1.1.1", "dns.google", ""} {
		code, _, errOut := run(t, "scan", "--resolver", bad, "mx-ok.test")
		if code != ExitUsage || errOut == "" {
			t.Errorf("--resolver %q: code %d, stderr %q", bad, code, errOut)
		}
	}
}

func TestScanJSONAndOutputFile(t *testing.T) {
	code, out, errOut := run(t, "scan", "-f", "json", "mx-none.test")
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errOut)
	}
	var r struct {
		Schema   int `json:"schema"`
		Findings []struct {
			CheckID string `json:"check_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Schema != 1 || len(r.Findings) != 1 {
		t.Fatalf("bad JSON (%v): %s", err, out)
	}

	path := filepath.Join(t.TempDir(), "report.txt")
	code, out, _ = run(t, "scan", "-o", path, "mx-none.test")
	data, err := os.ReadFile(path)
	if code != ExitOK || out != "" || err != nil || !strings.Contains(string(data), "email.mx.missing") {
		t.Fatalf("code %d, stdout %q, file %q, %v", code, out, data, err)
	}

	if code, _, errOut := run(t, "scan", "-f", "xml", "mx-none.test"); code != ExitUsage || !strings.Contains(errOut, "unknown --format") {
		t.Fatalf("bad format: code %d, %s", code, errOut)
	}
}

func TestScanSelection(t *testing.T) {
	h := &harness{checks: email.Checks()}
	code, out, _ := h.run(t, "scan", "--only", "email.spf.*", "mx-none.test")
	if code != ExitOK || strings.Contains(out, "email.mx.missing") || !strings.Contains(out, "email.spf.missing") {
		t.Fatalf("--only: code %d\n%s", code, out)
	}
	if !strings.Contains(out, "6 checks") || strings.Contains(out, "active check") {
		t.Errorf("--only email.spf.* should run 6 passive checks without an active-check note:\n%s", out)
	}

	code, out, _ = h.run(t, "scan", "mx-none.test")
	if code != ExitOK || !strings.Contains(out, "3 active checks not run") {
		t.Errorf("default scan should note skipped active checks:\n%s", out)
	}

	code, _, errOut := h.run(t, "scan", "--only", "email.starttls.*", "mx-none.test")
	if code != ExitUsage || !strings.Contains(errOut, "pass --active") {
		t.Errorf("active-only selection without --active: code %d, %s", code, errOut)
	}
	if code, _, errOut := h.run(t, "scan", "--only", "email.nope.*", "mx-none.test"); code != ExitUsage || !strings.Contains(errOut, "matches no checks") {
		t.Errorf("unknown pattern: code %d, %s", code, errOut)
	}
}

func TestChecksExplain(t *testing.T) {
	h := &harness{checks: email.Checks()}
	code, out, _ := h.run(t, "checks", "explain", "email.spf.lookup_limit")
	for _, want := range []string{"email.spf.lookup_limit\n", "Severity:  high", "Why it matters", "How to fix", "rfc7208"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
	if code != ExitOK {
		t.Errorf("code %d", code)
	}
	if code, _, errOut := h.run(t, "checks", "explain", "email.nope.nope"); code != ExitUsage || !strings.Contains(errOut, "unknown check") {
		t.Errorf("unknown check: code %d, %s", code, errOut)
	}
}
