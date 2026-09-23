package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testPlugin = &Plugin{Name: "demo", Version: "1.0.0", Checks: []Check{
	{
		CheckInfo: CheckInfo{ID: "demo.x.echo", Title: "Echo", Mode: Passive, Severity: Low},
		Run: func(ctx context.Context, req *Request) ([]Finding, error) {
			var cfg struct{ Hosts []string }
			if err := req.DecodeConfig(&cfg); err != nil {
				return nil, err
			}
			_, hasDeadline := ctx.Deadline()
			var out []Finding
			for _, h := range cfg.Hosts {
				out = append(out, Finding{Subject: h + "." + req.Target.Name, Evidence: map[string]string{"deadline": map[bool]string{true: "yes"}[hasDeadline]}})
			}
			return out, nil
		},
	},
	{
		CheckInfo: CheckInfo{ID: "demo.x.fail", Title: "Fail", Mode: Active, Severity: High},
		Run:       func(context.Context, *Request) ([]Finding, error) { return nil, errors.New("lookup failed") },
	},
	{
		CheckInfo: CheckInfo{ID: "demo.x.panic", Title: "Panic", Mode: Passive, Severity: High},
		Run:       func(context.Context, *Request) ([]Finding, error) { panic("oops") },
	},
}}

func serve(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := testPlugin.Serve(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestDescribe(t *testing.T) {
	code, out, _ := serve(t, "", "describe")
	var d Describe
	if err := json.Unmarshal([]byte(out), &d); err != nil || code != 0 {
		t.Fatalf("code %d, %v: %s", code, err, out)
	}
	if d.Protocol != 1 || d.Name != "demo" || d.Version != "1.0.0" || len(d.Checks) != 3 || d.Checks[1].Mode != Active {
		t.Errorf("describe = %+v", d)
	}
}

func run(t *testing.T, req string) Response {
	t.Helper()
	code, out, errOut := serve(t, req, "run")
	var resp Response
	if err := json.Unmarshal([]byte(out), &resp); err != nil || code != 0 {
		t.Fatalf("code %d, %v: %s %s", code, err, out, errOut)
	}
	if resp.Findings == nil {
		t.Error("findings must be [], not null")
	}
	return resp
}

func TestRun(t *testing.T) {
	deadline := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	resp := run(t, `{"protocol":1,"check":"demo.x.echo","target":{"kind":"domain","name":"example.com"},"config":{"hosts":["www","mail"]},"deadline":"`+deadline+`"}`)
	if resp.Error != nil || len(resp.Findings) != 2 || resp.Findings[1].Subject != "mail.example.com" || resp.Findings[0].Evidence["deadline"] != "yes" {
		t.Errorf("echo = %+v", resp)
	}
	if resp := run(t, `{"protocol":1,"check":"demo.x.echo","target":{"kind":"domain","name":"a.com"},"config":{}}`); resp.Error != nil || len(resp.Findings) != 0 {
		t.Errorf("empty config = %+v", resp)
	}

	for req, want := range map[string]string{
		`{"protocol":1,"check":"demo.x.fail"}`:                          "lookup failed",
		`{"protocol":1,"check":"demo.x.panic"}`:                         "check panicked: oops",
		`{"protocol":1,"check":"demo.x.nope"}`:                          `unknown check "demo.x.nope"`,
		`{"protocol":2,"check":"demo.x.echo"}`:                          "unsupported protocol 2",
		`{"protocol":1,"check":"demo.x.echo","config":{"hostz":["a"]}}`: `unknown field "hostz"`,
		`nope`: "invalid request",
	} {
		if resp := run(t, req); resp.Error == nil || !strings.Contains(*resp.Error, want) {
			t.Errorf("%s: %+v, want error %q", req, resp, want)
		}
	}
}

func TestUsage(t *testing.T) {
	if code, _, errOut := serve(t, "", "frobnicate"); code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Errorf("code %d: %s", code, errOut)
	}
	if code, _, errOut := serve(t, ""); code != 2 || !strings.Contains(errOut, "usage: seta-plugin-demo describe|run") {
		t.Errorf("code %d: %s", code, errOut)
	}
}
