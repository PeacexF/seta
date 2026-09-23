package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityOrderAndText(t *testing.T) {
	sevs := Severities()
	for i := 1; i < len(sevs); i++ {
		if !(sevs[i-1] < sevs[i]) {
			t.Fatalf("severities out of order: %v >= %v", sevs[i-1], sevs[i])
		}
	}
	for _, s := range sevs {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Fatalf("round trip %v: got %v, %v", s, back, err)
		}
	}
	if _, err := json.Marshal(SeverityUnset); err == nil {
		t.Error("marshaling unset severity should fail")
	}
	if _, err := ParseSeverity("HIGH"); err == nil {
		t.Error("severity names are lowercase only")
	}
}

func TestParseDomain(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "example.com", want: "example.com"},
		{in: "  Example.COM.  ", want: "example.com"},
		{in: "sub.example.co.uk", want: "sub.example.co.uk"},
		{in: "_dmarc.example.com", want: "_dmarc.example.com"},
		{in: "bücher.example", want: "xn--bcher-kva.example"},
		{in: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{in: "", wantErr: "empty"},
		{in: "localhost", wantErr: "fully qualified"},
		{in: "https://example.com", wantErr: "not a URL"},
		{in: "example.com/path", wantErr: "not a URL"},
		{in: "example.com:443", wantErr: "host:port"},
		{in: "user@example.com", wantErr: "not a domain"},
		{in: "exa mple.com", wantErr: "not a domain"},
		{in: "example..com", wantErr: "empty label"},
		{in: "-bad.example.com", wantErr: "hyphen"},
		{in: "bad!.example.com", wantErr: "invalid"},
		{in: strings.Repeat("a", 64) + ".com", wantErr: "63"},
		{in: strings.Repeat("abcdefghi.", 26) + "com", wantErr: "253"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDomain(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseDomain(%q) error = %v, want containing %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDomain(%q): %v", tt.in, err)
			}
			if got.Name != tt.want || got.Kind != KindDomain {
				t.Fatalf("ParseDomain(%q) = %+v, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateCheckID(t *testing.T) {
	valid := []string{"email.spf.missing", "email.dmarc.policy_none", "foo.bar2.baz_3"}
	for _, id := range valid {
		if err := ValidateCheckID(id); err != nil {
			t.Errorf("ValidateCheckID(%q): %v", id, err)
		}
	}
	invalid := []string{"", "email", "email.spf", "email.spf.lookup.limit", "Email.spf.missing",
		"email.spf-x.missing", "email..missing", "1email.spf.missing", "email.spf.missing "}
	for _, id := range invalid {
		if err := ValidateCheckID(id); err == nil {
			t.Errorf("ValidateCheckID(%q) accepted an invalid ID", id)
		}
	}
}

func TestMetaValidate(t *testing.T) {
	ok := Meta{ID: "email.mx.missing", Module: "email", Title: "No MX", Severity: SeverityHigh}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid meta rejected: %v", err)
	}
	tests := map[string]func(m *Meta){
		"module mismatch": func(m *Meta) { m.Module = "dns" },
		"no title":        func(m *Meta) { m.Title = "" },
		"unset severity":  func(m *Meta) { m.Severity = SeverityUnset },
		"bad mode":        func(m *Meta) { m.Mode = Mode(7) },
		"bad alias":       func(m *Meta) { m.Aliases = []string{"nope"} },
		"self alias":      func(m *Meta) { m.Aliases = []string{m.ID} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m := ok
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatal("invalid meta accepted")
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	// The fingerprint algorithm is persisted in state databases and baseline
	// files. If this value changes, every user's findings become "new".
	const want = "1b445612ad9db7924c547ab08f698a83"
	got := Fingerprint("email.mx.missing", "example.com", "")
	if len(got) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(got))
	}
	if got != want {
		t.Fatalf("Fingerprint changed: got %s, want %s", got, want)
	}

	f := Finding{CheckID: "email.mx.missing", Target: "example.com", Title: "a", Evidence: map[string]string{"x": "1"}}
	g := f
	g.Title, g.Evidence, g.Severity, g.Remediation = "b", map[string]string{"x": "2"}, SeverityLow, "fix"
	if f.Fingerprint() != g.Fingerprint() {
		t.Error("fingerprint must ignore title, evidence, severity and remediation")
	}

	// Field boundaries must matter: shifting text between fields changes it.
	if Fingerprint("a.b.c", "xy", "") == Fingerprint("a.b.c", "x", "y") {
		t.Error("fingerprint does not separate target and subject")
	}
	if Fingerprint("a.b.c", "x", "s1") == Fingerprint("a.b.c", "x", "s2") {
		t.Error("fingerprint ignores subject")
	}
}
