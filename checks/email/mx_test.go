package email

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
)

func TestMXMissing(t *testing.T) {
	fixtures := checktest.Fixtures(t)
	tests := []struct {
		domain      string
		wantFinding bool
		implicitMX  string
	}{
		{domain: "mx-ok.test"},
		{domain: "mx-null.test"},
		{domain: "mx-none.test", wantFinding: true, implicitMX: "192.0.2.80, 2001:db8::80"},
		{domain: "mx-none-noaddr.test", wantFinding: true, implicitMX: "none: mail to this domain is undeliverable"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			findings, err := checktest.Run(t, MXMissing{}, fixtures, tt.domain)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.wantFinding {
				if len(findings) != 0 {
					t.Fatalf("unexpected findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %+v", findings)
			}
			f := findings[0]
			if f.CheckID != "email.mx.missing" || f.Severity != core.SeverityHigh || f.Subject != "" {
				t.Errorf("unexpected finding: %+v", f)
			}
			if got := f.Evidence["implicit_mx"]; got != tt.implicitMX {
				t.Errorf("implicit_mx = %q, want %q", got, tt.implicitMX)
			}
		})
	}
}

func TestMXMissingErrorsAreNotFindings(t *testing.T) {
	t.Run("nonexistent domain", func(t *testing.T) {
		_, err := checktest.Run(t, MXMissing{}, checktest.Fixtures(t), "does-not-exist.test")
		if err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
			t.Fatalf("want NXDOMAIN check error, got %v", err)
		}
	})
	t.Run("SERVFAIL on MX", func(t *testing.T) {
		fixtures := checktest.Fixtures(t)
		fixtures.SetError("mx-none.test", dns.TypeMX, nil)
		if _, err := checktest.Run(t, MXMissing{}, fixtures, "mx-none.test"); err == nil {
			t.Fatal("want check error, got none")
		}
	})
	t.Run("SERVFAIL on A only degrades evidence", func(t *testing.T) {
		fixtures := checktest.Fixtures(t)
		fixtures.SetError("mx-none.test", dns.TypeA, nil)
		findings, err := checktest.Run(t, MXMissing{}, fixtures, "mx-none.test")
		if err != nil || len(findings) != 1 {
			t.Fatalf("want 1 finding, got %v, %v", findings, err)
		}
		if got := findings[0].Evidence["implicit_mx"]; !strings.HasPrefix(got, "unknown (") {
			t.Errorf("implicit_mx = %q", got)
		}
	})
}
