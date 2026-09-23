package dmarc

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		txt  string
		want func(*Record) bool
	}{
		{"v=DMARC1; p=none", func(r *Record) bool { return r.P == None && r.Pct == 100 && r.ADKIM == "r" }},
		{"v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=s", func(r *Record) bool {
			return r.P == Reject && r.SP == Quarantine && r.Pct == 50 && r.ADKIM == "s" && r.ASPF == "s"
		}},
		// RFC 7489 appendix B examples.
		{"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com", func(r *Record) bool {
			return len(r.RUA) == 1 && r.RUA[0].Domain == "example.com" && r.RUA[0].Address == "dmarc-feedback@example.com"
		}},
		{"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net", func(r *Record) bool {
			return len(r.RUF) == 1 && r.RUF[0].Domain == "thirdparty.example.net"
		}},
		{"v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25", func(r *Record) bool {
			return len(r.RUA) == 2 && r.RUA[1].Domain == "thirdparty.example.net" && r.Pct == 25
		}},
		// No p= but a valid rua= means p=none.
		{"v=DMARC1; rua=mailto:d@example.com", func(r *Record) bool { return r.P == None && r.ImplicitP }},
		// Case, spacing, trailing semicolon, unknown tags.
		{"v=DMARC1;P=Reject ; RUA = mailto:D@Example.COM ; fo=1:d; ri=3600; future=x;", func(r *Record) bool {
			return r.P == Reject && r.RUA[0].Domain == "example.com"
		}},
	}
	for _, tt := range tests {
		r, err := Parse(tt.txt)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.txt, err)
			continue
		}
		if !tt.want(r) {
			t.Errorf("Parse(%q) = %+v", tt.txt, r)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	tests := map[string]string{
		"p=reject; v=DMARC1":                        "v=DMARC1",
		"v=DMARC2; p=reject":                        "v=DMARC1",
		"v=DMARC1":                                  "missing required p=",
		"v=DMARC1; p=block":                         "none, quarantine or reject",
		"v=DMARC1; p=reject; sp=all":                "none, quarantine or reject",
		"v=DMARC1; p=reject; pct=150":               "pct",
		"v=DMARC1; p=reject; pct=abc":               "pct",
		"v=DMARC1; p=reject; adkim=x":               "r or s",
		"v=DMARC1; p=reject; rua=dmarc@example.com": "not a URI",
		"v=DMARC1; p=reject; rua=mailto:nobody":     "not a valid mailto",
		"v=DMARC1; p=reject; rua=mailto:a@b.c!10x":  "size limit",
		"v=DMARC1; p=reject; fo=2":                  "fo=",
		"v=DMARC1; p=reject; p=none":                "duplicate",
		"v=DMARC1; p=reject; v=DMARC1":              "duplicate",
		"v=DMARC1; p reject":                        "no '='",
	}
	for txt, want := range tests {
		_, err := Parse(txt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want containing %q", txt, err, want)
		}
	}
}

func TestIsDMARC(t *testing.T) {
	for txt, want := range map[string]bool{
		"v=DMARC1; p=none":  true,
		"v = DMARC1;p=none": true,
		"v=dmarc1; p=none":  true,
		"v=spf1 -all":       false,
		"p=none; v=DMARC1":  false,
		"":                  false,
	} {
		if IsDMARC(txt) != want {
			t.Errorf("IsDMARC(%q) != %v", txt, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("v=DMARC1; p=quarantine; rua=mailto:a@example.com,mailto:b@example.net!10m; pct=25; fo=1:d")
	f.Add("v=DMARC1; rua=mailto:x@y.z")
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err == nil && r.P == "" {
			t.Fatalf("parsed record without a policy: %q", s)
		}
	})
}
