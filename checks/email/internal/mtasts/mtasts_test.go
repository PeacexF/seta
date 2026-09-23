package mtasts

import (
	"slices"
	"strings"
	"testing"
)

func TestParseTXT(t *testing.T) {
	if id, err := ParseTXT("v=STSv1; id=20160831085700Z;"); err != nil || id != "20160831085700Z" {
		t.Errorf("RFC example: %q %v", id, err)
	}
	for txt, want := range map[string]string{
		"v=STSv1":                                "missing id",
		"id=1; v=STSv1":                          "start with v=STSv1",
		"v=STSv1; id=has-dash":                   "letters and digits",
		"v=STSv1; id=" + strings.Repeat("a", 33): "1-32",
	} {
		if _, err := ParseTXT(txt); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseTXT(%q) error = %v, want %q", txt, err, want)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	// RFC 8461 §3.2 example, with CRLF line endings.
	body := "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmx: backupmx.example.com\r\nmax_age: 604800\r\n"
	p, err := ParsePolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "enforce" || p.MaxAge != 604800 || !slices.Equal(p.MX, []string{"mail.example.com", "*.example.net", "backupmx.example.com"}) {
		t.Errorf("policy = %+v", p)
	}
	if p, err := ParsePolicy("version: STSv1\nmode: none\nmax_age: 0\n"); err != nil || p.Mode != "none" {
		t.Errorf("mode none without mx: %+v %v", p, err)
	}

	for body, want := range map[string]string{
		"mode: enforce\nmx: a.example\nmax_age: 1":                                "missing version",
		"version: STSv1\nmode: enforce\nmax_age: 1":                               "missing mx",
		"version: STSv1\nmode: enforce\nmx: a.example":                            "missing max_age",
		"version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 1":                "want STSv1",
		"version: STSv1\nmode: strict\nmx: a.example\nmax_age: 1":                 "want enforce",
		"version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 99999999999":      "max_age",
		"version: STSv1\nmode: enforce\nmode: testing\nmx: a.example\nmax_age: 1": "duplicate",
		"version: STSv1\nmode: enforce\nmx: *.*.example\nmax_age: 1":              "not a host",
		"<html>404</html>": "key: value",
	} {
		if _, err := ParsePolicy(body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParsePolicy(%q) error = %v, want %q", body, err, want)
		}
	}
}

func TestMatch(t *testing.T) {
	for _, tt := range []struct {
		pattern, host string
		want          bool
	}{
		{"mail.example.com", "mail.example.com.", true},
		{"mail.example.com", "MAIL.example.com", true},
		{"*.example.net", "mx1.example.net", true},
		{"*.example.net", "example.net", false},
		{"*.example.net", "a.b.example.net", false},
		{"mail.example.com", "mail2.example.com", false},
	} {
		if got := Match(tt.pattern, tt.host); got != tt.want {
			t.Errorf("Match(%q, %q) = %v", tt.pattern, tt.host, got)
		}
	}
}
