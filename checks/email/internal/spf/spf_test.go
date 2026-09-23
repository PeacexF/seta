package spf

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/dnsx"
)

func TestIsSPF(t *testing.T) {
	for txt, want := range map[string]bool{
		"v=spf1":                 true,
		"v=spf1 -all":            true,
		"V=SPF1 -all":            true,
		"v=spf10 -all":           false,
		"v=spf1-all":             false,
		" v=spf1 -all":           false,
		"spf2.0/pra include:x.y": false,
		"":                       false,
	} {
		if got := IsSPF(txt); got != want {
			t.Errorf("IsSPF(%q) = %v", txt, got)
		}
	}
}

func TestParseValid(t *testing.T) {
	tests := []struct {
		txt  string
		mech []string
	}{
		// RFC 7208 appendix A examples.
		{"v=spf1 +all", []string{"all"}},
		{"v=spf1 a -all", []string{"a", "-all"}},
		{"v=spf1 a:example.org -all", []string{"a:example.org", "-all"}},
		{"v=spf1 mx -all", []string{"mx", "-all"}},
		{"v=spf1 mx:example.org -all", []string{"mx:example.org", "-all"}},
		{"v=spf1 mx mx:example.org -all", []string{"mx", "mx:example.org", "-all"}},
		{"v=spf1 mx/30 mx:example.org/30 -all", []string{"mx", "mx:example.org", "-all"}},
		{"v=spf1 ptr -all", []string{"ptr", "-all"}},
		{"v=spf1 ip4:192.0.2.128/28 -all", []string{"ip4:192.0.2.128/28", "-all"}},
		{"v=spf1 include:example.com include:example.net -all", []string{"include:example.com", "include:example.net", "-all"}},
		{"v=spf1 redirect=_spf.example.com", nil},
		{"v=spf1 mx -all exp=explain._spf.%{d}", []string{"mx", "-all"}},
		{"v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all", []string{"-include:ip4._spf.%{d}", "-include:ptr._spf.%{d}", "all"}},
		{"v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all", []string{"exists:%{ir}.%{l1r+-}._spf.%{d}", "-all"}},
		// Real-world shapes.
		{"v=spf1 include:_spf.google.com ~all", []string{"include:_spf.google.com", "~all"}},
		{"v=spf1 ip6:2001:db8::/32 ip4:203.0.113.5 a//64 a/24//64 ?all", []string{"ip6:2001:db8::/32", "ip4:203.0.113.5/32", "a", "a", "?all"}},
		{"v=spf1   INCLUDE:Example.COM   -ALL", []string{"include:Example.COM", "-all"}},
		{"v=spf1 unknown-mod=foo -all", []string{"-all"}},
		{"v=spf1", nil},
	}
	for _, tt := range tests {
		rec, err := Parse(tt.txt)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.txt, err)
			continue
		}
		var got []string
		for _, m := range rec.Mechanisms {
			got = append(got, m.String())
		}
		if !slices.Equal(got, tt.mech) {
			t.Errorf("Parse(%q) mechanisms = %q, want %q", tt.txt, got, tt.mech)
		}
	}

	rec, _ := Parse("v=spf1 a:mail.example.com/24//64 redirect=_spf.example.com")
	if m := rec.Mechanisms[0]; m.CIDR4 != 24 || m.CIDR6 != 64 || m.Domain != "mail.example.com" {
		t.Errorf("dual CIDR parsed as %+v", m)
	}
	if rec.Redirect != "_spf.example.com" {
		t.Errorf("redirect = %q", rec.Redirect)
	}
}

func TestParseInvalid(t *testing.T) {
	tests := map[string]string{
		"v=spf1 include:192.0.2.1 -all":                "top-level label",
		"v=spf1 include -all":                          "requires a domain",
		"v=spf1 include: -all":                         "requires a domain",
		"v=spf1 ip4:192.0.2.300 -all":                  "invalid IP",
		"v=spf1 ip4:2001:db8::1 -all":                  "not an IPv4",
		"v=spf1 ip6:192.0.2.1 -all":                    "not an IPv6",
		"v=spf1 ip4:192.0.2.0/33 -all":                 "CIDR",
		"v=spf1 ip4:192.0.2.0/024 -all":                "CIDR",
		"v=spf1 ip4 -all":                              "requires an address",
		"v=spf1 a/33 -all":                             "CIDR",
		"v=spf1 a:/24 -all":                            "malformed",
		"v=spf1 ptr/24 -all":                           "no CIDR",
		"v=spf1 all:foo":                               "no arguments",
		"v=spf1 include:example.com -al":               "unknown mechanism",
		"v=spf1 ipv4:192.0.2.1 -all":                   "unknown mechanism",
		"v=spf1 redirect=a.example redirect=b.example": "more than once",
		"v=spf1 exists:%{z}.example.com -all":          "macro letter",
		"v=spf1 exists:%{d.example.com -all":           "unterminated",
		"v=spf1 exists:%x.example.com -all":            "invalid macro",
		"v=spf1 include:localhost -all":                "fully qualified",
		"v=spf1 exists:%{c}.example.com -all":          "macro letter", // c is exp-only
		"spf1 -all":                                    "v=spf1",
	}
	for txt, want := range tests {
		_, err := Parse(txt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want containing %q", txt, err, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"v=spf1 include:_spf.google.com ~all",
		"v=spf1 a:mail.example.com/24//64 mx ptr exists:%{ir}.%{l1r+-}._spf.%{d} redirect=x.example",
		"v=spf1 ip6:2001:db8::/32 ip4:192.0.2.0/24 -all exp=%{d}",
		"v=spf1 %{",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := Parse(s)
		if err != nil {
			return
		}
		for _, m := range rec.Mechanisms {
			_ = m.String()
		}
	})
}

const evalZone = `
$ORIGIN eval.test.
@           TXT "v=spf1 include:a.eval.test include:b.eval.test mx a -all"
@           MX  10 mx
@           A   192.0.2.1
mx          A   192.0.2.25
a           TXT "v=spf1 include:c.eval.test ip4:192.0.2.0/24 ~all"
b           TXT "v=spf1 a:gone.eval.test mx:nomx.eval.test -all"
c           TXT "v=spf1 exists:%{i}.x.eval.test -all"
nomx        A   192.0.2.1
many        TXT "v=spf1 mx:bigmx.eval.test -all"
bigmx       MX  1 m1
bigmx       MX  2 m2
bigmx       MX  3 m3
bigmx       MX  4 m4
bigmx       MX  5 m5
bigmx       MX  6 m6
bigmx       MX  7 m7
bigmx       MX  8 m8
bigmx       MX  9 m9
bigmx       MX  10 m10
bigmx       MX  11 m11
loop        TXT "v=spf1 include:loop2.eval.test -all"
loop2       TXT "v=spf1 include:loop.eval.test -all"
redir       TXT "v=spf1 a redirect=target.eval.test"
target      TXT "v=spf1 mx ?all"
target      MX  10 mx
nospf       TXT "google-site-verification=abc"
brokeninc   TXT "v=spf1 include:nospf.eval.test include:missing.eval.test -all"
permissive  TXT "v=spf1 include:plusall.eval.test -all"
plusall     TXT "v=spf1 +all"
`

func evaluate(t *testing.T, name string) *Evaluation {
	t.Helper()
	f := dnsx.NewFake()
	if err := f.AddZoneString("eval.test", evalZone); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	records, _, _, err := Fetch(ctx, f, name)
	if err != nil || len(records) != 1 {
		t.Fatalf("fetch %s: %v %v", name, records, err)
	}
	rec, err := Parse(records[0])
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Evaluate(ctx, f, name, rec)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestEvaluateCountsRecursively(t *testing.T) {
	ev := evaluate(t, "eval.test")
	// include:a(1) > include:c(1) > exists(1) + include:b(1) > a(1) mx(1) + mx(1) + a(1)
	if ev.Lookups != 8 {
		t.Errorf("lookups = %d, want 8", ev.Lookups)
	}
	wantCost := []TermCost{{"include:a.eval.test", 3}, {"include:b.eval.test", 3}, {"mx", 1}, {"a", 1}}
	if !slices.Equal(ev.Cost, wantCost) {
		t.Errorf("cost = %v, want %v", ev.Cost, wantCost)
	}
	// a:gone (NXDOMAIN) and mx:nomx (no MX) are void.
	if ev.VoidLookups != 2 || !slices.Equal(ev.Voids, []string{"a:gone.eval.test", "mx:nomx.eval.test"}) {
		t.Errorf("voids = %d %v", ev.VoidLookups, ev.Voids)
	}
	if !slices.Equal(ev.Unexpanded, []string{"exists:%{i}.x.eval.test"}) {
		t.Errorf("unexpanded = %v", ev.Unexpanded)
	}
	if !ev.HasEffective || ev.Effective.Qualifier != Fail {
		t.Errorf("effective all = %v %v", ev.HasEffective, ev.Effective)
	}
	if len(ev.Problems) != 0 {
		t.Errorf("unexpected problems: %v", ev.Problems)
	}
}

func TestEvaluateProblems(t *testing.T) {
	if ev := evaluate(t, "many.eval.test"); len(ev.Problems) != 1 || !strings.Contains(ev.Problems[0].Msg, "11 MX records") {
		t.Errorf("many MX: %v", ev.Problems)
	}
	if ev := evaluate(t, "loop.eval.test"); len(ev.Problems) != 1 || !strings.Contains(ev.Problems[0].Msg, "loops") {
		t.Errorf("loop: %v", ev.Problems)
	}
	ev := evaluate(t, "brokeninc.eval.test")
	if len(ev.Problems) != 2 {
		t.Fatalf("broken includes: %v", ev.Problems)
	}
	// nospf has TXT records (not void); missing is NXDOMAIN (void).
	if ev.VoidLookups != 1 || ev.Voids[0] != "include:missing.eval.test" {
		t.Errorf("voids = %v", ev.Voids)
	}
	if ev := evaluate(t, "permissive.eval.test"); !slices.Equal(ev.PermissiveIncludes, []string{"include:plusall.eval.test"}) {
		t.Errorf("permissive includes = %v", ev.PermissiveIncludes)
	}
}

func TestEvaluateRedirect(t *testing.T) {
	ev := evaluate(t, "redir.eval.test")
	if ev.Lookups != 3 { // a + redirect + mx
		t.Errorf("lookups = %d, want 3", ev.Lookups)
	}
	if !ev.HasEffective || ev.Effective.Qualifier != Neutral {
		t.Errorf("effective all should come from the redirect target: %v", ev.Effective)
	}
	if !slices.Equal(ev.Cost, []TermCost{{"a", 1}, {"redirect=target.eval.test", 2}}) {
		t.Errorf("cost = %v", ev.Cost)
	}
}

func TestEvaluatePropagatesDNSErrors(t *testing.T) {
	f := dnsx.NewFake()
	f.AddZoneString("eval.test", evalZone) //nolint:errcheck
	f.SetError("a.eval.test", dns.TypeTXT, nil)
	rec, _ := Parse("v=spf1 include:a.eval.test -all")
	if _, err := Evaluate(context.Background(), f, "eval.test", rec); err == nil {
		t.Fatal("DNS failure must be an error, not a problem")
	}
}
