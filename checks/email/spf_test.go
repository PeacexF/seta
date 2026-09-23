package email

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/checktest"
)

const spfZone = `
$ORIGIN spf.test.
@         MX  10 mx
mx        A   192.0.2.25
good      TXT "v=spf1 mx -all"
good      MX  10 mx.spf.test.
none      A   192.0.2.1
multi     TXT "v=spf1 -all"
multi     TXT "v=spf1 mx -all"
bad       TXT "v=spf1 include:192.0.2.1 -all"
badinc    TXT "v=spf1 include:noinc.spf.test include:gone.spf.test -all"
noinc     TXT "google-site-verification=x"
many      TXT "v=spf1 include:l.spf.test include:l.spf.test include:l.spf.test include:l.spf.test include:l.spf.test include:l.spf.test mx mx mx mx a -all"
many      MX  10 mx.spf.test.
many      A   192.0.2.1
l         TXT "v=spf1 ip4:192.0.2.0/24 -all"
void      TXT "v=spf1 a:v1.spf.test a:v2.spf.test mx:v3.spf.test -all"
plus      TXT "v=spf1 +all"
bare      TXT "v=spf1 mx all"
bare      MX  10 mx.spf.test.
neutral   TXT "v=spf1 ?all"
noall     TXT "v=spf1 ip4:192.0.2.1"
incplus   TXT "v=spf1 include:plus.spf.test -all"
redir     TXT "v=spf1 redirect=plus.spf.test"
`

func TestSPFChecks(t *testing.T) {
	env := checktest.Env{Resolver: checktest.Zone(t, "spf.test", spfZone)}
	tests := map[string][]string{
		"good.spf.test":  nil,
		"none.spf.test":  {"email.spf.missing=high"},
		"multi.spf.test": {"email.spf.multiple=high"},
		"bad.spf.test":   {"email.spf.syntax=high"},
		"badinc.spf.test": {
			"email.spf.syntax[include:gone.spf.test]=high",
			"email.spf.syntax[include:noinc.spf.test]=high",
		},
		"many.spf.test":    {"email.spf.lookup_limit=high"},
		"void.spf.test":    {"email.spf.void_lookups=medium"},
		"plus.spf.test":    {"email.spf.permissive_all=critical"},
		"bare.spf.test":    {"email.spf.permissive_all=critical"},
		"neutral.spf.test": {"email.spf.permissive_all=low"},
		"noall.spf.test":   {"email.spf.permissive_all=low"},
		"incplus.spf.test": {"email.spf.permissive_all[include:plus.spf.test]=critical"},
		"redir.spf.test":   {"email.spf.permissive_all=critical"},
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			assertResults(t, results(t, env, domain(t, name), "email.spf."), want...)
		})
	}
}

func TestSPFLookupLimitEvidence(t *testing.T) {
	f, err := checktest.Run(t, Check("email.spf.lookup_limit"), checktest.Zone(t, "spf.test", spfZone), "many.spf.test")
	if err != nil || len(f) != 1 {
		t.Fatalf("%v %v", f, err)
	}
	if f[0].Title != "SPF needs 11 DNS lookups (limit is 10)" || f[0].Evidence["lookups"] != "11" {
		t.Errorf("finding: %+v", f[0])
	}
	if got := f[0].Evidence["breakdown"]; got != "include:l.spf.test=1, include:l.spf.test=1, include:l.spf.test=1, include:l.spf.test=1, include:l.spf.test=1, include:l.spf.test=1, mx=1, mx=1, mx=1, mx=1, a=1" {
		t.Errorf("breakdown = %q", got)
	}
}

func TestSPFDNSFailureIsAnError(t *testing.T) {
	r := checktest.Zone(t, "spf.test", spfZone)
	r.SetError("good.spf.test", dns.TypeTXT, nil)
	got := results(t, checktest.Env{Resolver: r}, domain(t, "good.spf.test"), "email.spf.")
	for _, g := range got {
		if !strings.Contains(g, "!") {
			t.Errorf("DNS failure produced a finding: %s", g)
		}
	}
	assertError(t, got, "email.spf.missing", "SERVFAIL")
}
