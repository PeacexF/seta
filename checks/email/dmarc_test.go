package email

import (
	"testing"

	"github.com/PeacexF/seta/internal/checktest"
)

func TestDMARCChecks(t *testing.T) {
	r := fake(t, map[string]string{
		"dmarc.test": `
$ORIGIN dmarc.test.
@            MX  0 .
_dmarc       TXT "v=DMARC1; p=reject; sp=none; rua=mailto:d@dmarc.test"
sub          A   192.0.2.1
good         A   192.0.2.1
_dmarc.good  TXT "v=DMARC1; p=quarantine; rua=mailto:d@dmarc.test"
none         A   192.0.2.1
_dmarc.none  TXT "v=DMARC1; p=none"
bad          A   192.0.2.1
_dmarc.bad   TXT "v=DMARC1; p=block"
two          A   192.0.2.1
_dmarc.two   TXT "v=DMARC1; p=reject"
_dmarc.two   TXT "v=DMARC1; p=none"
ext          A   192.0.2.1
_dmarc.ext   TXT "v=DMARC1; p=reject; rua=mailto:a@vendor.test,mailto:b@authorized.test; ruf=mailto:c@sub.dmarc.test"
`,
		"nodmarc.test": `
$ORIGIN nodmarc.test.
@       A   192.0.2.1
_dmarc  TXT "not a dmarc record"
`,
		"vendor.test":     "@ A 192.0.2.1\n",
		"authorized.test": "ext.dmarc.test._report._dmarc TXT \"v=DMARC1\"\n",
	})
	env := checktest.Env{Resolver: r}
	tests := map[string][]string{
		"nodmarc.test":    {"email.dmarc.missing=high"},
		"good.dmarc.test": nil,
		// The org domain protects itself but not its subdomains...
		"dmarc.test": {"email.dmarc.policy_none[subdomains]=medium"},
		// ...which inherit sp=none.
		"sub.dmarc.test":  {"email.dmarc.policy_none=medium"},
		"none.dmarc.test": {"email.dmarc.policy_none=medium", "email.dmarc.no_reporting=low"},
		"bad.dmarc.test":  {"email.dmarc.syntax=high"},
		"two.dmarc.test":  {"email.dmarc.syntax=high"},
		// vendor.test isn't authorized; authorized.test is; sub.dmarc.test is the same org.
		"ext.dmarc.test": {"email.dmarc.external_auth[vendor.test]=medium"},
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			assertResults(t, results(t, env, domain(t, name), "email.dmarc."), want...)
		})
	}
}

func TestDMARCInheritedEvidence(t *testing.T) {
	r := fake(t, map[string]string{"dmarc.test": `
$ORIGIN dmarc.test.
@       A   192.0.2.1
_dmarc  TXT "v=DMARC1; p=none"
sub     A   192.0.2.1
`})
	f, err := checktest.Run(t, Check("email.dmarc.policy_none"), r, "sub.dmarc.test")
	if err != nil || len(f) != 1 || f[0].Evidence["inherited_from"] != "_dmarc.dmarc.test" {
		t.Fatalf("%+v %v", f, err)
	}
}
