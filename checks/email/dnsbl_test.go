package email

import (
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/checktest"
)

func TestDNSBL(t *testing.T) {
	r := fake(t, map[string]string{
		"mail.test": `
$ORIGIN mail.test.
@        MX 10 mx1
@        MX 20 mx2
mx1      A  192.0.2.25
mx1      AAAA 2001:db8::25
mx2      A  192.0.2.26
clean    MX 10 mx3
mx3      A  198.51.100.1
`,
		// A well-behaved list that lists 192.0.2.25.
		"bl.test": `
2.0.0.127        A 127.0.0.2
25.2.0.192       A 127.0.0.2
25.2.0.192       A 127.0.0.4
`,
		// A retired list that answers every query, including 127.0.0.1.
		"everything.test": "2.0.0.127 A 127.0.0.2\n1.0.0.127 A 127.0.0.2\n",
		"dead.test":       "@ A 192.0.2.1\n",
		// Spamhaus refusing queries from a public resolver.
		"refuse.test": "2.0.0.127 A 127.255.255.254\n",
		// A list whose domain was taken over and now points at a web host.
		"hijacked.test": "2.0.0.127 A 127.0.0.2\n25.2.0.192 A 203.0.113.9\n",
		"zen.dq.spamhaus.net": `
2.0.0.127.SECRETKEY   A 127.0.0.2
26.2.0.192.SECRETKEY  A 127.0.0.3
`,
	})
	env := checktest.Env{Resolver: r}
	run := func(name, key string, lists ...string) []string {
		tg := domain(t, name)
		tg.Email.DNSBLs, tg.Email.SpamhausDQSKey = lists, key
		return results(t, env, tg, "email.dnsbl.")
	}

	assertResults(t, run("mail.test", "", "bl.test"), "email.dnsbl.listed[bl.test:192.0.2.25]=high")
	assertResults(t, run("clean.mail.test", "", "bl.test"))

	withKey := run("mail.test", "secretkey", "bl.test")
	assertResults(t, withKey,
		"email.dnsbl.listed[bl.test:192.0.2.25]=high",
		"email.dnsbl.listed[zen.spamhaus.org (DQS):192.0.2.26]=high")
	withKeyErr := run("mail.test", "secretkey", "dead.test")
	for _, s := range append(withKey, withKeyErr...) {
		if strings.Contains(strings.ToLower(s), "secretkey") {
			t.Errorf("DQS key leaked: %s", s)
		}
	}

	assertError(t, run("mail.test", "", "dead.test"), "email.dnsbl.listed", "does not list its 127.0.0.2 test address")
	assertError(t, run("mail.test", "", "everything.test"), "email.dnsbl.listed", "lists 127.0.0.1")
	assertError(t, run("mail.test", "", "refuse.test"), "email.dnsbl.listed", "refused the query")
	assertError(t, run("mail.test", "", "hijacked.test"), "email.dnsbl.listed", "not a DNSBL return code")
}
