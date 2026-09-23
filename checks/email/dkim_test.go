//go:debug rsa1024min=0

package email

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
)

// dkimTXT renders a DKIM key record as zone-file TXT data, split into
// 255-byte strings as DNS requires.
func dkimTXT(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	rec := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	var parts []string
	for len(rec) > 255 {
		parts, rec = append(parts, rec[:255]), rec[255:]
	}
	parts = append(parts, rec)
	return `"` + strings.Join(parts, `" "`) + `"`
}

func TestDKIMChecks(t *testing.T) {
	strong, weak, broken := dkimTXT(t, 2048), dkimTXT(t, 1024), dkimTXT(t, 512)
	r := checktest.Zone(t, "dkim.test", fmt.Sprintf(`
$ORIGIN dkim.test.
@                  A   192.0.2.1
s1._domainkey      TXT %s
s2._domainkey      TXT %s
s3._domainkey      TXT %s
s5._domainkey      TXT "v=DKIM1; p="
s6._domainkey      TXT "v=DKIM1; p=bm90IGEga2V5"
guess              A   192.0.2.1
google._domainkey.guess TXT %s
nothing            A   192.0.2.1
parked             TXT "v=spf1 -all"
`, strong, weak, broken, strong))
	env := checktest.Env{Resolver: r}

	configured := domain(t, "dkim.test")
	configured.Email.DKIMSelectors = []string{"s1", "s2", "s3", "s4", "s5", "s6"}
	assertResults(t, results(t, env, configured, "email.dkim."),
		"email.dkim.weak_key[selector:s2]=high",
		"email.dkim.weak_key[selector:s3]=critical",
		"email.dkim.missing[selector:s4]=medium",
		"email.dkim.missing[selector:s5]=medium",
		"email.dkim.missing[selector:s6]=medium",
	)

	// Without configured selectors, a key at a common selector is enough...
	assertResults(t, results(t, env, domain(t, "guess.dkim.test"), "email.dkim."))
	// ...and finding none is only informational.
	assertResults(t, results(t, env, domain(t, "nothing.dkim.test"), "email.dkim."),
		"email.dkim.missing[common-selectors]=info")

	// A domain declaring that it sends no mail needs no DKIM.
	assertResults(t, results(t, env, domain(t, "parked.dkim.test"), "email.dkim."))

	// Selectors passed on the command line as guesses behave the same way.
	guessed := domain(t, "nothing.dkim.test")
	guessed.Email = core.EmailOptions{DKIMSelectors: []string{"x"}, SelectorsGuessed: true}
	assertResults(t, results(t, env, guessed, "email.dkim."), "email.dkim.missing[common-selectors]=info")
}
