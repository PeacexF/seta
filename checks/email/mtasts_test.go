package email

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/netx"
)

const stsZone = `
$ORIGIN sts.test.
@                   MX  10 mx
mx                  A   192.0.2.25
*.mta-sts           A   192.0.2.80
`

// stsDomain returns zone lines for a domain under sts.test whose MX is
// mx.sts.test, optionally announcing MTA-STS and TLS-RPT.
func stsDomain(name string, sts, tlsrpt bool) string {
	z := name + " MX 10 mx.sts.test.\n"
	if sts {
		z += "_mta-sts." + name + ` TXT "v=STSv1; id=20240101"` + "\n"
		z += "mta-sts." + name + " A 192.0.2.80\n"
	}
	if tlsrpt {
		z += "_smtp._tls." + name + ` TXT "v=TLSRPTv1; rua=mailto:tls@sts.test"` + "\n"
	}
	return z
}

func policy(mode string, mx ...string) string {
	p := "version: STSv1\r\nmode: " + mode + "\r\nmax_age: 604800\r\n"
	for _, m := range mx {
		p += "mx: " + m + "\r\n"
	}
	return p
}

func TestMTASTSAndTLSRPTChecks(t *testing.T) {
	zone := stsZone +
		stsDomain("good", true, true) +
		stsDomain("testing", true, true) +
		stsDomain("nomatch", true, true) +
		stsDomain("testnomatch", true, true) +
		stsDomain("redirect", true, true) +
		stsDomain("notfound", true, true) +
		stsDomain("html", true, true) +
		stsDomain("badcert", true, true) +
		stsDomain("syntax", true, true) +
		stsDomain("modenone", true, true) +
		stsDomain("none", false, false) +
		"badtxt MX 10 mx.sts.test.\n_mta-sts.badtxt TXT \"v=STSv1\"\n_smtp._tls.badtxt TXT \"v=TLSRPTv1\"\n" +
		"twotxt MX 10 mx.sts.test.\n_mta-sts.twotxt TXT \"v=STSv1; id=1\"\n_mta-sts.twotxt TXT \"v=STSv1; id=2\"\n" +
		"_smtp._tls.twotxt TXT \"v=TLSRPTv1; rua=mailto:a@b.test\"\n_smtp._tls.twotxt TXT \"v=TLSRPTv1; rua=mailto:c@b.test\"\n" +
		"noaddr MX 10 mx.sts.test.\n_mta-sts.noaddr TXT \"v=STSv1; id=1\"\n" +
		"nullmx MX 0 .\n"

	policies := map[string]func(w http.ResponseWriter){
		"good":        text(policy("enforce", "mx.sts.test")),
		"testing":     text(policy("testing", "*.sts.test")),
		"nomatch":     text(policy("enforce", "mail.elsewhere.test")),
		"testnomatch": text(policy("testing", "mail.elsewhere.test")),
		"redirect":    func(w http.ResponseWriter) { w.Header().Set("Location", "https://x.test/"); w.WriteHeader(301) },
		"notfound":    func(w http.ResponseWriter) { w.WriteHeader(404) },
		"html":        func(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/html"); w.Write([]byte("<html>")) }, //nolint:errcheck
		"badcert":     text(policy("enforce", "mx.sts.test")),
		"syntax":      text("version: STSv1\nmode: enforce\n"),
		"modenone":    text(policy("none")),
	}

	ca := checktest.NewCA(t)
	now := time.Now()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.Host, "mta-sts."), ".sts.test")
		if h, ok := policies[name]; ok {
			h(w)
			return
		}
		http.NotFound(w, r)
	}))
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "mta-sts.badcert.sts.test" {
			name = "somewhere-else.test"
		}
		c := ca.Issue(now.Add(-time.Hour), now.Add(90*24*time.Hour), name)
		return &c, nil
	}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the badcert case logs handshake errors
	srv.StartTLS()
	t.Cleanup(srv.Close)

	env := checktest.Env{
		Resolver: checktest.Zone(t, "sts.test", zone),
		Net:      netx.Options{DialAddr: checktest.RedirectTo(srv.Listener.Addr().String()), RootCAs: ca.Pool()},
	}
	tests := map[string][]string{
		"good":        nil,
		"testing":     {"email.mtasts.testing=info"},
		"nomatch":     {"email.mtasts.invalid[mx:mx.sts.test]=high"},
		"testnomatch": {"email.mtasts.invalid[mx:mx.sts.test]=medium", "email.mtasts.testing=info"},
		"redirect":    {"email.mtasts.invalid[policy]=medium"},
		"notfound":    {"email.mtasts.invalid[policy]=medium"},
		"html":        {"email.mtasts.invalid[policy]=medium"},
		"badcert":     {"email.mtasts.invalid[policy]=medium"},
		"syntax":      {"email.mtasts.invalid[policy]=medium"},
		"modenone":    nil,
		"none":        {"email.mtasts.missing=low", "email.tlsrpt.missing=low"},
		"badtxt":      {"email.mtasts.invalid[record]=medium", "email.tlsrpt.missing=low"},
		"twotxt":      {"email.mtasts.invalid[record]=medium", "email.tlsrpt.missing=low"},
		"noaddr":      {"email.mtasts.invalid[policy]=medium", "email.tlsrpt.missing=low"},
		"nullmx":      nil,
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			target := domain(t, name+".sts.test")
			got := append(results(t, env, target, "email.mtasts."), results(t, env, target, "email.tlsrpt.")...)
			assertResults(t, got, want...)
		})
	}

	f, err := checktest.RunWith(t, Check("email.mtasts.invalid"), env, domain(t, "redirect.sts.test"))
	if err != nil || !strings.Contains(f[0].Evidence["error"], "must not follow redirects") {
		t.Errorf("redirect evidence: %+v %v", f, err)
	}
	f, _ = checktest.RunWith(t, Check("email.mtasts.invalid"), env, domain(t, "badcert.sts.test"))
	if !strings.Contains(f[0].Evidence["error"], "certificate") {
		t.Errorf("bad cert evidence: %+v", f)
	}
}

func text(body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(body)) //nolint:errcheck
	}
}
