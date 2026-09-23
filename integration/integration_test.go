//go:build integration

// Package integration runs the checks against real DNS, SMTP and HTTPS
// servers. It only works inside the compose network: see docker-compose.yml.
package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	dnscheck "github.com/PeacexF/seta/checks/dns"
	"github.com/PeacexF/seta/checks/email"
	httpcheck "github.com/PeacexF/seta/checks/http"
	tlscheck "github.com/PeacexF/seta/checks/tls"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/netx"
)

func env(t *testing.T) (dnsx.Resolver, *x509.CertPool) {
	t.Helper()
	server, caFile := os.Getenv("SETA_IT_DNS"), os.Getenv("SETA_IT_CA")
	if server == "" || caFile == "" {
		t.Skip("SETA_IT_DNS and SETA_IT_CA not set; run via docker compose (make integration)")
	}
	r, err := dnsx.NewClient([]string{server}, dnsx.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return r, pool
}

// waitForSMTP gives Postfix time to start; compose only orders startup.
func waitForSMTP(t *testing.T, r dnsx.Resolver) {
	n := netx.New(r, netx.Options{Timeout: time.Second})
	deadline := time.Now().Add(60 * time.Second)
	for _, host := range []string{"mx-tls.int.test", "mx-plain.int.test", "mx-expired.int.test"} {
		for {
			conn, err := n.Dial(context.Background(), "tcp", host+":25")
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s:25 never came up: %v", host, err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func TestEmailChecks(t *testing.T) {
	r, pool := env(t)
	waitForSMTP(t, r)

	target := func(name string) core.Target {
		tg, err := core.ParseDomain(name)
		if err != nil {
			t.Fatal(err)
		}
		tg.Email = core.EmailOptions{DKIMSelectors: []string{"s1"}, DNSBLs: []string{"bl.int.test"}}
		return tg
	}
	eng := &engine.Engine{Resolver: r, Net: netx.Options{RootCAs: pool}}
	res := eng.Run(context.Background(), []engine.Job{
		{Target: target("tls.int.test"), Checks: email.Checks()},
		{Target: target("plain.int.test"), Checks: email.Checks()},
		{Target: target("expired.int.test"), Checks: email.Checks()},
	})
	for _, e := range res.Errors {
		t.Errorf("check error: %v", e)
	}

	got := map[string][]string{}
	for _, f := range res.Findings {
		s := f.CheckID
		if f.Subject != "" {
			s += "[" + f.Subject + "]"
		}
		got[f.Target] = append(got[f.Target], s)
		t.Logf("%s %s %v", f.Target, s, f.Evidence)
	}
	if len(got["tls.int.test"]) > 0 {
		t.Errorf("well-configured domain has findings: %v", got["tls.int.test"])
	}
	if !slices.Contains(got["plain.int.test"], "email.starttls.unsupported[mx-plain.int.test]") {
		t.Errorf("plain.int.test: want STARTTLS unsupported, got %v", got["plain.int.test"])
	}
	if !slices.Contains(got["expired.int.test"], "email.starttls.cert_invalid[mx-expired.int.test]") {
		t.Errorf("expired.int.test: want invalid certificate, got %v", got["expired.int.test"])
	}
	for _, f := range got["expired.int.test"] {
		if strings.HasPrefix(f, "email.starttls.cert_expiring") || strings.HasPrefix(f, "email.starttls.unsupported") {
			t.Errorf("expired.int.test: unexpected %s", f)
		}
	}
}

func waitForHTTPS(t *testing.T, r dnsx.Resolver) {
	n := netx.New(r, netx.Options{Timeout: time.Second})
	deadline := time.Now().Add(60 * time.Second)
	for _, host := range []string{"web-good.int.test", "web-legacy.int.test"} {
		for {
			conn, err := n.Dial(context.Background(), "tcp", host+":443")
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s:443 never came up: %v", host, err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func TestWebAndDNSChecks(t *testing.T) {
	r, pool := env(t)
	waitForHTTPS(t, r)

	// Hosts are declared explicitly, as in seta.yaml, so a failure to connect
	// is a check error rather than a skipped host.
	target := func(name string, hosts ...string) core.Target {
		tg, err := core.ParseDomain(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			parsed, err := core.ParseHost(h)
			if err != nil {
				t.Fatal(err)
			}
			tg.Hosts = append(tg.Hosts, parsed)
		}
		return tg
	}
	web := slices.Concat(tlscheck.Checks(), httpcheck.Checks())
	eng := &engine.Engine{Resolver: r, Net: netx.Options{RootCAs: pool}}
	res := eng.Run(context.Background(), []engine.Job{
		{Target: target("web-good.int.test", "web-good.int.test"), Checks: web},
		{Target: target("web-legacy.int.test", "web-legacy.int.test"), Checks: web},
		{Target: target("web-expired.int.test", "web-expired.int.test"), Checks: tlscheck.Checks()},
		{Target: target("web-mismatch.int.test", "web-mismatch.int.test"), Checks: tlscheck.Checks()},
		{Target: target("int.test", "gone.int.test", "app.int.test"), Checks: dnscheck.Checks()},
	})

	got := map[string][]string{}
	for _, f := range res.Findings {
		s := f.CheckID
		if f.Subject != "" {
			s += "[" + f.Subject + "]"
		}
		got[f.Target] = append(got[f.Target], s+"="+f.Severity.String())
		t.Logf("%s %s %v", f.Target, s, f.Evidence)
	}
	for _, e := range res.Errors {
		got[e.Target] = append(got[e.Target], e.CheckID+"!"+e.Err.Error())
	}
	want := map[string][]string{
		"web-good.int.test": nil,
		"web-legacy.int.test": {
			"http.exposure.sensitive_path[web-legacy.int.test/.env]=critical",
			"http.exposure.sensitive_path[web-legacy.int.test/.git/HEAD]=high",
			"http.headers.csp_missing[web-legacy.int.test]=low",
			"http.headers.frame_protection_missing[web-legacy.int.test]=low",
			"http.headers.nosniff_missing[web-legacy.int.test]=low",
			"http.headers.referrer_policy_missing[web-legacy.int.test]=info",
			"http.hsts.missing[web-legacy.int.test]=medium",
			"http.redirect.missing[web-legacy.int.test]=medium",
			"tls.cipher.weak[web-legacy.int.test]=low",
			"tls.protocol.deprecated[web-legacy.int.test]=medium",
		},
		"web-expired.int.test":  {"tls.cert.invalid[web-expired.int.test]=critical"},
		"web-mismatch.int.test": {"tls.cert.hostname_mismatch[web-mismatch.int.test]=high"},
		"int.test": {
			"dns.axfr.allowed[ns.int.test]=high",
			"dns.caa.missing=low",
			"dns.cname.dangling[gone.int.test]=medium",
			"dns.dnssec.missing=low",
			"dns.takeover.possible[app.int.test]=high",
		},
	}
	for tg, w := range want {
		g := got[tg]
		slices.Sort(g)
		slices.Sort(w)
		if !slices.Equal(g, w) {
			t.Errorf("%s:\n got  %q\n want %q", tg, g, w)
		}
	}
}

// TestCLI runs the real binary end to end, trusting the test CA the way a
// user would, via SSL_CERT_FILE.
func TestCLI(t *testing.T) {
	r, _ := env(t)
	waitForSMTP(t, r)
	cmd := exec.Command("go", "run", "../cmd/seta", "scan",
		"--resolver", os.Getenv("SETA_IT_DNS"), "--skip-dns-check",
		"--active", "--only", "email.starttls.*", "-f", "json",
		"tls.int.test", "plain.int.test")
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+os.Getenv("SETA_IT_CA"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("seta scan: %v\n%s", err, out)
	}
	var rep struct {
		Findings []struct {
			CheckID, Target, Subject string
		} `json:"findings"`
		Errors []any `json:"errors"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(rep.Errors) != 0 || len(rep.Findings) != 1 || rep.Findings[0].Target != "plain.int.test" {
		t.Errorf("unexpected report:\n%s", out)
	}
}
