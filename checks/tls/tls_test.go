package tlscheck

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/netx"
	"github.com/PeacexF/seta/internal/registry"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// serve starts a TLS server and returns its address.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

const zone = `
$ORIGIN web.test.
@    A 192.0.2.1
www  A 192.0.2.1
api  A 192.0.2.2
`

func env(t *testing.T, ca *checktest.CA, addr string) checktest.Env {
	return checktest.Env{
		Resolver: checktest.Zone(t, "web.test", zone),
		Net:      netx.Options{DialAddr: checktest.RedirectTo(addr), RootCAs: ca.Pool()},
		Now:      func() time.Time { return now },
	}
}

func target(t *testing.T, hosts ...string) core.Target {
	tg := checktest.Domain(t, "web.test")
	for _, h := range hosts {
		parsed, err := core.ParseHost(h)
		if err != nil {
			t.Fatal(err)
		}
		tg.Hosts = append(tg.Hosts, parsed)
	}
	return tg
}

func TestCertificateChecks(t *testing.T) {
	ca := checktest.NewCA(t)
	cert := func(days int, names ...string) *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{ca.Issue(now.AddDate(0, -2, 0), now.AddDate(0, 0, days), names...)}}
	}
	selfSigned := checktest.NewCA(t)
	tests := []struct {
		name string
		cfg  *tls.Config
		want []string
	}{
		{"healthy", cert(90, "web.test", "www.web.test"), nil},
		{"www missing from certificate", cert(90, "web.test"), []string{"tls.cert.hostname_mismatch[www.web.test]=high"}},
		{"expiring", cert(15, "web.test", "www.web.test"), []string{"tls.cert.expiring[web.test]=medium", "tls.cert.expiring[www.web.test]=medium"}},
		{"expiring very soon", cert(3, "web.test", "www.web.test"), []string{"tls.cert.expiring[web.test]=high", "tls.cert.expiring[www.web.test]=high"}},
		{"expired", cert(-1, "web.test", "www.web.test"), []string{"tls.cert.invalid[web.test]=critical", "tls.cert.invalid[www.web.test]=critical"}},
		{"untrusted", &tls.Config{Certificates: []tls.Certificate{selfSigned.Issue(now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), "web.test", "www.web.test")}},
			[]string{"tls.cert.invalid[web.test]=high", "tls.cert.invalid[www.web.test]=high"}},
		{"TLS 1.1 only", func() *tls.Config {
			c := cert(90, "web.test", "www.web.test")
			c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
			return c
		}(), []string{"tls.protocol.no_modern[web.test]=high", "tls.protocol.no_modern[www.web.test]=high"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checktest.Results(t, Checks(), env(t, ca, serve(t, tt.cfg)), target(t), "tls.")
			checktest.Want(t, filterPassive(got), tt.want...)
		})
	}
}

// filterPassive drops the results of active checks.
func filterPassive(results []string) []string {
	var out []string
	for _, r := range results {
		id := r
		for i, c := range r {
			if c == '[' || c == '=' || c == '!' {
				id = r[:i]
				break
			}
		}
		if Check(id).Meta().Mode == core.Passive {
			out = append(out, r)
		}
	}
	return out
}

func TestProtocolProbes(t *testing.T) {
	ca := checktest.NewCA(t)
	cert := ca.Issue(now.AddDate(0, -2, 0), now.AddDate(1, 0, 0), "web.test", "www.web.test")
	tests := []struct {
		name string
		cfg  *tls.Config
		want []string
	}{
		{"modern only", &tls.Config{Certificates: []tls.Certificate{cert}}, nil},
		{"TLS 1.0 and weak ciphers", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}},
			[]string{"tls.protocol.deprecated[web.test]=medium", "tls.protocol.deprecated[www.web.test]=medium",
				"tls.cipher.weak[web.test]=medium", "tls.cipher.weak[www.web.test]=medium"}},
		{"only CBC-SHA256", &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}},
			[]string{"tls.cipher.weak[web.test]=low", "tls.cipher.weak[www.web.test]=low"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := env(t, ca, serve(t, tt.cfg))
			var got []string
			for _, id := range []string{"tls.protocol.deprecated", "tls.cipher.weak"} {
				got = append(got, checktest.Results(t, Checks(), e, target(t), id)...)
			}
			checktest.Want(t, got, tt.want...)
		})
	}

	e := env(t, ca, serve(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}}))
	fs, err := checktest.RunWith(t, Check("tls.cipher.weak"), e, target(t, "web.test"))
	if err != nil || len(fs) != 1 || fs[0].Evidence["accepted"] != "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" {
		t.Errorf("evidence: %+v, %v", fs, err)
	}
}

func TestHostSelection(t *testing.T) {
	ca := checktest.NewCA(t)
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{ca.Issue(now.AddDate(0, -2, 0), now.AddDate(1, 0, 0), "web.test", "api.web.test")}})

	// www has no certificate name, but it isn't declared and has no A record in this zone.
	e := env(t, ca, addr)
	e.Resolver = checktest.Zone(t, "web.test", "$ORIGIN web.test.\n@ A 192.0.2.1\n")
	checktest.Want(t, checktest.Results(t, Checks(), e, target(t), "tls.cert."))

	// Explicit hosts must exist and answer.
	checktest.Want(t, checktest.Results(t, Checks(), env(t, ca, addr), target(t, "api.web.test", "gone.web.test"), "tls.cert.hostname_mismatch"),
		"tls.cert.hostname_mismatch!gone.web.test has no A or AAAA records")

	// Implicit hosts that refuse connections are skipped; timeouts are errors.
	refused := env(t, ca, addr)
	refused.Net.DialAddr = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	checktest.Want(t, checktest.Results(t, Checks(), refused, target(t), "tls.cert.expiring"))
	timeout := env(t, ca, addr)
	timeout.Net.DialAddr = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("i/o timeout") }
	checktest.Want(t, checktest.Results(t, Checks(), timeout, target(t), "tls.cert.expiring"), "tls.cert.expiring!i/o timeout")

	// www that only exists through a wildcard record isn't a site.
	wild := env(t, ca, addr)
	wild.Resolver = checktest.Zone(t, "web.test", "$ORIGIN web.test.\n@ A 192.0.2.1\nwww A 192.0.2.9\nseta-wildcard-probe-q7x2 A 192.0.2.9\n")
	checktest.Want(t, checktest.Results(t, Checks(), wild, target(t), "tls.cert."))
	tg := target(t, "www.web.test")
	checktest.Want(t, checktest.Results(t, Checks(), wild, tg, "tls.cert.hostname_mismatch"), "tls.cert.hostname_mismatch[www.web.test]=high")

	// https URLs add their hosts.
	tg = target(t, "web.test")
	tg.URLs = []string{"https://api.web.test/login", "http://www.web.test/"}
	checktest.Want(t, checktest.Results(t, Checks(), env(t, ca, addr), tg, "tls.cert.hostname_mismatch"))
}

func TestMetadataAndRegistration(t *testing.T) {
	for _, c := range Checks() {
		m := c.Meta()
		if m.Description == "" || m.Remediation == "" || len(m.References) == 0 {
			t.Errorf("%s: description, remediation and references are required", m.ID)
		}
		if _, ok := registry.Default.Lookup(m.ID); !ok {
			t.Errorf("%s is not registered", m.ID)
		}
	}
}
