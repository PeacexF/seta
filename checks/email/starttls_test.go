package email

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/netx"
)

type smtpServer struct {
	noSTARTTLS   bool
	rejectTLS    bool
	cert         tls.Certificate
	greetingWait time.Duration
}

// start serves a minimal ESMTP dialogue: greeting, EHLO, STARTTLS, QUIT.
func (s smtpServer) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go s.serve(conn)
		}
	}()
	return ln.Addr().String()
}

func (s smtpServer) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	time.Sleep(s.greetingWait)
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	say := func(lines ...string) {
		for _, l := range lines {
			rw.WriteString(l + "\r\n") //nolint:errcheck
		}
		rw.Flush() //nolint:errcheck
	}
	say("220 mx.test ESMTP")
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(strings.Fields(line)[0]); cmd {
		case "EHLO":
			if s.noSTARTTLS {
				say("250-mx.test", "250 PIPELINING")
			} else {
				say("250-mx.test", "250-PIPELINING", "250 STARTTLS")
			}
		case "STARTTLS":
			if s.rejectTLS {
				say("454 4.7.0 TLS not available")
				continue
			}
			say("220 2.0.0 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if tc.Handshake() != nil {
				return
			}
			rw = bufio.NewReadWriter(bufio.NewReader(tc), bufio.NewWriter(tc))
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func TestSTARTTLSChecks(t *testing.T) {
	ca := checktest.NewCA(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	valid := func(days int, names ...string) tls.Certificate {
		return ca.Issue(now.Add(-30*24*time.Hour), now.Add(time.Duration(days)*24*time.Hour), names...)
	}
	r := checktest.Zone(t, "tls.test", `
$ORIGIN tls.test.
@     MX 10 mx1
@     MX 20 mx2
mx1   A  192.0.2.25
mx2   A  192.0.2.26
`)
	tests := []struct {
		name   string
		server smtpServer
		want   []string
	}{
		{"healthy", smtpServer{cert: valid(90, "mx1.tls.test", "mx2.tls.test")}, nil},
		{"no starttls", smtpServer{noSTARTTLS: true}, []string{
			"email.starttls.unsupported[mx1.tls.test]=high", "email.starttls.unsupported[mx2.tls.test]=high"}},
		{"starttls rejected", smtpServer{rejectTLS: true}, []string{
			"email.starttls.unsupported[mx1.tls.test]=high", "email.starttls.unsupported[mx2.tls.test]=high"}},
		{"wrong name", smtpServer{cert: valid(90, "mx1.tls.test")}, []string{
			"email.starttls.cert_invalid[mx2.tls.test]=medium"}},
		{"expired", smtpServer{cert: valid(-1, "mx1.tls.test", "mx2.tls.test")}, []string{
			"email.starttls.cert_invalid[mx1.tls.test]=medium", "email.starttls.cert_invalid[mx2.tls.test]=medium"}},
		{"expiring soon", smtpServer{cert: valid(15, "mx1.tls.test", "mx2.tls.test")}, []string{
			"email.starttls.cert_expiring[mx1.tls.test]=medium", "email.starttls.cert_expiring[mx2.tls.test]=medium"}},
		{"expiring very soon", smtpServer{cert: valid(5, "mx1.tls.test", "mx2.tls.test")}, []string{
			"email.starttls.cert_expiring[mx1.tls.test]=high", "email.starttls.cert_expiring[mx2.tls.test]=high"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := checktest.Env{
				Resolver: r,
				Net:      netx.Options{DialAddr: checktest.RedirectTo(tt.server.start(t)), RootCAs: ca.Pool()},
				Now:      func() time.Time { return now },
			}
			assertResults(t, results(t, env, domain(t, "tls.test"), "email.starttls."), tt.want...)
		})
	}

	t.Run("port 25 blocked", func(t *testing.T) {
		env := checktest.Env{
			Resolver: r,
			Net: netx.Options{DialAddr: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("i/o timeout")
			}},
		}
		got := results(t, env, domain(t, "tls.test"), "email.starttls.")
		if len(got) != 3 {
			t.Fatalf("want 3 check errors, got %s", fmtList(got))
		}
		assertError(t, got, "email.starttls.unsupported", "could not reach any of 2 MX hosts on port 25")
	})
}

func TestMXChecks(t *testing.T) {
	r := checktest.Zone(t, "mx.test", `
$ORIGIN mx.test.
@           MX 10 good
@           MX 20 gone
@           MX 30 192.0.2.99.
good        A  192.0.2.25
nullmx      MX 0 .
nomx        A  192.0.2.1
; Forward-confirmed: PTR points back at a name resolving to the address.
25.2.0.192.in-addr.arpa. PTR good.mx.test.
fc          MX 10 mail.fc
mail.fc     A  192.0.2.30
mail.fc     A  192.0.2.31
30.2.0.192.in-addr.arpa. PTR mail.fc.mx.test.
31.2.0.192.in-addr.arpa. PTR elsewhere.example.
`)
	env := checktest.Env{Resolver: r}
	assertResults(t, results(t, env, domain(t, "mx.test"), "email.mx."),
		"email.mx.unresolvable[gone.mx.test]=high",
		"email.mx.unresolvable[192.0.2.99]=high",
	)
	assertResults(t, results(t, env, domain(t, "fc.mx.test"), "email.mx."),
		"email.mx.fcrdns[mail.fc.mx.test]=low")
	assertResults(t, results(t, env, domain(t, "nullmx.mx.test"), "email.mx."))
	assertResults(t, results(t, env, domain(t, "nomx.mx.test"), "email.mx."), "email.mx.missing=high")

	f, _ := checktest.RunWith(t, Check("email.mx.fcrdns"), env, domain(t, "fc.mx.test"))
	if got := f[0].Evidence["addresses"]; got != "192.0.2.31 (PTR elsewhere.example does not resolve back)" {
		t.Errorf("fcrdns evidence = %q", got)
	}
}
