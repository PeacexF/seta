package dnsx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startServer runs an in-process DNS server on 127.0.0.1 over UDP and TCP on
// the same port, and returns its address.
func startServer(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	var (
		pc  net.PacketConn
		ln  net.Listener
		err error
	)
	for range 10 {
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
	}
	if err != nil {
		t.Fatalf("could not bind UDP and TCP on one port: %v", err)
	}
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go srv.ActivateAndServe() //nolint:errcheck
		<-started
		t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	}
	return pc.LocalAddr().String()
}

func rcodeHandler(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		w.WriteMsg(m) //nolint:errcheck
	}
}

func mxHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if r.Question[0].Name != "example.test." {
		m.SetRcode(r, dns.RcodeNameError)
	} else {
		rr, _ := dns.NewRR("example.test. 300 IN MX 10 mx.example.test.")
		m.Answer = append(m.Answer, rr)
	}
	w.WriteMsg(m) //nolint:errcheck
}

func newTestClient(t *testing.T, servers ...string) *Client {
	t.Helper()
	c, err := NewClient(servers, Options{Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientAnswers(t *testing.T) {
	c := newTestClient(t, startServer(t, mxHandler))
	ctx := context.Background()

	resp, err := c.Lookup(ctx, "Example.Test", dns.TypeMX)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Name != "example.test." || len(resp.MX()) != 1 || resp.MX()[0].Mx != "mx.example.test." {
		t.Fatalf("unexpected response %+v", resp)
	}

	resp, err = c.Lookup(ctx, "missing.test", dns.TypeMX)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.NXDomain() {
		t.Fatalf("want NXDOMAIN, got rcode %d", resp.Rcode)
	}
}

func TestClientFallsBackToNextServer(t *testing.T) {
	bad := startServer(t, rcodeHandler(dns.RcodeServerFailure))
	good := startServer(t, mxHandler)
	resp, err := newTestClient(t, bad, good).Lookup(context.Background(), "example.test", dns.TypeMX)
	if err != nil || len(resp.MX()) != 1 {
		t.Fatalf("want answer from second server, got %v, %v", resp, err)
	}
}

func TestClientReportsUnusableRcode(t *testing.T) {
	c := newTestClient(t, startServer(t, rcodeHandler(dns.RcodeRefused)))
	_, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
	var dnsErr *Error
	if !errors.As(err, &dnsErr) || dnsErr.Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED error, got %v", err)
	}
	if got, want := err.Error(), "lookup MX example.test: server responded REFUSED"; got != want {
		t.Fatalf("error text = %q, want %q", got, want)
	}
}

func TestClientRetriesTruncatedOverTCP(t *testing.T) {
	addr := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if w.LocalAddr().Network() == "udp" {
			m.Truncated = true
		} else {
			for range 3 {
				rr, _ := dns.NewRR(`example.test. 300 IN TXT "big"`)
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	resp, err := newTestClient(t, addr).Lookup(context.Background(), "example.test", dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.TXT()) != 3 {
		t.Fatalf("want full TCP answer with 3 records, got %d", len(resp.TXT()))
	}
}

func TestClientTimeoutIsAnError(t *testing.T) {
	addr := startServer(t, func(dns.ResponseWriter, *dns.Msg) {}) // never answers
	c, err := NewClient([]string{addr}, Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Lookup(context.Background(), "example.test", dns.TypeMX)
	var dnsErr *Error
	if !errors.As(err, &dnsErr) || dnsErr.Err == nil {
		t.Fatalf("want transport error, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not honored: took %v", time.Since(start))
	}
}

func TestParseServer(t *testing.T) {
	tests := []struct {
		spec string
		want Server
	}{
		{"1.1.1.1", Server{Transport: Plain, Addr: "1.1.1.1:53"}},
		{"1.1.1.1:5353", Server{Transport: Plain, Addr: "1.1.1.1:5353"}},
		{"2620:fe::fe", Server{Transport: Plain, Addr: "[2620:fe::fe]:53"}},
		{"[2620:fe::fe]:53", Server{Transport: Plain, Addr: "[2620:fe::fe]:53"}},
		{"tls://1.1.1.1", Server{Transport: TLS, Addr: "1.1.1.1:853", ServerName: "1.1.1.1"}},
		{"tls://dns.quad9.net:8853", Server{Transport: TLS, Addr: "dns.quad9.net:8853", ServerName: "dns.quad9.net"}},
		{"tls://[2620:fe::fe]", Server{Transport: TLS, Addr: "[2620:fe::fe]:853", ServerName: "2620:fe::fe"}},
		{"https://1.1.1.1/dns-query", Server{Transport: HTTPS, URL: "https://1.1.1.1/dns-query"}},
		{"https://dns.example:8443", Server{Transport: HTTPS, URL: "https://dns.example:8443/dns-query"}},
	}
	for _, tt := range tests {
		got, err := ParseServer(tt.spec)
		if err != nil || got != tt.want {
			t.Errorf("ParseServer(%q) = %+v, %v; want %+v", tt.spec, got, err, tt.want)
		}
	}
	for _, spec := range []string{"", "dns.google", "1.1.1.1:dns", "udp://1.1.1.1", "http://1.1.1.1/dns-query",
		"https://", "https://user@1.1.1.1/dns-query", "tls://", "tls://host/path"} {
		if _, err := ParseServer(spec); err == nil {
			t.Errorf("ParseServer(%q) accepted an invalid spec", spec)
		}
	}
	for name, specs := range Presets {
		c, err := NewClient(specs, Options{})
		if err != nil || !c.Encrypted() {
			t.Errorf("preset %q: %v (encrypted: %v)", name, err, err == nil && c.Encrypted())
		}
	}
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Error("NewClient with no servers should fail")
	}
	if c, _ := NewClient([]string{"tls://1.1.1.1", "9.9.9.9"}, Options{}); c.Encrypted() {
		t.Error("a client with a plain server is not encrypted")
	}
}

// testTLS returns a server certificate valid for 127.0.0.1 and a pool that
// trusts it, borrowed from httptest.
func testTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.TLS.Certificates[0], pool
}

func TestClientDNSOverTLS(t *testing.T) {
	cert, pool := testTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(mxHandler)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe() //nolint:errcheck
	<-started
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck

	c, err := NewClient([]string{"tls://" + ln.Addr().String()}, Options{Timeout: time.Second, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
	if err != nil || len(resp.MX()) != 1 {
		t.Fatalf("got %v, %v", resp, err)
	}

	// Without trusting the test CA, the handshake must fail.
	untrusting, _ := NewClient([]string{"tls://" + ln.Addr().String()}, Options{Timeout: time.Second})
	if _, err := untrusting.Lookup(context.Background(), "example.test", dns.TypeMX); err == nil {
		t.Fatal("DoT accepted an untrusted certificate")
	}
}

// dohServer serves RFC 8484 POST requests with h, and lets tests override
// the HTTP response through mutate.
func dohServer(t *testing.T, h func(q *dns.Msg) *dns.Msg, mutate func(w http.ResponseWriter) bool) (string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mutate != nil && mutate(w) {
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil || q.Id != 0 {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		wire, _ := h(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.URL + "/dns-query", pool
}

func mxAnswer(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("example.test. 300 IN MX 10 mx.example.test.")
	m.Answer = append(m.Answer, rr)
	return m
}

func TestClientDNSOverHTTPS(t *testing.T) {
	url, pool := dohServer(t, mxAnswer, nil)
	c, err := NewClient([]string{url}, Options{Timeout: time.Second, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
	if err != nil || len(resp.MX()) != 1 {
		t.Fatalf("got %v, %v", resp, err)
	}
}

func TestClientDNSOverHTTPSRejectsBadResponses(t *testing.T) {
	tests := map[string]struct {
		handler func(q *dns.Msg) *dns.Msg
		mutate  func(w http.ResponseWriter) bool
		want    string
	}{
		"HTTP error": {mxAnswer, func(w http.ResponseWriter) bool {
			http.Error(w, "nope", http.StatusServiceUnavailable)
			return true
		}, "HTTP 503"},
		"wrong content type": {mxAnswer, func(w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>")) //nolint:errcheck
			return true
		}, "content type"},
		"mismatched question": {func(q *dns.Msg) *dns.Msg {
			m := new(dns.Msg)
			m.SetQuestion("other.test.", dns.TypeMX)
			m.Response = true
			return m
		}, nil, "does not match"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			url, pool := dohServer(t, tt.handler, tt.mutate)
			c, _ := NewClient([]string{url}, Options{Timeout: time.Second, RootCAs: pool})
			_, err := c.Lookup(context.Background(), "example.test", dns.TypeMX)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}
