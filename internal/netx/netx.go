// Package netx provides the dialer, TLS config and HTTP client checks use.
// Hostnames are resolved through Seta's resolver rather than the OS, so
// connections see the same DNS answers as the checks that led to them.
package netx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/dnsx"
)

const DefaultTimeout = 10 * time.Second

type Options struct {
	// DialAddr connects to an already-resolved IP:port. Tests use it to
	// redirect connections to local servers.
	DialAddr  func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs   *x509.CertPool
	UserAgent string
	Timeout   time.Duration
}

type Net struct {
	resolver dnsx.Resolver
	opts     Options
	http     func() *http.Client
}

func New(r dnsx.Resolver, opts Options) *Net {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.DialAddr == nil {
		d := &net.Dialer{Timeout: opts.Timeout}
		opts.DialAddr = d.DialContext
	}
	n := &Net{resolver: r, opts: opts}
	n.http = sync.OnceValue(n.newHTTPClient)
	return n
}

// ErrNoAddress means the host name has no A or AAAA records.
var ErrNoAddress = errors.New("host has no A or AAAA records")

// Dial connects to host:port, trying IPv4 addresses before IPv6.
func (n *Net) Dial(ctx context.Context, network, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	addrs, err := n.LookupAddrs(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := n.opts.DialAddr(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// LookupAddrs returns host's IPv4 then IPv6 addresses. A failure of one
// family is ignored when the other has answers.
func (n *Net) LookupAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	var addrs []netip.Addr
	var firstErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := n.resolver.Lookup(ctx, host, qtype)
		if err != nil {
			firstErr = cmpErr(firstErr, err)
			continue
		}
		addrs = append(addrs, resp.Addrs()...)
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("%s: %w", host, ErrNoAddress)
}

func cmpErr(prev, next error) error {
	if prev != nil {
		return prev
	}
	return next
}

func (n *Net) TLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, RootCAs: n.opts.RootCAs, MinVersion: tls.VersionTLS12}
}

func (n *Net) RootCAs() *x509.CertPool { return n.opts.RootCAs }

func (n *Net) Timeout() time.Duration { return n.opts.Timeout }

func (n *Net) UserAgent() string { return n.opts.UserAgent }

// HTTPClient never follows redirects: callers inspect them, and some
// protocols (MTA-STS) forbid following them.
func (n *Net) HTTPClient() *http.Client { return n.http() }

func (n *Net) newHTTPClient() *http.Client {
	tr := &http.Transport{
		DialContext:         n.Dial,
		TLSClientConfig:     &tls.Config{RootCAs: n.opts.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: n.opts.Timeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Timeout:       n.opts.Timeout,
		Transport:     &userAgent{next: tr, ua: n.opts.UserAgent},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type userAgent struct {
	next http.RoundTripper
	ua   string
}

func (u *userAgent) RoundTrip(r *http.Request) (*http.Response, error) {
	if u.ua != "" && r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", u.ua)
	}
	return u.next.RoundTrip(r)
}
