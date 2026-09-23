package dnsx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// FallbackServers are used when the system resolver configuration cannot be
// read (for example on Windows, which has no /etc/resolv.conf).
var FallbackServers = []string{"1.1.1.1:53", "9.9.9.9:53"}

// DefaultTimeout bounds a single query to a single server.
const DefaultTimeout = 5 * time.Second

// Options configures a Client.
type Options struct {
	// Timeout bounds one query to one server. Zero means DefaultTimeout.
	Timeout time.Duration
	// UserAgent is sent to DNS-over-HTTPS servers.
	UserAgent string
	// RootCAs verifies DNS-over-TLS and DNS-over-HTTPS servers. Nil means the
	// system roots; tests set it to trust their own certificates.
	RootCAs *x509.CertPool
}

// Client is a recursive-resolver client backed by miekg/dns. It speaks plain
// DNS (UDP with EDNS0, retried over TCP when truncated), DNS over TLS, and
// DNS over HTTPS, and tries each configured server in turn until one gives a
// usable answer.
type Client struct {
	upstreams []upstream
}

type upstream struct {
	Server
	exchange func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

// NewClient returns a client for the given server specs (see ParseServer).
func NewClient(specs []string, opts Options) (*Client, error) {
	if len(specs) == 0 {
		return nil, errors.New("no DNS servers configured")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	c := &Client{}
	for _, spec := range specs {
		s, err := ParseServer(spec)
		if err != nil {
			return nil, err
		}
		c.upstreams = append(c.upstreams, upstream{Server: s, exchange: exchanger(s, opts)})
	}
	return c, nil
}

func exchanger(s Server, opts Options) func(context.Context, *dns.Msg) (*dns.Msg, error) {
	switch s.Transport {
	case TLS:
		dot := &dns.Client{Net: "tcp-tls", Timeout: opts.Timeout, TLSConfig: &tls.Config{
			ServerName: s.ServerName,
			RootCAs:    opts.RootCAs,
			MinVersion: tls.VersionTLS12,
		}}
		return func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
			resp, _, err := dot.ExchangeContext(ctx, msg, s.Addr)
			return resp, err
		}

	case HTTPS:
		hc := &http.Client{
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		return func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
			return dohExchange(ctx, hc, s.URL, opts.UserAgent, msg)
		}
	}

	udp := &dns.Client{Net: "udp", Timeout: opts.Timeout, UDPSize: 1232}
	tcp := &dns.Client{Net: "tcp", Timeout: opts.Timeout}
	return func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
		resp, _, err := udp.ExchangeContext(ctx, msg, s.Addr)
		if err == nil && resp.Truncated {
			resp, _, err = tcp.ExchangeContext(ctx, msg, s.Addr)
		}
		return resp, err
	}
}

// dohExchange sends msg as an RFC 8484 POST request.
func dohExchange(ctx context.Context, hc *http.Client, url, userAgent string, msg *dns.Msg) (*dns.Msg, error) {
	q := msg.Copy()
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS-over-HTTPS server responded HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("DNS-over-HTTPS server responded with content type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dns.MaxMsgSize {
		return nil, errors.New("DNS-over-HTTPS response exceeds the maximum DNS message size")
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("malformed DNS-over-HTTPS response: %w", err)
	}
	if len(out.Question) != 1 || !strings.EqualFold(out.Question[0].Name, msg.Question[0].Name) ||
		out.Question[0].Qtype != msg.Question[0].Qtype {
		return nil, errors.New("DNS-over-HTTPS response does not match the query")
	}
	return out, nil
}

// SystemServers reads the nameservers from /etc/resolv.conf.
func SystemServers() ([]string, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read system resolver config: %w", err)
	}
	var servers []string
	for _, s := range conf.Servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		servers = append(servers, netip.AddrPortFrom(a, parsePort(conf.Port)).String())
	}
	if len(servers) == 0 {
		return nil, errors.New("read system resolver config: no usable nameservers in /etc/resolv.conf")
	}
	return servers, nil
}

func parsePort(s string) uint16 {
	var p uint16
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil || p == 0 {
		return 53
	}
	return p
}

// Servers returns the servers the client queries, in order.
func (c *Client) Servers() []Server {
	out := make([]Server, len(c.upstreams))
	for i, u := range c.upstreams {
		out[i] = u.Server
	}
	return out
}

// Encrypted reports whether every server is reached over TLS or HTTPS.
func (c *Client) Encrypted() bool {
	for _, u := range c.upstreams {
		if !u.Transport.Encrypted() {
			return false
		}
	}
	return true
}

func (c *Client) Lookup(ctx context.Context, name string, qtype uint16) (*Response, error) {
	name = CanonicalName(name)
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, false)

	var lastErr error
	for _, u := range c.upstreams {
		resp, err := u.exchange(ctx, msg)
		if err != nil {
			lastErr = &Error{Name: name, Type: qtype, Err: err}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
			return &Response{Name: name, Type: qtype, Rcode: resp.Rcode, Answer: resp.Answer}, nil
		}
		lastErr = &Error{Name: name, Type: qtype, Rcode: resp.Rcode}
	}
	return nil, lastErr
}
