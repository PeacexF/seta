// Package web connects to a target's web hosts for the tls, http and dns
// checks, once per run: the TLS handshake and page fetches are memoized.
package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/netx"
)

// TLSHosts returns the hosts TLS checks look at: the target's web hosts and
// the hosts of its https URLs.
func TLSHosts(t core.Target) []core.Host {
	hosts := t.WebHosts()
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.String()] = true
	}
	for _, raw := range t.URLs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			continue
		}
		h, err := core.ParseHost(u.Host)
		if err == nil && !seen[h.String()] {
			seen[h.String()] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// Page is a URL the http checks fetch.
type Page struct {
	URL  string
	Host core.Host
}

// Pages returns the target's URLs, or "/" on each web host.
func Pages(t core.Target) []Page {
	if len(t.URLs) == 0 {
		var out []Page
		for _, h := range t.WebHosts() {
			out = append(out, Page{URL: "https://" + h.String() + "/", Host: h})
		}
		return out
	}
	var out []Page
	for _, raw := range t.URLs {
		u, _ := url.Parse(raw) // validated while loading
		h, _ := core.ParseHost(u.Host)
		if u.Scheme == "http" && u.Port() == "" {
			h.Port = 80
		}
		out = append(out, Page{URL: raw, Host: h})
	}
	return out
}

// ErrAbsent means an implicit host doesn't exist or doesn't serve the
// port. Checks skip such hosts: many domains have no website.
var ErrAbsent = errors.New("host serves nothing")

// Dial connects to host:port. For implicit hosts, a name without addresses
// or a refused connection is ErrAbsent; a timeout is always an error, since
// it can't tell "no server" from "server unreachable".
func Dial(ctx context.Context, env core.Env, h core.Host, port int) (net.Conn, error) {
	addr := net.JoinHostPort(h.Name, strconv.Itoa(port))
	if !h.Explicit {
		if wild, err := wildcardArtifact(ctx, env, h.Name); err != nil {
			return nil, err
		} else if wild {
			return nil, fmt.Errorf("%s only exists through a wildcard record: %w", h.Name, ErrAbsent)
		}
	}
	conn, err := env.Net.Dial(ctx, "tcp", addr)
	switch {
	case err == nil:
		return conn, nil
	case !h.Explicit && (errors.Is(err, netx.ErrNoAddress) || errors.Is(err, syscall.ECONNREFUSED)):
		return nil, fmt.Errorf("%s: %w", addr, ErrAbsent)
	case errors.Is(err, netx.ErrNoAddress):
		return nil, fmt.Errorf("%s has no A or AAAA records", h.Name)
	case ctx.Err() != nil:
		return nil, err
	}
	if _, dnsErr := errors.AsType[*dnsx.Error](err); dnsErr {
		return nil, err
	}
	return nil, &ConnectError{Addr: addr, Err: err}
}

// wildcardProbe is a label no one uses, so an answer for it can only come
// from a wildcard record.
const wildcardProbe = "seta-wildcard-probe-q7x2"

// wildcardArtifact reports whether an implicit www host exists only because
// the domain has a wildcard record: then it is no website anyone set up.
func wildcardArtifact(ctx context.Context, env core.Env, name string) (bool, error) {
	parent, ok := strings.CutPrefix(name, "www.")
	if !ok {
		return false, nil
	}
	probe, err := env.Net.LookupAddrs(ctx, wildcardProbe+"."+parent)
	if errors.Is(err, netx.ErrNoAddress) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	addrs, err := env.Net.LookupAddrs(ctx, name)
	if err != nil {
		return false, nil // Dial reports it
	}
	slices.SortFunc(probe, netip.Addr.Compare)
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Equal(probe, addrs), nil
}

// ConnectError is a host that exists but couldn't be connected to.
type ConnectError struct {
	Addr string
	Err  error
}

func (e *ConnectError) Error() string { return fmt.Sprintf("connect to %s: %v", e.Addr, e.Err) }
func (e *ConnectError) Unwrap() error { return e.Err }

// Handshake is what a TLS client sees when connecting to a host.
type Handshake struct {
	Host    core.Host
	Version uint16
	Cipher  uint16
	// Chain is the certificates as the server sent them, leaf first.
	Chain []*x509.Certificate
}

// TLS handshakes with h the way a browser would, except that it accepts
// TLS 1.0 and doesn't verify the certificate, so that the checks can report
// what is wrong instead of failing.
func TLS(ctx context.Context, env core.Env, h core.Host) (*Handshake, error) {
	return core.Memoize(ctx, env.Memo, "web.tls:"+h.String(), func(ctx context.Context) (*Handshake, error) {
		cfg := &tls.Config{ServerName: h.Name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
		state, err := Connect(ctx, env, h, cfg)
		if err != nil {
			return nil, err
		}
		return &Handshake{Host: h, Version: state.Version, Cipher: state.CipherSuite, Chain: state.PeerCertificates}, nil
	})
}

// Connect completes a TLS handshake with h using cfg. A handshake the
// server rejects is a *HandshakeError.
func Connect(ctx context.Context, env core.Env, h core.Host, cfg *tls.Config) (tls.ConnectionState, error) {
	conn, err := Dial(ctx, env, h, h.Port)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return tls.ConnectionState{}, ctx.Err()
		}
		return tls.ConnectionState{}, &HandshakeError{Host: h, Err: err}
	}
	return tc.ConnectionState(), nil
}

type HandshakeError struct {
	Host core.Host
	Err  error
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("TLS handshake with %s failed: %v", e.Host, e.Err)
}
func (e *HandshakeError) Unwrap() error { return e.Err }

// Verify checks the chain against the trusted roots, without the host name.
func Verify(env core.Env, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: env.Net.RootCAs(), Intermediates: inter, CurrentTime: env.Now()})
	return err
}

// Each runs fn for every item (a host, a page) concurrently. Absent
// implicit hosts are skipped; any other error fails the whole check, so an
// unreachable host never looks like a fixed one.
func Each[I, T any](ctx context.Context, items []I, fn func(I) (T, error)) ([]T, error) {
	results := make([]T, len(items))
	errs := make([]error, len(items))
	ok := make([]bool, len(items))
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Go(func() {
			results[i], errs[i] = fn(it)
			ok[i] = errs[i] == nil
		})
	}
	wg.Wait()
	var out []T
	for i := range items {
		switch {
		case ok[i]:
			out = append(out, results[i])
		case errors.Is(errs[i], ErrAbsent):
		default:
			return nil, errs[i]
		}
	}
	return out, nil
}

// Response is a fetched page.
type Response struct {
	// URL is the final URL after redirects; Redirects lists the URLs before it.
	URL       string
	Redirects []string
	Status    int
	Header    http.Header
	Body      []byte
	TLS       bool
}

const (
	maxRedirects = 10
	maxBody      = 256 << 10
)

// Follow decides whether Get follows a redirect to next.
type Follow func(next *url.URL) bool

// Get fetches rawURL, following up to 10 redirects that follow allows (nil
// follows none); a redirect it doesn't follow is the response. name
// identifies follow in the memo key. The certificate isn't verified: the
// tls checks report certificate problems, and the http checks still want to
// see the headers.
func Get(ctx context.Context, env core.Env, h core.Host, rawURL, name string, follow Follow) (*Response, error) {
	key := fmt.Sprintf("web.get:%s:%s", rawURL, name)
	return core.Memoize(ctx, env.Memo, key, func(ctx context.Context) (*Response, error) {
		client := httpClient(env)
		resp := &Response{URL: rawURL}
		for {
			r, err := get(ctx, env, client, h, resp.URL)
			if err != nil {
				return nil, err
			}
			resp.Status, resp.Header, resp.Body, resp.TLS = r.status, r.header, r.body, r.tls
			next, ok := resp.Location()
			if !ok || follow == nil || !follow(next) {
				return resp, nil
			}
			if len(resp.Redirects) == maxRedirects {
				return nil, fmt.Errorf("%s: more than %d redirects", rawURL, maxRedirects)
			}
			resp.Redirects = append(resp.Redirects, resp.URL)
			resp.URL = next.String()
			// Hosts reached by redirect were never declared, so their
			// failures are errors rather than absent defaults.
			h = core.Host{Name: next.Hostname(), Explicit: true}
		}
	})
}

// Location returns where a redirect response points, resolved against URL.
func (r *Response) Location() (*url.URL, bool) {
	loc := r.Header.Get("Location")
	if r.Status < 300 || r.Status > 399 || loc == "" {
		return nil, false
	}
	base, err := url.Parse(r.URL)
	if err != nil {
		return nil, false
	}
	next, err := base.Parse(loc)
	if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
		return nil, false
	}
	return next, true
}

type rawResponse struct {
	status int
	header http.Header
	body   []byte
	tls    bool
}

func get(ctx context.Context, env core.Env, client *http.Client, h core.Host, rawURL string) (*rawResponse, error) {
	req, err := http.NewRequestWithContext(context.WithValue(ctx, hostKey{}, h), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	req.Header.Set("User-Agent", env.Net.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		if errors.Is(err, ErrAbsent) {
			return nil, err
		}
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &rawResponse{status: resp.StatusCode, header: resp.Header, body: body, tls: resp.TLS != nil}, nil
}

// httpClient dials through Dial, so implicit hosts that serve nothing are
// ErrAbsent, and never follows redirects itself.
func httpClient(env core.Env) *http.Client {
	c, _ := core.Memoize(context.Background(), env.Memo, "web.client", func(context.Context) (*http.Client, error) {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(port)
				return Dial(ctx, env, hostFromContext(ctx, host), p)
			},
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
			TLSHandshakeTimeout: env.Net.Timeout(),
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 2,
		}
		return &http.Client{Transport: tr, Timeout: env.Net.Timeout(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
	})
	return c
}

type hostKey struct{}

// hostFromContext recovers whether the host being dialed is explicit; the
// transport only passes the address.
func hostFromContext(ctx context.Context, name string) core.Host {
	if h, ok := ctx.Value(hostKey{}).(core.Host); ok && h.Name == name {
		return h
	}
	return core.Host{Name: name, Explicit: true}
}
