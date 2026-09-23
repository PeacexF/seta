package dnsx

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Transport is how queries reach an upstream resolver.
type Transport int

const (
	// Plain is classic DNS over UDP, retried over TCP when truncated.
	Plain Transport = iota
	// TLS is DNS over TLS (RFC 7858).
	TLS
	// HTTPS is DNS over HTTPS (RFC 8484).
	HTTPS
)

// Encrypted reports whether queries are protected from on-path tampering.
func (t Transport) Encrypted() bool { return t == TLS || t == HTTPS }

// Server is one upstream recursive resolver.
type Server struct {
	Transport Transport
	// Addr is host:port for Plain and TLS servers.
	Addr string
	// ServerName is the name the TLS certificate is verified against (TLS only).
	ServerName string
	// URL is the endpoint for HTTPS servers.
	URL string
}

// Presets are named server lists accepted wherever server specs are.
// They use IP literals so that reaching them doesn't depend on the very
// resolver they are meant to replace.
var Presets = map[string][]string{
	"doh": {"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"},
	"dot": {"tls://1.1.1.1", "tls://9.9.9.9"},
}

// ParseServer parses a server spec:
//
//	1.1.1.1, 1.1.1.1:53, [2620:fe::fe]:53   plain DNS (IP literals only)
//	tls://1.1.1.1, tls://dns.quad9.net:853  DNS over TLS (default port 853)
//	https://1.1.1.1/dns-query               DNS over HTTPS
func ParseServer(spec string) (Server, error) {
	switch {
	case strings.HasPrefix(spec, "https://"):
		u, err := url.Parse(spec)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
			return Server{}, fmt.Errorf("invalid DNS-over-HTTPS server %q: want a URL like https://1.1.1.1/dns-query", spec)
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		return Server{Transport: HTTPS, URL: u.String()}, nil

	case strings.HasPrefix(spec, "tls://"):
		hostport := strings.TrimPrefix(spec, "tls://")
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			host, port = strings.Trim(hostport, "[]"), "853"
		}
		if host == "" || strings.ContainsAny(host, "/?#@ ") {
			return Server{}, fmt.Errorf("invalid DNS-over-TLS server %q: want tls://host[:port]", spec)
		}
		return Server{Transport: TLS, Addr: net.JoinHostPort(host, port), ServerName: host}, nil

	case strings.Contains(spec, "://"):
		return Server{}, fmt.Errorf("invalid DNS server %q: supported schemes are tls:// and https://", spec)
	}

	if ap, err := netip.ParseAddrPort(spec); err == nil {
		return Server{Transport: Plain, Addr: ap.String()}, nil
	}
	if a, err := netip.ParseAddr(spec); err == nil {
		return Server{Transport: Plain, Addr: netip.AddrPortFrom(a, 53).String()}, nil
	}
	return Server{}, fmt.Errorf("invalid DNS server %q: want an IP address with optional port, tls://host, or https://host/path", spec)
}

func (s Server) String() string {
	switch s.Transport {
	case HTTPS:
		return s.URL
	case TLS:
		return "tls://" + s.Addr
	}
	return s.Addr
}
