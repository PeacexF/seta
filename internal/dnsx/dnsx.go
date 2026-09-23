// Package dnsx provides the DNS resolver used by checks: an interface, a
// miekg/dns-backed client, a per-run cache, and a zone-fixture fake for tests.
package dnsx

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Resolver performs a single DNS query.
//
// Lookup returns a response only for NOERROR and NXDOMAIN answers. Every other
// outcome (timeouts, SERVFAIL, REFUSED, malformed replies) is an error, so a
// check can always tell "the record does not exist" from "we could not find
// out" — the latter must never produce a finding.
type Resolver interface {
	Lookup(ctx context.Context, name string, qtype uint16) (*Response, error)
}

// DNSSECResolver is a Resolver that can also fetch DNSSEC data.
//
// LookupDNSSEC sets the DO and CD bits: answers include the RRSIG records
// covering them, and a zone whose signatures don't validate still answers,
// so its breakage can be examined rather than showing up as SERVFAIL.
type DNSSECResolver interface {
	Resolver
	LookupDNSSEC(ctx context.Context, name string, qtype uint16) (*Response, error)
}

// Response is the answer to one query. Responses may be cached and shared
// between checks, so callers must not modify them.
type Response struct {
	Name   string // canonical query name (lowercase, fully qualified)
	Type   uint16
	Rcode  int
	Answer []dns.RR
}

// NXDomain reports whether the queried name does not exist.
func (r *Response) NXDomain() bool { return r.Rcode == dns.RcodeNameError }

// Records returns the answer records of the queried type, skipping any CNAMEs
// the resolver followed to reach them.
func (r *Response) Records() []dns.RR {
	var out []dns.RR
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == r.Type {
			out = append(out, rr)
		}
	}
	return out
}

// RRSIGs returns the signatures in the answer that cover the queried type.
func (r *Response) RRSIGs() []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range r.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == r.Type {
			out = append(out, sig)
		}
	}
	return out
}

// MX returns the MX records in the answer.
func (r *Response) MX() []*dns.MX {
	var out []*dns.MX
	for _, rr := range r.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, mx)
		}
	}
	return out
}

// TXT returns each TXT record in the answer as a single string. Records
// published as multiple character-strings are concatenated without
// separators, as RFC 7208 §3.3 and RFC 7489 §6.4 require.
func (r *Response) TXT() []string {
	var out []string
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

// Addrs returns the addresses from A and AAAA records in the answer.
func (r *Response) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A); ok {
				out = append(out, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// Error describes a query that did not produce a usable answer.
type Error struct {
	Name  string
	Type  uint16
	Rcode int   // set when the server answered with an unusable rcode
	Err   error // set for transport failures
}

func (e *Error) Error() string {
	q := fmt.Sprintf("lookup %s %s", dns.TypeToString[e.Type], strings.TrimSuffix(e.Name, "."))
	if e.Err != nil {
		return q + ": " + e.Err.Error()
	}
	return q + ": " + rcodeText(e.Rcode)
}

func (e *Error) Unwrap() error { return e.Err }

func rcodeText(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return "server responded " + s
	}
	return fmt.Sprintf("server responded rcode %d", rcode)
}

// CanonicalName lowercases name and makes it fully qualified.
func CanonicalName(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}
