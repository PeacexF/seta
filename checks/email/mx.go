package email

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/checks/email/internal/mtasts"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/netx"
)

var _ = define(core.Meta{
	ID:    "email.mx.missing",
	Title: "No MX records",
	Description: "The domain publishes no MX records. Senders then fall back to the domain's " +
		"A/AAAA records (the \"implicit MX\" of RFC 5321), which is rarely intended: mail is either " +
		"delivered to a web server or bounces after retrying for days. Domains that do not receive " +
		"mail should say so explicitly with a null MX record (RFC 7505).",
	Remediation: "Publish MX records pointing at your mail servers. If the domain does not receive mail, " +
		"publish a null MX record instead (\"@ IN MX 0 .\") so senders fail fast.",
	Mode:       core.Passive,
	Severity:   core.SeverityHigh,
	References: []string{rfc(5321, "5.1"), rfc(7505, "")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || mx.Null || len(mx.Hosts) > 0 {
		return nil, err
	}
	return []core.Finding{{Evidence: map[string]string{
		"mx_records":  "none",
		"implicit_mx": implicitMX(ctx, env, t.Name),
	}}}, nil
})

// implicitMX describes where senders deliver without MX records. Lookup
// failures only degrade the evidence.
func implicitMX(ctx context.Context, env core.Env, name string) string {
	addrs, err := env.Net.LookupAddrs(ctx, name)
	switch {
	case errors.Is(err, netx.ErrNoAddress):
		return "none: mail to this domain is undeliverable"
	case err != nil:
		return "unknown (" + err.Error() + ")"
	}
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

var _ = define(core.Meta{
	ID:    "email.mx.unresolvable",
	Title: "MX host does not resolve",
	Description: "An MX record points at a host name with no A or AAAA records, or at an IP address " +
		"instead of a host name. Senders cannot deliver to it and fall through to the next MX, or " +
		"queue and eventually bounce if it is the only one.",
	Remediation: "Point the MX record at a host name that has A/AAAA records, or remove the stale MX record.",
	Mode:        core.Passive,
	Severity:    core.SeverityHigh,
	References:  []string{rfc(5321, "5.1"), rfc(2181, "10.3")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	addrs, err := mxAddrs(ctx, env, mx.Hosts)
	if err != nil {
		return nil, err
	}
	var out []core.Finding
	for i, host := range mx.Hosts {
		switch _, ipErr := netip.ParseAddr(host); {
		case ipErr == nil:
			out = append(out, core.Finding{
				Subject:  host,
				Title:    "MX record points at an IP address",
				Evidence: map[string]string{"mx": host},
			})
		case len(addrs[i]) == 0:
			out = append(out, core.Finding{Subject: host, Evidence: map[string]string{"mx": host, "addresses": "none"}})
		}
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.mx.unexpected",
	Title: "MX records differ from the expected set",
	Description: "The domain's MX hosts don't match the expected_mx list in the config: a host is " +
		"published that isn't expected, or an expected host is missing. An unexpected MX host can " +
		"receive (and read) the domain's mail, and is a common sign of a hijacked DNS zone or a " +
		"forgotten migration. Only runs when expected_mx is configured.",
	Remediation: "If the change was intended, update expected_mx in the config. Otherwise restore the MX " +
		"records and find out who changed the zone.",
	Mode:       core.Passive,
	Severity:   core.SeverityMedium,
	References: []string{rfc(5321, "5.1")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	expected := t.Email.ExpectedMX
	if len(expected) == 0 {
		return nil, nil
	}
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil {
		return nil, err
	}
	actual := "none"
	switch {
	case mx.Null:
		actual = "null MX (the domain receives no mail)"
	case len(mx.Hosts) > 0:
		actual = strings.Join(mx.Hosts, ", ")
	}
	evidence := func(k, v string) map[string]string {
		return map[string]string{k: v, "expected": strings.Join(expected, ", "), "actual": actual}
	}
	var out []core.Finding
	for _, host := range mx.Hosts {
		if !slices.ContainsFunc(expected, func(p string) bool { return mtasts.Match(p, host) }) {
			out = append(out, core.Finding{Subject: host, Title: "Unexpected MX host", Evidence: evidence("mx", host)})
		}
	}
	for _, p := range expected {
		if !slices.ContainsFunc(mx.Hosts, func(host string) bool { return mtasts.Match(p, host) }) {
			out = append(out, core.Finding{Subject: p, Title: "Expected MX host missing", Evidence: evidence("missing", p)})
		}
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.mx.fcrdns",
	Title: "MX host lacks forward-confirmed reverse DNS",
	Description: "An address of an MX host has no PTR record, or its PTR names don't resolve back to " +
		"the same address. Many receivers penalize or reject mail from servers without " +
		"forward-confirmed reverse DNS, and MX hosts usually send mail too.",
	Remediation: "Ask the owner of the IP range (your hosting provider) to set a PTR record for each MX " +
		"address that names a host resolving back to that address.",
	Mode:       core.Passive,
	Severity:   core.SeverityLow,
	References: []string{rfc(8601, "2.7.3"), "https://support.google.com/a/answer/81126"},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	addrs, err := mxAddrs(ctx, env, mx.Hosts)
	if err != nil {
		return nil, err
	}
	type probe struct {
		host   int
		addr   netip.Addr
		ok     bool
		detail string
	}
	var probes []probe
	for h, as := range addrs {
		for _, a := range as {
			probes = append(probes, probe{host: h, addr: a})
		}
	}
	err = forEach(len(probes), func(i int) error {
		var err error
		probes[i].ok, probes[i].detail, err = confirmed(ctx, env, probes[i].addr)
		return err
	})
	if err != nil {
		return nil, err
	}
	bad := make([][]string, len(mx.Hosts))
	for _, p := range probes {
		if !p.ok {
			bad[p.host] = append(bad[p.host], p.addr.String()+" ("+p.detail+")")
		}
	}
	var out []core.Finding
	for h, host := range mx.Hosts {
		if len(bad[h]) > 0 {
			out = append(out, core.Finding{Subject: host, Evidence: map[string]string{"addresses": strings.Join(bad[h], "; ")}})
		}
	}
	return out, nil
})

func confirmed(ctx context.Context, env core.Env, a netip.Addr) (ok bool, detail string, err error) {
	rev, err := dns.ReverseAddr(a.String())
	if err != nil {
		return false, "", err
	}
	resp, err := env.Resolver.Lookup(ctx, rev, dns.TypePTR)
	if err != nil {
		return false, "", err
	}
	var names []string
	for _, rr := range resp.Records() {
		names = append(names, strings.TrimSuffix(rr.(*dns.PTR).Ptr, "."))
	}
	if len(names) == 0 {
		return false, "no PTR record", nil
	}
	for _, name := range names {
		back, err := env.Net.LookupAddrs(ctx, name)
		if err != nil && !errors.Is(err, netx.ErrNoAddress) {
			return false, "", err
		}
		for _, b := range back {
			if b == a {
				return true, "", nil
			}
		}
	}
	return false, "PTR " + strings.Join(names, ", ") + " does not resolve back", nil
}
