// Package dnscheck implements the dns checks: DNSSEC, CAA, dangling CNAMEs
// and subdomain takeover, and nameserver misconfigurations.
package dnscheck

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/checks/internal/checkdef"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
)

var set = &checkdef.Set{Module: "dns"}

func Checks() []core.Check       { return set.Checks() }
func Check(id string) core.Check { return set.Check(id) }

func rfc(n int, section string) string {
	u := "https://www.rfc-editor.org/rfc/rfc" + strconv.Itoa(n)
	if section != "" {
		u += "#section-" + section
	}
	return u
}

// isApex reports whether name is a zone apex (has its own SOA). Zone-level
// checks (DNSSEC, nameservers) only apply there.
func isApex(ctx context.Context, env core.Env, name string) (bool, error) {
	resp, err := env.Resolver.Lookup(ctx, name, dns.TypeSOA)
	if err != nil {
		return false, err
	}
	for _, rr := range resp.Records() {
		if strings.EqualFold(rr.Header().Name, dnsx.CanonicalName(name)) {
			return true, nil
		}
	}
	return false, nil
}

// nameservers returns the zone's NS host names, sorted.
func nameservers(ctx context.Context, env core.Env, zone string) ([]string, error) {
	resp, err := env.Resolver.Lookup(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Records() {
		out = append(out, strings.TrimSuffix(strings.ToLower(rr.(*dns.NS).Ns), "."))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
