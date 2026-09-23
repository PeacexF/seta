package email

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/core"
)

// DefaultDNSBLs allow free queries through public resolvers. Spamhaus does
// not (it answers 127.255.255.254) and is only used with a DQS key.
var DefaultDNSBLs = []string{"bl.spamcop.net", "psbl.surriel.com"}

func dnsblZones(t core.Target) []string {
	zones := t.Email.DNSBLs
	if len(zones) == 0 {
		zones = DefaultDNSBLs
	}
	if key := t.Email.SpamhausDQSKey; key != "" {
		zones = append(slices.Clone(zones), key+".zen.dq.spamhaus.net")
	}
	return zones
}

// displayZone keeps a Spamhaus DQS key out of findings, errors and logs.
func displayZone(zone string) string {
	if strings.HasSuffix(zone, ".zen.dq.spamhaus.net") {
		return "zen.spamhaus.org (DQS)"
	}
	return zone
}

// reverseV4 turns 192.0.2.1 into 1.2.0.192.
func reverseV4(a netip.Addr) string {
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

// dnsblQuery returns the 127.0.0.0/8 codes a list returns for addr (empty
// when not listed). Anything else means the list can't be trusted right now.
func dnsblQuery(ctx context.Context, env core.Env, zone string, addr netip.Addr) ([]string, error) {
	name := reverseV4(addr) + "." + zone
	resp, err := env.Resolver.Lookup(ctx, name, dns.TypeA)
	if err != nil {
		if displayZone(zone) != zone {
			return nil, fmt.Errorf("query %s for %s failed", displayZone(zone), addr) // err would contain the key
		}
		return nil, err
	}
	zone = displayZone(zone)
	var codes []string
	for _, a := range resp.Addrs() {
		b := a.As4()
		switch {
		case !a.Is4() || b[0] != 127:
			return nil, fmt.Errorf("%s answered %s, which is not a DNSBL return code; the list may be defunct or hijacked", zone, a)
		case b[1] == 255 && b[2] == 255:
			return nil, fmt.Errorf("%s refused the query (%s); it may not allow queries via this resolver", zone, a)
		}
		codes = append(codes, a.String())
	}
	return codes, nil
}

// checkList applies the RFC 5782 §5 test points: 127.0.0.2 must be listed
// and 127.0.0.1 must not. A list failing them would produce false results.
func checkList(ctx context.Context, env core.Env, zone string) error {
	listed, err := dnsblQuery(ctx, env, zone, netip.AddrFrom4([4]byte{127, 0, 0, 2}))
	if err != nil {
		return err
	}
	if len(listed) == 0 {
		return fmt.Errorf("%s does not list its 127.0.0.2 test address; it may be defunct or blocking this resolver", displayZone(zone))
	}
	bogus, err := dnsblQuery(ctx, env, zone, netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	if err != nil {
		return err
	}
	if len(bogus) > 0 {
		return fmt.Errorf("%s lists 127.0.0.1, so it would report every address as listed", displayZone(zone))
	}
	return nil
}

var _ = define(core.Meta{
	ID:    "email.dnsbl.listed",
	Title: "Mail server is on a DNS blocklist",
	Description: "An IPv4 address of an MX host appears on a DNS blocklist. MX hosts usually also send " +
		"mail, and receivers consult these lists to reject or junk mail from listed addresses.",
	Remediation: "Find out why the address was listed (compromised account, open relay, shared IP " +
		"reputation), fix the cause, then request delisting on the blocklist's website.",
	Mode:     core.Passive,
	Severity: core.SeverityHigh,
	References: []string{
		rfc(5782, ""),
		"https://www.spamcop.net/bl.shtml",
		"https://psbl.org/",
		"https://docs.spamhaustech.com/40-real-world-usage/DQS/000-intro.html",
	},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	type ipHost struct {
		addr netip.Addr
		host string
	}
	addrs, err := mxAddrs(ctx, env, mx.Hosts)
	if err != nil {
		return nil, err
	}
	var ips []ipHost
	for h, as := range addrs {
		for _, a := range as {
			if a.Is4() && !slices.ContainsFunc(ips, func(x ipHost) bool { return x.addr == a }) {
				ips = append(ips, ipHost{a, mx.Hosts[h]})
			}
		}
	}
	zones := dnsblZones(t)
	if err := forEach(len(zones), func(i int) error { return checkList(ctx, env, zones[i]) }); err != nil {
		return nil, err
	}
	codes := make([][]string, len(zones)*len(ips))
	err = forEach(len(codes), func(i int) error {
		var err error
		codes[i], err = dnsblQuery(ctx, env, zones[i/len(ips)], ips[i%len(ips)].addr)
		return err
	})
	if err != nil {
		return nil, err
	}
	var out []core.Finding
	for i, c := range codes {
		if len(c) == 0 {
			continue
		}
		ip, list := ips[i%len(ips)], displayZone(zones[i/len(ips)])
		out = append(out, core.Finding{
			Subject: list + ":" + ip.addr.String(),
			Title:   fmt.Sprintf("%s (%s) is listed on %s", ip.addr, ip.host, list),
			Evidence: map[string]string{
				"address": ip.addr.String(),
				"mx":      ip.host,
				"codes":   strings.Join(c, ", "),
			},
		})
	}
	return out, nil
})
