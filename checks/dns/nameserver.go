package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/core"
)

const nsTimeout = 5 * time.Second

// eachNameserver runs fn for every nameserver of the zone t.Name, if it is
// one. Any error fails the check, so an unreachable nameserver never looks
// fixed.
func eachNameserver(ctx context.Context, env core.Env, t core.Target, fn func(ctx context.Context, ns string) (*core.Finding, error)) ([]core.Finding, error) {
	apex, err := isApex(ctx, env, t.Name)
	if err != nil || !apex {
		return nil, err
	}
	nss, err := nameservers(ctx, env, t.Name)
	if err != nil {
		return nil, err
	}
	found := make([]*core.Finding, len(nss))
	errs := make([]error, len(nss))
	var wg sync.WaitGroup
	for i, ns := range nss {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, nsTimeout)
			defer cancel()
			found[i], errs[i] = fn(ctx, ns)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	var out []core.Finding
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}

func dialNS(ctx context.Context, env core.Env, network, ns string) (*dns.Conn, error) {
	conn, err := env.Net.Dial(ctx, network, net.JoinHostPort(ns, "53"))
	if err != nil {
		return nil, fmt.Errorf("connect to nameserver %s over %s: %w", ns, strings.ToUpper(network), err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	return &dns.Conn{Conn: conn}, nil
}

func init() {
	set.Define(core.Meta{
		ID:    "dns.axfr.allowed",
		Title: "Nameserver allows zone transfers to anyone",
		Description: "A nameserver answers AXFR requests from arbitrary clients, handing out the whole zone: " +
			"every host name, including internal and staging ones never meant to be discovered. Seta reads only " +
			"the first message of the transfer and reports how many records it held.",
		Remediation: "Restrict zone transfers to your secondary nameservers' addresses (BIND: allow-transfer; " +
			"PowerDNS: allow-axfr-ips; NSD: provide-xfr), ideally with TSIG.",
		Mode:       core.Active,
		Severity:   core.SeverityHigh,
		References: []string{rfc(5936, "6"), "https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		return eachNameserver(ctx, env, t, func(ctx context.Context, ns string) (*core.Finding, error) {
			conn, err := dialNS(ctx, env, "tcp", ns)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			q := new(dns.Msg)
			q.SetAxfr(dns.Fqdn(t.Name))
			tr := &dns.Transfer{Conn: conn, ReadTimeout: nsTimeout, WriteTimeout: nsTimeout}
			envs, err := tr.In(q, "")
			if err != nil {
				return nil, fmt.Errorf("AXFR from %s: %w", ns, err)
			}
			first, ok := <-envs
			switch {
			case !ok || first.Error != nil || len(first.RR) == 0:
				// A refusal: an error rcode, or the server closing the connection.
				return nil, nil
			}
			return &core.Finding{Subject: ns, Evidence: map[string]string{
				"records_in_first_message": strconv.Itoa(len(first.RR)),
			}}, nil
		})
	})

	set.Define(core.Meta{
		ID:    "dns.nameserver.open_resolver",
		Title: "Nameserver is an open resolver",
		Description: "A nameserver answers recursive queries for names outside its zones from anyone. Open " +
			"resolvers are used to amplify DDoS attacks and are easier targets for cache poisoning.",
		Remediation: "Disable recursion on authoritative nameservers (BIND: recursion no; or allow-recursion " +
			"limited to your own networks), and run recursive resolvers only for your own clients.",
		Mode:       core.Active,
		Severity:   core.SeverityMedium,
		References: []string{rfc(5358, ""), "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		return eachNameserver(ctx, env, t, func(ctx context.Context, ns string) (*core.Finding, error) {
			conn, err := dialNS(ctx, env, "udp", ns)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			// The root NS set is outside every customer zone: an authoritative
			// server refuses it or refers upward, only a resolver answers it.
			q := new(dns.Msg)
			q.SetQuestion(".", dns.TypeNS)
			q.RecursionDesired = true
			q.SetEdns0(1232, false)
			if err := conn.WriteMsg(q); err != nil {
				return nil, fmt.Errorf("query nameserver %s: %w", ns, err)
			}
			resp, err := conn.ReadMsg()
			if err != nil {
				return nil, fmt.Errorf("query nameserver %s: %w", ns, err)
			}
			if !resp.RecursionAvailable || resp.Rcode != dns.RcodeSuccess || resp.Authoritative || len(resp.Answer) == 0 {
				return nil, nil
			}
			return &core.Finding{Subject: ns, Evidence: map[string]string{
				"query": ". NS (recursion desired)", "answers": strconv.Itoa(len(resp.Answer)),
			}}, nil
		})
	})
}
