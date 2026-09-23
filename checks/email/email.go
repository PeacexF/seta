// Package email implements the email posture checks: MX, SPF, DMARC, DKIM,
// MTA-STS, TLS-RPT, DNSBL and STARTTLS.
package email

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/netx"
	"github.com/PeacexF/seta/internal/registry"
)

func init() {
	for _, c := range Checks() {
		registry.Register(c)
	}
}

type check struct {
	meta core.Meta
	run  func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error)
}

func (c *check) Meta() core.Meta { return c.meta }

func (c *check) Run(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	return c.run(ctx, env, t)
}

var checks []*check

func define(meta core.Meta, run func(context.Context, core.Env, core.Target) ([]core.Finding, error)) *check {
	meta.Module = "email"
	c := &check{meta: meta, run: run}
	checks = append(checks, c)
	return c
}

func Checks() []core.Check {
	out := make([]core.Check, len(checks))
	for i, c := range checks {
		out[i] = c
	}
	return out
}

func Check(id string) core.Check {
	for _, c := range checks {
		if c.meta.ID == id {
			return c
		}
	}
	return nil
}

func rfc(n int, section string) string {
	u := fmt.Sprintf("https://www.rfc-editor.org/rfc/rfc%d", n)
	if section != "" {
		u += "#section-" + section
	}
	return u
}

type mxInfo struct {
	Hosts []string // by preference, lowercase, no trailing dot
	Null  bool
}

// ReceivesMail is false for null-MX domains and domains without MX, for
// which inbound-mail checks (MTA-STS, STARTTLS, ...) don't apply.
func (m *mxInfo) ReceivesMail() bool { return !m.Null && len(m.Hosts) > 0 }

// loadMX also serves as the existence check for the target: every check
// calls it first, so a nonexistent domain is a check error, not findings.
func loadMX(ctx context.Context, env core.Env, domain string) (*mxInfo, error) {
	return core.Memoize(ctx, env.Memo, "mx:"+domain, func(ctx context.Context) (*mxInfo, error) {
		resp, err := env.Resolver.Lookup(ctx, domain, dns.TypeMX)
		if err != nil {
			return nil, err
		}
		if resp.NXDomain() {
			return nil, fmt.Errorf("domain %s does not exist (NXDOMAIN)", domain)
		}
		mxs := resp.MX()
		slices.SortFunc(mxs, func(a, b *dns.MX) int {
			return cmp.Or(cmp.Compare(a.Preference, b.Preference), strings.Compare(a.Mx, b.Mx))
		})
		info := &mxInfo{Null: len(mxs) == 1 && mxs[0].Mx == "."}
		for _, mx := range mxs {
			host := strings.ToLower(strings.TrimSuffix(mx.Mx, "."))
			if host != "" && !slices.Contains(info.Hosts, host) {
				info.Hosts = append(info.Hosts, host)
			}
		}
		return info, nil
	})
}

// orgDomain is the organizational domain (RFC 7489 §3.2): the public
// suffix plus one label.
func orgDomain(name string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(strings.ToLower(name), "."))
	if err != nil {
		return name
	}
	return d
}

func txtRecords(ctx context.Context, env core.Env, name string, keep func(string) bool) ([]string, error) {
	resp, err := env.Resolver.Lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, txt := range resp.TXT() {
		if keep(txt) {
			out = append(out, txt)
		}
	}
	return out, nil
}

// forEach runs fn for 0..n-1, at most 8 at a time, and returns the error of
// the lowest index so results don't depend on scheduling.
func forEach(n int, fn func(i int) error) error {
	errs := make([]error, n)
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			errs[i] = fn(i)
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// mxAddrs resolves every MX host name (skipping IP literals and hosts with
// no addresses, which email.mx.unresolvable reports).
func mxAddrs(ctx context.Context, env core.Env, hosts []string) ([][]netip.Addr, error) {
	out := make([][]netip.Addr, len(hosts))
	err := forEach(len(hosts), func(i int) error {
		if _, err := netip.ParseAddr(hosts[i]); err == nil {
			return nil
		}
		addrs, err := env.Net.LookupAddrs(ctx, hosts[i])
		if errors.Is(err, netx.ErrNoAddress) {
			return nil
		}
		out[i] = addrs
		return err
	})
	return out, err
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
