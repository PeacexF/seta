package dnscheck

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/checks/internal/web"
	"github.com/PeacexF/seta/internal/core"
)

// service is a hosting provider where a dangling CNAME can be claimed by
// whoever creates the resource it names. Only services listed as vulnerable
// by can-i-take-over-xyz are included; "edge case" services would produce
// false alarms.
type service struct {
	name     string
	suffixes []string
	// nxdomain: the CNAME target not existing means it can be claimed.
	nxdomain bool
	// body: the service's page for an unclaimed name contains this.
	body string
	// pattern matches targets suffixes can't describe.
	pattern *regexp.Regexp
}

var services = []service{
	{name: "Microsoft Azure", nxdomain: true, suffixes: []string{
		"cloudapp.net", "cloudapp.azure.com", "azurewebsites.net", "blob.core.windows.net", "azure-api.net",
		"azurehdinsight.net", "azureedge.net", "azurecontainer.io", "database.windows.net", "azuredatalakestore.net",
		"search.windows.net", "azurecr.io", "redis.cache.windows.net", "servicebus.windows.net", "trafficmanager.net",
	}},
	{name: "AWS Elastic Beanstalk", nxdomain: true, suffixes: []string{"elasticbeanstalk.com"}},
	// Bucket endpoints: bucket.s3.amazonaws.com, bucket.s3.eu-west-1.amazonaws.com,
	// bucket.s3-website-us-east-1.amazonaws.com, bucket.s3-website.eu-west-1.amazonaws.com.
	{name: "AWS S3", pattern: regexp.MustCompile(`\.s3(-website)?([.-][a-z0-9-]+)?\.amazonaws\.com$`), body: "NoSuchBucket"},
	{name: "GitHub Pages", suffixes: []string{"github.io"}, body: "There isn't a GitHub Pages site here."},
	{name: "Bitbucket", suffixes: []string{"bitbucket.io"}, body: "Repository not found"},
	{name: "Ghost", suffixes: []string{"ghost.io"}, body: "Failed to resolve DNS path for this host"},
	{name: "Pantheon", suffixes: []string{"pantheonsite.io"}, body: "The gods are wise, but do not know of the site which you seek."},
	{name: "Surge.sh", suffixes: []string{"surge.sh"}, body: "project not found"},
	{name: "ReadMe", suffixes: []string{"readme.io"}, body: "Project doesnt exist... yet!"},
	{name: "Help Scout", suffixes: []string{"helpscoutdocs.com"}, body: "No settings were found for this company:"},
	{name: "Helpjuice", suffixes: []string{"helpjuice.com"}, body: "We could not find what you're looking for."},
	{name: "WordPress.com", suffixes: []string{"wordpress.com"}, body: "Do you want to register"},
	{name: "Kinsta", suffixes: []string{"kinsta.cloud"}, body: "No Site For Domain"},
	{name: "JetBrains YouTrack", suffixes: []string{"myjetbrains.com"}, body: "is not a registered InCloud YouTrack"},
	{name: "Uberflip", suffixes: []string{"read.uberflip.com"}, body: "The URL you've accessed does not provide a hub."},
	{name: "Agile CRM", suffixes: []string{"agilecrm.com"}, body: "Sorry, this page is no longer available."},
	{name: "Ngrok", suffixes: []string{"ngrok.io"}, body: "ngrok.io not found"},
}

func matchService(target string) *service {
	for i, s := range services {
		if s.pattern != nil && s.pattern.MatchString(target) {
			return &services[i]
		}
		for _, suffix := range s.suffixes {
			if target == suffix || strings.HasSuffix(target, "."+suffix) {
				return &services[i]
			}
		}
	}
	return nil
}

// cnameChain is how a name resolves through CNAMEs.
type cnameChain struct {
	name    string
	targets []string
	// dangling: the last target doesn't exist.
	dangling bool
}

func (c cnameChain) String() string {
	return strings.Join(append([]string{c.name}, c.targets...), " → ")
}

func (c cnameChain) last() string { return c.targets[len(c.targets)-1] }

// takeoverNames are the target's names that could point at a service: the
// domain, its web hosts and the hosts of its URLs.
func takeoverNames(t core.Target) []string {
	names := []string{t.Name}
	for _, h := range web.TLSHosts(t) {
		names = append(names, h.Name)
	}
	for _, p := range web.Pages(t) {
		names = append(names, p.Host.Name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// chains resolves each name and returns those that go through a CNAME.
func chains(ctx context.Context, env core.Env, t core.Target) ([]cnameChain, error) {
	return core.Memoize(ctx, env.Memo, "dns.cnames:"+t.Name, func(ctx context.Context) ([]cnameChain, error) {
		var out []cnameChain
		for _, name := range takeoverNames(t) {
			resp, err := env.Resolver.Lookup(ctx, name, dns.TypeA)
			if err != nil {
				return nil, err
			}
			c := cnameChain{name: name}
			for _, rr := range resp.Answer {
				if cn, ok := rr.(*dns.CNAME); ok {
					c.targets = append(c.targets, strings.TrimSuffix(strings.ToLower(cn.Target), "."))
				}
			}
			if len(c.targets) == 0 {
				continue
			}
			c.dangling = resp.NXDomain()
			out = append(out, c)
		}
		return out, nil
	})
}

// claimable returns the service the chain points at and whether its
// fingerprint says the resource is unclaimed.
func claimable(ctx context.Context, env core.Env, c cnameChain) (*service, string, error) {
	var svc *service
	for _, target := range c.targets {
		if svc = matchService(target); svc != nil {
			break
		}
	}
	switch {
	case svc == nil:
		return nil, "", nil
	case svc.nxdomain:
		if c.dangling {
			return svc, "CNAME target " + c.last() + " does not exist", nil
		}
		return svc, "", nil
	case c.dangling:
		return svc, "", nil // nothing answers the fingerprint request; cname.dangling reports it
	}
	// Unclaimed resources still answer, with the service's "not found" page.
	resp, err := web.Get(ctx, env, core.Host{Name: c.name, Port: 80}, "http://"+c.name+"/", "", nil)
	if errors.Is(err, web.ErrAbsent) {
		return svc, "", nil
	}
	if _, unreachable := errors.AsType[*web.ConnectError](err); unreachable {
		return svc, "", nil
	} else if err != nil {
		return nil, "", err
	}
	if strings.Contains(string(resp.Body), svc.body) {
		return svc, "page says " + `"` + svc.body + `"`, nil
	}
	return svc, "", nil
}

func init() {
	set.Define(core.Meta{
		ID:    "dns.takeover.possible",
		Title: "Subdomain can be taken over",
		Description: "A CNAME points at a cloud or SaaS resource (a storage bucket, an app, a Pages site) that no " +
			"longer exists, on a service where anyone can create a resource with that name. Whoever claims it " +
			"serves their content, cookies and phishing pages on your domain. Seta only looks for the service's " +
			"\"doesn't exist\" signature and never tries to claim anything.",
		Remediation: "Delete the CNAME record now, or recreate the resource it points at in your own account. " +
			"Remove DNS records before deprovisioning the resources they point at.",
		Mode:       core.Passive,
		Severity:   core.SeverityHigh,
		References: []string{"https://github.com/EdOverflow/can-i-take-over-xyz", "https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		cs, err := chains(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, c := range cs {
			svc, why, err := claimable(ctx, env, c)
			if err != nil {
				return nil, err
			}
			if why != "" {
				out = append(out, core.Finding{Subject: c.name, Evidence: map[string]string{
					"cname": c.String(), "service": svc.name, "fingerprint": why}})
			}
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "dns.cname.dangling",
		Title: "CNAME points at a name that doesn't exist",
		Description: "A CNAME's target doesn't exist (NXDOMAIN), so the name is broken. If the target's domain " +
			"is unregistered or on a service that lets anyone create that name, it can be taken over.",
		Remediation: "Remove the CNAME record, or point it at a name that exists. Check whether the target's " +
			"domain has expired.",
		Mode:       core.Passive,
		Severity:   core.SeverityMedium,
		References: []string{rfc(1034, "3.6.2")},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		cs, err := chains(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, c := range cs {
			if !c.dangling {
				continue
			}
			// Known services are dns.takeover.possible's finding.
			if svc, why, _ := claimable(ctx, env, c); svc != nil && why != "" {
				continue
			}
			out = append(out, core.Finding{Subject: c.name, Evidence: map[string]string{"cname": c.String()}})
		}
		return out, nil
	})
}
