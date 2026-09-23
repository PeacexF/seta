// Package httpcheck implements the http checks: HTTPS redirects, HSTS,
// security headers and exposed files.
package httpcheck

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/PeacexF/seta/checks/internal/checkdef"
	"github.com/PeacexF/seta/checks/internal/web"
	"github.com/PeacexF/seta/internal/core"
)

var set = &checkdef.Set{Module: "http"}

func Checks() []core.Check       { return set.Checks() }
func Check(id string) core.Check { return set.Check(id) }

const (
	// hstsMinAge is the shortest max-age not reported as weak (180 days).
	hstsMinAge = 180 * 24 * 3600
	// hstsPreloadAge is what hstspreload.org requires (1 year).
	hstsPreloadAge = 365 * 24 * 3600
)

var (
	mdnHeaders = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
	rfc6797    = "https://www.rfc-editor.org/rfc/rfc6797"
)

// httpsResponses are the hosts' HTTPS responses whose headers the HSTS
// checks read; absent implicit hosts are skipped.
func httpsResponses(ctx context.Context, env core.Env, t core.Target) ([]hostResponse, error) {
	return web.Each(ctx, web.TLSHosts(t), func(h core.Host) (hostResponse, error) {
		// Browsers honor HSTS on any HTTPS response, redirects included.
		r, err := web.Get(ctx, env, h, "https://"+h.String()+"/", "", nil)
		if err != nil || r.Header.Get("Strict-Transport-Security") != "" {
			return hostResponse{h, r}, err
		}
		next, redirects := r.Location()
		if !redirects {
			return hostResponse{h, r}, nil
		}
		// A host that only sends visitors elsewhere is judged where they land.
		sameHost := func(next *url.URL) bool { return next.Scheme == "https" && strings.EqualFold(next.Host, h.String()) }
		if !sameHost(next) {
			return hostResponse{}, web.ErrAbsent
		}
		if r, err = web.Get(ctx, env, h, "https://"+h.String()+"/", "same-host", sameHost); err != nil {
			return hostResponse{}, err
		}
		if _, stillRedirects := r.Location(); stillRedirects && r.Header.Get("Strict-Transport-Security") == "" {
			return hostResponse{}, web.ErrAbsent
		}
		return hostResponse{h, r}, nil
	})
}

type hostResponse struct {
	host core.Host
	resp *web.Response
}

type hsts struct {
	raw               string
	maxAge            int
	includeSubDomains bool
	preload           bool
	invalid           string
}

// parseHSTS follows RFC 6797 §6.1: directives are case-insensitive, may be
// quoted, and max-age is required.
func parseHSTS(v string) hsts {
	h := hsts{raw: v, maxAge: -1}
	seen := map[string]bool{}
	for d := range strings.SplitSeq(v, ";") {
		name, val, _ := strings.Cut(strings.TrimSpace(d), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if seen[name] {
			h.invalid = "directive " + name + " appears more than once"
		}
		seen[name] = true
		switch name {
		case "max-age":
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
			if err != nil || n < 0 {
				h.invalid = "invalid max-age " + strconv.Quote(val)
				continue
			}
			h.maxAge = n
		case "includesubdomains":
			h.includeSubDomains = true
		case "preload":
			h.preload = true
		}
	}
	if h.maxAge < 0 && h.invalid == "" {
		h.invalid = "no max-age directive"
	}
	return h
}

func init() {
	set.Define(core.Meta{
		ID:    "http.redirect.missing",
		Title: "HTTP doesn't redirect to HTTPS",
		Description: "The host answers plain-HTTP requests on port 80 without redirecting them to HTTPS, so " +
			"visitors who type the bare name or follow an old http:// link use an unencrypted connection " +
			"that anyone on the network can read and modify.",
		Remediation: "Answer every request on port 80 with a 301 (or 308) redirect to the same URL over https://.",
		Mode:        core.Passive,
		Severity:    core.SeverityMedium,
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_redirections"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		var hosts []core.Host
		for _, h := range web.TLSHosts(t) {
			if h.Port == 443 {
				hosts = append(hosts, h)
			}
		}
		type result struct {
			host core.Host
			resp *web.Response
		}
		rs, err := web.Each(ctx, hosts, func(h core.Host) (result, error) {
			// Port 80 is often firewalled rather than closed; either way no
			// plain-HTTP site is served, so there's nothing to redirect.
			plain := core.Host{Name: h.Name, Port: 80}
			r, err := web.Get(ctx, env, plain, "http://"+h.Name+"/", "plain", func(next *url.URL) bool { return next.Scheme == "http" })
			if _, ok := errors.AsType[*web.ConnectError](err); ok {
				return result{}, web.ErrAbsent
			}
			return result{h, r}, err
		})
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range rs {
			if next, ok := r.resp.Location(); ok && next.Scheme == "https" {
				continue
			}
			ev := map[string]string{"status": strconv.Itoa(r.resp.Status), "final_url": r.resp.URL}
			if len(r.resp.Redirects) > 0 {
				ev["redirects"] = strings.Join(r.resp.Redirects, " → ")
			}
			out = append(out, core.Finding{Subject: r.host.Name, Evidence: ev})
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "http.hsts.missing",
		Title: "No HSTS header",
		Description: "The host's HTTPS responses have no Strict-Transport-Security header, so browsers " +
			"will keep trying plain HTTP first, and an attacker on the network can strip the redirect to HTTPS.",
		Remediation: "Send \"Strict-Transport-Security: max-age=31536000; includeSubDomains\" on every HTTPS response " +
			"once the whole site works over HTTPS.",
		Mode:       core.Passive,
		Severity:   core.SeverityMedium,
		References: []string{rfc6797, mdnHeaders + "Strict-Transport-Security"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		rs, err := httpsResponses(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range rs {
			if r.resp.Header.Get("Strict-Transport-Security") == "" {
				out = append(out, core.Finding{Subject: r.host.String(), Evidence: map[string]string{"status": strconv.Itoa(r.resp.Status)}})
			}
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "http.hsts.weak",
		Title: "HSTS header is invalid or short-lived",
		Description: "The Strict-Transport-Security header is malformed, or its max-age is under 180 days, so " +
			"browsers forget it quickly and returning visitors are exposed to HTTPS stripping again. " +
			"max-age=0 turns HSTS off.",
		Remediation: "Use a max-age of at least 15552000 (180 days); 31536000 (a year) is the common choice.",
		Mode:        core.Passive,
		Severity:    core.SeverityLow,
		References:  []string{rfc6797 + "#section-6.1"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		rs, err := httpsResponses(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range rs {
			v := r.resp.Header.Get("Strict-Transport-Security")
			if v == "" {
				continue
			}
			h := parseHSTS(v)
			switch {
			case h.invalid != "":
				out = append(out, core.Finding{Subject: r.host.String(), Evidence: map[string]string{"header": v, "problem": h.invalid}})
			case h.maxAge < hstsMinAge:
				out = append(out, core.Finding{Subject: r.host.String(), Evidence: map[string]string{"header": v, "max_age": strconv.Itoa(h.maxAge)}})
			}
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "http.hsts.preload_not_ready",
		Title: "HSTS asks for preloading but doesn't qualify",
		Description: "The domain's HSTS header carries the preload directive, but the domain doesn't meet " +
			"the requirements of the browsers' HSTS preload list (max-age of at least a year, includeSubDomains, " +
			"and an HTTP-to-HTTPS redirect on the same host), so a preload submission would be rejected.",
		Remediation: "Serve \"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\" on the apex " +
			"domain and redirect http:// to https:// on the same host first, or drop the preload directive.",
		Mode:       core.Passive,
		Severity:   core.SeverityLow,
		References: []string{"https://hstspreload.org/#submission-requirements"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		apex := core.Host{Name: t.Name, Port: 443}
		r, err := web.Get(ctx, env, apex, "https://"+t.Name+"/", "", nil)
		if errors.Is(err, web.ErrAbsent) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		v := r.Header.Get("Strict-Transport-Security")
		h := parseHSTS(v)
		if !h.preload {
			return nil, nil
		}
		var problems []string
		if h.maxAge < hstsPreloadAge {
			problems = append(problems, fmt.Sprintf("max-age %d is under 31536000", h.maxAge))
		}
		if !h.includeSubDomains {
			problems = append(problems, "no includeSubDomains")
		}
		plain, err := web.Get(ctx, env, core.Host{Name: t.Name, Port: 80}, "http://"+t.Name+"/", "", nil)
		if _, ok := errors.AsType[*web.ConnectError](err); err != nil && !ok && !errors.Is(err, web.ErrAbsent) {
			return nil, err
		}
		if err == nil {
			loc, _ := url.Parse(plain.Header.Get("Location"))
			if plain.Status < 300 || plain.Status > 399 || loc == nil || loc.Scheme != "https" || !strings.EqualFold(loc.Hostname(), t.Name) {
				problems = append(problems, "http://"+t.Name+"/ doesn't redirect to https://"+t.Name+" first")
			}
		}
		if len(problems) == 0 {
			return nil, nil
		}
		return []core.Finding{{Subject: t.Name, Evidence: map[string]string{"header": v, "problems": strings.Join(problems, "; ")}}}, nil
	})
}

// page is a fetched page whose headers are evaluated once, however many
// configured URLs redirect to it.
type page struct {
	subject string
	resp    *web.Response
	html    bool
}

// pages fetches the target's pages, following redirects. Pages that end up
// outside the target (a hosted login, a CDN error page) or on an error
// status are skipped: their headers aren't the target's to fix.
func pages(ctx context.Context, env core.Env, t core.Target) ([]page, error) {
	type fetched struct {
		p    web.Page
		resp *web.Response
	}
	rs, err := web.Each(ctx, web.Pages(t), func(p web.Page) (fetched, error) {
		r, err := web.Get(ctx, env, p.Host, p.URL, "in-scope", func(next *url.URL) bool { return inScope(t, next.Hostname()) })
		return fetched{p, r}, err
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []page
	for _, f := range rs {
		final, _ := url.Parse(f.resp.URL)
		if f.resp.Status < 200 || f.resp.Status > 299 {
			// A redirect off the target (a hosted login) is left alone.
			if f.p.Host.Explicit && f.resp.Status >= 400 {
				return nil, fmt.Errorf("GET %s: HTTP %d", f.p.URL, f.resp.Status)
			}
			continue
		}
		if !inScope(t, final.Hostname()) || seen[f.resp.URL] {
			continue
		}
		seen[f.resp.URL] = true
		subject := final.Host
		if final.Path != "" && final.Path != "/" {
			subject += final.Path
		}
		mt, _, _ := mime.ParseMediaType(f.resp.Header.Get("Content-Type"))
		out = append(out, page{subject: subject, resp: f.resp, html: mt == "text/html" || mt == "application/xhtml+xml"})
	}
	return out, nil
}

func inScope(t core.Target, host string) bool {
	host = strings.ToLower(host)
	if host == t.Name || strings.HasSuffix(host, "."+t.Name) {
		return true
	}
	return slices.ContainsFunc(t.Hosts, func(h core.Host) bool { return h.Name == host })
}

// headerCheck defines a check that inspects each page's headers.
func headerCheck(meta core.Meta, htmlOnly bool, missing func(h http.Header) (bool, map[string]string)) {
	set.Define(meta, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		ps, err := pages(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, p := range ps {
			if htmlOnly && !p.html {
				continue
			}
			if bad, ev := missing(p.resp.Header); bad {
				if ev == nil {
					ev = map[string]string{}
				}
				ev["url"] = p.resp.URL
				out = append(out, core.Finding{Subject: p.subject, Evidence: ev})
			}
		}
		return out, nil
	})
}

var frameAncestors = regexp.MustCompile(`(?i)(^|;)\s*frame-ancestors\s`)

func init() {
	headerCheck(core.Meta{
		ID:    "http.headers.csp_missing",
		Title: "No Content-Security-Policy",
		Description: "The page sets no Content-Security-Policy, so a single cross-site scripting bug lets an " +
			"attacker run any script and load it from anywhere. A report-only policy doesn't count.",
		Remediation: "Add a Content-Security-Policy header. Start with Content-Security-Policy-Report-Only to find " +
			"what the page loads, then enforce a policy such as \"default-src 'self'; object-src 'none'; base-uri 'none'\".",
		Mode:       core.Passive,
		Severity:   core.SeverityLow,
		References: []string{mdnHeaders + "Content-Security-Policy", "https://www.w3.org/TR/CSP3/"},
	}, true, func(h http.Header) (bool, map[string]string) {
		return h.Get("Content-Security-Policy") == "", nil
	})

	headerCheck(core.Meta{
		ID:    "http.headers.frame_protection_missing",
		Title: "Page can be framed by other sites",
		Description: "The page sets neither X-Frame-Options nor a CSP frame-ancestors directive, so any site can " +
			"embed it in a frame and trick visitors into clicking on it (clickjacking).",
		Remediation: "Send \"Content-Security-Policy: frame-ancestors 'self'\" (or 'none'), or \"X-Frame-Options: DENY\" " +
			"for older browsers.",
		Mode:       core.Passive,
		Severity:   core.SeverityLow,
		References: []string{mdnHeaders + "X-Frame-Options", "https://owasp.org/www-community/attacks/Clickjacking"},
	}, true, func(h http.Header) (bool, map[string]string) {
		xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
		return xfo != "DENY" && xfo != "SAMEORIGIN" && !frameAncestors.MatchString(h.Get("Content-Security-Policy")), nil
	})

	headerCheck(core.Meta{
		ID:    "http.headers.nosniff_missing",
		Title: "No X-Content-Type-Options: nosniff",
		Description: "Without \"X-Content-Type-Options: nosniff\", browsers may guess a response's type from its " +
			"content, so an uploaded file served as text can be executed as script or style.",
		Remediation: "Send \"X-Content-Type-Options: nosniff\" on every response.",
		Mode:        core.Passive,
		Severity:    core.SeverityLow,
		References:  []string{mdnHeaders + "X-Content-Type-Options"},
	}, false, func(h http.Header) (bool, map[string]string) {
		return !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff"), nil
	})

	headerCheck(core.Meta{
		ID:    "http.headers.referrer_policy_missing",
		Title: "No Referrer-Policy",
		Description: "The page sets no Referrer-Policy. Current browsers default to strict-origin-when-cross-origin, " +
			"but older ones send full URLs, including paths and query strings, to every site the page links to.",
		Remediation: "Send \"Referrer-Policy: strict-origin-when-cross-origin\" (or stricter).",
		Mode:        core.Passive,
		Severity:    core.SeverityInfo,
		References:  []string{mdnHeaders + "Referrer-Policy"},
	}, true, func(h http.Header) (bool, map[string]string) {
		return h.Get("Referrer-Policy") == "", nil
	})
}

// sensitivePaths are files that leak source or secrets when served. Each
// needs content that proves it's the real file, since many sites answer
// every path with their home page.
var sensitivePaths = []struct {
	path     string
	severity core.Severity
	match    func(body string) (bool, map[string]string)
}{
	{"/.git/HEAD", core.SeverityHigh, func(body string) (bool, map[string]string) {
		line, _, _ := strings.Cut(strings.TrimSpace(body), "\n")
		if gitRef.MatchString(line) {
			return true, map[string]string{"content": line}
		}
		return false, nil
	}},
	{"/.env", core.SeverityCritical, func(body string) (bool, map[string]string) {
		var names []string
		for line := range strings.SplitSeq(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			m := envLine.FindStringSubmatch(line)
			if m == nil {
				return false, nil
			}
			names = append(names, m[1])
		}
		if len(names) == 0 {
			return false, nil
		}
		// Only the names: the values are the secrets.
		if len(names) > 8 {
			names = append(names[:8], "…")
		}
		return true, map[string]string{"variables": strings.Join(names, ", ")}
	}},
}

var (
	gitRef  = regexp.MustCompile(`^(ref: refs/\S+|[0-9a-f]{40}|[0-9a-f]{64})$`)
	envLine = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)
)

func init() {
	set.Define(core.Meta{
		ID:    "http.exposure.sensitive_path",
		Title: "Sensitive file is publicly readable",
		Description: "The web server serves a file that should never be public: /.git/HEAD means the whole Git " +
			"repository (source code and history, often with credentials) can be downloaded, and /.env usually " +
			"holds database passwords and API keys. Seta reads only these files and reports variable names, " +
			"never values.",
		Remediation: "Deny access to dotfiles in the web server (e.g. nginx \"location ~ /\\. { deny all; }\"), deploy " +
			"without the .git directory, and rotate every secret the exposed files contained.",
		Mode:       core.Active,
		Severity:   core.SeverityHigh,
		References: []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		type probe struct {
			host core.Host
			i    int
		}
		var probes []probe
		for _, h := range web.TLSHosts(t) {
			for i := range sensitivePaths {
				probes = append(probes, probe{h, i})
			}
		}
		found, err := web.Each(ctx, probes, func(p probe) (*core.Finding, error) {
			sp := sensitivePaths[p.i]
			r, err := web.Get(ctx, env, p.host, "https://"+p.host.String()+sp.path, "", nil)
			if err != nil || r.Status != http.StatusOK {
				return nil, err
			}
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt == "text/html" {
				return nil, nil
			}
			ok, ev := sp.match(string(r.Body))
			if !ok {
				return nil, nil
			}
			ev["url"] = "https://" + p.host.String() + sp.path
			return &core.Finding{Subject: p.host.String() + sp.path, Severity: sp.severity, Evidence: ev}, nil
		})
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, f := range found {
			if f != nil {
				out = append(out, *f)
			}
		}
		return out, nil
	})
}
