package dnscheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/PeacexF/seta/internal/core"
)

type caaSet struct {
	// owner is the name the records were found at: the domain or the
	// closest ancestor with CAA records.
	owner   string
	records []*dns.CAA
}

// relevantCAA climbs from name towards the public suffix, as CAs do (RFC
// 8659 §3), and returns the first non-empty CAA set.
func relevantCAA(ctx context.Context, env core.Env, name string) (*caaSet, error) {
	return core.Memoize(ctx, env.Memo, "dns.caa:"+name, func(ctx context.Context) (*caaSet, error) {
		suffix, _ := publicsuffix.PublicSuffix(name)
		for n := name; n != suffix && n != ""; {
			resp, err := env.Resolver.Lookup(ctx, n, dns.TypeCAA)
			if err != nil {
				return nil, err
			}
			var recs []*dns.CAA
			for _, rr := range resp.Records() {
				recs = append(recs, rr.(*dns.CAA))
			}
			if len(recs) > 0 {
				return &caaSet{owner: n, records: recs}, nil
			}
			_, n, _ = strings.Cut(n, ".")
		}
		return &caaSet{}, nil
	})
}

// Property tags CAs understand (RFC 8659 §4, RFC 8657).
var knownCAATags = map[string]bool{"issue": true, "issuewild": true, "iodef": true, "issuemail": true, "contactemail": true, "contactphone": true}

// caaProblem describes a record CAs would refuse to issue under by mistake.
func caaProblem(r *dns.CAA) string {
	tag := strings.ToLower(r.Tag)
	if !knownCAATags[tag] {
		if r.Flag&128 != 0 {
			return fmt.Sprintf("unknown tag %q is marked critical, so every CA must refuse to issue", r.Tag)
		}
		return ""
	}
	if tag != "issue" && tag != "issuewild" {
		return ""
	}
	// issuer-domain-name [";" parameters]; an empty value forbids issuance
	// deliberately.
	issuer, _, _ := strings.Cut(r.Value, ";")
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ""
	}
	if _, err := core.ParseDomain(issuer); err != nil || strings.ContainsAny(issuer, " \t") {
		return fmt.Sprintf("%s value %q is not a CA domain name, so no CA matches it", tag, r.Value)
	}
	return ""
}

func init() {
	set.Define(core.Meta{
		ID:    "dns.caa.missing",
		Title: "No CAA records",
		Description: "Neither the domain nor its parent domains publish CAA records, so any public CA may issue " +
			"certificates for it. CAA limits issuance to the CAs you use, which blocks mis-issuance through " +
			"other CAs' weaker validation.",
		Remediation: "Publish CAA records naming the CAs you use, e.g. \"example.com. CAA 0 issue \\\"letsencrypt.org\\\"\", " +
			"and optionally an iodef record for violation reports.",
		Mode:       core.Passive,
		Severity:   core.SeverityLow,
		References: []string{rfc(8659, "")},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		caa, err := relevantCAA(ctx, env, t.Name)
		if err != nil || len(caa.records) > 0 {
			return nil, err
		}
		return []core.Finding{{Evidence: map[string]string{"caa": "none"}}}, nil
	})

	set.Define(core.Meta{
		ID:    "dns.caa.invalid",
		Title: "CAA records block all issuance by mistake",
		Description: "The CAA records that apply to the domain contain a record CAs can't honor: an unknown " +
			"property marked critical, or an issue value that isn't a CA domain name. CAs then refuse to issue " +
			"(or renew) certificates, and the site breaks when the current certificate expires.",
		Remediation: "Fix or remove the record: issue values are CA domain names such as \"letsencrypt.org\" or " +
			"\"pki.goog\", and the critical flag (128) must only be set on tags CAs understand.",
		Mode:       core.Passive,
		Severity:   core.SeverityMedium,
		References: []string{rfc(8659, "4")},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		caa, err := relevantCAA(ctx, env, t.Name)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range caa.records {
			if p := caaProblem(r); p != "" {
				subject := fmt.Sprintf("%d %s %q", r.Flag, r.Tag, r.Value)
				out = append(out, core.Finding{Subject: subject, Evidence: map[string]string{"owner": caa.owner, "problem": p}})
			}
		}
		return out, nil
	})
}
