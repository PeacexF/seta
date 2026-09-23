package email

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/dmarc"
	"github.com/PeacexF/seta/internal/core"
)

type dmarcInfo struct {
	// Domain is where the policy was found: the target, or its
	// organizational domain when inherited (RFC 7489 §6.6.3).
	Domain    string
	Inherited bool
	Records   []string
	Rec       *dmarc.Record
	ParseErr  error
}

// Policy is the policy that applies to the target itself.
func (d *dmarcInfo) Policy() dmarc.Policy {
	if d.Inherited && d.Rec.SP != "" {
		return d.Rec.SP
	}
	return d.Rec.P
}

func loadDMARC(ctx context.Context, env core.Env, domain string) (*dmarcInfo, error) {
	if _, err := loadMX(ctx, env, domain); err != nil {
		return nil, err
	}
	return core.Memoize(ctx, env.Memo, "dmarc:"+domain, func(ctx context.Context) (*dmarcInfo, error) {
		info := &dmarcInfo{Domain: domain}
		records, err := txtRecords(ctx, env, "_dmarc."+domain, dmarc.IsDMARC)
		if err != nil {
			return nil, err
		}
		if org := orgDomain(domain); len(records) == 0 && org != domain {
			if records, err = txtRecords(ctx, env, "_dmarc."+org, dmarc.IsDMARC); err != nil {
				return nil, err
			}
			info.Domain, info.Inherited = org, len(records) > 0
		}
		info.Records = records
		if len(records) == 1 {
			info.Rec, info.ParseErr = dmarc.Parse(records[0])
		}
		return info, nil
	})
}

func (d *dmarcInfo) evidence() map[string]string {
	e := map[string]string{"record": d.Records[0]}
	if d.Inherited {
		e["inherited_from"] = "_dmarc." + d.Domain
	}
	return e
}

var dmarcRefs = []string{rfc(7489, "")}

var _ = define(core.Meta{
	ID:    "email.dmarc.missing",
	Title: "No DMARC record",
	Description: "Neither the domain nor its organizational domain publishes a DMARC record at _dmarc. " +
		"Receivers apply no policy to mail that fails SPF and DKIM alignment, and you get no reports " +
		"about who sends mail as your domain.",
	Remediation: "Publish a TXT record at _dmarc, starting with \"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\" " +
		"and moving to p=quarantine or p=reject once reports show legitimate mail passes.",
	Mode:       core.Passive,
	Severity:   core.SeverityHigh,
	References: dmarcRefs,
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadDMARC(ctx, env, t.Name)
	if err != nil || len(info.Records) > 0 {
		return nil, err
	}
	return []core.Finding{{Evidence: map[string]string{"queried": "_dmarc." + t.Name}}}, nil
})

var _ = define(core.Meta{
	ID:    "email.dmarc.syntax",
	Title: "Invalid DMARC record",
	Description: "The DMARC record is malformed, or more than one is published. Receivers then ignore " +
		"DMARC for the domain entirely.",
	Remediation: "Publish exactly one record starting with \"v=DMARC1;\" and a valid p= tag.",
	Mode:        core.Passive,
	Severity:    core.SeverityHigh,
	References:  []string{rfc(7489, "6.3"), rfc(7489, "6.6.3")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadDMARC(ctx, env, t.Name)
	if err != nil {
		return nil, err
	}
	switch {
	case len(info.Records) > 1:
		return []core.Finding{{
			Title:    fmt.Sprintf("%d DMARC records published at _dmarc.%s", len(info.Records), info.Domain),
			Evidence: map[string]string{"records": strings.Join(info.Records, " | ")},
		}}, nil
	case info.ParseErr != nil:
		e := info.evidence()
		e["error"] = info.ParseErr.Error()
		return []core.Finding{{Evidence: e}}, nil
	}
	return nil, nil
})

var _ = define(core.Meta{
	ID:    "email.dmarc.policy_none",
	Title: "DMARC policy is p=none",
	Description: "The DMARC policy only monitors: receivers deliver mail that fails authentication as " +
		"if there were no DMARC at all. p=none is meant as a short first step, but often stays forever.",
	Remediation: "Review aggregate reports, make sure legitimate senders pass, then move to p=quarantine " +
		"and finally p=reject.",
	Mode:       core.Passive,
	Severity:   core.SeverityMedium,
	References: []string{rfc(7489, "6.3"), rfc(7489, "6.7")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadDMARC(ctx, env, t.Name)
	if err != nil || info.Rec == nil {
		return nil, err
	}
	var out []core.Finding
	if info.Policy() == dmarc.None {
		e := info.evidence()
		if info.Rec.ImplicitP {
			e["note"] = "no p= tag; treated as none because rua= is set"
		}
		out = append(out, core.Finding{Evidence: e})
	} else if !info.Inherited && info.Rec.SP == dmarc.None {
		out = append(out, core.Finding{
			Subject:  "subdomains",
			Title:    "DMARC subdomain policy is sp=none",
			Evidence: info.evidence(),
		})
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.dmarc.no_reporting",
	Title: "DMARC aggregate reporting is not configured",
	Description: "The DMARC record has no rua= address, so you never learn which servers send mail as " +
		"your domain or whether legitimate mail fails authentication. Without reports it's unsafe to " +
		"tighten the policy.",
	Remediation: "Add rua=mailto:<address> to the DMARC record, or point it at a DMARC report processor.",
	Mode:        core.Passive,
	Severity:    core.SeverityLow,
	References:  []string{rfc(7489, "7.2")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadDMARC(ctx, env, t.Name)
	if err != nil || info.Rec == nil || len(info.Rec.RUA) > 0 {
		return nil, err
	}
	return []core.Finding{{Evidence: info.evidence()}}, nil
})

var _ = define(core.Meta{
	ID:    "email.dmarc.external_auth",
	Title: "External DMARC report destination is not authorized",
	Description: "The DMARC record sends reports to a mailbox in another organization's domain, but " +
		"that domain does not publish the authorization record receivers check before sending " +
		"(<domain>._report._dmarc.<destination>). Receivers silently drop those reports.",
	Remediation: "Ask the report destination (or your DMARC vendor) to publish " +
		"\"<your-domain>._report._dmarc.<their-domain> TXT v=DMARC1\", or send reports to your own domain.",
	Mode:       core.Passive,
	Severity:   core.SeverityMedium,
	References: []string{rfc(7489, "7.1")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadDMARC(ctx, env, t.Name)
	if err != nil || info.Rec == nil {
		return nil, err
	}
	own := orgDomain(info.Domain)
	var dests []string
	for _, u := range slices.Concat(info.Rec.RUA, info.Rec.RUF) {
		if u.Domain != "" && orgDomain(u.Domain) != own && !slices.Contains(dests, u.Domain) {
			dests = append(dests, u.Domain)
		}
	}
	var out []core.Finding
	for _, dest := range dests {
		name := info.Domain + "._report._dmarc." + dest
		auth, err := txtRecords(ctx, env, name, dmarc.IsDMARC)
		if err != nil {
			return nil, err
		}
		if len(auth) == 0 {
			out = append(out, core.Finding{
				Subject:  dest,
				Title:    "DMARC reports to " + dest + " are not authorized",
				Evidence: map[string]string{"queried": name, "record": info.Records[0]},
			})
		}
	}
	return out, nil
})

func itoa(n int) string { return strconv.Itoa(n) }
