package email

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/spf"
	"github.com/PeacexF/seta/internal/core"
)

type spfInfo struct {
	Records  []string
	Rec      *spf.Record
	ParseErr error
	Eval     *spf.Evaluation
}

func loadSPF(ctx context.Context, env core.Env, domain string) (*spfInfo, error) {
	if _, err := loadMX(ctx, env, domain); err != nil {
		return nil, err
	}
	return core.Memoize(ctx, env.Memo, "spf:"+domain, func(ctx context.Context) (*spfInfo, error) {
		records, _, _, err := spf.Fetch(ctx, env.Resolver, domain)
		if err != nil {
			return nil, err
		}
		info := &spfInfo{Records: records}
		if len(records) != 1 {
			return info, nil
		}
		if info.Rec, info.ParseErr = spf.Parse(records[0]); info.ParseErr != nil {
			return info, nil
		}
		info.Eval, err = spf.Evaluate(ctx, env.Resolver, domain, info.Rec)
		return info, err
	})
}

var spfRefs = []string{rfc(7208, "")}

var _ = define(core.Meta{
	ID:    "email.spf.missing",
	Title: "No SPF record",
	Description: "The domain publishes no SPF record, so receivers cannot tell which servers may send " +
		"mail for it. Spoofed mail is more likely to be delivered, and DMARC can only pass via DKIM. " +
		"Domains that never send mail need a record too, to say so.",
	Remediation: "Publish a TXT record listing your senders, e.g. \"v=spf1 include:_spf.google.com -all\". " +
		"For a domain that sends no mail, publish \"v=spf1 -all\".",
	Mode:       core.Passive,
	Severity:   core.SeverityHigh,
	References: spfRefs,
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil || len(info.Records) > 0 {
		return nil, err
	}
	return []core.Finding{{}}, nil
})

var _ = define(core.Meta{
	ID:    "email.spf.multiple",
	Title: "Multiple SPF records",
	Description: "The domain publishes more than one SPF record. RFC 7208 makes this a permanent " +
		"error: receivers ignore all of them, as if the domain had no SPF at all.",
	Remediation: "Merge the records into a single \"v=spf1 ...\" TXT record.",
	Mode:        core.Passive,
	Severity:    core.SeverityHigh,
	References:  []string{rfc(7208, "4.5")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil || len(info.Records) < 2 {
		return nil, err
	}
	return []core.Finding{{
		Title:    fmt.Sprintf("%d SPF records published", len(info.Records)),
		Evidence: map[string]string{"records": strings.Join(info.Records, " | ")},
	}}, nil
})

var _ = define(core.Meta{
	ID:    "email.spf.syntax",
	Title: "Invalid SPF record",
	Description: "The SPF record, or a record it includes or redirects to, is malformed or cannot be " +
		"evaluated. Receivers treat this as a permanent error and SPF stops protecting the domain.",
	Remediation: "Fix the reported term. Included domains must publish exactly one valid SPF record.",
	Mode:        core.Passive,
	Severity:    core.SeverityHigh,
	References:  []string{rfc(7208, "4.6"), rfc(7208, "5.2")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil {
		return nil, err
	}
	if info.ParseErr != nil {
		return []core.Finding{{Evidence: map[string]string{"record": info.Records[0], "error": info.ParseErr.Error()}}}, nil
	}
	if info.Eval == nil {
		return nil, nil
	}
	var out []core.Finding
	byWhere := map[string][]string{}
	var order []string
	for _, p := range info.Eval.Problems {
		if _, ok := byWhere[p.Where]; !ok {
			order = append(order, p.Where)
		}
		byWhere[p.Where] = append(byWhere[p.Where], p.Msg)
	}
	for _, where := range order {
		title := "SPF record cannot be evaluated"
		if where != "" {
			title = "SPF " + where + " cannot be evaluated"
		}
		out = append(out, core.Finding{
			Subject:  where,
			Title:    title,
			Evidence: map[string]string{"error": strings.Join(byWhere[where], "; ")},
		})
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.spf.lookup_limit",
	Title: "SPF exceeds the 10 DNS lookup limit",
	Description: "Evaluating the SPF record takes more than 10 DNS-querying terms (include, a, mx, ptr, " +
		"exists, redirect), counted recursively through includes. Receivers stop at 10 and return a " +
		"permanent error, so SPF fails for legitimate mail. This usually happens silently when a new " +
		"SaaS sender is added.",
	Remediation: "Remove includes for services you no longer use, replace a/mx terms with ip4/ip6 ranges, " +
		"or split senders across subdomains.",
	Mode:       core.Passive,
	Severity:   core.SeverityHigh,
	References: []string{rfc(7208, "4.6.4")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil || info.Eval == nil || info.Eval.Lookups <= spf.MaxLookups {
		return nil, err
	}
	ev := info.Eval
	costs := slices.Clone(ev.Cost)
	slices.SortStableFunc(costs, func(a, b spf.TermCost) int { return cmp.Compare(b.Lookups, a.Lookups) })
	var breakdown []string
	for _, c := range costs {
		breakdown = append(breakdown, fmt.Sprintf("%s=%d", c.Term, c.Lookups))
	}
	evidence := map[string]string{
		"lookups":   strconv.Itoa(ev.Lookups),
		"breakdown": strings.Join(breakdown, ", "),
	}
	if ev.Incomplete {
		evidence["note"] = "evaluation stopped early; the real count is higher"
	}
	return []core.Finding{{
		Title:    fmt.Sprintf("SPF needs %d DNS lookups (limit is %d)", ev.Lookups, spf.MaxLookups),
		Evidence: evidence,
	}}, nil
})

var _ = define(core.Meta{
	ID:    "email.spf.void_lookups",
	Title: "SPF has too many void lookups",
	Description: "More than two DNS lookups made while evaluating SPF return no records. RFC 7208 " +
		"lets receivers fail evaluation after two, so stale includes and a/mx terms for deleted " +
		"hosts can break SPF.",
	Remediation: "Remove terms that point at names which no longer exist or have no records.",
	Mode:        core.Passive,
	Severity:    core.SeverityMedium,
	References:  []string{rfc(7208, "4.6.4")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil || info.Eval == nil || info.Eval.VoidLookups <= spf.MaxVoidLookups {
		return nil, err
	}
	return []core.Finding{{
		Title: fmt.Sprintf("SPF makes %d void lookups (limit is %d)", info.Eval.VoidLookups, spf.MaxVoidLookups),
		Evidence: map[string]string{
			"void_lookups": strconv.Itoa(info.Eval.VoidLookups),
			"terms":        strings.Join(info.Eval.Voids, ", "),
		},
	}}, nil
})

var _ = define(core.Meta{
	ID:    "email.spf.permissive_all",
	Title: "SPF allows any sender",
	Description: "The SPF policy authorizes every server on the internet: the record ends in \"+all\" " +
		"(or a bare \"all\"), or includes a record that does. \"?all\" and a missing \"all\" are " +
		"weaker problems: they make SPF neutral for unlisted senders, so it never fails.",
	Remediation: "End the record with \"-all\" (or \"~all\" while rolling out) and remove includes of " +
		"records that end in +all.",
	Mode:       core.Passive,
	Severity:   core.SeverityCritical,
	References: []string{rfc(7208, "5.1")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	info, err := loadSPF(ctx, env, t.Name)
	if err != nil || info.Eval == nil {
		return nil, err
	}
	ev := info.Eval
	var out []core.Finding
	switch {
	case !ev.HasEffective && info.Rec.Redirect == "":
		out = append(out, core.Finding{
			Severity: core.SeverityLow,
			Title:    "SPF record has no \"all\" mechanism",
			Evidence: map[string]string{"record": info.Records[0], "effect": "unlisted senders get a neutral result"},
		})
	case !ev.HasEffective:
	case ev.Effective.Qualifier == spf.Pass:
		out = append(out, core.Finding{
			Title:    "SPF record ends in +all",
			Evidence: map[string]string{"record": info.Records[0]},
		})
	case ev.Effective.Qualifier == spf.Neutral:
		out = append(out, core.Finding{
			Severity: core.SeverityLow,
			Title:    "SPF record ends in ?all",
			Evidence: map[string]string{"record": info.Records[0], "effect": "unlisted senders get a neutral result"},
		})
	}
	for _, via := range ev.PermissiveIncludes {
		out = append(out, core.Finding{
			Subject:  via,
			Title:    "SPF " + via + " authorizes any sender",
			Evidence: map[string]string{"reason": "the included record ends in +all, so the include matches every sender"},
		})
	}
	return out, nil
})

// sendsNoMail reports whether the domain's SPF record is exactly
// "v=spf1 -all", the standard way to declare that it sends no mail.
func sendsNoMail(ctx context.Context, env core.Env, domain string) (bool, error) {
	info, err := loadSPF(ctx, env, domain)
	if err != nil || info.Rec == nil {
		return false, err
	}
	m := info.Rec.Mechanisms
	return len(m) == 1 && m[0].Kind == "all" && m[0].Qualifier == spf.Fail && info.Rec.Redirect == "", nil
}
