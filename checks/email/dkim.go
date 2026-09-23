package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/dkim"
	"github.com/PeacexF/seta/internal/core"
)

// CommonSelectors are tried when no selectors are configured. DKIM
// selectors can't be enumerated from DNS, so these are only guesses.
var CommonSelectors = []string{"google", "selector1", "selector2", "default", "k1", "s1", "mail"}

type dkimSelector struct {
	Name     string
	Records  []string
	Key      *dkim.Key
	ParseErr error
}

func (s dkimSelector) usable() bool { return s.Key != nil && !s.Key.Revoked }

func loadDKIM(ctx context.Context, env core.Env, t core.Target) (selectors []dkimSelector, guessed bool, err error) {
	if _, err := loadMX(ctx, env, t.Name); err != nil {
		return nil, false, err
	}
	names, guessed := t.Email.DKIMSelectors, t.Email.SelectorsGuessed
	if len(names) == 0 {
		names, guessed = CommonSelectors, true
	}
	selectors, err = core.Memoize(ctx, env.Memo, "dkim:"+t.Name, func(ctx context.Context) ([]dkimSelector, error) {
		out := make([]dkimSelector, len(names))
		err := forEach(len(names), func(i int) error {
			s := &out[i]
			s.Name = names[i]
			var err error
			if s.Records, err = txtRecords(ctx, env, s.Name+"._domainkey."+t.Name, dkim.IsKey); err != nil {
				return err
			}
			if len(s.Records) > 0 {
				// Several keys under one selector is a misconfiguration; judge the first.
				s.Key, s.ParseErr = dkim.Parse(s.Records[0])
			}
			return nil
		})
		return out, err
	})
	return selectors, guessed, err
}

var _ = define(core.Meta{
	ID:    "email.dkim.missing",
	Title: "DKIM key not found",
	Description: "A configured DKIM selector publishes no usable key at <selector>._domainkey, so " +
		"signatures made with it fail verification. Selectors can't be discovered from DNS: without " +
		"configured selectors Seta only tries common names, and finding none there doesn't mean the " +
		"domain lacks DKIM.",
	Remediation: "Publish the public key your mail provider gives you at <selector>._domainkey.<domain>, " +
		"or remove the selector from the configuration if it's no longer used.",
	Mode:       core.Passive,
	Severity:   core.SeverityMedium,
	References: []string{rfc(6376, "3.6.2")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	selectors, guessed, err := loadDKIM(ctx, env, t)
	if err != nil {
		return nil, err
	}
	if guessed {
		if quiet, err := sendsNoMail(ctx, env, t.Name); err != nil || quiet {
			return nil, err
		}
		var tried []string
		for _, s := range selectors {
			if s.usable() {
				return nil, nil
			}
			tried = append(tried, s.Name)
		}
		return []core.Finding{{
			Subject:  "common-selectors",
			Severity: core.SeverityInfo,
			Title:    "No DKIM key found at common selectors (DKIM may still be set up)",
			Evidence: map[string]string{"selectors_tried": strings.Join(tried, ", ")},
			Remediation: "Configure your real DKIM selectors so Seta can check them. They appear in the " +
				"s= tag of the DKIM-Signature header of mail you send.",
		}}, nil
	}
	var out []core.Finding
	for _, s := range selectors {
		f := core.Finding{Subject: "selector:" + s.Name, Evidence: map[string]string{"queried": s.Name + "._domainkey." + t.Name}}
		switch {
		case len(s.Records) == 0:
			f.Title = fmt.Sprintf("No DKIM key for selector %s", s.Name)
		case s.ParseErr != nil:
			f.Title = fmt.Sprintf("DKIM key for selector %s is invalid", s.Name)
			f.Evidence["error"] = s.ParseErr.Error()
		case s.Key.Revoked:
			f.Title = fmt.Sprintf("DKIM key for selector %s is revoked (empty p=)", s.Name)
		default:
			continue
		}
		out = append(out, f)
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.dkim.weak_key",
	Title: "DKIM RSA key is too short",
	Description: "A DKIM selector publishes an RSA key shorter than 2048 bits. 1024-bit keys are " +
		"considered breakable by well-resourced attackers, and anything shorter can be factored " +
		"cheaply, letting anyone forge signatures for the domain.",
	Remediation: "Generate a 2048-bit key with your mail provider, publish it under a new selector, " +
		"switch signing to it, then revoke the old selector.",
	Mode:       core.Passive,
	Severity:   core.SeverityHigh,
	References: []string{rfc(8301, "3.2")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	selectors, _, err := loadDKIM(ctx, env, t)
	if err != nil {
		return nil, err
	}
	var out []core.Finding
	for _, s := range selectors {
		if !s.usable() || s.Key.Type != "rsa" || s.Key.Bits >= 2048 {
			continue
		}
		f := core.Finding{
			Subject:  "selector:" + s.Name,
			Title:    fmt.Sprintf("DKIM key for selector %s is %d-bit RSA", s.Name, s.Key.Bits),
			Evidence: map[string]string{"bits": itoa(s.Key.Bits)},
		}
		if s.Key.Bits < 1024 {
			f.Severity = core.SeverityCritical
		}
		out = append(out, f)
	}
	return out, nil
})
