package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/tags"
	"github.com/PeacexF/seta/internal/core"
)

func isTLSRPT(txt string) bool {
	first, _, _ := strings.Cut(txt, ";")
	name, value, ok := strings.Cut(first, "=")
	return ok && strings.TrimSpace(name) == "v" && strings.TrimSpace(value) == "TLSRPTv1"
}

func parseTLSRPT(txt string) error {
	list, err := tags.Parse(txt, false)
	if err != nil {
		return err
	}
	rua, ok := list.Get("rua")
	if !ok || rua == "" {
		return errors.New("missing rua= tag")
	}
	for u := range strings.SplitSeq(rua, ",") {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(u, "mailto:") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("rua destination %q must be a mailto: or https: URI", u)
		}
	}
	return nil
}

var _ = define(core.Meta{
	ID:    "email.tlsrpt.missing",
	Title: "No TLS-RPT record",
	Description: "The domain publishes no valid TLS reporting record at _smtp._tls, so sending servers " +
		"have nowhere to report TLS failures delivering to you. You won't learn that MTA-STS or " +
		"STARTTLS is broken until mail stops arriving.",
	Remediation: "Publish \"_smtp._tls TXT v=TLSRPTv1; rua=mailto:tlsrpt@<domain>\".",
	Mode:        core.Passive,
	Severity:    core.SeverityLow,
	References:  []string{rfc(8460, "3")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	name := "_smtp._tls." + t.Name
	records, err := txtRecords(ctx, env, name, isTLSRPT)
	if err != nil {
		return nil, err
	}
	switch len(records) {
	case 0:
		return []core.Finding{{Evidence: map[string]string{"queried": name}}}, nil
	case 1:
		if err := parseTLSRPT(records[0]); err != nil {
			return []core.Finding{{
				Title:    "TLS-RPT record is invalid",
				Evidence: map[string]string{"record": records[0], "error": err.Error()},
			}}, nil
		}
		return nil, nil
	}
	return []core.Finding{{
		Title:    fmt.Sprintf("%d TLS-RPT records published; senders ignore all of them", len(records)),
		Evidence: map[string]string{"records": strings.Join(records, " | ")},
	}}, nil
})
