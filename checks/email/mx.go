// Package email implements the email posture checks: MX, SPF, DMARC, DKIM,
// MTA-STS, TLS-RPT, STARTTLS, and DNSBL.
package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/registry"
)

func init() {
	registry.Register(MXMissing{})
}

// MXMissing reports domains that publish neither MX records nor a null MX.
type MXMissing struct{}

func (MXMissing) Meta() core.Meta {
	return core.Meta{
		ID:     "email.mx.missing",
		Module: "email",
		Title:  "No MX records",
		Description: "The domain publishes no MX records. Senders then fall back to the domain's " +
			"A/AAAA records (the \"implicit MX\" of RFC 5321), which is rarely intended: mail is either " +
			"delivered to a web server or bounces after retrying for days. Domains that do not receive " +
			"mail should say so explicitly with a null MX record (RFC 7505).",
		Remediation: "Publish MX records pointing at your mail servers. If the domain does not receive mail, " +
			"publish a null MX record instead (\"@ IN MX 0 .\") so senders fail fast.",
		Mode:     core.Passive,
		Severity: core.SeverityHigh,
		References: []string{
			"https://www.rfc-editor.org/rfc/rfc5321#section-5.1",
			"https://www.rfc-editor.org/rfc/rfc7505",
		},
	}
}

func (MXMissing) Run(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	resp, err := env.Resolver.Lookup(ctx, t.Name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	if resp.NXDomain() {
		return nil, fmt.Errorf("domain %s does not exist (NXDOMAIN)", t.Name)
	}
	if len(resp.MX()) > 0 {
		// Real MX hosts or a null MX: either way the domain has stated its intent.
		return nil, nil
	}

	evidence := map[string]string{"mx_records": "none"}
	evidence["implicit_mx"] = implicitMX(ctx, env, t.Name)
	return []core.Finding{{Evidence: evidence}}, nil
}

// implicitMX describes where senders will deliver in the absence of MX
// records. Lookup failures only degrade the evidence, not the finding.
func implicitMX(ctx context.Context, env core.Env, name string) string {
	var addrs []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := env.Resolver.Lookup(ctx, name, qtype)
		if err != nil {
			return "unknown (" + err.Error() + ")"
		}
		for _, a := range resp.Addrs() {
			addrs = append(addrs, a.String())
		}
	}
	if len(addrs) == 0 {
		return "none: mail to this domain is undeliverable"
	}
	return strings.Join(addrs, ", ")
}
